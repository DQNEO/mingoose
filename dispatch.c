#include "mingoose.h"

static int remove_directory(struct mg_connection *conn, const char *dir) {
    char path[PATH_MAX];
    struct dirent *dp;
    DIR *dirp;
    struct de de;

    if ((dirp = opendir(dir)) == NULL) {
        return 0;
    } else {
        de.conn = conn;

        while ((dp = readdir(dirp)) != NULL) {
            // Do not show current dir, but show hidden files
            if (!strcmp(dp->d_name, ".") ||
                !strcmp(dp->d_name, "..")) {
                continue;
            }

            mg_snprintf(path, sizeof(path), "%s%c%s", dir, '/', dp->d_name);

            // If we don't memset stat structure to zero, mtime will have
            // garbage and strftime() will segfault later on in
            // print_dir_entry(). memset is required only if mg_stat()
            // fails. For more details, see
            // http://code.google.com/p/mongoose/issues/detail?id=79
            memset(&de.file, 0, sizeof(de.file));
            mg_stat(path, &de.file);
            if(de.file.modification_time) {
                if(de.file.is_directory) {
                    remove_directory(conn, path);
                } else {
                    mg_remove(path);
                }
            }

        }
        (void) closedir(dirp);

        rmdir(dir);
    }

    return 1;
}


static void handle_delete_request(struct mg_connection *conn,
                                  const char *path) {
    struct file file = STRUCT_FILE_INITIALIZER;

    if (!mg_stat(path, &file)) {
        response_error(conn, 404, "Not Found", "%s", "File not found");
    } else if (!file.modification_time) {
        response_error(conn, 500, http_500_error, "remove(%s): %s", path,
                        strerror(ERRNO));
    } else if (file.is_directory) {
        remove_directory(conn, path);
        response_error(conn, 204, "No Content", "%s", "");
    } else if (mg_remove(path) == 0) {
        response_error(conn, 204, "No Content", "%s", "");
    } else {
        response_error(conn, 423, "Locked", "remove(%s): %s", path,
                        strerror(ERRNO));
    }
}



static int is_put_or_delete_request(const struct mg_connection *conn) {
    const char *s = conn->request_info.request_method;
    return s != NULL && (!strcmp(s, "PUT") ||
                         !strcmp(s, "DELETE"));
}


static int isbyte(int n) {
    return n >= 0 && n <= 255;
}

static uint32_t get_remote_ip(const struct mg_connection *conn) {
    return ntohl(* (uint32_t *) &conn->client.rsa.sin.sin_addr);
}

static int parse_net(const char *spec, uint32_t *net, uint32_t *mask) {
    int n, a, b, c, d, slash = 32, len = 0;

    if ((sscanf(spec, "%d.%d.%d.%d/%d%n", &a, &b, &c, &d, &slash, &n) == 5 ||
         sscanf(spec, "%d.%d.%d.%d%n", &a, &b, &c, &d, &n) == 4) &&
        isbyte(a) && isbyte(b) && isbyte(c) && isbyte(d) &&
        slash >= 0 && slash < 33) {
        len = n;
        *net = ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | d;
        *mask = slash ? 0xffffffffU << (32 - slash) : 0;
    }

    return len;
}


static int set_throttle(const char *spec, uint32_t remote_ip, const char *uri) {
    int throttle = 0;
    struct vec vec, val;
    uint32_t net, mask;
    char mult;
    double v;

    while ((spec = next_vector_eq(spec, &vec, &val)) != NULL) {
        mult = ',';
        if (sscanf(val.ptr, "%lf%c", &v, &mult) < 1 || v < 0 ||
            (lowercase(&mult) != 'k' && lowercase(&mult) != 'm' && mult != ',')) {
            continue;
        }
        v *= lowercase(&mult) == 'k' ? 1024 : lowercase(&mult) == 'm' ? 1048576 : 1;
        if (vec.len == 1 && vec.ptr[0] == '*') {
            throttle = (int) v;
        } else if (parse_net(vec.ptr, &net, &mask) > 0) {
            if ((remote_ip & mask) == net) {
                throttle = (int) v;
            }
        } else if (match_prefix(vec.ptr, vec.len, uri) > 0) {
            throttle = (int) v;
        }
    }

    return throttle;
}


int forward_body_data(struct mg_connection *conn, FILE *fp,
                             SOCKET sock, SSL *ssl) {
    const char *expect, *body;
    char buf[MG_BUF_LEN];
    int nread, buffered_len, success = 0;
    int64_t left;

    expect = mg_get_header(conn, "Expect");
    assert(fp != NULL);

    if (conn->content_len == INT64_MAX) {
        response_error(conn, 411, "Length Required", "%s", "");
    } else if (expect != NULL && mg_strcasecmp(expect, "100-continue")) {
        response_error(conn, 417, "Expectation Failed", "%s", "");
    } else {
        if (expect != NULL) {
            (void) mg_printf(conn, "%s", "HTTP/1.1 100 Continue\r\n\r\n");
        }

        buffered_len = conn->data_len - conn->request_len;
        body = conn->buf + conn->request_len;
        assert(buffered_len >= 0);

        if (buffered_len > 0) {
            if ((int64_t) buffered_len > conn->content_len) {
                buffered_len = (int) conn->content_len;
            }
            push(fp, sock, ssl, body, (int64_t) buffered_len);
            memmove((char *) body, body + buffered_len, buffered_len);
            conn->data_len -= buffered_len;
        }

        nread = 0;
        while (conn->num_bytes_read < conn->content_len + conn->request_len) {
            left = left_to_read(conn);
            if (left > (int64_t) sizeof(buf)) {
                left = sizeof(buf);
            }
            nread = pull(NULL, conn, buf, (int) left);
            if (nread <= 0 || push(fp, sock, ssl, buf, nread) != nread) {
                break;
            }
        }

        if (left_to_read(conn) == 0) {
            success = nread >= 0;
        }

        // Each error code path in this function must send an error
        if (!success) {
            response_error(conn, 577, http_500_error, "%s", "");
        }
    }

    return success;
}



// For a given PUT path, create all intermediate subdirectories
// for given path. Return 0 if the path itself is a directory,
// or -1 on error, 1 if OK.
static int put_dir(const char *path) {
    char buf[PATH_MAX];
    const char *s, *p;
    struct file file = STRUCT_FILE_INITIALIZER;
    int len, res = 1;

    for (s = p = path + 2; (p = strchr(s, '/')) != NULL; s = ++p) {
        len = p - path;
        if (len >= (int) sizeof(buf)) {
            res = -1;
            break;
        }
        memcpy(buf, path, len);
        buf[len] = '\0';

        // Try to create intermediate directory
        DEBUG_TRACE(("mkdir(%s)", buf));
        if (!mg_stat(buf, &file) && mg_mkdir(buf, 0755) != 0) {
            res = -1;
            break;
        }

        // Is path itself a directory?
        if (p[1] == '\0') {
            res = 0;
        }
    }

    return res;
}


static void put_file(struct mg_connection *conn, const char *path) {
    struct file file = STRUCT_FILE_INITIALIZER;
    FILE *fp;
    const char *range;
    int64_t r1, r2;
    int rc;

    conn->status_code = mg_stat(path, &file) ? 200 : 201;

    if ((rc = put_dir(path)) == 0) {
        mg_printf(conn, "HTTP/1.1 %d OK\r\n\r\n", conn->status_code);
    } else if (rc == -1) {
        response_error(conn, 500, http_500_error,
                        "put_dir(%s): %s", path, strerror(ERRNO));
    } else if ((fp = fopen(path, "wb+")) == NULL) {
        fclose(fp);
        response_error(conn, 500, http_500_error,
                        "fopen(%s): %s", path, strerror(ERRNO));
    } else {
        fclose_on_exec(fp);
        range = mg_get_header(conn, "Content-Range");
        r1 = r2 = 0;
        if (range != NULL && parse_range_header(range, &r1, &r2) > 0) {
            conn->status_code = 206;
            fseeko(fp, r1, SEEK_SET);
        }
        if (!forward_body_data(conn, fp, INVALID_SOCKET, NULL)) {
            conn->status_code = 500;
        }
        mg_printf(conn, "HTTP/1.1 %d OK\r\nContent-Length: 0\r\n\r\n",
                  conn->status_code);
        fclose(fp);
    }
}

// Return True if we should reply 304 Not Modified.
static int is_not_modified(const struct mg_connection *conn,
                           const struct file *filep) {
    char etag[64];
    const char *ims = mg_get_header(conn, "If-Modified-Since");
    const char *inm = mg_get_header(conn, "If-None-Match");
    construct_etag(etag, sizeof(etag), filep);
    return (inm != NULL && !mg_strcasecmp(etag, inm)) ||
        (ims != NULL && filep->modification_time <= parse_date_string(ims));
}


// For given directory path, substitute it to valid index file.
// Return 0 if index file has been found, -1 if not found.
// If the file is found, it's stats is returned in stp.
static int substitute_index_file(struct mg_connection *conn, char *path,
                                 size_t path_len, struct file *filep) {
    const char *list = conn->ctx->config[op("index_files")];
    struct file file = STRUCT_FILE_INITIALIZER;
    struct vec filename_vec;
    size_t n = strlen(path);
    int found = 0;

    // The 'path' given to us points to the directory. Remove all trailing
    // directory separator characters from the end of the path, and
    // then append single directory separator character.
    while (n > 0 && path[n - 1] == '/') {
        n--;
    }
    path[n] = '/';

    // Traverse index files list. For each entry, append it to the given
    // path and see if the file exists. If it exists, break the loop
    while ((list = next_vector(list, &filename_vec)) != NULL) {

        // Ignore too long entries that may overflow path buffer
        if (filename_vec.len > path_len - (n + 2))
            continue;

        // Prepare full path to the index file
        mg_strlcpy(path + n + 1, filename_vec.ptr, filename_vec.len + 1);

        // Does it exist?
        if (mg_stat(path, &file)) {
            // Yes it does, break the loop
            *filep = file;
            found = 1;
            break;
        }
    }

    // If no index file exists, restore directory path
    if (!found) {
        path[n] = '\0';
    }

    return found;
}

// Protect against directory disclosure attack by removing '..',
// excessive '/' and '\' characters
static void remove_double_dots_and_double_slashes(char *s) {
    char *p = s;

    while (*s != '\0') {
        *p++ = *s++;
        if (s[-1] == '/' || s[-1] == '\\') {
            // Skip all following slashes, backslashes and double-dots
            while (s[0] != '\0') {
                if (s[0] == '/' || s[0] == '\\') {
                    s++;
                } else if (s[0] == '.' && s[1] == '.') {
                    s += 2;
                } else {
                    break;
                }
            }
        }
    }
    *p = '\0';
}

// Return 1 if real file has been found, 0 otherwise
static int convert_uri_to_file_name(struct mg_connection *conn, char *buf,
                                    size_t buf_len, struct file *filep) {
    struct vec a, b;
    const char *rewrite, *uri = conn->request_info.uri,
        *root = conn->ctx->settings.document_root;
    int match_len;
    char gz_path[PATH_MAX];
    char const* accept_encoding;

    // No filesystem access
    if (root == NULL) {
        return 0;
    }

    // Using buf_len - 1 because memmove() for PATH_INFO may shift part
    // of the path one byte on the right.
    // If document_root is NULL, leave the file empty.
    mg_snprintf(buf, buf_len - 1, "%s%s", root, uri);

    rewrite = conn->ctx->config[op("url_rewrite_patterns")];
    while ((rewrite = next_vector_eq(rewrite, &a, &b)) != NULL) {
        if ((match_len = match_prefix(a.ptr, a.len, uri)) > 0) {
            mg_snprintf(buf, buf_len - 1, "%.*s%s", (int) b.len, b.ptr,
                        uri + match_len);
            break;
        }
    }

    if (mg_stat(buf, filep)) {
        return 1;
    }

    // if we can't find the actual file, look for the file
    // with the same name but a .gz extension. If we find it,
    // use that and set the gzipped flag in the file struct
    // to indicate that the response need to have the content-
    // encoding: gzip header
    // we can only do this if the browser declares support
    if ((accept_encoding = mg_get_header(conn, "Accept-Encoding")) != NULL) {
        if (strstr(accept_encoding,"gzip") != NULL) {
            snprintf(gz_path, sizeof(gz_path), "%s.gz", buf);
            if (mg_stat(gz_path, filep)) {
                filep->gzipped = 1;
                return 1;
            }
        }
    }

    return 0;
}


// This is the heart of the Mongoose's logic.
// This function is called when the request is read, parsed and validated,
// and Mongoose must decide what action to take: serve a file, or
// a directory, or call embedded function, etcetera.
void dispatch_and_send_response(struct mg_connection *conn) {
    struct mg_request_info *ri = &conn->request_info;
    char path[PATH_MAX];
    int uri_len;
    struct file file = STRUCT_FILE_INITIALIZER;

    if ((conn->request_info.query_string = strchr(ri->uri, '?')) != NULL) {
        * ((char *) conn->request_info.query_string++) = '\0';
    }
    uri_len = (int) strlen(ri->uri);
    mg_url_decode(ri->uri, uri_len, (char *) ri->uri, uri_len + 1, 0);
    remove_double_dots_and_double_slashes((char *) ri->uri);
    conn->throttle = set_throttle(conn->ctx->config[op("throttle")],
                                  get_remote_ip(conn), ri->uri);
    path[0] = '\0';
    convert_uri_to_file_name(conn, path, sizeof(path), &file);

    // Perform redirect and auth checks before calling begin_request() handler.
    // Otherwise, begin_request() would need to perform auth checks and redirects.
    if (!is_put_or_delete_request(conn) &&
        !check_authorization(conn, path)) {
        send_authorization_request(conn);
        return ;
    } else if (call_user(MG_REQUEST_BEGIN, conn, (void *) ri->uri) == 1) {
        // Do nothing, callback has served the request
        return ;
    } else if (!strcmp(ri->request_method, "OPTIONS")) {
        response_options(conn);
        return ;
    } else if (conn->ctx->settings.document_root == NULL) {
        response_error(conn, 404, "Not Found", "Not Found");
        return ;
    } else if (is_put_or_delete_request(conn) &&
               (is_authorized_for_put(conn) != 1)) {
        send_authorization_request(conn);
        return ;
    } else if (!strcmp(ri->request_method, "PUT")) {
        put_file(conn, path);
        return ;
    } else if (!strcmp(ri->request_method, "DELETE")) {
        handle_delete_request(conn, path);
        return ;
    } else if (file.modification_time == (time_t) 0 ||
               must_hide_file(conn, path)) {
        response_error(conn, 404, "Not Found", "%s", "File not found");
        return ;
    } else if (file.is_directory && ri->uri[uri_len - 1] != '/') {
        mg_printf(conn, "HTTP/1.1 301 Moved Permanently\r\n"
                  "Location: %s/\r\n\r\n", ri->uri);
        return ;
    } else if (file.is_directory &&
               !substitute_index_file(conn, path, sizeof(path), &file)) {
        if (!mg_strcasecmp(conn->ctx->config[op("enable_directory_listing")], "yes")) {
            response_directory_index(conn, path);
            return ;
        } else {
            response_error(conn, 403, "Directory Listing Denied",
                            "Directory listing denied");
            return ;
        }
    } else if (is_not_modified(conn, &file)) {
        response_error(conn, 304, "Not Modified", "%s", "");
        return ;
    } else {
        response_file(conn, path, &file);
        return ;
    }
}
