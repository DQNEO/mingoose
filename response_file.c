#include "mingoose.h"
// Look at the "path" extension and figure what mime type it has.
// Store mime type in the vector.
static void get_mime_type(const char *path,
                          struct vec *vec) {

    vec->ptr = mg_get_builtin_mime_type(path);
    vec->len = strlen(vec->ptr);
}

// Send len bytes from the opened file to the client.
static void send_file_data(struct mg_connection *conn, FILE *fp,
                           int64_t offset, int64_t len) {
    char buf[MG_BUF_LEN];
    int num_read, num_written, to_read;

    // If offset is beyond file boundaries, don't send anything
    if (offset > 0 && fseeko(fp, offset, SEEK_SET) != 0) {
        return;
    }

    while (len > 0) {
        // Calculate how much to read from the file in the buffer
        to_read = sizeof(buf);
        if ((int64_t) to_read > len) {
            to_read = (int) len;
        }

        // Read from file, exit the loop on error
        if ((num_read = fread(buf, 1, (size_t) to_read, fp)) <= 0) {
            break;
        }

        // Send read bytes to the client, exit the loop on error
        if ((num_written = mg_write(conn, buf, (size_t) num_read)) != num_read) {
            break;
        }

        // Both read and were successful, adjust counters
        conn->num_bytes_sent += num_written;
        len -= num_written;
    }
}


void response_file(struct mg_connection *conn, const char *path,
                                struct file *filep) {
    char date[64], lm[64], etag[64], range[64];
    const char *msg = "OK", *hdr;
    time_t curtime = time(NULL);
    int64_t cl, r1, r2;
    struct vec mime_vec;
    int n;
    char gz_path[PATH_MAX];
    char const* encoding = "";
    FILE *fp;

    get_mime_type(path, &mime_vec);
    cl = filep->size;
    conn->status_code = 200;
    range[0] = '\0';

    // if this file is in fact a pre-gzipped file, rewrite its filename
    // it's important to rewrite the filename after resolving
    // the mime type from it, to preserve the actual file's type
    if (filep->gzipped) {
        snprintf(gz_path, sizeof(gz_path), "%s.gz", path);
        path = gz_path;
        encoding = "Content-Encoding: gzip\r\n";
    }

    if ((fp = fopen(path, "rb")) == NULL) {
        response_error(conn, 500, http_500_error,
                        "fopen(%s): %s", path, strerror(ERRNO));
        return;
    }

    fclose_on_exec(fp);

    // If Range: header specified, act accordingly
    r1 = r2 = 0;
    hdr = mg_get_header(conn, "Range");
    if (hdr != NULL && (n = parse_range_header(hdr, &r1, &r2)) > 0 &&
        r1 >= 0 && r2 >= 0) {
        // actually, range requests don't play well with a pre-gzipped
        // file (since the range is specified in the uncmpressed space)
        if (filep->gzipped) {
            response_error(conn, 501, "Not Implemented",
                            "range requests in gzipped files are not supported");
            return;
        }
        conn->status_code = 206;
        cl = n == 2 ? (r2 > cl ? cl : r2) - r1 + 1: cl - r1;
        mg_snprintf(range, sizeof(range),
                    "Content-Range: bytes "
                    "%" INT64_FMT "-%"
                    INT64_FMT "/%" INT64_FMT "\r\n",
                    r1, r1 + cl - 1, filep->size);
        msg = "Partial Content";
    }

    // Prepare Etag, Date, Last-Modified headers. Must be in UTC, according to
    // http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.3
    gmt_time_string(date, sizeof(date), &curtime);
    gmt_time_string(lm, sizeof(lm), &filep->modification_time);
    construct_etag(etag, sizeof(etag), filep);

    (void) mg_printf(conn,
                     "HTTP/1.1 %d %s\r\n"
                     "Date: %s\r\n"
                     "Last-Modified: %s\r\n"
                     "Etag: %s\r\n"
                     "Content-Type: %.*s\r\n"
                     "Content-Length: %" INT64_FMT "\r\n"
                     "Connection: %s\r\n"
                     "Accept-Ranges: bytes\r\n"
                     "%s%s%s\r\n",
                     conn->status_code, msg, date, lm, etag, (int) mime_vec.len,
                     mime_vec.ptr, cl, suggest_connection_header(conn), range, encoding,
                     EXTRA_HTTP_HEADERS);

    if (strcmp(conn->request_info.request_method, "HEAD") != 0) {
        send_file_data(conn, fp, r1, cl);
    }
    fclose(fp);
}
