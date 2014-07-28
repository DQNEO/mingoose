#include "mingoose.h"

// Skip the characters until one of the delimiters characters found.
// 0-terminate resulting word. Skip the delimiter and following whitespaces.
// Advance pointer to buffer to the next word. Return found 0-terminated word.
// Delimiters can be quoted with quotechar.
char *skip_quoted(char **buf, const char *delimiters,
                         const char *whitespace, char quotechar) {
  char *p, *begin_word, *end_word, *end_whitespace;

  begin_word = *buf;
  end_word = begin_word + strcspn(begin_word, delimiters);

  // Check for quotechar
  if (end_word > begin_word) {
    p = end_word - 1;
    while (*p == quotechar) {
      // If there is anything beyond end_word, copy it
      if (*end_word == '\0') {
        *p = '\0';
        break;
      } else {
        size_t end_off = strcspn(end_word + 1, delimiters);
        memmove (p, end_word, end_off + 1);
        p += end_off; // p must correspond to end_word - 1
        end_word += end_off + 1;
      }
    }
    for (p++; p < end_word; p++) {
      *p = '\0';
    }
  }

  if (*end_word == '\0') {
    *buf = end_word;
  } else {
    end_whitespace = end_word + 1 + strspn(end_word + 1, whitespace);

    for (p = end_word; p < end_whitespace; p++) {
      *p = '\0';
    }

    *buf = end_whitespace;
  }

  return begin_word;
}

// Parse HTTP headers from the given buffer, advance buffer to the point
// where parsing stopped.
static void parse_http_headers(char **buf, struct mg_request_info *ri) {
  int i;

  for (i = 0; i < (int) ARRAY_SIZE(ri->http_headers); i++) {
    ri->http_headers[i].name = skip_quoted(buf, ":", " ", 0);
    ri->http_headers[i].value = skip_quoted(buf, "\r\n", "\r\n", 0);
    if (ri->http_headers[i].name[0] == '\0')
      break;
    ri->num_headers = i + 1;
  }
}

// Check whether full request is buffered. Return:
//   -1  if request is malformed
//    0  if request is not yet fully buffered
//   >0  actual request length, including last \r\n\r\n
int get_request_len(const char *buf, int buf_len) {
  int i;

  for (i = 0; i < buf_len; i++) {
    // Control characters are not allowed but >=128 is.
    // Abort scan as soon as one malformed character is found;
    // don't let subsequent \r\n\r\n win us over anyhow
    if (!isprint(* (const unsigned char *) &buf[i]) && buf[i] != '\r' &&
        buf[i] != '\n' && * (const unsigned char *) &buf[i] < 128) {
      return -1;
    } else if (buf[i] == '\n' && i + 1 < buf_len && buf[i + 1] == '\n') {
      return i + 2;
    } else if (buf[i] == '\n' && i + 2 < buf_len && buf[i + 1] == '\r' &&
               buf[i + 2] == '\n') {
      return i + 3;
    }
  }

  return 0;
}

static int is_valid_http_method(const char *method) {
  return !strcmp(method, "GET") || !strcmp(method, "POST") ||
    !strcmp(method, "HEAD") || !strcmp(method, "CONNECT") ||
    !strcmp(method, "PUT") || !strcmp(method, "DELETE") ||
    !strcmp(method, "OPTIONS")
      ;
}


// Parse HTTP request, fill in mg_request_info structure.
// This function modifies the buffer by NUL-terminating
// HTTP request components, header names and header values.
// @return -1 on error
int parse_http_message(char *buf, int len, struct mg_request_info *ri) {
  int is_request, request_length = get_request_len(buf, len);
  if (request_length > 0) {
    // Reset attributes. DO NOT TOUCH is_ssl, remote_ip, remote_port
    ri->remote_user = ri->request_method = ri->uri = ri->http_version = NULL;
    ri->num_headers = 0;

    buf[request_length - 1] = '\0';

    // RFC says that all initial whitespaces should be ingored
    while (*buf != '\0' && isspace(* (unsigned char *) buf)) {
      buf++;
    }

    char *p;
    p = strchr(buf, ' ');
    *p = '\0';
    ri->request_method = buf;

    buf = p + 1;
    p = strchr(buf, ' ');
    *p = '\0';
    ri->uri = buf;

    buf = p + 1;
    p = strchr(buf , '\r');
    *p = '\0';
    ri->http_version = buf;
    buf = p + 2;

    // HTTP message could be either HTTP request or HTTP response, e.g.
    // "GET / HTTP/1.0 ...." or  "HTTP/1.0 200 OK ..."
    is_request = is_valid_http_method(ri->request_method);
    if (!is_request) {
      return -1;
    }

    if (memcmp(ri->http_version, "HTTP/", 5) != 0) {
      return -1;
    }

    ri->http_version += 5;
    parse_http_headers(&buf, ri);

  }
  return request_length;
}


// Return HTTP header value, or NULL if not found.
static const char *get_header(const struct mg_request_info *ri,
                              const char *name) {
  int i;

  for (i = 0; i < ri->num_headers; i++)
    if (!mg_strcasecmp(name, ri->http_headers[i].name))
      return ri->http_headers[i].value;

  return NULL;
}

const char *mg_get_header(const struct mg_connection *conn, const char *name) {
  return get_header(&conn->request_info, name);
}


// Keep reading the input (either opened file descriptor fd, or socket sock,
// or SSL descriptor ssl) into buffer buf, until \r\n\r\n appears in the
// buffer (which marks the end of HTTP request). Buffer buf may already
// have some data. The length of the data is stored in nread.
// Upon every read operation, increase nread by the number of bytes read.
static int read_request(FILE *fp, struct mg_connection *conn,
                        char *buf, int bufsiz, int *nread) {
  int request_len, n = 0;

  request_len = get_request_len(buf, *nread);
  while (conn->ctx->stop_flag == 0 &&
         *nread < bufsiz &&
         request_len == 0 &&
         (n = pull(fp, conn, buf + *nread, bufsiz - *nread)) > 0) {
    *nread += n;
    assert(*nread <= bufsiz);
    request_len = get_request_len(buf, *nread);
  }

  return request_len <= 0 && n <= 0 ? -1 : request_len;
}

static void reset_per_request_attributes(struct mg_connection *conn) {
  conn->path_info = NULL;
  conn->num_bytes_sent = conn->num_bytes_read = 0;
  conn->status_code = -1;
  conn->must_close = conn->request_len = conn->throttle = 0;
}

int getreq(struct mg_connection *conn, char *ebuf, size_t ebuf_len) {
  const char *cl;

  ebuf[0] = '\0';
  reset_per_request_attributes(conn);
  conn->request_len = read_request(NULL, conn, conn->buf, conn->buf_size,
                                   &conn->data_len);
  assert(conn->request_len < 0 || conn->data_len >= conn->request_len);

  if (conn->request_len == 0 && conn->data_len == conn->buf_size) {
    snprintf(ebuf, ebuf_len, "%s", "Request Too Large");
  } else if (conn->request_len <= 0) {
    snprintf(ebuf, ebuf_len, "%s", "Client closed connection");
  } else if (parse_http_message(conn->buf, conn->buf_size,
                                &conn->request_info) <= 0) {
    snprintf(ebuf, ebuf_len, "Bad request: [%.*s]", conn->data_len, conn->buf);
  } else {
    // Request is valid. Set content_len attribute by parsing Content-Length
    // If Content-Length is absent, set content_len to 0 if request is GET,
    // and set it to INT64_MAX otherwise. Setting to INT64_MAX instructs
    // mg_read() to read from the socket until socket is closed.
    // The reason for treating GET and POST/PUT differently is that libraries
    // like jquery do not set Content-Length in GET requests, and we don't
    // want mg_read() to hang waiting until socket is timed out.
    // See https://github.com/cesanta/mongoose/pull/121 for more.
    conn->content_len = INT64_MAX;
    if (!mg_strcasecmp(conn->request_info.request_method, "GET")) {
      conn->content_len = 0;
    }
    if ((cl = get_header(&conn->request_info, "Content-Length")) != NULL) {
      conn->content_len = strtoll(cl, NULL, 10);
    }
    conn->birth_time = time(NULL);
  }
  return ebuf[0] == '\0';
}


