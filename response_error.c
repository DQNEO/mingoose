#include "mingoose.h"

void response_error(struct mg_connection *conn, int status,
                            const char *reason, const char *fmt, ...) {
  char buf[MG_BUF_LEN];
  va_list ap;
  int len = 0;

  conn->status_code = status;
  buf[0] = '\0';

  // Errors 1xx, 204 and 304 MUST NOT send a body
  if (status > 199 && status != 204 && status != 304) {
    len = mg_snprintf(buf, sizeof(buf), "Error %d: %s", status, reason);
    buf[len++] = '\n';

    va_start(ap, fmt);
    len += mg_vsnprintf(buf + len, sizeof(buf) - len, fmt, ap);
    va_end(ap);
  }
  DEBUG_TRACE(("[%s]", buf));

  if (call_user(MG_HTTP_ERROR, conn, (void *) (long) status) == 0) {
    mg_printf(conn, "HTTP/1.1 %d %s\r\n"
              "Content-Length: %d\r\n"
              "Connection: %s\r\n\r\n", status, reason, len,
              suggest_connection_header(conn));
    conn->num_bytes_sent += mg_printf(conn, "%s", buf);
  }
}
