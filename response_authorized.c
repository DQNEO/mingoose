#include "mingoose.h"

void send_authorization_request(struct mg_connection *conn) {
  conn->status_code = 401;
  mg_printf(conn,
            "HTTP/1.1 401 Unauthorized\r\n"
            "Content-Length: 0\r\n"
            "WWW-Authenticate: Digest qop=\"auth\", "
            "realm=\"%s\", nonce=\"%lu\"\r\n\r\n",
            conn->ctx->config[op("authentication_domain")],
            (unsigned long) time(NULL));
}

