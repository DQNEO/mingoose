#include "mingoose.h"

void response_options(struct mg_connection *conn) {
    static const char reply[] = "HTTP/1.1 200 OK\r\n"
        "Allow: GET, POST, HEAD, CONNECT, PUT, DELETE, OPTIONS\r\n"
        "DAV: 1\r\n\r\n";

    conn->status_code = 200;
    mg_write(conn, reply, sizeof(reply) - 1);
}

