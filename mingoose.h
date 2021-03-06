// Copyright (c) 2004-2013 Sergey Lyubka <valenok@gmail.com>
// Copyright (c) 2013 Cesanta Software Limited
// All rights reserved
//
// This library is dual-licensed: you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation. For the terms of this
// license, see <http://www.gnu.org/licenses/>.
//
// You are free to use this library under the terms of the GNU General
// Public License, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// Alternatively, you can license this library under a commercial
// license, as set out in <http://cesanta.com/products.html>.

#ifndef MONGOOSE_HEADER_INCLUDED
#define  MONGOOSE_HEADER_INCLUDED

#define _XOPEN_SOURCE 600  // For PATH_MAX on linux

#include <stdio.h>
#include <stddef.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <limits.h>
#include <stddef.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>

#include <time.h>
#include <assert.h>

#include <sys/socket.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <stdint.h>
#include <inttypes.h>
#include <netdb.h>

#include <pwd.h>
#include <dirent.h>

#include <string.h>
#include <ctype.h>
#include <openssl/md5.h>

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

// This structure contains information about the HTTP request.
struct mg_request_info {
    const char *request_method; // "GET", "POST", etc
    const char *uri;            // URL-decoded URI
    const char *http_version;   // E.g. "1.0", "1.1"
    const char *query_string;   // URL part after '?', not including '?', or NULL
    const char *remote_user;    // Authenticated user, or NULL if no auth used
    long remote_ip;             // Client's IP address
    int remote_port;            // Client's port
    int is_ssl;                 // 1 if SSL-ed, 0 if not

    int num_headers;            // Number of HTTP headers
    struct mg_header {
        const char *name;         // HTTP header name
        const char *value;        // HTTP header value
    } http_headers[64];         // Maximum 64 headers
};

int parse_http_message(char *buf, int len, struct mg_request_info *ri);
int get_request_len(const char *buf, int buf_len);

void mg_strlcpy(register char *dst, register const char *src, size_t n);
char * mg_strndup(const char *ptr, size_t len);
char * mg_strdup(const char *str);

#if !defined(_LARGEFILE_SOURCE)
#define _LARGEFILE_SOURCE     // Enable 64-bit file offsets
#endif

#define __STDC_FORMAT_MACROS  // <inttypes.h> wants this for C++
#define __STDC_LIMIT_MACROS   // C++ wants that for INT64_MAX


#if !defined(NO_SSL_DL) && !defined(NO_SSL)
#include <dlfcn.h>
#endif
#include <pthread.h>
#if defined(__MACH__)
#define SSL_LIB   "libssl.dylib"
#define CRYPTO_LIB  "libcrypto.dylib"
#else
#if !defined(SSL_LIB)
#define SSL_LIB   "libssl.so"
#endif
#if !defined(CRYPTO_LIB)
#define CRYPTO_LIB  "libcrypto.so"
#endif
#endif
#ifndef O_BINARY
#define O_BINARY  0
#endif // O_BINARY
#define closesocket(a) close(a)
#define mg_mkdir(x, y) mkdir(x, y)
#define mg_remove(x) remove(x)
#define mg_sleep(x) usleep((x) * 1000)
#define ERRNO errno
#define INVALID_SOCKET (-1)
#define INT64_FMT PRId64
typedef int SOCKET;

struct mg_context;     // Web server instance
struct mg_connection;  // HTTP request descriptor


struct mg_event {
    int type;                   // Event type, possible types are defined below
#define MG_REQUEST_BEGIN  1   // event_param: NULL
#define MG_REQUEST_END    2   // event_param: NULL
#define MG_HTTP_ERROR     3   // event_param: int status_code
#define MG_EVENT_LOG      4   // event_param: const char *message
#define MG_THREAD_BEGIN   5   // event_param: NULL
#define MG_THREAD_END     6   // event_param: NULL

    void *user_data;            // User data pointer passed to mg_start()
    void *conn_data;            // Connection-specific, per-thread user data.
    void *event_param;          // Event-specific parameter

    struct mg_connection *conn;
    struct mg_request_info *request_info;
};

typedef int (*mg_event_handler_t)(struct mg_event *event);

struct mg_context *mg_start(const char **configuration_options,
                            mg_event_handler_t func, void *user_data);
void mg_stop(struct mg_context *);

const char **mg_get_valid_option_names(void);
int mg_modify_passwords_file(const char *passwords_file_name,
                             const char *domain,
                             const char *user,
                             const char *password);
int mg_write(struct mg_connection *, const void *buf, int len);

// Macros for enabling compiler-specific checks for printf-like arguments.
#undef PRINTF_FORMAT_STRING
#define PRINTF_FORMAT_STRING(s) s

#ifdef __GNUC__
#define PRINTF_ARGS(x, y) __attribute__((format(printf, x, y)))
#else
#define PRINTF_ARGS(x, y)
#endif

// Send data to the client using printf() semantics.
//
// Works exactly like mg_write(), but allows to do message formatting.
int mg_printf(struct mg_connection *,
              PRINTF_FORMAT_STRING(const char *fmt), ...) PRINTF_ARGS(2, 3);


// Get the value of particular HTTP header.
//
// This is a helper function. It traverses request_info->http_headers array,
// and if the header is present in the array, returns its value. If it is
// not present, NULL is returned.
const char *mg_get_header(const struct mg_connection *, const char *name);


// Get a value of particular form variable.
//
// Parameters:
//   data: pointer to form-uri-encoded buffer. This could be either POST data,
//         or request_info.query_string.
//   data_len: length of the encoded data.
//   var_name: variable name to decode from the buffer
//   dst: destination buffer for the decoded variable
//   dst_len: length of the destination buffer
//
// Return:
//   On success, length of the decoded variable.
//   On error:
//      -1 (variable not found).
//      -2 (destination buffer is NULL, zero length or too small to hold the
//          decoded variable).
//
// Destination buffer is guaranteed to be '\0' - terminated if it is not
// NULL or zero length.
int mg_get_var(const char *data, size_t data_len,
               const char *var_name, char *dst, size_t dst_len);

// Fetch value of certain cookie variable into the destination buffer.
//
// Destination buffer is guaranteed to be '\0' - terminated. In case of
// failure, dst[0] == '\0'. Note that RFC allows many occurrences of the same
// parameter. This function returns only first occurrence.
//
// Return:
//   On success, value length.
//   On error:
//      -1 (either "Cookie:" header is not present at all or the requested
//          parameter is not found).
//      -2 (destination buffer is NULL, zero length or too small to hold the
//          value).
int mg_get_cookie(const char *cookie, const char *var_name,
                  char *buf, size_t buf_len);


// Download data from the remote web server.
//   host: host name to connect to, e.g. "foo.com", or "10.12.40.1".
//   port: port number, e.g. 80.
//   use_ssl: wether to use SSL connection.
//   error_buffer, error_buffer_size: error message placeholder.
//   request_fmt,...: HTTP request.
// Return:
//   On success, valid pointer to the new connection, suitable for mg_read().
//   On error, NULL. error_buffer contains error message.
// Example:
//   char ebuf[100];
//   struct mg_connection *conn;
//   conn = mg_download("google.com", 80, 0, ebuf, sizeof(ebuf),
//                      "%s", "GET / HTTP/1.0\r\nHost: google.com\r\n\r\n");
struct mg_connection *mg_download(const char *host, int port, int use_ssl,
                                  char *error_buffer, size_t error_buffer_size,
                                  PRINTF_FORMAT_STRING(const char *request_fmt),
                                  ...) PRINTF_ARGS(6, 7);


// Close the connection opened by mg_download().
void mg_close_connection(struct mg_connection *conn);


// Read multipart-form-data POST buffer, save uploaded files into
// destination directory, and return path to the saved filed.
// This function can be called multiple times for the same connection,
// if more then one file is uploaded.
// Return: path to the uploaded file, or NULL if there are no more files.
FILE *mg_upload(struct mg_connection *conn, const char *destination_dir,
                char *path, int path_len);


// Convenience function -- create detached thread.
// Return: 0 on success, non-0 on error.
typedef void * (*mg_thread_func_t)(void *);
int mg_start_thread(mg_thread_func_t f, void *p);


// Return builtin mime type for the given file name.
// For unrecognized extensions, "text/plain" is returned.
const char *mg_get_builtin_mime_type(const char *file_name);


// Return Mongoose version.
const char *mg_version(void);

// URL-decode input buffer into destination buffer.
// 0-terminate the destination buffer.
// form-url-encoded data differs from URI encoding in a way that it
// uses '+' as character for space, see RFC 1866 section 8.2.1
// http://ftp.ics.uci.edu/pub/ietf/html/rfc1866.txt
// Return: length of the decoded data, or -1 if dst buffer is too small.
int mg_url_decode(const char *src, int src_len, char *dst,
                  int dst_len, int is_form_url_encoded);

// MD5 hash given strings.
// Buffer 'buf' must be 33 bytes long. Varargs is a NULL terminated list of
// ASCIIz strings. When function returns, buf will contain human-readable
// MD5 hash. Example:
//   char buf[33];
//   mg_md5(buf, "aa", "bb", NULL);
char *mg_md5(char buf[33], ...);


#define MONGOOSE_VERSION "0.0.1"
#define PASSWORDS_FILE_NAME ".htpasswd"
#define CGI_ENVIRONMENT_SIZE 4096
#define MAX_CGI_ENVIR_VARS 64
#define MG_BUF_LEN 8192
#define MAX_REQUEST_SIZE 16384

#ifdef DEBUG_TRACE
#undef DEBUG_TRACE
#define DEBUG_TRACE(x)
#else
#if defined(DEBUG)
#define DEBUG_TRACE(x) do {                                         \
        flockfile(stdout);                                          \
        printf("*** %lu.%p.%s.%d: ",                                \
               (unsigned long) time(NULL), (void *) pthread_self(), \
               __func__, __LINE__);                                 \
        printf x;                                                   \
        putchar('\n');                                              \
        fflush(stdout);                                             \
        funlockfile(stdout);                                        \
    } while (0)
#else
#define DEBUG_TRACE(x)
#endif // DEBUG
#endif // DEBUG_TRACE

#define DIRSEP '/'
#define abs_path(rel, abs, abs_size) realpath((rel), (abs))


#define MAX_OPTIONS 100
#define MAX_CONF_FILE_LINE_SIZE (8 * 1024)

// Darwin prior to 7.0 and Win32 do not have socklen_t
#ifdef NO_SOCKLEN_T
typedef int socklen_t;
#endif // NO_SOCKLEN_T
#define _DARWIN_UNLIMITED_SELECT

#define IP_ADDR_STR_LEN 50  // IPv6 hex string is 46 chars

#if !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif

#if !defined(SOMAXCONN)
#define SOMAXCONN 100
#endif

#if !defined(PATH_MAX)
#define PATH_MAX 4096
#endif

// Size of the accepted socket queue
#if !defined(MGSQLEN)
#define MGSQLEN 20
#endif

// Extra HTTP headers to send in every static file reply
#if !defined(EXTRA_HTTP_HEADERS)
#define EXTRA_HTTP_HEADERS ""
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>

// Unified socket address. For IPv6 support, add IPv6 address structure
// in the union u.
union usa {
    struct sockaddr sa;
    struct sockaddr_in sin;
};


// Describes a string (chunk of memory).
struct vec {
    const char *ptr;
    size_t len;
};

struct file {
    int is_directory;
    time_t modification_time;
    int64_t size;
    // set to 1 if the content is gzipped
    // in which case we need a content-encoding: gzip header
    int gzipped;
};
#define STRUCT_FILE_INITIALIZER { 0, 0, 0, 0 }


// Describes listening socket, or socket which was accept()-ed by the master
// thread and queued for future handling by the worker thread.
struct socket {
    SOCKET sock;          // Listening socket
    union usa lsa;        // Local socket address
    union usa rsa;        // Remote socket address
};


// NOTE(lsm): this shoulds be in sync with the config_options.
#define NUM_OPTIONS 17

int op(const char *);

struct settings {
    char *put_delete_auth_file;
    char *protect_uri;
    char *authentication_domain;
    char *throttle;
    char *access_log_file;
    char *enable_directory_listing;
    char *error_log_file;
    char *global_passwords_file;
    char *index_files;
    char *enable_keep_alive;
    char *ports;
    char *document_root;
    int  num_threads;
    char *run_as_user;
    char *url_rewrite_patterns;
    char *hide_files_patterns;
    char *request_timeout_ms;
};

struct mg_context {
    volatile int stop_flag;         // Should we stop event loop
    SSL_CTX *ssl_ctx;               // SSL context
    char *config[NUM_OPTIONS];      // Mongoose configuration parameters
    struct settings settings;
    mg_event_handler_t event_handler;  // User-defined callback function
    void *user_data;                // User-defined data

    SOCKET listening_socket_fd;

    volatile int num_threads;  // Number of threads
    pthread_mutex_t mutex;     // Protects (max|num)_threads
    pthread_cond_t  cond;      // Condvar for tracking workers terminations

    struct socket queue[MGSQLEN];   // Accepted sockets
    volatile int sq_head;      // Head of the socket queue
    volatile int sq_tail;      // Tail of the socket queue
    pthread_cond_t sq_full;    // Signaled when socket is produced
    pthread_cond_t sq_empty;   // Signaled when socket is consumed
};

struct mg_connection {
    struct mg_request_info request_info;
    struct mg_event event;
    struct mg_context *ctx;
    SSL *ssl;                   // SSL descriptor
    SSL_CTX *client_ssl_ctx;    // SSL context for client connections
    struct socket client;       // Connected client
    time_t birth_time;          // Time when request was received
    int64_t num_bytes_sent;     // Total bytes sent to client
    int64_t content_len;        // Content-Length header value
    int64_t num_bytes_read;     // Bytes read from a remote socket
    char *buf;                  // Buffer for received data
    char *path_info;            // PATH_INFO part of the URL
    int must_close;             // 1 if connection must be closed
    int buf_size;               // Buffer size
    int request_len;            // Size of the request + headers in a buffer
    int data_len;               // Total size of data in a buffer
    int status_code;            // HTTP reply status code, e.g. 200
    int throttle;               // Throttling, bytes/sec. <= 0 means no throttle
    time_t last_throttle_time;  // Last time throttled data was sent
    int64_t last_throttle_bytes;// Bytes sent this second
};

// Directory entry
struct de {
    struct mg_connection *conn;
    char *file_name;
    struct file file;
};

struct mime_type {
    const char *extension;
    size_t ext_len;
    const char *mime_type;
};

char *skip_quoted(char **buf, const char *delimiters,
                  const char *whitespace, char quotechar);

int mg_stat(const char *path, struct file *filep);
void response_error(struct mg_connection *, int, const char *,
                     PRINTF_FORMAT_STRING(const char *fmt), ...)
    PRINTF_ARGS(4, 5);
void cry(struct mg_connection *conn,
         PRINTF_FORMAT_STRING(const char *fmt), ...) PRINTF_ARGS(2, 3);
int getreq(struct mg_connection *conn, char *ebuf, size_t ebuf_len);
int exit_flag;
struct mg_context *ctx;      // Set by start_mongoose()

int lowercase(const char *s) ;

int mg_strncasecmp(const char *s1, const char *s2, size_t len) ;
int mg_strcasecmp(const char *s1, const char *s2) ;
const char *mg_strcasestr(const char *big_str, const char *small_str);
int mg_vsnprintf(char *buf, size_t buflen, const char *fmt, va_list ap);

int mg_snprintf(char *buf, size_t buflen,
                PRINTF_FORMAT_STRING(const char *fmt), ...) PRINTF_ARGS(3, 4);

extern const char *config_options[];
time_t parse_date_string(const char *datetime);

int match_prefix(const char *pattern, int pattern_len, const char *str);

const char *next_vector_eq(const char *list, struct vec *val,
                        struct vec *eq_val) ;
const char *next_vector(const char *list, struct vec *val);


int check_authorization(struct mg_connection *conn, const char *path);
void send_authorization_request(struct mg_connection *conn) ;
int is_authorized_for_put(struct mg_connection *conn);

int mg_printf(struct mg_connection *conn, const char *fmt, ...) ;
int mg_chunked_printf(struct mg_connection *conn, const char *fmt, ...) ;

int pull(FILE *fp, struct mg_connection *conn, char *buf, int len) ;

int call_user(int type, struct mg_connection *conn, void *p) ;

const char *suggest_connection_header(const struct mg_connection *conn);
void sockaddr_to_string(char *buf, size_t len,
                        const union usa *usa) ;

void log_access(const struct mg_connection *conn) ;

char * get_absolute_path(char *relpath,
                         const char *path_to_mongoose_exe) ;


void verify_document_root(char *path) ;

void die(const char *fmt, ...) ;

void show_usage_and_exit(void) ;

void set_options(struct mg_context * ctx, char *argv[]);
struct mg_connection *create_fake_connection(struct mg_context *ctx) ;
void free_context(struct mg_context *ctx) ;
const char *mg_get_builtin_mime_type(const char *path) ;

#define http_500_error  "Internal Server Error"
void fclose_on_exec(FILE *fp);
int parse_range_header(const char *header, int64_t *a, int64_t *b) ;
void gmt_time_string(char *buf, size_t buf_len, time_t *t) ;

void construct_etag(char *buf, size_t buf_len,
                    const struct file *filep);
void response_file(struct mg_connection *conn, const char *path,
                   struct file *filep) ;

int must_hide_file(struct mg_connection *conn, const char *path) ;
void mg_url_encode(const char *src, char *dst, size_t dst_len);
void response_options(struct mg_connection *conn) ;
void send_authorization_request(struct mg_connection *conn);
void response_directory_index(struct mg_connection *conn,
                              const char *dir) ;

void dispatch_and_send_response(struct mg_connection *conn);
int64_t left_to_read(const struct mg_connection *conn) ;
int64_t push(FILE *fp, SOCKET sock, SSL *ssl, const char *buf, int64_t len);

#endif // MONGOOSE_HEADER_INCLUDED
