#include <stddef.h>
// This array must be in sync with enum in internal.h
static const char *config_options[] = {
  "put_delete_auth_file", NULL,
  "protect_uri", NULL,
  "authentication_domain", "mydomain.com",
  "ssi_pattern", "**.shtml$|**.shtm$",
  "throttle", NULL,
  "access_log_file", NULL,
  "enable_directory_listing", "yes",
  "error_log_file", NULL,
  "global_auth_file", NULL,
  "index_files",
    "index.html,index.htm,index.shtml,index.php,index.lp",
  "enable_keep_alive", "no",
  "access_control_list", NULL,
  "extra_mime_types", NULL,
  "listening_ports", "8080",
  "document_root",  NULL,
  "void", NULL,
  "num_threads", "50",
  "run_as_user", NULL,
  "url_rewrite_patterns", NULL,
  "hide_files_patterns", NULL,
  "request_timeout_ms", "30000",
  NULL
};

