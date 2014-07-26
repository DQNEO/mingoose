#include "mingoose.h"

// This array must be in sync with enum in internal.h
const char *config_options[] = {
  "put_delete_auth_file",
  "protect_uri",
  "authentication_domain",
  "throttle",
  "access_log_file",
  "enable_directory_listing",
  "error_log_file",
  "global_auth_file",
  "index_files",
  "enable_keep_alive",
  "listening_ports",
  "document_root",
  "num_threads",
  "run_as_user",
  "url_rewrite_patterns",
  "hide_files_patterns",
  "request_timeout_ms",
  NULL
};


int op(const char *name) {
  int i;

  for (i = 0; config_options[i] != NULL; i++) {
    if (strcmp(config_options[i], name) == 0) {
      return i;
    }
  }

  die("invalid option key:%s", name);
  
  return -1; // not found
}


static char *sdup(const char *str) {
  char *p;
  if ((p = (char *) malloc(strlen(str) + 1)) != NULL) {
    strcpy(p, str);
  }
  return p;
}

static int is_path_absolute(const char *path) {
  return path != NULL && path[0] == '/';
}


void verify_document_root(char *path) {
  struct stat st;

  if (path != NULL && (stat(path, &st) != 0 || !S_ISDIR(st.st_mode) )  ) {
    die("Invalid path for document_root: [%s]: %s.\nMake sure that path is either "
        "absolute, or it is relative to mongoose executable.",
        path, strerror(errno));
  }
}

char * get_absolute_path(char *relpath,
                              const char *path_to_mongoose_exe) {
    char path[PATH_MAX], abs[PATH_MAX];
  const char *p;

  // Check whether option is already set

  if (relpath == NULL) {
      return NULL;
  }

  // If option is already set and it is an absolute path,
  // leave it as it is.
  if (is_path_absolute(relpath)) {
      return relpath;
  }

  // Not absolute. Use the directory where mongoose executable lives
  // be the relative directory for everything.
  // Extract mongoose executable directory into path.
  if ((p = strrchr(path_to_mongoose_exe, DIRSEP)) == NULL) {
      getcwd(path, sizeof(path));
  } else {
      snprintf(path, sizeof(path), "%.*s", (int) (p - path_to_mongoose_exe),
               path_to_mongoose_exe);
  }

  strncat(path, "/", sizeof(path) - 1);
  strncat(path, relpath, sizeof(path) - 1);

  // Absolutize the path, and set the option
  abs_path(path, abs, sizeof(abs));
  free(relpath);
  return sdup(abs);
}

void set_options(struct mg_context * ctx, char *argv[]) {
    int i;
    const char *name, *value;

    ctx->config[op("authentication_domain")]  = mg_strdup("mydomain.com");
    ctx->config[op("enable_directory_listing")]  = mg_strdup("yes");
    ctx->config[op("index_files")]  = mg_strdup("index.html,index.htm,index.shtml,index.php,index.lp");
    ctx->config[op("enable_keep_alive")]  = mg_strdup("no");
    ctx->config[op("listening_ports")] = mg_strdup("8080");
    ctx->config[op("num_threads")] = mg_strdup("5");
    ctx->config[op("request_timeout_ms")] = mg_strdup("30000");

    // set default document_root
    ctx->config[op("document_root")] = mg_strdup(".");

    // Handle command line flags.
    // They override config file and default settings.
    for (i = 1; argv[i] != NULL; i += 2) {
        if (argv[i][0] != '-' || argv[i + 1] == NULL) {
            show_usage_and_exit();
        }
        name =  &argv[i][1];
        value = argv[i + 1];

        if (op(name) == -1) {
            cry(create_fake_connection(ctx), "Invalid option: %s", name);
            free_context(ctx);
            die("%s", "Failed to start Mongoose.");
        }

        ctx->config[op(name)] = mg_strdup(value);
        DEBUG_TRACE(("[%s] -> [%s]", name, value));
    }

    /* dump ctx->config
    */
    for (i=0;config_options[i] != NULL; i++) {
        fprintf(stderr, "%s, ctx->config[%d]=%s\n", config_options[i], i, ctx->config[i]);
    }

    ctx->settings.put_delete_auth_file = ctx->config[op("put_delete_auth_file")];
    ctx->settings.access_log_file =  ctx->config[op("access_log_file")];
    ctx->settings.error_log_file = ctx->config[op("error_log_file")];
    ctx->settings.document_root = ctx->config[op("document_root")];
    ctx->settings.ports  = ctx->config[op("listening_ports")];
    ctx->settings.num_threads  = atoi(ctx->config[op("num_threads")]);
    ctx->settings.global_passwords_file = ctx->config[op("global_auth_file")];

    ctx->settings.document_root = get_absolute_path(ctx->settings.document_root, argv[0]);
    ctx->settings.put_delete_auth_file = get_absolute_path(ctx->settings.put_delete_auth_file,argv[0]);
    ctx->settings.access_log_file = get_absolute_path(ctx->settings.access_log_file,argv[0]);
    ctx->settings.error_log_file = get_absolute_path(ctx->settings.error_log_file,argv[0]);
    ctx->settings.global_passwords_file = get_absolute_path(ctx->settings.global_passwords_file,argv[0]);

    // Make extra verification for certain options
    verify_document_root(ctx->settings.document_root);

}

