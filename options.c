#include "mingoose.h"

// This array must be in sync with enum in internal.h
const char *config_options[] = {
  "put_delete_auth_file", NULL,
  "protect_uri", NULL,
  "authentication_domain", "mydomain.com",
  "throttle", NULL,
  "access_log_file", NULL,
  "enable_directory_listing", "yes",
  "error_log_file", NULL,
  "global_auth_file", NULL,
  "index_files",
    "index.html,index.htm,index.shtml,index.php,index.lp",
  "enable_keep_alive", "no",
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


int get_option_index(const char *name) {
  int i;

  for (i = 0; config_options[i * 2] != NULL; i++) {
    if (strcmp(config_options[i * 2], name) == 0) {
      return i;
    }
  }
  return -1;
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


void set_option(char **options, const char *name, const char *value) {
  int i;

  for (i = 0; i < MAX_OPTIONS - 3; i++) {
    if (options[i] == NULL) {
      options[i] = sdup(name);
      options[i + 1] = sdup(value);
      options[i + 2] = NULL;
      break;
    } else if (!strcmp(options[i], name)) {
      free(options[i + 1]);
      options[i + 1] = sdup(value);
      break;
    }
  }

  if (i == MAX_OPTIONS - 3) {
    die("%s", "Too many options specified");
  }
}


char *get_option(char **options, const char *option_name) {
  int i;

  for (i = 0; options[i] != NULL; i++)
    if (!strcmp(options[i], option_name))
      return options[i + 1];

  return NULL;
}

void verify_document_root(char *path) {
  struct stat st;

  if (path != NULL && (stat(path, &st) != 0 || !S_ISDIR(st.st_mode) )  ) {
    die("Invalid path for document_root: [%s]: %s.\nMake sure that path is either "
        "absolute, or it is relative to mongoose executable.",
        path, strerror(errno));
  }
}

void set_absolute_path(char *options[], const char *option_name,
                              const char *path_to_mongoose_exe) {
  char path[PATH_MAX], abs[PATH_MAX], *option_value;
  const char *p;

  // Check whether option is already set
  option_value = get_option(options, option_name);

  // If option is already set and it is an absolute path,
  // leave it as it is -- it's already absolute.
  if (option_value != NULL && !is_path_absolute(option_value)) {
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
    strncat(path, option_value, sizeof(path) - 1);

    // Absolutize the path, and set the option
    abs_path(path, abs, sizeof(abs));
    set_option(options, option_name, abs);
  }
}

void set_options(char *argv[], char **options) {
  size_t i, cmd_line_opts_start = 1;

  //initialize
  options[0] = NULL;
  // set default document_root
  set_option(options, "document_root", ".");

    // Handle command line flags.
    // They override config file and default settings.
    for (i = cmd_line_opts_start; argv[i] != NULL; i += 2) {
      if (argv[i][0] != '-' || argv[i + 1] == NULL) {
        show_usage_and_exit();
      }
      set_option(options, &argv[i][1], argv[i + 1]);
    }

  // Make sure we have absolute paths for files and directories
  // https://github.com/valenok/mongoose/issues/181
  set_absolute_path(options, "document_root", argv[0]);
  set_absolute_path(options, "put_delete_auth_file", argv[0]);
  set_absolute_path(options, "access_log_file", argv[0]);
  set_absolute_path(options, "error_log_file", argv[0]);
  set_absolute_path(options, "global_auth_file", argv[0]);

  // Make extra verification for certain options
  verify_document_root(get_option(options, "document_root"));


}
