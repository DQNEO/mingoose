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


int get_option_index(const char *name) {
  int i;

  for (i = 0; config_options[i] != NULL; i++) {
    if (strcmp(config_options[i], name) == 0) {
      return i;
    }
  }
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

