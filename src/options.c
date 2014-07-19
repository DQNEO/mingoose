#include "options.h"
#include <string.h>

int get_option_index(const char *name) {
  int i;

  for (i = 0; config_options[i * 2] != NULL; i++) {
    if (strcmp(config_options[i * 2], name) == 0) {
      return i;
    }
  }
  return -1;
}
