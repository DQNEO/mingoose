#include "mingoose.h"

const char *month_names[] = {
  "Jan", "Feb", "Mar", "Apr", "May", "Jun",
  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

// Convert month to the month number. Return -1 on error, or month number
int get_month_index(const char *s) {
  int i;

  for (i = 0; i < (int) ARRAY_SIZE(month_names); i++)
    if (!strcmp(s, month_names[i]))
      return i;

  return -1;
}
