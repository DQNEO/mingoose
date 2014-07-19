#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>

void mg_strlcpy(register char *dst, register const char *src, size_t n) {
  for (; *src != '\0' && n > 1; n--) {
    *dst++ = *src++;
  }
  *dst = '\0';
}

char * mg_strndup(const char *ptr, size_t len) {
  char *p;

  if ((p = (char *) malloc(len + 1)) != NULL) {
    mg_strlcpy(p, ptr, len + 1);
  }

  return p;
}

char * mg_strdup(const char *str) {
  return mg_strndup(str, strlen(str));
}


int lowercase(const char *s) {
  return tolower(* (const unsigned char *) s);
}

int mg_strncasecmp(const char *s1, const char *s2, size_t len) {
  int diff = 0;

  if (len > 0)
    do {
      diff = lowercase(s1++) - lowercase(s2++);
    } while (diff == 0 && s1[-1] != '\0' && --len > 0);

  return diff;
}

int mg_strcasecmp(const char *s1, const char *s2) {
  int diff;

  do {
    diff = lowercase(s1++) - lowercase(s2++);
  } while (diff == 0 && s1[-1] != '\0');

  return diff;
}

const char *mg_strcasestr(const char *big_str, const char *small_str) {
  int i, big_len = strlen(big_str), small_len = strlen(small_str);

  for (i = 0; i <= big_len - small_len; i++) {
    if (mg_strncasecmp(big_str + i, small_str, small_len) == 0) {
      return big_str + i;
    }
  }

  return NULL;
}

// Like snprintf(), but never returns negative value, or a value
// that is larger than a supplied buffer.
// Thanks to Adam Zeldis to pointing snprintf()-caused vulnerability
// in his audit report.
int mg_vsnprintf(char *buf, size_t buflen, const char *fmt, va_list ap) {
  int n;

  if (buflen == 0) {
    return 0;
  }

  n = vsnprintf(buf, buflen, fmt, ap);

  if (n < 0) {
    n = 0;
  } else if (n >= (int) buflen) {
    n = (int) buflen - 1;
  }
  buf[n] = '\0';

  return n;
}
