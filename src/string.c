#include <string.h>
#include <stdlib.h>
#include <ctype.h>


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
