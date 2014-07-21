#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include "mingoose.h"


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


int mg_snprintf(char *buf, size_t buflen, const char *fmt, ...) {
  va_list ap;
  int n;

  va_start(ap, fmt);
  n = mg_vsnprintf(buf, buflen, fmt, ap);
  va_end(ap);

  return n;
}

// Perform case-insensitive match of string against pattern
int match_prefix(const char *pattern, int pattern_len, const char *str) {
  const char *or_str;
  int i, j, len, res;

  if ((or_str = (const char *) memchr(pattern, '|', pattern_len)) != NULL) {
    res = match_prefix(pattern, or_str - pattern, str);
    return res > 0 ? res :
        match_prefix(or_str + 1, (pattern + pattern_len) - (or_str + 1), str);
  }

  i = j = 0;
  res = -1;
  for (; i < pattern_len; i++, j++) {
    if (pattern[i] == '?' && str[j] != '\0') {
      continue;
    } else if (pattern[i] == '$') {
      return str[j] == '\0' ? j : -1;
    } else if (pattern[i] == '*') {
      i++;
      if (pattern[i] == '*') {
        i++;
        len = (int) strlen(str + j);
      } else {
        len = (int) strcspn(str + j, "/");
      }
      if (i == pattern_len) {
        return j + len;
      }
      do {
        res = match_prefix(pattern + i, pattern_len - i, str + j + len);
      } while (res == -1 && len-- > 0);
      return res == -1 ? -1 : j + res + len;
    } else if (lowercase(&pattern[i]) != lowercase(&str[j])) {
      return -1;
    }
  }
  return j;
}

// A helper function for traversing a comma separated list of values.
// It returns a list pointer shifted to the next value, or NULL if the end
// of the list found.
// Value is stored in val vector. If value has form "x=y", then eq_val
// vector is initialized to point to the "y" part, and val vector length
// is adjusted to point only to "x".
const char *next_vector(const char *list, struct vec *val,
                        struct vec *eq_val) {
    if (list == NULL || *list == '\0') {
        // End of the list
        list = NULL;
        return list;
    }

    val->ptr = list;
    if ((list = strchr(val->ptr, ',')) != NULL) {
        // Comma found. Store length and shift the list ptr
        val->len = list - val->ptr;
        list++;
    } else {
        // This value is the last one
        list = val->ptr + strlen(val->ptr);
        val->len = list - val->ptr;
    }

    if (eq_val != NULL) {
        // Value has form "x=y", adjust pointers and lengths
        // so that val points to "x", and eq_val points to "y".
        eq_val->len = 0;
        eq_val->ptr = (const char *) memchr(val->ptr, '=', val->len);
        if (eq_val->ptr != NULL) {
            eq_val->ptr++;  // Skip over '=' character
            eq_val->len = val->ptr + val->len - eq_val->ptr;
            val->len = (eq_val->ptr - val->ptr) - 1;
        }
    }

    return list;
}
