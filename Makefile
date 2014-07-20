# This Makefile is part of Mingoose web server project,
#
# Example custom build:
# CFLAGS_EXTRA="-g -O0 -DNO_SSL_DL -llua -lcrypto -lssl" make linux
#
# Flags are:
# -DNDEBUG                - strip off all debug code (-5kb)
# -DDEBUG                 - build debug version (very noisy) (+7kb)
# -DNO_CGI                - disable CGI support (-5kb)
# -DNO_SSL                - disable SSL functionality (-2kb)
# -DNO_SSL_DL             - link against system libssl library (-1kb)
# -DCONFIG_FILE=\"file\"  - use `file' as the default config file
# -DSSL_LIB=\"libssl.so.<version>\"   - use system versioned SSL shared object
# -DCRYPTO_LIB=\"libcrypto.so.<version>\" - use system versioned CRYPTO so

PROG = mingoose
CFLAGS = -std=c99 -W -Wall -pedantic -pthread -g -O0 -DNO_SSL_DL -DNO_SSL -DNO_CGI -ldl -lm -lssl

# Make sure that the compiler flags come last in the compilation string.
# If not so, this can break some on some Linux distros which use
# "-Wl,--as-needed" turned on by default  in cc command.
# Also, this is turned in many other distros in static linkage builds.
$(PROG): mingoose.c mingoose.h request.c string.c parse_date.c mg_printf.c response.c logger.c
	$(CC) mingoose.c request.c string.c options.c parse_date.c auth.c mg_printf.c response.c logger.c -o $@ $(CFLAGS)

test:	$(PROG)
	prove t/00.t

tests:
	perl testold/test.pl $(TEST)

clean:
	rm -rf *.o $(PROG)
