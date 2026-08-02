CC      ?= cc
SRC_DIR := src
BIN     := microhttpd

# --- optimization philosophy ---
# -Os                      : optimize for size (matters for flash/embedded)
# -ffunction-sections
# -fdata-sections           : let the linker drop unused code per-symbol
# -Wl,--gc-sections         : ...and actually drop it at link time
# -fno-asynchronous-unwind-tables : drop C++-style unwind tables we never use
# -fomit-frame-pointer      : one more register free, slightly smaller/faster
# -flto                     : cross-TU inlining/dead-code elim
# -s (strip) at link time   : drop symbol table from the final binary
CFLAGS_COMMON := -std=c11 -Wall -Wextra -Os -flto \
                  -ffunction-sections -fdata-sections \
                  -fno-asynchronous-unwind-tables -fomit-frame-pointer \
                  -D_GNU_SOURCE
LDFLAGS_COMMON := -flto -Wl,--gc-sections -s

SRCS := $(SRC_DIR)/main.c $(SRC_DIR)/server.c $(SRC_DIR)/http.c
SRCS_TLS := $(SRCS) $(SRC_DIR)/tls.c

.PHONY: all tls tiny debug clean sizes run run-tls

# Default: no TLS, smallest/fastest plain-HTTP build.
all: $(BIN)

$(BIN): $(SRCS)
	$(CC) $(CFLAGS_COMMON) $(LDFLAGS_COMMON) -o $@ $(SRCS)

# TLS-enabled build, links mbedTLS (apt: libmbedtls-dev /
# opkg: libmbedtls on OpenWRT). ~40-80KB larger binary, brings HTTPS.
tls: $(SRCS_TLS)
	$(CC) $(CFLAGS_COMMON) -DENABLE_TLS $(LDFLAGS_COMMON) -o $(BIN) $(SRCS_TLS) \
	    -lmbedtls -lmbedx509 -lmbedcrypto

# Static binary for embedded targets with no shared libmbedtls available.
# (Requires static mbedTLS .a libs installed, e.g. via a cross toolchain.)
tls-static: $(SRCS_TLS)
	$(CC) $(CFLAGS_COMMON) -DENABLE_TLS $(LDFLAGS_COMMON) -static -o $(BIN) $(SRCS_TLS) \
	    -lmbedtls -lmbedx509 -lmbedcrypto

# "tiny": plain HTTP, no TLS, maximum size squeeze. Good default for
# read-only flash / very low RAM devices that sit behind a reverse
# proxy or VPN for TLS termination anyway.
tiny: CFLAGS_COMMON += -DMAX_CONNS=16 -DREAD_BUF_SIZE=2048 -DWRITE_BUF_SIZE=2048
tiny: $(SRCS)
	$(CC) $(CFLAGS_COMMON) $(LDFLAGS_COMMON) -o $(BIN) $(SRCS)
	@echo "--- tiny build ---"; ls -lh $(BIN)

debug: CFLAGS_COMMON := -std=c11 -Wall -Wextra -g -O0 -fsanitize=address,undefined -D_GNU_SOURCE
debug: LDFLAGS_COMMON := -fsanitize=address,undefined
debug: $(SRCS)
	$(CC) $(CFLAGS_COMMON) $(LDFLAGS_COMMON) -o $(BIN)-debug $(SRCS)

sizes:
	@echo "sizeof(connection_t) and binary size:"
	@printf '#include "server.h"\n#include <stdio.h>\nint main(void){printf("sizeof(connection_t) = %%zu bytes\\nsizeof(server_t)     = %%zu bytes (%%d conns)\\n", sizeof(connection_t), sizeof(server_t), MAX_CONNS);return 0;}\n' > /tmp/_sz.c
	@$(CC) -D_GNU_SOURCE -I$(SRC_DIR) /tmp/_sz.c -o /tmp/_sz && /tmp/_sz
	@ls -lh $(BIN) 2>/dev/null || echo "(build first: make)"

run: all
	./$(BIN) -p 8080 -d www

run-tls: tls
	./$(BIN) -p 8443 -d www -c certs/server.crt -k certs/server.key

clean:
	rm -f $(BIN) $(BIN)-debug /tmp/_sz /tmp/_sz.c
