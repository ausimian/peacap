CFLAGS = -O2 -Wall -Wextra -fPIC -I$(ERTS_INCLUDE_DIR)
LDFLAGS = -shared -lpcap

ifeq ($(shell uname),Darwin)
	LDFLAGS += -undefined dynamic_lookup
endif

TARGET = priv/peacap_nif.so

all: priv $(TARGET)

priv:
	mkdir -p priv

$(TARGET): c_src/peacap_nif.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
