ifneq ($(V),1)
	Q=@
endif

DESTDIR?=
PREFIX?=/usr/
CC:=$(CROSS_COMPILE)gcc
PKG_CONFIG ?= pkg-config

CFLAGS += -fPIC -g -O2 -I.
CFLAGS += `$(PKG_CONFIG) --cflags glib-2.0 gio-2.0`
LDFLAGS += `$(PKG_CONFIG) --libs glib-2.0 gio-2.0`

EXTRA_LDFLAGS = -L. -lginetflow
NDPIVERSION := $(shell $(PKG_CONFIG) --atleast-version=1.7 libndpi && echo NEW || ($(PKG_CONFIG) --exists libndpi && echo OLD || echo NONE))
ifneq ($(NDPIVERSION),NONE)
EXTRA_CFLAGS += $(shell $(PKG_CONFIG) --cflags libndpi)
EXTRA_CFLAGS += -DLIBNDPI_$(NDPIVERSION)_API
EXTRA_LDFLAGS += $(shell $(PKG_CONFIG) --libs libndpi)
endif
EXTRA_LDFLAGS += -lpcap -pthread

LIBRARY = libginetflow.so

all: $(LIBRARY) demo

$(LIBRARY): ginetflow.o
	@echo "Building "$@""
	$(Q)$(CC) -shared $(LDFLAGS) -o $@ $^

%.o: %.c
	@echo "Compiling "$<""
	$(Q)$(CC) $(CFLAGS) -c $< -o $@

demo: demo.c $(LIBRARY)
	@echo "Compiling $@"
	$(Q)$(CC) $(EXTRA_CFLAGS) $(CFLAGS) -o $@ $^ $(EXTRA_LDFLAGS) $(LDFLAGS)

install: all
	@install -d $(DESTDIR)/$(PREFIX)/lib
	@install -D $(LIBRARY) $(DESTDIR)/$(PREFIX)/lib/
	@install -d $(DESTDIR)/$(PREFIX)/include
	@install -D ginetflow.h $(DESTDIR)/$(PREFIX)/include
	@install -d $(DESTDIR)/$(PREFIX)/lib/pkgconfig
	@install -D ginetflow.pc $(DESTDIR)/$(PREFIX)/lib/pkgconfig/

clean:
	@echo "Cleaning..."
	@rm -f $(LIBRARY) *.o demo

.PHONY: all clean
