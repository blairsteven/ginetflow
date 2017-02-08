ifneq ($(V),1)
	Q=@
endif

CFLAGS += -fPIC -g -O2
CFLAGS += `pkg-config --cflags glib-2.0 gio-2.0`
LDFLAGS += `pkg-config --libs glib-2.0 gio-2.0`

LIBRARY = libginetflow.so

all: $(LIBRARY)

$(LIBRARY): ginetflow.o
	@echo "Building "$@""
	$(Q)$(CC) -shared $(LDFLAGS) -o $@ $^

%.o: %.c
	@echo "Compiling "$<""
	$(Q)$(CC) $(CFLAGS) -c $< -o $@

clean:
	@echo "Cleaning..."
	@rm -f $(LIBRARY) *.o

.PHONY: all clean
