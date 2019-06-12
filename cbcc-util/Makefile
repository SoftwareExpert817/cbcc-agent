
CBCC_UTIL_OBJS=cbcc_buffer.o cbcc_debug.o cbcc_util.o cbcc_sock.o cbcc_json.o
CBCC_UTIL_DST=libcbcc_util.so
CBCC_UTIL_CFLAGS=$(CFLAGS) -fPIC -I../cbcc-common/

$(CBCC_UTIL_DST): $(CBCC_UTIL_OBJS)
	$(CC) $(CBCC_UTIL_CFLAGS) -shared -o $(CBCC_UTIL_DST) $(CBCC_UTIL_OBJS) -ljson-c

.c.o:
	$(CC) $(CBCC_UTIL_CFLAGS) -c -o $@ $<
	
clean:
	rm -rf $(CBCC_UTIL_DST) $(CBCC_UTIL_OBJS)

install: $(CBCC_UTIL_DST)
	install -d $(DESTDIR)/$(CBCC_INST_DIR)/lib
	install -D -m755 $(CBCC_UTIL_DST) $(DESTDIR)/$(CBCC_INST_DIR)/lib/

uninstall:
	rm -rf $(DESTDIR)/$(CBCC_INST_DIR)/lib/$(CBCC_UTIL_DST)
