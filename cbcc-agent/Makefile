
CBCC_AGENT_OBJS=cbcc_agent.o cbcc_session.o cbcc_monitor.o cbcc_config.o cbcc_admin.o
CBCC_AGENT_DST=cbcc-agent
CBCC_AGENT_CFLAGS=$(CFLAGS) -I../cbcc-common/ -I../cbcc-util/
CBCC_AGENT_LIBS=$(LIBS) -L../cbcc-util -lcbcc_util

all: $(CBCC_AGENT_OBJS)
	$(CC) $(CBCC_AGENT_CFLAGS) $(CBCC_AGENT_LIBS) -o $(CBCC_AGENT_DST) $(CBCC_AGENT_OBJS)

$(CBCC_AGENT_DST): $(CBCC_AGENT_OBJS)
	$(CC) $(CBCC_AGENT_CFLAGS) $(CBCC_AGENT_LIBS) -o $(CBCC_AGENT_DST) $(CBCC_AGENT_OBJS)

.c.o:
	$(CC) $(CBCC_AGENT_CFLAGS) -c -o $@ $<
	
clean:
	rm -rf $(CBCC_AGENT_DST) $(CBCC_AGENT_OBJS)

install: $(CBCC_AGENT_DST)
	install -d $(DESTDIR)/$(CBCC_INST_DIR)/sbin
	install -D -m755 $(CBCC_AGENT_DST) $(DESTDIR)/$(CBCC_INST_DIR)/sbin/
	
uninstall:
	rm -rf $(DESTDIR)/$(CBCC_INST_DIR)/sbin/$(CBCC_AGENT_DST)
