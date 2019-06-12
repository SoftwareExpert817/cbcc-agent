# Makefile for CBCC

export MAKE = make
export CC = gcc
export CFLAGS += --std=gnu99 -Wall -pedantic -Wextra -Wformat-nonliteral -Wformat-security -Winit-self \
		 -Wswitch-default -Wunused-parameter -Wundef -Wunsafe-loop-optimizations -Wbad-function-cast -Wcast-qual -Wwrite-strings \
		 -Wlogical-op -fmessage-length=0

export CBCC_INST_DIR = /usr

export LIBS += -lpthread -ljson-c -lcrypto -lssl

all: build-util build-cbcc-agent

build-util:
	$(MAKE) -C cbcc-util
	
build-cbcc-agent: build-util
	$(MAKE) -C cbcc-agent
	
clean:
	$(MAKE) -C cbcc-util clean
	$(MAKE) -C cbcc-agent clean

install:
	$(MAKE) -C cbcc-util install
	$(MAKE) -C cbcc-agent install

uninstall:
	$(MAKE) -C cbcc-util uninstall
	$(MAKE) -C cbcc-agent install
