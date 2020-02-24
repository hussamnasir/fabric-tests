# SPDX-License-Identifier: GPL-2.0
#CFLAGS += -I../../../../../usr/include
CFLAGS += -I.
CC=gcc
objects=tcpserver

#all: $(TEST_PROGS)

#top_srcdir = ../../../../..
#KSFT_KHDR_INSTALL := 1
#include ../../lib.mk

$(objects): %: %.c
	$(CC) $(CFLAGS) -o $@ $<

all: $(objects)

clean: 
	$(RM) $(objects) *.o
