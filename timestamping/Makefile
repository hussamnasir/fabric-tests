# SPDX-License-Identifier: GPL-2.0
#CFLAGS += -I../../../../../usr/include
CFLAGS += -I.
CC=gcc 

#TEST_GEN_FILES := hwtstamp_config rxtimestamp timestamping txtimestamp

#all: $(TEST_PROGS)

#top_srcdir = ../../../../..
#KSFT_KHDR_INSTALL := 1
#include ../../lib.mk

all: timestamping.o 
	$(CC) -o timestamping timestamping.o

clean: 
	rm timestamping timestamping.o
