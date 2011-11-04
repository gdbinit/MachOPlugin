ifdef __EA64__
SWITCH64=-D__EA64__
endif
SDKPATH=CHANGME_AND_POINT_TO_THE_SDK_DIR
SRC=machoplugin.cpp processheader.cpp
OBJS=machoplugin.o processheader.o
CC=g++
LD=g++
CFLAGS=-arch i386 -D__IDP__ -D__PLUGIN__ -c -D__MAC__ $(SWITCH64) -I$(SDKPATH)/include $(SRC)
LDFLAGS=-arch i386 --shared $(OBJS) -L$(SDKPATH) -L$(SDKPATH)/bin -lida --no-undefined -Wl

all:
	$(CC) $(CFLAGS)
	$(LD) $(LDFLAGS) -o machoplugin.pmc

