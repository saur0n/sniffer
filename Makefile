################################################################################
#   Advanced network sniffer
#   Build rules
#   
#   © 2013—2017, Sauron
################################################################################

CC=gcc
CFLAGS=-Os -Wall -std=gnu++11
LIBRARIES=-lstdc++ -lpthread -lm -lz
SOURCES=*.cpp
OUTPUT=sniffer

all:
	$(CC) -o $(OUTPUT) $(CFLAGS) $(LIBRARIES) $(SOURCES)
