################################################################################
#   Advanced network sniffer
#   Build rules
#   
#   © 2013—2020, Sauron
################################################################################

CC=g++
CFLAGS=-Os -Wall -std=gnu++11 -g -pthread
LIBRARIES=-lstdc++ -lm -lz
SOURCES=*.cpp core/*.cpp plugins/*.cpp
HEADERS=*.hpp core/*.hpp
OUTPUT=sniffer

all: $(OUTPUT)

clean:
	rm -f $(OUTPUT)

package: sniffer.tar.xz

sniffer.tar.xz: sniffer.tar
	xz sniffer.tar

sniffer.tar: Makefile README.md $(HEADERS) $(SOURCES)
	tar -cvf $@ $+

$(OUTPUT): $(SOURCES) $(HEADERS)
	$(CC) -o $(OUTPUT) $(CFLAGS) $(SOURCES) $(LIBRARIES)

.PHONY: all clean package
