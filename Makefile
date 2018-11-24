################################################################################
#   Advanced network sniffer
#   Build rules
#   
#   © 2013—2018, Sauron
################################################################################

CC=gcc
CFLAGS=-Os -Wall -std=gnu++11 -g
LIBRARIES=-lstdc++ -lpthread -lm -lz
SOURCES=*.cpp core/*.cpp plugins/*.cpp
OUTPUT=sniffer

all: $(OUTPUT)

clean:
	rm -f $(OUTPUT)

$(OUTPUT): $(SOURCES) *.hpp
	$(CC) -o $(OUTPUT) $(CFLAGS) $(LIBRARIES) $(SOURCES)

.PHONY: all clean
