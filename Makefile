################################################################################
#   Advanced network sniffer
#   Build rules
#   
#   © 2013—2020, Sauron
################################################################################

CC=g++
CFLAGS=-Os -Wall -std=gnu++11 -g
LIBRARIES=-lstdc++ -lpthread -lm -lz
SOURCES=*.cpp core/*.cpp plugins/*.cpp
HEADERS=*.hpp core/*.hpp
OUTPUT=sniffer

all: $(OUTPUT)

clean:
	rm -f $(OUTPUT)

$(OUTPUT): $(SOURCES) $(HEADERS)
	$(CC) -o $(OUTPUT) $(CFLAGS) $(LIBRARIES) $(SOURCES)

.PHONY: all clean
