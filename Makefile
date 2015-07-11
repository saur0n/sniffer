all:
	gcc -o sniffer -lstdc++ -lpthread -Os -Wall -std=gnu++11 *.cpp
