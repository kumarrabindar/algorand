CPPC=g++
STD=-std=c++20

SRC= ./
INCLUDE= -I.

LDFLAGS = -pthread -lssl -lcrypto -lvrf

CPPS= $(foreach dir, $(SRC), $(wildcard $(dir)*.cpp))
OBJS=$(CPPS:.cpp=.o)

all: run

run: $(OBJS)
	$(CPPC) -o $@ $^ $(LDFLAGS)

.PHONY: clean 
clean: 
	rm -f run *.o *.d