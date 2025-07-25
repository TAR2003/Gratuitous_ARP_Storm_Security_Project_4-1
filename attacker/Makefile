# Makefile for ARP Storm Attack Tools
# Educational/Research Purpose Only

CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra -O2 -pthread
TARGET = arp_storm
SOURCE = arp_storm.cpp

# Platform-specific settings
UNAME := $(shell uname)
ifeq ($(UNAME), Linux)
    LDFLAGS = -pthread
endif
ifeq ($(UNAME), Darwin)  # macOS
    LDFLAGS = -pthread
endif

# Windows (MinGW)
ifdef OS
    ifeq ($(OS), Windows_NT)
        LDFLAGS = -lws2_32 -liphlpapi
        TARGET = arp_storm.exe
    endif
endif

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCE) $(LDFLAGS)

clean:
	rm -f $(TARGET) arp_storm.exe

install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/

uninstall:
	sudo rm -f /usr/local/bin/$(TARGET)

# Run with default parameters
run: $(TARGET)
	sudo ./$(TARGET)

# Run with custom parameters
test: $(TARGET)
	sudo ./$(TARGET) --subnet 192.168.1 --duration 10 --threads 2 --rate 50

help:
	@echo "Available targets:"
	@echo "  all      - Build the ARP storm tool"
	@echo "  clean    - Remove compiled binaries"
	@echo "  install  - Install to /usr/local/bin (Linux/macOS)"
	@echo "  run      - Run with default parameters"
	@echo "  test     - Run with test parameters"
	@echo "  help     - Show this help"
	@echo ""
	@echo "Note: Raw socket operations require administrator/root privileges"

.PHONY: all clean install uninstall run test help
