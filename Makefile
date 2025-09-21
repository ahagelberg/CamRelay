# CamRelay2 Makefile
# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -g -static
INCLUDES = -I./include
LDFLAGS = 
LIBS = -lpthread -lssl -lcrypto -ldl

# Source files
SOURCES = $(wildcard src/*.cpp) $(wildcard src/*/*.cpp)
OBJECTS = $(SOURCES:.cpp=.o)
TARGET = camrelay

# Build rules
$(TARGET): $(OBJECTS)
	$(CXX) $(OBJECTS) -o $(TARGET) $(LDFLAGS) $(LIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

# Installation target
install: $(TARGET)
	install -d /usr/local/bin
	install -m 755 $(TARGET) /usr/local/bin/
	install -d /etc/camrelay
	install -m 644 config/camrelay.ini.example /etc/camrelay/
	install -d /var/log/camrelay
	useradd -r -s /bin/false camrelay 2>/dev/null || true
	chown camrelay:camrelay /var/log/camrelay

clean:
	rm -f $(OBJECTS) $(TARGET)

.PHONY: clean install
