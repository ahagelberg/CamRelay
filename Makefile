# CamRelay Makefile
# Lightweight RTSP Relay for Linux

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2 -g
LDFLAGS = -lpthread -lrt -lssl -lcrypto $(CJSON_LIBS)

# Try to get cJSON include path from pkg-config
PKG_CONFIG := pkg-config
CJSON_CFLAGS := $(shell $(PKG_CONFIG) --cflags libcjson 2>/dev/null)
CJSON_LIBS := $(shell $(PKG_CONFIG) --libs libcjson 2>/dev/null)

# If pkg-config fails, use default paths
ifeq ($(CJSON_CFLAGS),)
    CJSON_CFLAGS := -I/usr/include/cjson
endif
ifeq ($(CJSON_LIBS),)
    CJSON_LIBS := -lcjson
endif

# Directories
SRC_DIR = src
INCLUDE_DIR = include
BUILD_DIR = build
OBJ_DIR = $(BUILD_DIR)/obj
BIN_DIR = $(BUILD_DIR)/bin

# Target executable
TARGET = $(BIN_DIR)/camrelay

# Source files (will be expanded as we add modules)
SOURCES = $(wildcard $(SRC_DIR)/*.c) \
          $(wildcard $(SRC_DIR)/*/*.c)

# Object files
OBJECTS = $(SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

# Include directories
INCLUDES = -I$(INCLUDE_DIR) -I$(SRC_DIR) $(CJSON_CFLAGS)

# Default target
all: $(TARGET)

# Create target executable
$(TARGET): $(OBJECTS) | $(BIN_DIR)
	@echo "Linking $@"
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

# Compile source files to object files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	@echo "Compiling $<"
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Create necessary directories
$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts"
	rm -rf $(BUILD_DIR)

# Install the binary
install: $(TARGET)
	@echo "Installing camrelay"
	install -m 755 $(TARGET) /usr/local/bin/
	install -m 644 config/camrelay.conf.example /etc/camrelay.conf
	install -m 644 systemd/camrelay.service /etc/systemd/system/

# Uninstall
uninstall:
	@echo "Uninstalling camrelay"
	rm -f /usr/local/bin/camrelay
	rm -f /etc/camrelay.conf
	rm -f /etc/systemd/system/camrelay.service

# Run the program (for testing)
run: $(TARGET)
	@echo "Running camrelay"
	./$(TARGET) -c config/camrelay.conf.example

# Debug build
debug: CFLAGS += -DDEBUG -g3 -O0
debug: $(TARGET)

# Release build
release: CFLAGS += -DNDEBUG -O3
release: clean $(TARGET)

# Show help
help:
	@echo "Available targets:"
	@echo "  all      - Build the project (default)"
	@echo "  clean    - Remove build artifacts"
	@echo "  install  - Install the binary and config files"
	@echo "  uninstall- Remove installed files"
	@echo "  run      - Build and run with example config"
	@echo "  debug    - Build with debug flags"
	@echo "  release  - Build optimized release version"
	@echo "  help     - Show this help message"

# Phony targets
.PHONY: all clean install uninstall run debug release help
