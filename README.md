# CamRelay

Lightweight RTSP Relay for Linux

A single-process, multi-threaded RTSP relay service that efficiently streams multiple camera feeds to multiple clients with on-demand source connection management.

## Features

- **Single Process Design**: Lightweight daemon with thread-per-client model
- **On-Demand Streaming**: Only connects to cameras when clients are viewing
- **Multiple Stream Support**: Handle multiple streams per camera
- **Resource Management**: Configurable limits for memory, CPU, and connections
- **Protocol Support**: RTSP 1.0/2.0 over TCP (primary) and UDP
- **Codec Support**: H.264 (primary), H.265 (future)
- **Web Browser Compatible**: Streams suitable for web browser viewing
- **Authentication**: Support for camera authentication
- **Error Handling**: Robust error handling with camera offline detection

## Quick Start

### Build

```bash
# Build release version
./scripts/build.sh

# Build debug version
./scripts/build.sh -t debug

# Clean build
./scripts/build.sh -c

# Build and install
./scripts/build.sh -i
```

### Configuration

1. Copy the example configuration:
```bash
sudo cp config/camrelay.conf.example /etc/camrelay.conf
```

2. Edit the configuration file:
```bash
sudo nano /etc/camrelay.conf
```

3. Start the service:
```bash
sudo systemctl start camrelay
```

### Manual Run

```bash
# Run with example config
./build/bin/camrelay -c config/camrelay.conf.example

# Run as daemon
./build/bin/camrelay -c /etc/camrelay.conf -d

# Debug mode
./build/bin/camrelay -c config/camrelay.conf.example --log-level debug
```

## Configuration

CamRelay supports multiple configuration formats:

- **INI format** (default): `camrelay.conf`
- **JSON format**: `camrelay.json`

### Example Configuration

```ini
# Global settings
listen_port = 8554
max_clients = 16
max_memory_mb = 512
log_level = info

# Stream configurations
[stream]
camera_id = cam1
name = cam1_main
rtsp_url = rtsp://192.168.1.100:554/stream1
username = admin
password = mypassword
```

## Architecture

- **Main Controller**: Coordinates all system components
- **Stream Manager**: Manages camera connections and on-demand logic
- **Client Pool**: One thread per client for handling connections
- **Resource Manager**: Enforces configurable resource limits
- **Error Handler**: Centralized error handling and recovery

## Requirements

- Linux (Debian/Ubuntu recommended)
- GCC 4.9+ or Clang 3.5+
- POSIX threads support
- Network camera with RTSP support

## Building from Source

### Dependencies

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install build-essential pkg-config

# Optional: live555 for RTSP support
sudo apt-get install liblive555-dev
```

### Build Steps

```bash
git clone <repository-url>
cd CamRelay
./scripts/build.sh
```

## Project Status

This is the initial version (v0.1.0) with basic structure and build system.

### Completed
- [x] Project structure and build system
- [x] Basic configuration parsing
- [x] Logging system
- [x] Error handling framework
- [x] Systemd service integration

### In Progress
- [ ] Core RTSP implementation
- [ ] Stream management
- [ ] Client handling
- [ ] Resource management

## License

[License information to be added]

## Contributing

[Contributing guidelines to be added]
