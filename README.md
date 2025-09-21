# CamRelay - RTSP Camera Relay System

A Linux-based RTSP camera relay system that connects to network cameras with authentication and forwards streams to multiple clients. The system optimizes bandwidth by only streaming when clients are connected.

## Features

- **Multi-Camera Support**: Connect to multiple RTSP cameras simultaneously
- **RTSP Client Support**: Support RTSP clients (VLC, ffplay)
- **On-Demand Streaming**: Only stream video when clients are connected
- **Authentication**: Support RTSP authentication (Basic and Digest)
- **RTP Fragmentation**: Handles large video packets with automatic fragmentation
- **Configuration**: INI-style configuration with sensible defaults
- **Logging**: Comprehensive logging for monitoring and debugging
- **Custom RTSP Implementation**: No external dependencies beyond OpenSSL

## Requirements

- **Platform**: Ubuntu 22+ / Debian 11+ (ideally any Linux distribution)
- **Dependencies**: 
  - GCC 7+ (C++17 support)
  - Make 4.0+
  - build-essential
  - libssl-dev
  - pkg-config

## Installation

### 1. Install Dependencies

```bash
sudo apt update
sudo apt install build-essential libssl-dev pkg-config
```

### 2. Build CamRelay

```bash
# Clone the repository
git clone <repository-url>
cd CamRelay

# Build the project
make

# Clean build (if needed)
make clean && make
```

### 3. Install (Optional)

```bash
sudo make install
```

## Configuration

Create a configuration file in INI format:

```bash
# Create configuration directory
sudo mkdir -p /etc/camrelay

# Create configuration file
sudo nano /etc/camrelay/camrelay.ini
```

### Configuration File Format

```ini
[server]
rtsp_port=8554
max_clients_per_stream=10
connection_timeout_seconds=30
buffer_size_kb=1024

[camera.1]
id=camera_1
name=Front Door Camera
rtsp_url=rtsp://192.168.1.100:554/stream1
username=admin
password=password123
enabled=true
max_streams=5
retry_interval_seconds=30
connection_timeout_seconds=10

[logging]
level=info
file_path=/var/log/camrelay.log
max_file_size_mb=100
max_files=5
console_output=true

[performance]
thread_pool_size=4
keepalive_interval_seconds=30
max_memory_usage_mb=512
```

## Usage

### Direct Execution

```bash
# Run with default configuration
./camrelay

# Run with custom configuration
./camrelay --config /path/to/config.ini

# Run in background
nohup ./camrelay > /dev/null 2>&1 &
```

### Systemd Service

```bash
# Enable and start service
sudo systemctl enable camrelay
sudo systemctl start camrelay

# Check status
sudo systemctl status camrelay

# View logs
sudo journalctl -u camrelay -f
```

## Client Access

Once running, clients can connect to the relay server:

```bash
# Using VLC
vlc rtsp://relay-server:8554/camera_1

# Using ffplay
ffplay rtsp://relay-server:8554/camera_1
```

## Logging

Logs are written to:
- Console (if `console_output=true`)
- File: `/var/log/camrelay.log` (configurable)

Log levels: `trace`, `debug`, `info`, `warn`, `error`, `critical`

### Architecture

CamRelay uses a custom RTSP implementation with the following components:

- **RTSPClient**: Connects to source cameras and receives RTP streams
- **RTSPServer**: Serves RTSP streams to clients with session management
- **RTSPCamera**: Manages individual camera connections and state
- **ConfigManager**: Handles INI configuration file parsing
- **Logger**: Provides structured logging with multiple levels

The system handles RTP packet fragmentation automatically for large video frames and supports both Basic and Digest authentication methods.

## Development

### Project Structure

```
CamRelay/
├── src/
│   ├── main.cpp
│   ├── config/
│   │   └── ConfigManager.cpp
│   ├── camera/
│   │   ├── RTSPCamera.cpp
│   │   └── RTSPClient.cpp
│   ├── server/
│   │   └── RTSPServer.cpp
│   ├── logging/
│   │   └── Logger.cpp
│   └── utils/
│       └── Utils.cpp
├── include/
│   └── camrelay/
│       ├── config/
│       ├── camera/
│       ├── server/
│       ├── logging/
│       └── utils/
├── config/
├── tests/
└── docs/
```

### Building

```bash
# Debug build
make

# Clean build
make clean && make

# Install
sudo make install
```

## License

[License information to be added]

## Contributing

[Contributing guidelines to be added]
