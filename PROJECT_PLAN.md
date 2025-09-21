# CamRelay - RTSP Camera Relay System
## Project Planning Document

### Executive Summary
A Linux-based RTSP camera relay system that connects to network cameras with authentication and forwards streams to multiple clients. The system optimizes bandwidth by only streaming when clients are connected.

---

## 1. Requirements Analysis

### 1.1 Functional Requirements
- **Multi-Camera Support**: Connect to one or more RTSP cameras simultaneously
- **RTSP Camera Support**: Support RTSP cameras with authentication
- **Authentication**: Support RTSP authentication (username/password)
- **Stream Relay**: Forward camera streams to multiple clients
- **On-Demand Streaming**: Only stream video when clients are connected
- **Client Management**: Handle multiple concurrent client connections
- **RTSP Client Support**: Support RTSP clients (VLC, ffplay)
- **Future Client Protocol Support**: Design for future web client protocols (HTTP, WebSocket, etc.)
- **Modular Architecture**: Design for future protocol extensibility
- **Configuration**: INI-style configuration with sensible defaults
- **Logging**: Comprehensive logging for monitoring and debugging

### 1.2 Non-Functional Requirements
- **Platform**: Ubuntu 22+ / Debian 11+ (ideally any Linux distribution)
- **Dependencies**: Minimal external libraries
- **Performance**: Low latency, efficient resource usage
- **Reliability**: Handle network interruptions and camera disconnections
- **Scalability**: Support multiple cameras and clients
- **Maintainability**: Clean code with constants, no magic numbers

### 1.3 Development Constraints
- **Development Environment**: SSH-based development
- **Target Deployment**: Same machine as development
- **Code Quality**: No magic numbers, configurable values with defaults

### 1.4 Success Criteria
- **Functional**: Successfully relay RTSP streams from cameras to multiple clients
- **Performance**: Support 10+ concurrent clients per camera with <2 second latency
- **Reliability**: Handle camera disconnections and network interruptions gracefully
- **Usability**: Simple configuration and deployment process

---

## 2. Technology Stack Decision

### 2.1 Selected: C++ with Custom RTSP Implementation
**Decision**: C++ with custom RTSP implementation has been selected for the following reasons:

**Pros:**
- High performance and low latency
- Complete control over RTSP protocol implementation
- Minimal runtime dependencies (no external RTSP libraries)
- Excellent control over memory and resources
- Custom implementation tailored to specific requirements
- No external library compatibility issues
- Full understanding of all protocol interactions

**Cons:**
- More complex development than using existing libraries
- Manual memory management requires careful attention
- Longer development time initially
- Need to implement RTSP protocol from scratch
- Higher risk of protocol implementation bugs

**Dependencies:**
- Custom RTSP implementation - handles RTSP protocol, RTP/RTCP, and media streaming
- C++17 standard library - threading, networking, utilities, configuration parsing
- GCC compiler (C++17 support)
- Make 4.0+ build system

### 2.2 Custom RTSP Implementation Strategy
**Decision**: Custom RTSP implementation has been selected with the following approach:
- Live555 doesn't work with multiple loops

**RTSP Protocol Implementation:**
- Implement core RTSP methods (OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN)
- Handle RTP/RTCP packet processing and synchronization
- Support both Basic and Digest authentication mechanisms
- Implement robust error handling and recovery mechanisms
- Focus on camera compatibility through extensive testing

**Development Approach:**
- Phased implementation starting with basic RTSP functionality
- Comprehensive testing with multiple camera manufacturers
- Incremental feature addition with thorough validation
- Reference RTSP RFC 2326 and RTP RFC 3550 for standards compliance
- Build upon proven networking patterns and socket programming

**Risk Mitigation:**
- Extensive testing with real RTSP cameras during development
- Implement comprehensive logging for debugging protocol issues
- Design modular architecture for easy protocol updates
- Create test suite covering various camera implementations
- Document all protocol interactions and edge cases

---

## 3. C++ Technology Stack Details

### 3.1 Selected Libraries

| Component | Purpose | Size | Integration | Notes |
|-----------|---------|------|-------------|-------|
| Custom RTSP | RTSP/RTP/RTCP | ~500KB | Built-in | Core streaming functionality |
| C++17 std | Config parsing | Built-in | Standard | Configuration management |
| C++17 std | Logging | Built-in | Standard | Basic logging functionality |
| C++17 std | Utilities | Built-in | Standard | Threading, networking, containers |

### 3.2 Build System: Make 4.0+

**Makefile Structure:**
```makefile
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
```

**Build System Benefits:**
- Simple and lightweight
- No additional build dependencies
- Easy to understand and modify
- Fast compilation
- Works on any system with Make 4.0+

**System Requirements for Building:**
- GCC 7+ (C++17 support required)
- Make 4.0+ 
- Standard Linux development tools (build-essential package)
- OpenSSL development libraries (libssl-dev)

**Installation on Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install build-essential libssl-dev
```

**Note**: No external RTSP libraries needed - using custom RTSP implementation with C++17 standard library only

### 3.3 INI Configuration Parsing (C++17 Standard Library)

**Approach**: Use C++17 standard library for INI-style configuration parsing

**Benefits:**
- No external dependencies
- Available on any system with C++17 support
- Smaller binary size
- No version compatibility issues
- Simple and reliable parsing
- Human-readable format

**Implementation Strategy:**
```cpp
// Simple INI parser using C++17 features
class INIParser {
public:
    static std::map<std::string, std::string> parseFile(const std::string& filename);
    static std::string getValue(const std::map<std::string, std::string>& config, 
                               const std::string& key, const std::string& defaultValue = "");
    static int getIntValue(const std::map<std::string, std::string>& config, 
                          const std::string& key, int defaultValue = 0);
    static bool getBoolValue(const std::map<std::string, std::string>& config, 
                            const std::string& key, bool defaultValue = false);
};

// Configuration loading
class ConfigManager {
private:
    std::string readFile(const std::string& filename);
    void parseConfig(const std::string& iniContent);
    std::map<std::string, std::string> config_;
};
```

**Configuration Format:**

**Standard INI Format:**
```ini
# CamRelay Configuration File

[server]
listen_port=8554
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

[camera.2]
id=camera_2
name=Back Door Camera
rtsp_url=rtsp://192.168.1.101:554/stream1
username=admin
password=password123
enabled=true
max_streams=3
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

**Benefits of INI Format:**
- Standard format used by many applications
- Easy to parse with simple string operations
- Human-readable and editable
- Supports comments with #
- Section-based organization
- No external dependencies required

### 3.4 Custom RTSP Implementation Strategy

**Custom RTSP Components We'll Implement:**
- `RTSPClient` - Connect to RTSP cameras with authentication
- `RTSPServer` - Serve streams to multiple clients
- `RTPHandler` - Handle RTP packet processing and synchronization
- `RTCPHandler` - Handle RTCP control and statistics
- `MediaSession` - Manage media stream sessions
- `AuthenticationManager` - Handle Basic and Digest authentication

**Implementation Approach:**
- Modular design with clear separation of concerns
- RAII patterns for automatic resource cleanup
- Exception-safe error handling
- Thread-safe operations for concurrent client handling
- Comprehensive logging for debugging and monitoring

### 3.5 C++ Development Best Practices

**Memory Management:**
- Use smart pointers (`std::unique_ptr`, `std::shared_ptr`)
- RAII for all resource management
- Avoid raw pointers where possible
- Use containers from standard library

**Error Handling:**
- Use exceptions for error conditions
- Custom exception classes for different error types
- Log errors with context information
- Graceful degradation where possible

**Threading:**
- Use `std::thread` for worker threads
- `std::mutex` and `std::condition_variable` for synchronization
- Thread-safe logging with spdlog
- Avoid data races with proper synchronization

**Code Organization:**
- Header-only libraries where possible
- Clear separation of concerns
- Consistent naming conventions
- Comprehensive documentation

---

## 4. System Architecture Design

### 4.1 High-Level Architecture
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   RTSP Camera   │───▶│                  │───▶│   RTSP Client   │
│   (Source)      │    │   CamRelay      │───▶│   (VLC, ffplay) │
└─────────────────┘    │   (Relay Server) │    └─────────────────┘
                       │                  │    ┌─────────────────┐
                       │                  │───▶│   Future Web    │
                       │                  │    │   Client        │
                       └──────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌──────────────────┐
                       │   Configuration  │
                       │   (INI)          │
                       └──────────────────┘
```

### 4.2 Component Architecture Options

#### Option A: Monolithic Design
- Single process handling all functionality
- Simpler deployment and debugging
- Potential single point of failure
- Easier resource management

#### Option B: Microservice Design
- Separate processes for different functions
- Better fault isolation
- More complex deployment
- Higher resource overhead

#### Option C: Modular Design with Future Protocol Extensibility (Recommended)
- Single process with well-defined modules
- RTSP-first implementation with extensible design
- Good balance of simplicity and maintainability
- Clear separation of concerns
- Easier testing and debugging
- Designed for future protocol additions (web clients, other protocols)

### 4.3 Core Components (C++ Implementation)

#### 4.3.1 Configuration Manager (`ConfigManager`)
**Responsibilities:**
- Load and validate INI configuration using C++17 standard library
- Provide default values for missing settings
- Support runtime configuration updates
- Validate camera configurations

**C++ Implementation Details:**
```cpp
class ConfigManager {
public:
    bool loadConfig(const std::string& configPath);
    const ServerConfig& getServerConfig() const;
    const std::vector<CameraConfig>& getCameraConfigs() const;
    const LoggingConfig& getLoggingConfig() const;
    
private:
    void setDefaults();
    bool validateConfig() const;
};
```

**Key Design Decisions:**
- Configuration reloadable at runtime (SIGHUP signal)
- Validation errors logged and defaults used
- Strong typing with configuration structs

#### 4.3.2 Camera Manager (`CameraManager`)
**Responsibilities:**
- Manage RTSP cameras (initial implementation)
- Handle RTSP authentication with cameras
- Monitor connection health
- Manage connection pooling
- Designed for future protocol extensibility

**C++ Implementation Details:**
```cpp
class CameraManager {
public:
    bool addCamera(const CameraConfig& config);
    bool removeCamera(const std::string& cameraId);
    std::shared_ptr<RTSPCamera> getCamera(const std::string& cameraId);
    
private:
    std::map<std::string, std::shared_ptr<RTSPCamera>> cameras_;
    std::thread healthCheckThread_;
    void healthCheckLoop();
};

// RTSP Camera implementation
class RTSPCamera {
public:
    bool connect();
    bool disconnect();
    bool isConnected() const;
    std::string getStreamUrl() const;
    
private:
    std::string rtspUrl_;
    std::string username_;
    std::string password_;
    std::unique_ptr<RTSPClient> rtspClient_;
    std::unique_ptr<AuthenticationManager> authManager_;
};
```

**Key Design Decisions:**
- RTSP-first implementation with extensible design
- Direct RTSP camera management (no plugin system initially)
- One connection per camera (custom RTSP implementation handles multiplexing)
- Exponential backoff retry strategy
- Authentication failures logged with retry
- Future: Can be refactored to plugin architecture

#### 4.3.3 Stream Manager (`StreamManager`)
**Responsibilities:**
- Manage video stream lifecycle using custom RTSP implementation
- Track client connections per stream
- Implement on-demand streaming
- Handle stream multiplexing

**C++ Implementation Details:**
```cpp
class StreamManager {
public:
    bool startStream(const std::string& cameraId);
    bool stopStream(const std::string& cameraId);
    void addClient(const std::string& cameraId, ClientConnection client);
    void removeClient(const std::string& cameraId, ClientConnection client);
    
private:
    std::map<std::string, std::shared_ptr<VideoStream>> activeStreams_;
    std::map<std::string, std::set<ClientConnection>> streamClients_;
};
```

**Key Design Decisions:**
- RTSP protocol monitoring for client detection
- Streams are live (no caching for simplicity)
- Quality/bitrate handled by camera settings

#### 4.3.4 Client Manager (`ClientManager`)
**Responsibilities:**
- Accept RTSP client connections (VLC, ffplay)
- Track active clients
- Handle client disconnections
- Enforce connection limits
- Designed for future protocol extensibility (web clients, HTTP, WebSocket)

**C++ Implementation Details:**
```cpp
class ClientManager {
public:
    bool startRTSP Server(int port);
    void stopServer();
    size_t getClientCount(const std::string& cameraId) const;
    
    // Future extensibility
    bool startWebServer(int port);  // For future web client support
    void stopWebServer();
    
private:
    std::unique_ptr<RTSPServer> rtspServer_;  // Custom RTSP server
    std::unique_ptr<WebServer> webServer_;    // Future web client support
    std::map<std::string, std::set<RTSPClient>> rtspClients_;
    std::map<std::string, std::set<WebClient>> webClients_;  // Future
    std::mutex clientsMutex_;
};
```

**Key Design Decisions:**
- RTSP-first implementation with extensible architecture
- Direct RTSP server management using custom implementation
- Connection limits enforced per camera and per protocol
- Future: Easy to add web client protocols (HTTP, WebSocket, HLS)
- Plugin architecture ready for future protocol additions

---

## 5. Configuration Schema Design

### 5.1 INI Configuration Structure
```ini
# CamRelay Configuration File

[server]
rtsp_port=8554
max_clients_per_stream=10
connection_timeout_seconds=30
buffer_size_kb=1024

# Future web client support (commented out for now)
# web_port=8080
# websocket_port=8081

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

[camera.2]
id=camera_2
name=Back Door Camera
rtsp_url=rtsp://192.168.1.101:554/stream1
username=admin
password=password123
enabled=true
max_streams=3
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

### 5.2 Configuration Constants (C++ Implementation)
```cpp
// Configuration constants - no magic numbers
namespace ConfigDefaults {
    // Server configuration
    constexpr int LISTEN_PORT = 8554;
    constexpr int MAX_CLIENTS_PER_STREAM = 10;
    constexpr int CONNECTION_TIMEOUT_SECONDS = 30;
    constexpr int BUFFER_SIZE_KB = 1024;
    
    // Camera configuration
    constexpr int RETRY_INTERVAL_SECONDS = 30;
    constexpr int CAMERA_CONNECTION_TIMEOUT_SECONDS = 10;
    constexpr int MAX_STREAMS_PER_CAMERA = 5;
    
    // Logging configuration
    constexpr int MAX_FILE_SIZE_MB = 100;
    constexpr int MAX_LOG_FILES = 5;
    constexpr std::string_view LOG_LEVEL = "info";
    constexpr std::string_view LOG_FILE_PATH = "/var/log/camrelay.log";
    
    // Performance configuration
    constexpr int THREAD_POOL_SIZE = 4;
    constexpr int KEEPALIVE_INTERVAL_SECONDS = 30;
    constexpr int MAX_MEMORY_USAGE_MB = 512;
}

// Configuration structures for type safety
struct ServerConfig {
    int rtspPort = ConfigDefaults::LISTEN_PORT;
    int maxClientsPerStream = ConfigDefaults::MAX_CLIENTS_PER_STREAM;
    int connectionTimeoutSeconds = ConfigDefaults::CONNECTION_TIMEOUT_SECONDS;
    int bufferSizeKb = ConfigDefaults::BUFFER_SIZE_KB;
    
    // Future web client support
    int webPort = 0;        // Disabled by default
    int websocketPort = 0;  // Disabled by default
};

struct CameraConfig {
    std::string id;
    std::string name;
    std::string rtspUrl;
    std::string username;
    std::string password;
    bool enabled = true;
    int maxStreams = ConfigDefaults::MAX_STREAMS_PER_CAMERA;
    int retryIntervalSeconds = ConfigDefaults::RETRY_INTERVAL_SECONDS;
    int connectionTimeoutSeconds = ConfigDefaults::CAMERA_CONNECTION_TIMEOUT_SECONDS;
};

struct LoggingConfig {
    std::string level = ConfigDefaults::LOG_LEVEL;
    std::string filePath = ConfigDefaults::LOG_FILE_PATH;
    int maxFileSizeMb = ConfigDefaults::MAX_FILE_SIZE_MB;
    int maxFiles = ConfigDefaults::MAX_LOG_FILES;
    bool consoleOutput = true;
};

struct PerformanceConfig {
    int threadPoolSize = ConfigDefaults::THREAD_POOL_SIZE;
    int keepaliveIntervalSeconds = ConfigDefaults::KEEPALIVE_INTERVAL_SECONDS;
    int maxMemoryUsageMb = ConfigDefaults::MAX_MEMORY_USAGE_MB;
};
```

---

## 7. Future Extensibility Considerations

### 7.1 Web Client Protocol Support
**Future Requirements:**
- Web browsers cannot directly consume RTSP streams
- Need HTTP-based streaming protocols for web clients
- Should support multiple web streaming formats

**Planned Protocol Support:**
- **HTTP Live Streaming (HLS)**: For broad browser compatibility
- **WebSocket Streaming**: For low-latency web applications
- **HTTP Chunked Transfer**: For simple web video streaming
- **WebRTC**: For real-time web communication (future consideration)

**Implementation Strategy:**
- Design client manager with protocol abstraction
- Use plugin architecture for different client protocols
- Separate stream processing for different client types
- Maintain single camera connection, multiple client protocols

### 7.2 Architecture Extensibility
**Design Principles:**
- **Protocol Abstraction**: Abstract client protocol handling
- **Stream Processing**: Separate stream processing from protocol handling
- **Configuration**: Extensible configuration for new protocols
- **Modular Components**: Easy to add new protocol handlers

**Future Integration Points:**
```cpp
// Abstract base for client protocol handlers
class ClientProtocolHandler {
public:
    virtual ~ClientProtocolHandler() = default;
    virtual bool startServer(int port) = 0;
    virtual void stopServer() = 0;
    virtual void handleClientConnection(ClientConnection client) = 0;
    virtual std::string getProtocolName() const = 0;
};

// RTSP protocol handler (initial implementation)
class RTSPClientHandler : public ClientProtocolHandler {
    // Implementation using custom RTSP
};

// Future web protocol handlers
class WebSocketClientHandler : public ClientProtocolHandler {
    // Implementation for WebSocket streaming
};

class HLSClientHandler : public ClientProtocolHandler {
    // Implementation for HTTP Live Streaming
};
```

---

## 8. Project Structure and File Organization

### 8.1 Directory Structure
```
CamRelay/
├── Makefile                    # Build configuration
├── README.md                   # Project documentation
├── config/
│   ├── camrelay.ini.example  # Example configuration
│   └── camrelay.ini         # Runtime configuration
├── src/
│   ├── main.cpp               # Application entry point
│   ├── config/
│   │   ├── ConfigManager.h
│   │   └── ConfigManager.cpp
│   ├── camera/
│   │   ├── CameraManager.h
│   │   ├── CameraManager.cpp
│   │   ├── RTSPCamera.h
│   │   └── RTSPCamera.cpp
│   ├── stream/
│   │   ├── StreamManager.h
│   │   ├── StreamManager.cpp
│   │   ├── VideoStream.h
│   │   └── VideoStream.cpp
│   ├── client/
│   │   ├── ClientManager.h
│   │   ├── ClientManager.cpp
│   │   ├── RTSPClient.h
│   │   └── WebClient.h
│   ├── logging/
│   │   ├── Logger.h
│   │   └── Logger.cpp
│   └── utils/
│       ├── Constants.h
│       └── Utils.h
├── include/
│   └── camrelay/
│       └── common.h           # Common includes and types
├── third_party/
│   └── (none)                 # No external RTSP libraries needed
├── tests/
│   ├── test_config.cpp
│   ├── test_camera.cpp
│   └── test_stream.cpp
├── scripts/
│   ├── install_dependencies.sh
│   ├── build.sh
│   └── run.sh
└── docs/
    ├── API.md
    ├── CONFIGURATION.md
    └── DEPLOYMENT.md
```

### 8.2 Build System Details
**Makefile Features:**
- Automatic dependency detection
- Parallel compilation support
- Debug and release build modes
- Clean target for build artifacts
- Single binary output (`camrelay`)
- Installation target for system deployment
- Static linking for portability

**Dependency Management:**
- Custom RTSP: Built-in implementation, no external dependencies
- Configuration parsing: C++17 standard library only
- Logging: C++17 standard library only

---

## 8. Key Design Decisions

### 8.1 Streaming Strategy
**Decision Point**: How to implement on-demand streaming?

**Options:**
1. **Proxy Mode**: Relay packets directly from camera to clients
2. **Buffer Mode**: Buffer stream data and serve to clients
3. **Hybrid Mode**: Start with proxy, add buffering if needed

**Recommendation**: Proxy Mode approach
- **RTSP Clients (VLC, ffplay)**: Use proxy mode for low latency
- **Rationale**: Simple implementation, low latency, efficient resource usage

### 8.2 Client Connection Detection
**Decision Point**: How to detect when clients connect/disconnect?

**Options:**
1. **RTSP Protocol**: Monitor RTSP PLAY/PAUSE/TEARDOWN
2. **TCP Connection**: Monitor TCP connection state
3. **Heartbeat**: Implement custom heartbeat mechanism

**Recommendation**: RTSP protocol monitoring
- **RTSP Clients**: Use RTSP protocol monitoring (PLAY/PAUSE/TEARDOWN)
- **Rationale**: RTSP protocol provides clear connection state information

### 8.3 Error Handling Strategy
**Decision Point**: How to handle various error conditions?

**Error Types:**
- Camera connection failures
- Network interruptions
- Client disconnections
- Configuration errors
- Resource exhaustion

**Strategy**: Implement graceful degradation with automatic recovery

**Error Handling Approach:**
```cpp
// Example error handling pattern
class ErrorHandler {
public:
    enum class ErrorType {
        CAMERA_CONNECTION_FAILED,
        NETWORK_INTERRUPTION,
        CLIENT_DISCONNECTED,
        CONFIGURATION_ERROR,
        RESOURCE_EXHAUSTION
    };
    
    void handleError(ErrorType type, const std::string& details);
    bool canRecover(ErrorType type) const;
    void attemptRecovery(ErrorType type);
    
private:
    void logError(ErrorType type, const std::string& details);
    void notifyOperators(ErrorType type, const std::string& details);
};
```

**Graceful Degradation Examples:**
- **Camera Disconnection**: Log error, attempt reconnection, continue serving other cameras
- **Network Interruption**: Log error, buffer data if possible, resume when connection restored
- **Client Disconnection**: Log info, clean up resources, continue serving other clients
- **Configuration Error**: Log error, use default values, continue operation
- **Resource Exhaustion**: Log warning, reject new connections, continue serving existing clients

**Recovery Mechanisms:**
- Automatic reconnection with exponential backoff
- Resource cleanup and reallocation
- Fallback to default configurations
- Circuit breaker pattern for failing services

### 8.4 Resource Management
**Decision Point**: How to manage system resources?

**Considerations:**
- Memory usage limits
- CPU usage optimization
- Network bandwidth management
- File descriptor limits

**Strategy**: Implement resource monitoring with configurable limits

---

## 9. Deployment and Operations

### 9.1 System Requirements
**Minimum Requirements:**
- CPU: 1 core, 1.5 GHz
- RAM: 512 MB
- Storage: 100 MB
- Network: Stable connection to cameras and clients

**Recommended Requirements:**
- CPU: 2 cores, 2.0 GHz
- RAM: 1 GB
- Storage: 500 MB
- Network: Gigabit Ethernet

### 9.2 Installation Process
1. **Dependencies**: Install build tools and libraries
2. **Build**: Compile from source using Make (creates single binary)
3. **Configuration**: Create and customize INI config
4. **Deployment Options**:
   - **Direct Run**: Execute binary directly with `./camrelay`
   - **Systemd Service**: Install as daemon service (optional)
5. **Testing**: Verify camera connections and client access

### 9.3 Configuration Management
**Configuration File Location:**
- Default: `/etc/camrelay/camrelay.ini`
- User override: `~/.config/camrelay/camrelay.ini`
- Command line: `--config /path/to/config.ini`

**Configuration Validation:**
- INI format validation
- Camera connectivity testing
- Port availability checking
- Permission verification

### 9.4 Monitoring and Logging
**Log Levels:**
- `trace`: Detailed debugging information
- `debug`: Debug information
- `info`: General information
- `warn`: Warning messages
- `error`: Error conditions
- `critical`: Critical errors

**Log Rotation:**
- Automatic log file rotation
- Configurable file size limits
- Retention policy for old logs
- Compression of archived logs

### 9.5 Health Monitoring
**Health Check Endpoints:**
- HTTP endpoint for health status
- Camera connection status
- Client connection counts
- Resource usage statistics

**Alerting:**
- Camera disconnection alerts
- High resource usage warnings
- Configuration error notifications
- System failure alerts

### 9.6 Deployment Options

#### Option 1: Direct Binary Execution
**Usage:**
```bash
# Build the binary
make

# Run directly
./camrelay

# Run with custom config
./camrelay --config /path/to/config.ini

# Run in background
nohup ./camrelay > /dev/null 2>&1 &
```

**Benefits:**
- Simple deployment
- No system integration required
- Easy to test and debug
- Portable across systems

#### Option 2: Systemd Service Installation
**Installation:**
```bash
# Build and install
make
sudo make install

# Enable and start service
sudo systemctl enable camrelay
sudo systemctl start camrelay

# Check status
sudo systemctl status camrelay
```

**Systemd Service File (`/etc/systemd/system/camrelay.service`):**
```ini
[Unit]
Description=CamRelay RTSP Camera Relay
After=network.target

[Service]
Type=simple
User=camrelay
Group=camrelay
ExecStart=/usr/local/bin/camrelay
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

**Benefits:**
- Automatic startup on boot
- Service management (start/stop/restart)
- Logging integration with systemd journal
- Automatic restart on failure
- User/group isolation for security

---

## 10. Implementation Strategy

### 10.1 Development Phases

#### Phase 1: Foundation (Weeks 1-2)
**Goals**: Establish basic project structure and core functionality
**Deliverables**:
- Project structure and Makefile build system
- Configuration management with INI parsing
- Basic logging system with C++17 standard library
- Constants and utilities
- Custom RTSP implementation framework

**Success Criteria**:
- Project builds successfully with GCC and Make
- Configuration loads and validates from INI
- Logging works correctly with file and console output
- Basic RTSP protocol structure is in place

#### Phase 2: RTSP Implementation (Weeks 3-6)
**Goals**: Implement custom RTSP protocol and camera connectivity
**Deliverables**:
- Core RTSP protocol implementation (OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN)
- RTP/RTCP packet handling
- Authentication support (Basic and Digest)
- RTSP camera connection handling
- Basic error handling

**Success Criteria**:
- Can connect to RTSP camera using custom implementation
- Authentication works with both Basic and Digest methods
- Handles connection failures gracefully
- RTP packets are properly processed and relayed

#### Phase 3: Stream Management (Weeks 7-8)
**Goals**: Implement stream relay functionality
**Deliverables**:
- Stream relay to clients
- Client connection tracking
- On-demand streaming
- RTSP server implementation for client connections

**Success Criteria**:
- Can relay stream to client using custom RTSP server
- Starts/stops streaming based on client connections
- Handles multiple clients per stream
- RTSP server properly handles client requests

#### Phase 4: Multi-Camera Support (Week 9)
**Goals**: Support multiple cameras simultaneously
**Deliverables**:
- Multiple camera management
- Per-camera configuration
- Resource management
- Concurrent stream handling

**Success Criteria**:
- Can handle multiple cameras
- Each camera operates independently
- Resource usage is reasonable
- No interference between camera streams

#### Phase 5: Production Readiness (Weeks 10-12)
**Goals**: Make system production-ready
**Deliverables**:
- Comprehensive error handling
- Performance optimization
- Extensive testing with real cameras
- Documentation
- Deployment scripts

**Success Criteria**:
- System runs stably under load
- Good performance characteristics
- Complete documentation
- Tested with multiple camera manufacturers

### 10.2 Risk Mitigation

#### Technical Risks
1. **RTSP Protocol Implementation Issues**
   - *Risk*: Custom RTSP implementation may have compatibility issues with different cameras
   - *Mitigation*: Test with multiple camera models early, follow RFC standards closely
   - *Contingency*: Implement camera-specific workarounds and protocol variations

2. **Performance Issues**
   - *Risk*: High concurrent load may cause problems
   - *Mitigation*: Implement performance testing early
   - *Contingency*: Optimize critical paths, add caching

3. **Network Reliability**
   - *Risk*: Unstable network connections
   - *Mitigation*: Implement robust reconnection logic
   - *Contingency*: Add connection pooling and buffering

#### Project Risks
1. **Timeline Overrun**
   - *Risk*: Custom RTSP implementation may take longer than expected
   - *Mitigation*: Phased development, extensive testing, follow RFC standards
   - *Contingency*: Reduce scope, focus on core functionality, consider fallback to existing libraries

2. **Protocol Implementation Complexity**
   - *Risk*: RTSP protocol complexity may lead to implementation bugs
   - *Mitigation*: Comprehensive testing, reference implementations, RFC compliance
   - *Contingency*: Implement minimal viable protocol first, add features incrementally

---

## 11. Troubleshooting and Common Issues

### 11.1 Common Camera Connection Issues
**Authentication Failures:**
- Verify username/password in configuration
- Check camera authentication method (Basic/Digest)
- Ensure camera supports the authentication method

**Network Connectivity:**
- Test camera accessibility with `telnet <camera_ip> <port>`
- Check firewall rules and network routing
- Verify camera is not behind NAT/firewall

**RTSP Protocol Issues:**
- Test with VLC: `vlc rtsp://camera_url`
- Check camera RTSP implementation compatibility
- Verify stream path and parameters

### 11.2 Client Connection Issues
**RTSP Client Problems:**
- Verify client can reach relay server
- Check port configuration and firewall rules
- Test with different RTSP clients (VLC, ffplay)

**Web Client Problems:**
- Check browser console for JavaScript errors
- Verify WebSocket connection establishment
- Test with different browsers

### 11.3 Performance Issues
**High CPU Usage:**
- Check number of concurrent streams
- Monitor thread usage and blocking operations
- Consider reducing stream quality or resolution

**Memory Issues:**
- Monitor memory usage patterns
- Check for memory leaks in long-running sessions
- Adjust buffer sizes in configuration

**Network Bandwidth:**
- Monitor network utilization
- Check for network congestion
- Consider stream quality adjustments

### 11.4 Configuration Issues
**INI Configuration Errors:**
- Validate INI syntax
- Check required fields and data types
- Verify file permissions and accessibility

**Port Conflicts:**
- Check for port availability
- Verify no other services using same ports
- Test port binding with `netstat` or `ss`

---

## 12. Testing Strategy

### 12.1 Testing Levels
1. **Unit Testing**: Test individual components in isolation
2. **Integration Testing**: Test component interactions
3. **System Testing**: Test complete system functionality
4. **Performance Testing**: Test under various load conditions

### 12.2 Test Scenarios
- Single camera, single client
- Single camera, multiple clients
- Multiple cameras, multiple clients
- Network interruption scenarios
- Camera disconnection scenarios
- Configuration error scenarios
- Resource exhaustion scenarios

### 12.3 Test Environment
- Virtual machines with simulated cameras
- Real RTSP cameras for integration testing
- Network simulation tools for failure testing
- Performance monitoring tools

---

## 13. Deployment Considerations

### 13.1 System Requirements
- **Minimum**: 512MB RAM, 1 CPU core, 100MB storage
- **Recommended**: 1GB RAM, 2 CPU cores, 500MB storage
- **Network**: Stable connection to cameras and clients

### 13.2 Security Considerations
- Configuration file permissions
- Network security (firewall rules)
- Log file security
- No hardcoded credentials

### 13.3 Monitoring
- Health check mechanisms
- Resource usage monitoring
- Connection statistics
- Error rate monitoring

---

## 14. Success Criteria

### 14.1 Functional Success
- [ ] Connects to RTSP cameras with authentication
- [ ] Relays streams to multiple concurrent clients
- [ ] Implements on-demand streaming
- [ ] Handles client disconnections gracefully
- [ ] Supports multiple cameras simultaneously
- [ ] Uses INI configuration with sensible defaults

### 14.2 Performance Success
- [ ] Supports 10+ concurrent clients per camera
- [ ] Memory usage < 100MB under normal load
- [ ] CPU usage < 50% on modern hardware
- [ ] Stream latency < 2 seconds
- [ ] Handles network interruptions gracefully

### 14.3 Quality Success
- [ ] Clean, maintainable code with no magic numbers
- [ ] Comprehensive error handling
- [ ] Good test coverage
- [ ] Complete documentation
- [ ] Production-ready deployment

---

## 15. Next Steps

### 15.1 Immediate Actions
1. **Review and refine this plan** - Identify any missing requirements or design issues
2. **Choose technology stack** - Decide between C++, Go, or other options
3. **Finalize architecture** - Confirm component design and interactions
4. **Define detailed interfaces** - Specify APIs between components

### 15.2 C++ Specific Planning Questions
1. **Custom RTSP Implementation**: Are you comfortable with implementing RTSP protocol from scratch?
2. **Memory Management**: Do you prefer the RAII/smart pointer approach outlined?
3. **Error Handling**: Is the exception-based error handling strategy acceptable?
4. **Threading Model**: Does the threading approach with std::thread work for you?
5. **Build System**: GCC with Make 4.0+ has been selected for simplicity

### 15.3 Remaining Decision Points
- **Deployment Model**: Single binary with optional systemd service (decided)
- **Testing Framework**: Google Test vs Catch2 vs custom testing
- **Documentation**: Doxygen vs Sphinx vs Markdown documentation
- **RTSP Protocol Scope**: Which RTSP methods and features to implement first

---

## 16. Appendices

### 16.1 Glossary
- **RTSP**: Real Time Streaming Protocol
- **On-demand streaming**: Streaming only when clients are connected
- **Stream relay**: Forwarding video streams from source to destination
- **Multiplexing**: Serving one stream to multiple clients

### 12.2 References
- RTSP RFC 2326
- RTP RFC 3550
- RTCP RFC 3550
- Linux system programming resources
- Socket programming guides

---

*This document is a living plan that should be updated as decisions are made and requirements evolve.*
