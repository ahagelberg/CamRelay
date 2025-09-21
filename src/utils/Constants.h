#pragma once

#include <string_view>

namespace camrelay {
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

    // RTSP Protocol constants
    constexpr std::string_view RTSP_VERSION = "RTSP/1.0";
    constexpr int RTSP_DEFAULT_PORT = 554;
    constexpr int RTP_DEFAULT_PORT_RANGE_START = 5004;
    constexpr int RTP_DEFAULT_PORT_RANGE_END = 65535;
    
    // Network constants
    constexpr int SOCKET_TIMEOUT_SECONDS = 5;
    constexpr int MAX_PACKET_SIZE = 1048576; // 1MB for high-resolution video buffers
    constexpr int RECEIVE_BUFFER_SIZE = 1048576; // 1MB for socket receive buffers
    constexpr int RTP_FRAGMENTATION_THRESHOLD = 65500; // Only fragment packets larger than this
    
    // Authentication constants
    constexpr std::string_view AUTH_BASIC = "Basic";
    constexpr std::string_view AUTH_DIGEST = "Digest";
    constexpr int AUTH_RETRY_COUNT = 3;
    
    // Stream constants
    constexpr int STREAM_TIMEOUT_SECONDS = 60;
    constexpr int MAX_FRAME_SIZE = 1024 * 1024; // 1MB
    constexpr int FRAME_BUFFER_SIZE = 10;

} // namespace ConfigDefaults

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
    std::string level = std::string(ConfigDefaults::LOG_LEVEL);
    std::string filePath = std::string(ConfigDefaults::LOG_FILE_PATH);
    int maxFileSizeMb = ConfigDefaults::MAX_FILE_SIZE_MB;
    int maxFiles = ConfigDefaults::MAX_LOG_FILES;
    bool consoleOutput = true;
};

struct PerformanceConfig {
    int threadPoolSize = ConfigDefaults::THREAD_POOL_SIZE;
    int keepaliveIntervalSeconds = ConfigDefaults::KEEPALIVE_INTERVAL_SECONDS;
    int maxMemoryUsageMb = ConfigDefaults::MAX_MEMORY_USAGE_MB;
};

} // namespace camrelay
