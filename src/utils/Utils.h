#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

namespace camrelay {
namespace utils {

/**
 * String utility functions
 */
class StringUtils {
public:
    // Trim whitespace from both ends of a string
    static std::string trim(const std::string& str);
    
    // Convert string to lowercase
    static std::string toLower(const std::string& str);
    
    // Convert string to uppercase
    static std::string toUpper(const std::string& str);
    
    // Split string by delimiter
    static std::vector<std::string> split(const std::string& str, char delimiter);
    
    // Check if string starts with prefix
    static bool startsWith(const std::string& str, const std::string& prefix);
    
    // Check if string ends with suffix
    static bool endsWith(const std::string& str, const std::string& suffix);
    
    // Replace all occurrences of substring
    static std::string replace(const std::string& str, const std::string& from, const std::string& to);
    
    // Check if string is empty or contains only whitespace
    static bool isEmpty(const std::string& str);
};

/**
 * Time utility functions
 */
class TimeUtils {
public:
    // Get current timestamp as string
    static std::string getCurrentTimestamp();
    
    // Get current time in milliseconds since epoch
    static uint64_t getCurrentTimeMs();
    
    // Format duration as human readable string
    static std::string formatDuration(std::chrono::milliseconds duration);
    
    // Sleep for specified milliseconds
    static void sleepMs(uint32_t milliseconds);
};

/**
 * Network utility functions
 */
class NetworkUtils {
public:
    // Parse URL and extract components
    struct URLComponents {
        std::string protocol;
        std::string host;
        int port;
        std::string path;
        std::string username;
        std::string password;
    };
    
    static URLComponents parseUrl(const std::string& url);
    static bool isValidIPAddress(const std::string& ip);
    static bool isValidPort(int port);
    
    // Check if port is available
    static bool isPortAvailable(int port);
    
    // Get local IP address
    static std::string getLocalIP();
    
    // Validate IP address format
    static bool isValidIP(const std::string& ip);
};

/**
 * File system utility functions
 */
class FileUtils {
public:
    // Check if file exists
    static bool fileExists(const std::string& path);
    
    // Check if directory exists
    static bool directoryExists(const std::string& path);
    
    // Create directory recursively
    static bool createDirectory(const std::string& path);
    
    // Get file size
    static size_t getFileSize(const std::string& path);
    
    // Read entire file as string
    static std::string readFile(const std::string& path);
    
    // Write string to file
    static bool writeFile(const std::string& path, const std::string& content);
    
    // Get directory path from file path
    static std::string getDirectory(const std::string& filePath);
    
    // Get filename from file path
    static std::string getFilename(const std::string& filePath);
};

/**
 * Base64 encoding/decoding
 */
class Base64 {
public:
    static std::string encode(const std::string& input);
    static std::string decode(const std::string& input);
};

/**
 * MD5 hash function
 */
class MD5 {
public:
    static std::string hash(const std::string& input);
};

/**
 * Configuration validation utilities
 */
class ConfigValidator {
public:
    // Validate RTSP URL format
    static bool isValidRTSPUrl(const std::string& url);
    
    // Validate log level
    static bool isValidLogLevel(const std::string& level);
    
    // Validate port range
    static bool isValidPortRange(int minPort, int maxPort);
    
    // Validate memory size (in MB)
    static bool isValidMemorySize(int sizeMb);
    
    // Validate timeout value
    static bool isValidTimeout(int timeoutSeconds);
};

} // namespace utils
} // namespace camrelay
