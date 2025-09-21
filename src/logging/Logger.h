#pragma once

#include <string>
#include <fstream>
#include <mutex>
#include <memory>
#include <queue>
#include <thread>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <sstream>
#include <iostream>

namespace camrelay {
namespace logging {

enum class LogLevel {
    TRACE = 0,
    DEBUG = 1,
    INFO = 2,
    WARN = 3,
    ERROR = 4,
    CRITICAL = 5
};

class Logger {
public:
    static Logger& getInstance();
    
    // Initialize logger with configuration
    void initialize(const std::string& level, 
                   const std::string& filePath, 
                   int maxFileSizeMb, 
                   int maxFiles, 
                   bool consoleOutput);
    
    // Initialize logger with separate console and file log levels
    void initialize(const std::string& fileLevel,
                   const std::string& consoleLevel,
                   const std::string& filePath, 
                   int maxFileSizeMb, 
                   int maxFiles, 
                   bool consoleOutput);
    
    // Logging methods
    void trace(const std::string& message);
    void debug(const std::string& message);
    void info(const std::string& message);
    void warn(const std::string& message);
    void error(const std::string& message);
    void critical(const std::string& message);
    
    // Shutdown logger
    void shutdown();
    
    // Set log level at runtime
    void setLogLevel(LogLevel level);
    
    // Set console log level at runtime
    void setConsoleLogLevel(LogLevel level);
    
    // Check if a log level is enabled for console
    bool isConsoleLevelEnabled(LogLevel level) const;
    
    // Check if a log level is enabled for file
    bool isFileLevelEnabled(LogLevel level) const;

    // Constructor and destructor (public for make_unique)
    Logger() = default;
    ~Logger() = default;
    
    // Disable copy constructor and assignment operator
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

private:
    
    // Internal logging method
    void log(LogLevel level, const std::string& message);
    
    // Format log message
    std::string formatMessage(LogLevel level, const std::string& message);
    
    // Get log level name
    std::string getLevelName(LogLevel level) const;
    
    // Get current timestamp
    std::string getCurrentTimestamp() const;
    
    // Background thread for writing logs
    void logWriterThread();
    
    // Rotate log file if needed
    void rotateLogFile();
    
    // Member variables
    std::atomic<LogLevel> fileLevel_{LogLevel::INFO};
    std::atomic<LogLevel> consoleLevel_{LogLevel::INFO};
    std::string filePath_;
    int maxFileSizeMb_;
    int maxFiles_;
    bool consoleOutput_;
    std::atomic<bool> shutdown_{false};
    
    // File output (simplified - no threading)
    std::unique_ptr<std::ofstream> logFile_;
};

// Convenience macros for logging
#define LOG_TRACE(msg) camrelay::logging::Logger::getInstance().trace(msg)
#define LOG_DEBUG(msg) camrelay::logging::Logger::getInstance().debug(msg)
#define LOG_INFO(msg) camrelay::logging::Logger::getInstance().info(msg)
#define LOG_WARN(msg) camrelay::logging::Logger::getInstance().warn(msg)
#define LOG_ERROR(msg) camrelay::logging::Logger::getInstance().error(msg)
#define LOG_CRITICAL(msg) camrelay::logging::Logger::getInstance().critical(msg)

// Macro for logging with stream-like syntax
#define LOG_STREAM(level, msg) do { \
    std::ostringstream oss; \
    oss << msg; \
    camrelay::logging::Logger::getInstance().level(oss.str()); \
} while(0)

#define LOG_TRACE_STREAM(msg) LOG_STREAM(trace, msg)
#define LOG_DEBUG_STREAM(msg) LOG_STREAM(debug, msg)
#define LOG_INFO_STREAM(msg) LOG_STREAM(info, msg)
#define LOG_WARN_STREAM(msg) LOG_STREAM(warn, msg)
#define LOG_ERROR_STREAM(msg) LOG_STREAM(error, msg)
#define LOG_CRITICAL_STREAM(msg) LOG_STREAM(critical, msg)

} // namespace logging
} // namespace camrelay
