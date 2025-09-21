#include "Logger.h"
#include <iostream>
#include <sstream>
#include <iomanip>

namespace camrelay {
namespace logging {

Logger& Logger::getInstance() {
    static std::once_flag flag;
    static std::unique_ptr<Logger> instance;
    std::call_once(flag, []() {
        instance = std::make_unique<Logger>();
    });
    return *instance;
}

void Logger::initialize(const std::string& level, 
                       const std::string& filePath, 
                       int maxFileSizeMb, 
                       int maxFiles, 
                       bool consoleOutput) {
    // Use the same level for both file and console
    initialize(level, level, filePath, maxFileSizeMb, maxFiles, consoleOutput);
}

void Logger::initialize(const std::string& fileLevel,
                       const std::string& consoleLevel,
                       const std::string& filePath, 
                       int maxFileSizeMb, 
                       int maxFiles, 
                       bool consoleOutput) {
    // Set file log level
    if (fileLevel == "trace") fileLevel_ = LogLevel::TRACE;
    else if (fileLevel == "debug") fileLevel_ = LogLevel::DEBUG;
    else if (fileLevel == "info") fileLevel_ = LogLevel::INFO;
    else if (fileLevel == "warn") fileLevel_ = LogLevel::WARN;
    else if (fileLevel == "error") fileLevel_ = LogLevel::ERROR;
    else if (fileLevel == "critical") fileLevel_ = LogLevel::CRITICAL;
    else fileLevel_ = LogLevel::INFO; // Default to INFO
    
    // Set console log level
    if (consoleLevel == "trace") consoleLevel_ = LogLevel::TRACE;
    else if (consoleLevel == "debug") consoleLevel_ = LogLevel::DEBUG;
    else if (consoleLevel == "info") consoleLevel_ = LogLevel::INFO;
    else if (consoleLevel == "warn") consoleLevel_ = LogLevel::WARN;
    else if (consoleLevel == "error") consoleLevel_ = LogLevel::ERROR;
    else if (consoleLevel == "critical") consoleLevel_ = LogLevel::CRITICAL;
    else consoleLevel_ = LogLevel::INFO; // Default to INFO
    
    filePath_ = filePath;
    maxFileSizeMb_ = maxFileSizeMb;
    maxFiles_ = maxFiles;
    consoleOutput_ = consoleOutput;
    
    // Note: File logging disabled to avoid external dependencies
    // Log directory creation would go here if needed
    
    // Don't log during initialization to avoid circular dependency
}

void Logger::trace(const std::string& message) {
    log(LogLevel::TRACE, message);
}

void Logger::debug(const std::string& message) {
    log(LogLevel::DEBUG, message);
}

void Logger::info(const std::string& message) {
    log(LogLevel::INFO, message);
}

void Logger::warn(const std::string& message) {
    log(LogLevel::WARN, message);
}

void Logger::error(const std::string& message) {
    log(LogLevel::ERROR, message);
}

void Logger::critical(const std::string& message) {
    log(LogLevel::CRITICAL, message);
}

void Logger::shutdown() {
    // Set shutdown flag to prevent new log messages
    shutdown_ = true;
    
    // Flush any pending output
    std::cout.flush();
}

bool Logger::isConsoleLevelEnabled(LogLevel level) const {
    return level >= consoleLevel_;
}

bool Logger::isFileLevelEnabled(LogLevel level) const {
    return level >= fileLevel_;
}

void Logger::log(LogLevel level, const std::string& message) {
    // Check if we should log to console (thread-safe atomic read)
    if (level < consoleLevel_) {
        return;
    }
    
    std::string formattedMessage = formatMessage(level, message);
    
    // Always output to console directly - no background thread, no mutex locks
    std::cout << formattedMessage << std::endl;
}

std::string Logger::formatMessage(LogLevel level, const std::string& message) {
    std::ostringstream oss;
    oss << "[" << getCurrentTimestamp() << "] "
        << "[" << getLevelName(level) << "] "
        << message;
    return oss.str();
}

std::string Logger::getLevelName(LogLevel level) const {
    switch (level) {
        case LogLevel::TRACE: return "TRACE";
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARN: return "WARN";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

std::string Logger::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    // Use thread-safe localtime_r instead of localtime
    struct tm timeinfo;
    localtime_r(&time_t, &timeinfo);
    
    std::ostringstream oss;
    oss << std::put_time(&timeinfo, "%Y-%m-%d %H:%M:%S");
    oss << "." << std::setfill('0') << std::setw(3) << ms.count();
    
    return oss.str();
}

} // namespace logging
} // namespace camrelay