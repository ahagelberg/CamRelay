#include "ConfigManager.h"
#include "../utils/Utils.h"
#include "../logging/Logger.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <stdexcept>

namespace camrelay {
namespace config {

ConfigManager::ConfigManager() : configLoaded_(false) {
    setDefaults();
}

bool ConfigManager::loadConfig(const std::string& configPath) {
    configPath_ = configPath;
    
    if (!utils::FileUtils::fileExists(configPath_)) {
        std::cerr << "Configuration file not found: " << configPath_ << std::endl;
        return false;
    }
    
    std::string content = utils::FileUtils::readFile(configPath_);
    if (content.empty()) {
        std::cerr << "Configuration file is empty: " << configPath_ << std::endl;
        return false;
    }
    
    if (!parseConfigFile(content)) {
        std::cerr << "Failed to parse configuration file: " << configPath_ << std::endl;
        return false;
    }
    
    if (!validateConfig()) {
        std::cerr << "Configuration validation failed" << std::endl;
        return false;
    }
    
    configLoaded_ = true;
    LOG_INFO("Configuration loaded successfully from: " + configPath_);
    return true;
}

bool ConfigManager::reloadConfig() {
    if (configPath_.empty()) {
        std::cerr << "No configuration file path set for reload" << std::endl;
        return false;
    }
    
    LOG_INFO("Reloading configuration from: " + configPath_);
    configLoaded_ = false;
    setDefaults();
    return loadConfig(configPath_);
}

const CameraConfig* ConfigManager::getCameraConfig(const std::string& cameraId) const {
    for (const auto& config : cameraConfigs_) {
        if (config.id == cameraId) {
            return &config;
        }
    }
    return nullptr;
}

bool ConfigManager::validateConfig() const {
    return validateServerConfig() && 
           validateCameraConfigs() && 
           validateLoggingConfig() && 
           validatePerformanceConfig();
}

bool ConfigManager::parseConfigFile(const std::string& content) {
    std::istringstream stream(content);
    std::string line;
    std::string currentSection;
    std::vector<std::string> sectionLines;
    
    while (std::getline(stream, line)) {
        // Remove comments and trim whitespace
        size_t commentPos = line.find('#');
        if (commentPos != std::string::npos) {
            line = line.substr(0, commentPos);
        }
        line = utils::StringUtils::trim(line);
        
        if (line.empty()) {
            continue;
        }
        
        // Check for section header [section]
        if (line.front() == '[' && line.back() == ']') {
            // Process previous section if exists
            if (!currentSection.empty()) {
                parseSection(currentSection, sectionLines);
            }
            
            // Start new section
            currentSection = line.substr(1, line.length() - 2);
            sectionLines.clear();
        } else {
            // Add line to current section
            sectionLines.push_back(line);
        }
    }
    
    // Process last section
    if (!currentSection.empty()) {
        parseSection(currentSection, sectionLines);
    }
    
    return true;
}

void ConfigManager::parseSection(const std::string& sectionName, const std::vector<std::string>& lines) {
    std::map<std::string, std::string> sectionData;
    
    for (const auto& line : lines) {
        size_t equalPos = line.find('=');
        if (equalPos != std::string::npos) {
            std::string key = utils::StringUtils::trim(line.substr(0, equalPos));
            std::string value = utils::StringUtils::trim(line.substr(equalPos + 1));
            sectionData[key] = value;
        }
    }
    
    rawConfig_[sectionName] = sectionData;
    
    // Parse specific sections
    if (sectionName == "server") {
        parseServerSection(lines);
    } else if (utils::StringUtils::startsWith(sectionName, "camera.")) {
        std::string cameraId = sectionName.substr(7); // Remove "camera." prefix
        parseCameraSection(cameraId, lines);
    } else if (sectionName == "logging") {
        parseLoggingSection(lines);
    } else if (sectionName == "performance") {
        parsePerformanceSection(lines);
    }
}

void ConfigManager::parseServerSection(const std::vector<std::string>& lines) {
    std::map<std::string, std::string> section;
    for (const auto& line : lines) {
        size_t equalPos = line.find('=');
        if (equalPos != std::string::npos) {
            std::string key = utils::StringUtils::trim(line.substr(0, equalPos));
            std::string value = utils::StringUtils::trim(line.substr(equalPos + 1));
            section[key] = value;
        }
    }
    
    serverConfig_.rtspPort = getIntValue(section, "rtsp_port", ConfigDefaults::LISTEN_PORT);
    serverConfig_.maxClientsPerStream = getIntValue(section, "max_clients_per_stream", ConfigDefaults::MAX_CLIENTS_PER_STREAM);
    serverConfig_.connectionTimeoutSeconds = getIntValue(section, "connection_timeout_seconds", ConfigDefaults::CONNECTION_TIMEOUT_SECONDS);
    serverConfig_.bufferSizeKb = getIntValue(section, "buffer_size_kb", ConfigDefaults::BUFFER_SIZE_KB);
    serverConfig_.webPort = getIntValue(section, "web_port", 0);
    serverConfig_.websocketPort = getIntValue(section, "websocket_port", 0);
}

void ConfigManager::parseCameraSection(const std::string& cameraId, const std::vector<std::string>& lines) {
    std::map<std::string, std::string> section;
    for (const auto& line : lines) {
        size_t equalPos = line.find('=');
        if (equalPos != std::string::npos) {
            std::string key = utils::StringUtils::trim(line.substr(0, equalPos));
            std::string value = utils::StringUtils::trim(line.substr(equalPos + 1));
            section[key] = value;
        }
    }
    
    CameraConfig config;
    config.id = getValue(section, "id", cameraId);
    config.name = getValue(section, "name", "Camera " + cameraId);
    config.rtspUrl = getValue(section, "rtsp_url", "");
    config.username = getValue(section, "username", "");
    config.password = getValue(section, "password", "");
    config.enabled = getBoolValue(section, "enabled", true);
    config.maxStreams = getIntValue(section, "max_streams", ConfigDefaults::MAX_STREAMS_PER_CAMERA);
    config.retryIntervalSeconds = getIntValue(section, "retry_interval_seconds", ConfigDefaults::RETRY_INTERVAL_SECONDS);
    config.connectionTimeoutSeconds = getIntValue(section, "connection_timeout_seconds", ConfigDefaults::CAMERA_CONNECTION_TIMEOUT_SECONDS);
    
    cameraConfigs_.push_back(config);
}

void ConfigManager::parseLoggingSection(const std::vector<std::string>& lines) {
    std::map<std::string, std::string> section;
    for (const auto& line : lines) {
        size_t equalPos = line.find('=');
        if (equalPos != std::string::npos) {
            std::string key = utils::StringUtils::trim(line.substr(0, equalPos));
            std::string value = utils::StringUtils::trim(line.substr(equalPos + 1));
            section[key] = value;
        }
    }
    
    loggingConfig_.level = getValue(section, "level", std::string(ConfigDefaults::LOG_LEVEL));
    loggingConfig_.filePath = getValue(section, "file_path", std::string(ConfigDefaults::LOG_FILE_PATH));
    loggingConfig_.maxFileSizeMb = getIntValue(section, "max_file_size_mb", ConfigDefaults::MAX_FILE_SIZE_MB);
    loggingConfig_.maxFiles = getIntValue(section, "max_files", ConfigDefaults::MAX_LOG_FILES);
    loggingConfig_.consoleOutput = getBoolValue(section, "console_output", true);
}

void ConfigManager::parsePerformanceSection(const std::vector<std::string>& lines) {
    std::map<std::string, std::string> section;
    for (const auto& line : lines) {
        size_t equalPos = line.find('=');
        if (equalPos != std::string::npos) {
            std::string key = utils::StringUtils::trim(line.substr(0, equalPos));
            std::string value = utils::StringUtils::trim(line.substr(equalPos + 1));
            section[key] = value;
        }
    }
    
    performanceConfig_.threadPoolSize = getIntValue(section, "thread_pool_size", ConfigDefaults::THREAD_POOL_SIZE);
    performanceConfig_.keepaliveIntervalSeconds = getIntValue(section, "keepalive_interval_seconds", ConfigDefaults::KEEPALIVE_INTERVAL_SECONDS);
    performanceConfig_.maxMemoryUsageMb = getIntValue(section, "max_memory_usage_mb", ConfigDefaults::MAX_MEMORY_USAGE_MB);
}

std::string ConfigManager::getValue(const std::map<std::string, std::string>& section, 
                                   const std::string& key, 
                                   const std::string& defaultValue) const {
    auto it = section.find(key);
    return (it != section.end()) ? it->second : defaultValue;
}

int ConfigManager::getIntValue(const std::map<std::string, std::string>& section, 
                              const std::string& key, 
                              int defaultValue) const {
    auto it = section.find(key);
    if (it != section.end()) {
        try {
            return std::stoi(it->second);
        } catch (const std::exception& e) {
            std::cerr << "Warning: Invalid integer value for " << key << ": " << it->second << std::endl;
        }
    }
    return defaultValue;
}

bool ConfigManager::getBoolValue(const std::map<std::string, std::string>& section, 
                                const std::string& key, 
                                bool defaultValue) const {
    auto it = section.find(key);
    if (it != section.end()) {
        std::string value = utils::StringUtils::toLower(it->second);
        return (value == "true" || value == "1" || value == "yes" || value == "on");
    }
    return defaultValue;
}

bool ConfigManager::validateServerConfig() const {
    if (serverConfig_.rtspPort < 1 || serverConfig_.rtspPort > 65535) {
        std::cerr << "Error: Invalid RTSP port: " << serverConfig_.rtspPort << std::endl;
        return false;
    }
    
    if (serverConfig_.maxClientsPerStream < 1) {
        std::cerr << "Error: Invalid max clients per stream: " << serverConfig_.maxClientsPerStream << std::endl;
        return false;
    }
    
    if (serverConfig_.connectionTimeoutSeconds < 1) {
        std::cerr << "Error: Invalid connection timeout: " << serverConfig_.connectionTimeoutSeconds << std::endl;
        return false;
    }
    
    if (serverConfig_.bufferSizeKb < 1) {
        std::cerr << "Error: Invalid buffer size: " << serverConfig_.bufferSizeKb << std::endl;
        return false;
    }
    
    return true;
}

bool ConfigManager::validateCameraConfigs() const {
    for (const auto& config : cameraConfigs_) {
        if (!validateCameraConfig(config)) {
            return false;
        }
    }
    return true;
}

bool ConfigManager::validateCameraConfig(const CameraConfig& config) const {
    if (config.id.empty()) {
        std::cerr << "Error: Camera ID cannot be empty" << std::endl;
        return false;
    }
    
    if (config.rtspUrl.empty()) {
        std::cerr << "Error: RTSP URL cannot be empty for camera: " << config.id << std::endl;
        return false;
    }
    
    if (!utils::ConfigValidator::isValidRTSPUrl(config.rtspUrl)) {
        std::cerr << "Error: Invalid RTSP URL for camera " << config.id << ": " << config.rtspUrl << std::endl;
        return false;
    }
    
    if (config.maxStreams < 1) {
        std::cerr << "Error: Invalid max streams for camera " << config.id << ": " << config.maxStreams << std::endl;
        return false;
    }
    
    if (config.retryIntervalSeconds < 1) {
        std::cerr << "Error: Invalid retry interval for camera " << config.id << ": " << config.retryIntervalSeconds << std::endl;
        return false;
    }
    
    if (config.connectionTimeoutSeconds < 1) {
        std::cerr << "Error: Invalid connection timeout for camera " << config.id << ": " << config.connectionTimeoutSeconds << std::endl;
        return false;
    }
    
    return true;
}

bool ConfigManager::validateLoggingConfig() const {
    if (!utils::ConfigValidator::isValidLogLevel(loggingConfig_.level)) {
        std::cerr << "Error: Invalid log level: " << loggingConfig_.level << std::endl;
        return false;
    }
    
    if (loggingConfig_.maxFileSizeMb < 1) {
        std::cerr << "Error: Invalid max file size: " << loggingConfig_.maxFileSizeMb << std::endl;
        return false;
    }
    
    if (loggingConfig_.maxFiles < 1) {
        std::cerr << "Error: Invalid max files: " << loggingConfig_.maxFiles << std::endl;
        return false;
    }
    
    return true;
}

bool ConfigManager::validatePerformanceConfig() const {
    if (performanceConfig_.threadPoolSize < 1) {
        std::cerr << "Error: Invalid thread pool size: " << performanceConfig_.threadPoolSize << std::endl;
        return false;
    }
    
    if (performanceConfig_.keepaliveIntervalSeconds < 1) {
        std::cerr << "Error: Invalid keepalive interval: " << performanceConfig_.keepaliveIntervalSeconds << std::endl;
        return false;
    }
    
    if (performanceConfig_.maxMemoryUsageMb < 1) {
        std::cerr << "Error: Invalid max memory usage: " << performanceConfig_.maxMemoryUsageMb << std::endl;
        return false;
    }
    
    return true;
}

void ConfigManager::setDefaults() {
    // Reset all configurations to defaults
    serverConfig_ = ServerConfig{};
    cameraConfigs_.clear();
    loggingConfig_ = LoggingConfig{};
    performanceConfig_ = PerformanceConfig{};
    rawConfig_.clear();
}

} // namespace config
} // namespace camrelay
