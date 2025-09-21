#pragma once

#include <string>
#include <map>
#include <vector>
#include <memory>
#include "../utils/Constants.h"

namespace camrelay {
namespace config {

class ConfigManager {
public:
    ConfigManager();
    ~ConfigManager() = default;
    
    // Disable copy constructor and assignment operator
    ConfigManager(const ConfigManager&) = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;
    
    // Load configuration from file
    bool loadConfig(const std::string& configPath);
    
    // Reload configuration (for SIGHUP signal handling)
    bool reloadConfig();
    
    // Get configuration sections
    const ServerConfig& getServerConfig() const { return serverConfig_; }
    const std::vector<CameraConfig>& getCameraConfigs() const { return cameraConfigs_; }
    const LoggingConfig& getLoggingConfig() const { return loggingConfig_; }
    const PerformanceConfig& getPerformanceConfig() const { return performanceConfig_; }
    
    // Get specific camera configuration
    const CameraConfig* getCameraConfig(const std::string& cameraId) const;
    
    // Validate configuration
    bool validateConfig() const;
    
    // Get configuration file path
    const std::string& getConfigPath() const { return configPath_; }
    
    // Check if configuration is loaded
    bool isLoaded() const { return configLoaded_; }

private:
    // Configuration parsing
    bool parseConfigFile(const std::string& content);
    void parseSection(const std::string& sectionName, const std::vector<std::string>& lines);
    void parseServerSection(const std::vector<std::string>& lines);
    void parseCameraSection(const std::string& cameraId, const std::vector<std::string>& lines);
    void parseLoggingSection(const std::vector<std::string>& lines);
    void parsePerformanceSection(const std::vector<std::string>& lines);
    
    // Utility methods
    std::string getValue(const std::map<std::string, std::string>& section, 
                        const std::string& key, 
                        const std::string& defaultValue = "") const;
    int getIntValue(const std::map<std::string, std::string>& section, 
                   const std::string& key, 
                   int defaultValue = 0) const;
    bool getBoolValue(const std::map<std::string, std::string>& section, 
                     const std::string& key, 
                     bool defaultValue = false) const;
    
    // Configuration validation
    bool validateServerConfig() const;
    bool validateCameraConfigs() const;
    bool validateLoggingConfig() const;
    bool validatePerformanceConfig() const;
    bool validateCameraConfig(const CameraConfig& config) const;
    
    // Set default values
    void setDefaults();
    
    // Member variables
    std::string configPath_;
    bool configLoaded_;
    
    // Configuration objects
    ServerConfig serverConfig_;
    std::vector<CameraConfig> cameraConfigs_;
    LoggingConfig loggingConfig_;
    PerformanceConfig performanceConfig_;
    
    // Raw configuration data for parsing
    std::map<std::string, std::map<std::string, std::string>> rawConfig_;
};

} // namespace config
} // namespace camrelay
