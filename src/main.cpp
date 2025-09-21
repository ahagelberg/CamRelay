#include <iostream>
#include <string>
#include <csignal>
#include <memory>
#include <thread>
#include <chrono>
#include <algorithm>

#include "config/ConfigManager.h"
#include "logging/Logger.h"
#include "utils/Constants.h"
#include "utils/Utils.h"
#include "camera/RTSPCamera.h"
#include "server/RTSPServer.h"

using namespace camrelay;
using namespace camrelay::config;
using namespace camrelay::logging;
using namespace camrelay::camera;
using namespace camrelay::server;
using namespace camrelay::utils;

// Global variables for signal handling
std::unique_ptr<ConfigManager> g_configManager;
std::atomic<bool> g_running{true};
std::vector<std::unique_ptr<RTSPCamera>> g_cameras;
std::unique_ptr<RTSPServer> g_rtspServer;
std::atomic<bool> g_cleanup_done{false};

// Function declarations
void initializeCameras(const ConfigManager& config);
void initializeRTSPServer(const ConfigManager& config);
void monitorCameras();
void cleanupCameras();

// Signal handler for graceful shutdown
void signalHandler(int signal) {
    switch (signal) {
        case SIGINT:
        case SIGTERM:
            LOG_INFO("Received shutdown signal, stopping gracefully...");
            g_running = false;
            cleanupCameras();
            break;
        case SIGHUP:
            LOG_INFO("Received reload signal, reloading configuration...");
            if (g_configManager && g_configManager->reloadConfig()) {
                LOG_INFO("Configuration reloaded successfully");
            } else {
                LOG_ERROR("Failed to reload configuration");
            }
            break;
        default:
            LOG_WARN("Received unknown signal: " + std::to_string(signal));
            break;
    }
}

// Setup signal handlers
void setupSignalHandlers() {
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);
    std::signal(SIGHUP, signalHandler);
}

// Print usage information
void printUsage(const char* programName) {
    std::cout << "Usage: " << programName << " [OPTIONS]\n";
    std::cout << "Options:\n";
    std::cout << "  -c, --config FILE    Configuration file path (default: /etc/camrelay/camrelay.ini)\n";
    std::cout << "  -l, --log-level LVL  Console log level: trace, debug, info, warn, error, critical\n";
    std::cout << "  -h, --help           Show this help message\n";
    std::cout << "  -v, --version        Show version information\n";
    std::cout << "\n";
    std::cout << "Examples:\n";
    std::cout << "  " << programName << " -c /path/to/config.ini\n";
    std::cout << "  " << programName << " --config /etc/camrelay/camrelay.ini --log-level debug\n";
    std::cout << "  " << programName << " -l trace  # Show all messages on console\n";
}

// Print version information
void printVersion() {
    std::cout << "CamRelay v1.0.0\n";
    std::cout << "RTSP Camera Relay System\n";
    std::cout << "Built with C++17 and custom RTSP implementation\n";
}

// Parse command line arguments
struct CommandLineArgs {
    std::string configFile = "/etc/camrelay/camrelay.ini";
    std::string consoleLogLevel = "";  // Empty means use config file setting
    bool showHelp = false;
    bool showVersion = false;
};

CommandLineArgs parseArguments(int argc, char* argv[]) {
    CommandLineArgs args;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            args.showHelp = true;
        } else if (arg == "-v" || arg == "--version") {
            args.showVersion = true;
        } else if (arg == "-c" || arg == "--config") {
            if (i + 1 < argc) {
                args.configFile = argv[++i];
            } else {
                std::cerr << "Error: --config requires a file path\n";
                exit(1);
            }
        } else if (arg == "-l" || arg == "--log-level") {
            if (i + 1 < argc) {
                args.consoleLogLevel = argv[++i];
                // Validate log level
                std::string lowerLevel = args.consoleLogLevel;
                std::transform(lowerLevel.begin(), lowerLevel.end(), lowerLevel.begin(), ::tolower);
                if (lowerLevel != "trace" && lowerLevel != "debug" && lowerLevel != "info" && 
                    lowerLevel != "warn" && lowerLevel != "error" && lowerLevel != "critical") {
                    std::cerr << "Error: Invalid log level: " << args.consoleLogLevel << "\n";
                    std::cerr << "Valid levels: trace, debug, info, warn, error, critical\n";
                    exit(1);
                }
            } else {
                std::cerr << "Error: --log-level requires a level (trace, debug, info, warn, error, critical)\n";
                exit(1);
            }
        } else {
            std::cerr << "Error: Unknown argument: " << arg << "\n";
            printUsage(argv[0]);
            exit(1);
        }
    }
    
    return args;
}

// Initialize logging system
bool initializeLogging(const LoggingConfig& config, const std::string& consoleLogLevel = "") {
    try {
        if (consoleLogLevel.empty()) {
            // Use config file setting for both file and console
            Logger::getInstance().initialize(
                config.level,
                config.filePath,
                config.maxFileSizeMb,
                config.maxFiles,
                config.consoleOutput
            );
        } else {
            // Use separate levels: config file for file, CLI for console
            Logger::getInstance().initialize(
                config.level,      // File log level from config
                consoleLogLevel,   // Console log level from CLI
                config.filePath,
                config.maxFileSizeMb,
                config.maxFiles,
                config.consoleOutput
            );
        }
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Failed to initialize logging: " << e.what() << std::endl;
        return false;
    }
}

// Main application logic (placeholder for now)
void runApplication(const ConfigManager& config) {
    LOG_DEBUG("CamRelay starting up...");
    
    // Log configuration summary
    const auto& serverConfig = config.getServerConfig();
    const auto& cameraConfigs = config.getCameraConfigs();
    const auto& loggingConfig = config.getLoggingConfig();
    const auto& performanceConfig = config.getPerformanceConfig();
    
    LOG_DEBUG("Server configuration:");
    LOG_DEBUG("  RTSP Port: " + std::to_string(serverConfig.rtspPort));
    LOG_DEBUG("  Max Clients per Stream: " + std::to_string(serverConfig.maxClientsPerStream));
    LOG_DEBUG("  Connection Timeout: " + std::to_string(serverConfig.connectionTimeoutSeconds) + "s");
    LOG_DEBUG("  Buffer Size: " + std::to_string(serverConfig.bufferSizeKb) + "KB");
    
    LOG_DEBUG("Camera configuration:");
    LOG_DEBUG("  Number of cameras: " + std::to_string(cameraConfigs.size()));
    for (const auto& camera : cameraConfigs) {
        LOG_DEBUG("  Camera " + camera.id + ": " + camera.name + " (" + camera.rtspUrl + ")");
    }
    
    LOG_DEBUG("Logging configuration:");
    LOG_DEBUG("  Level: " + loggingConfig.level);
    LOG_DEBUG("  File: " + loggingConfig.filePath);
    LOG_DEBUG("  Console Output: " + std::string(loggingConfig.consoleOutput ? "enabled" : "disabled"));
    
    LOG_DEBUG("Performance configuration:");
    LOG_DEBUG("  Thread Pool Size: " + std::to_string(performanceConfig.threadPoolSize));
    LOG_DEBUG("  Keepalive Interval: " + std::to_string(performanceConfig.keepaliveIntervalSeconds) + "s");
    LOG_DEBUG("  Max Memory Usage: " + std::to_string(performanceConfig.maxMemoryUsageMb) + "MB");
    
    LOG_INFO("CamRelay initialized successfully");
    LOG_DEBUG("About to initialize cameras...");
    
    // Initialize cameras
    initializeCameras(config);
    LOG_DEBUG("Cameras initialized, about to initialize RTSP server...");
    
    // Initialize RTSP server
    initializeRTSPServer(config);
    LOG_DEBUG("RTSP server initialized, entering main loop...");
    
    // Main application loop
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        // Monitor camera health
        monitorCameras();
    }
    
    LOG_INFO("CamRelay shutting down...");
    
    // Cleanup cameras if not already done by signal handler
    if (!g_cameras.empty()) {
        cleanupCameras();
    }
}

int main(int argc, char* argv[]) {
    // Parse command line arguments
    CommandLineArgs args = parseArguments(argc, argv);
    
    if (args.showHelp) {
        printUsage(argv[0]);
        return 0;
    }
    
    if (args.showVersion) {
        printVersion();
        return 0;
    }
    
    // Setup signal handlers
    setupSignalHandlers();
    
    // Create configuration manager
    g_configManager = std::make_unique<ConfigManager>();
    
    // Load configuration
    if (!g_configManager->loadConfig(args.configFile)) {
        std::cerr << "Failed to load configuration from: " << args.configFile << std::endl;
        return 1;
    }
    
    // Initialize logging with configuration
    if (!initializeLogging(g_configManager->getLoggingConfig(), args.consoleLogLevel)) {
        std::cerr << "Failed to initialize logging system" << std::endl;
        return 1;
    }
    
    // Validate configuration
    if (!g_configManager->validateConfig()) {
        LOG_ERROR("Configuration validation failed");
        return 1;
    }
    
    try {
        // Run main application
        runApplication(*g_configManager);
    } catch (const std::exception& e) {
        LOG_CRITICAL("Application error: " + std::string(e.what()));
        return 1;
    } catch (...) {
        LOG_CRITICAL("Unknown application error occurred");
        return 1;
    }
    
    // Shutdown logging
    Logger::getInstance().shutdown();
    
    LOG_INFO("CamRelay shutdown complete");
    return 0;
}

// Initialize cameras from configuration
void initializeCameras(const ConfigManager& config) {
    const auto& cameraConfigs = config.getCameraConfigs();
    
    LOG_DEBUG("Initializing " + std::to_string(cameraConfigs.size()) + " cameras...");
    LOG_DEBUG("Starting camera initialization loop...");
    
    for (const auto& cameraConfig : cameraConfigs) {
        LOG_DEBUG("Processing camera config: " + cameraConfig.id);
        if (!cameraConfig.enabled) {
            LOG_DEBUG("Skipping disabled camera: " + cameraConfig.id);
            continue;
        }
        
        LOG_DEBUG("Creating camera: " + cameraConfig.id + " (" + cameraConfig.name + ")");
        LOG_DEBUG("About to create RTSPCamera object...");
        
        auto camera = std::make_unique<RTSPCamera>(
            cameraConfig.id,
            cameraConfig.name,
            cameraConfig.rtspUrl,
            cameraConfig.username,
            cameraConfig.password
        );
        
        LOG_DEBUG("RTSPCamera object created successfully");
        
        // Set configuration
        LOG_DEBUG("Setting camera configuration...");
        camera->setConnectionTimeout(cameraConfig.connectionTimeoutSeconds);
        camera->setRetryCount(3);
        camera->setRetryInterval(cameraConfig.retryIntervalSeconds);
        camera->setStreamingTimeout(30); // 30 seconds timeout for streaming confirmation
        LOG_DEBUG("Camera configuration set successfully");
        
        // Set callbacks
        LOG_DEBUG("Setting camera callbacks...");
        camera->setStateCallback([](const std::string& camera_id, CameraState state) {
            std::string state_str;
            switch (state) {
                case CameraState::DISCONNECTED: state_str = "DISCONNECTED"; break;
                case CameraState::CONNECTING: state_str = "CONNECTING"; break;
                case CameraState::CONNECTED: state_str = "CONNECTED"; break;
                case CameraState::STREAMING: state_str = "STREAMING"; break;
                case CameraState::ERROR: state_str = "ERROR"; break;
            }
            LOG_DEBUG("Camera " + camera_id + " state changed to: " + state_str);
        });
        
        // RTP callback will be set after RTSP server is created
        LOG_DEBUG("Camera callbacks set successfully");
        
        // Connect to camera asynchronously
        LOG_DEBUG("About to start camera connection thread...");
        std::thread([camera_ptr = camera.get(), camera_id = cameraConfig.id]() {
            if (camera_ptr->connect()) {
                LOG_DEBUG("Camera " + camera_id + " connection initiated");
                
                // Wait for connection to complete, then start streaming
                // Poll the state until it's CONNECTED or ERROR
                int attempts = 0;
                while (attempts < 100) { // 10 seconds timeout
                    if (camera_ptr->isState(CameraState::CONNECTED)) {
                        LOG_DEBUG("Camera " + camera_id + " connected, starting stream...");
                        if (camera_ptr->startStream()) {
                            LOG_DEBUG("Camera " + camera_id + " stream started successfully");
                        } else {
                            LOG_ERROR("Camera " + camera_id + " failed to start stream");
                        }
                        break;
                    } else if (camera_ptr->isState(CameraState::ERROR)) {
                        LOG_ERROR("Camera " + camera_id + " connection failed");
                        break;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    attempts++;
                }
            } else {
                LOG_ERROR("Failed to initiate connection to camera: " + camera_id);
            }
        }).detach();
        LOG_DEBUG("Camera connection thread started");
        
        g_cameras.push_back(std::move(camera));
        LOG_DEBUG("Camera " + cameraConfig.id + " added to cameras list");
    }
    
    LOG_DEBUG("Camera initialization completed");
}

// Initialize RTSP server
void initializeRTSPServer(const ConfigManager& config) {
    const auto& serverConfig = config.getServerConfig();
    
    LOG_DEBUG("Initializing RTSP server on port " + std::to_string(serverConfig.rtspPort));
    
    // Create RTSP server
    g_rtspServer = std::make_unique<RTSPServer>();
    
    // Configure server
    RTSPServerConfig rtspConfig;
    rtspConfig.port = serverConfig.rtspPort;
    rtspConfig.maxClients = serverConfig.maxClientsPerStream * 10; // Allow more clients than streams
    rtspConfig.clientTimeoutSeconds = serverConfig.connectionTimeoutSeconds;
    rtspConfig.serverName = "CamRelay/1.0";
    
    // Set up camera list for server
    std::vector<std::shared_ptr<RTSPCamera>> cameraList;
    for (const auto& camera : g_cameras) {
        if (camera) {
            cameraList.push_back(std::shared_ptr<RTSPCamera>(camera.get(), [](RTSPCamera*){}));
        }
    }
    g_rtspServer->setCameras(cameraList);
    
    // Set up callbacks
    g_rtspServer->setClientConnectedCallback([](const std::string& sessionId, const std::string& clientIp) {
        LOG_DEBUG("RTSP client connected: " + sessionId + " from " + clientIp);
    });
    
    g_rtspServer->setClientDisconnectedCallback([](const std::string& sessionId, const std::string& clientIp) {
        LOG_DEBUG("RTSP client disconnected: " + sessionId + " from " + clientIp);
    });
    
    g_rtspServer->setStreamRequestCallback([](const std::string& sessionId, const std::string& cameraId) {
        LOG_DEBUG("Stream request: " + sessionId + " for camera " + cameraId);
        return true; // Allow all stream requests for now
    });
    
    // Start server
    if (!g_rtspServer->start(rtspConfig)) {
        LOG_ERROR("Failed to start RTSP server");
        g_rtspServer.reset();
        return;
    }
    
    LOG_DEBUG("RTSP server started successfully on port " + std::to_string(rtspConfig.port));
    
    // Set up RTP callbacks for all cameras now that server is available
    LOG_DEBUG("Setting up RTP callbacks for cameras...");
    for (const auto& camera : g_cameras) {
        if (camera) {
            camera->setRTPCallback([camera_id = camera->getId()](const std::string& camera_id_param, const RTPPacket& packet) {
                // Log packet reception every 30 packets
                static uint64_t packet_count = 0;
                packet_count++;
                if (packet_count % 30 == 0) {
                    LOG_DEBUG("Camera " + camera_id_param + " received RTP packet: seq=" + 
                             std::to_string(packet.sequence_number) + 
                             ", payload_size=" + std::to_string(packet.payload.size()) + 
                             ", total_packets=" + std::to_string(packet_count));
                }
                
                // Forward RTP packet to RTSP server for streaming to clients
                if (g_rtspServer) {
                    g_rtspServer->forwardRTPPacket(camera_id_param, packet);
                } else {
                    LOG_WARN("RTSP server not available to forward packet from camera " + camera_id_param);
                }
            });
        }
    }
    LOG_DEBUG("RTP callbacks set up successfully");
}

// Cleanup cameras during shutdown
void cleanupCameras() {
    // Check if cleanup has already been done
    bool expected = false;
    if (!g_cleanup_done.compare_exchange_strong(expected, true)) {
        return;
    }
    
    LOG_DEBUG("Cleaning up cameras...");
    
    // Stop RTSP server first
    if (g_rtspServer) {
        LOG_DEBUG("Stopping RTSP server...");
        g_rtspServer->stop();
        g_rtspServer.reset();
        LOG_DEBUG("RTSP server stopped");
    }
    
    // Clear all cameras
    g_cameras.clear();
    
    LOG_DEBUG("Camera cleanup completed");
}

// Monitor camera health
void monitorCameras() {
    static uint64_t last_monitor_time = 0;
    uint64_t current_time = TimeUtils::getCurrentTimeMs();
    
    // Monitor every 30 seconds
    if (current_time - last_monitor_time < 30000) {
        return;
    }
    last_monitor_time = current_time;
    
    for (const auto& camera : g_cameras) {
        if (!camera) continue;
        
        const auto& stats = camera->getStats();
        CameraState state = camera->getState();
        
        // Log camera status
        if (state == CameraState::STREAMING) {
            LOG_DEBUG("Camera " + camera->getId() + " stats: " +
                     "packets=" + std::to_string(stats.packets_received) +
                     ", bytes=" + std::to_string(stats.bytes_received) +
                     ", healthy=" + (camera->isHealthy() ? "yes" : "no"));
        } else if (state == CameraState::ERROR) {
            LOG_WARN("Camera " + camera->getId() + " in error state: " + camera->getLastError());
        }
    }
}
