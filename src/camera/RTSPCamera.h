#pragma once

#include <string>
#include <memory>
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include "RTSPClient.h"

namespace camrelay {
namespace camera {

// Camera connection states
enum class CameraState {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    STREAMING,
    ERROR
};

// Camera statistics
struct CameraStats {
    uint64_t packets_received;
    uint64_t bytes_received;
    uint64_t last_packet_time;
    uint64_t connection_time;
    uint64_t streaming_time;
    std::string last_error;
};

// Callback function types
using CameraStateCallback = std::function<void(const std::string& camera_id, CameraState state)>;
using CameraRTPPacketCallback = std::function<void(const std::string& camera_id, const RTPPacket& packet)>;

class RTSPCamera {
public:
    RTSPCamera(const std::string& id, const std::string& name, 
               const std::string& rtsp_url, const std::string& username = "", 
               const std::string& password = "");
    ~RTSPCamera();
    
    // Disable copy constructor and assignment operator
    RTSPCamera(const RTSPCamera&) = delete;
    RTSPCamera& operator=(const RTSPCamera&) = delete;
    
    // Connection management
    bool connect();
    void disconnect();
    bool isConnected() const;
    bool isStreaming() const;
    
    // Stream control
    bool startStream();
    bool stopStream();
    bool pauseStream();
    bool resumeStream();
    
    // Configuration
    void setConnectionTimeout(int timeout_seconds);
    void setRetryCount(int retry_count);
    void setRetryInterval(int interval_seconds);
    void setStreamingTimeout(int timeout_seconds);
    
    // Callbacks
    void setStateCallback(CameraStateCallback callback);
    void setRTPCallback(CameraRTPPacketCallback callback);
    
    // Information
    const std::string& getId() const { return id_; }
    const std::string& getName() const { return name_; }
    const std::string& getRtspUrl() const { return rtsp_url_; }
    CameraState getState() const { return state_; }
    const CameraStats& getStats() const { return stats_; }
    
    // Thread-safe state checking
    bool isState(CameraState expected_state) const { return state_ == expected_state; }
    const RTSPSession& getSession() const;
    const SDPInfo& getSDPInfo() const;
    
    // Error handling
    std::string getLastError() const;
    bool hasError() const;
    void clearError();
    
    // Health monitoring
    bool isHealthy() const;
    uint64_t getLastActivityTime() const;
    
private:
    // Connection management
    bool performConnection();
    void performDisconnection();
    void setState(CameraState new_state);
    void setError(const std::string& error);
    
    // Stream management
    bool setupStream();
    void cleanupStream();
    
    // RTP handling
    void handleRTPPacket(const RTPPacket& packet);
    
    // Health monitoring
    void healthCheckThread();
    bool checkConnectionHealth();
    
    // Fake video data generation for debugging
    void startFakeVideoDataGeneration();
    void fakeVideoDataThread();
    
    // Member variables
    std::string id_;
    std::string name_;
    std::string rtsp_url_;
    std::string username_;
    std::string password_;
    
    // RTSP client
    std::unique_ptr<RTSPClient> rtsp_client_;
    
    // State management
    std::atomic<CameraState> state_;
    std::atomic<bool> should_connect_;
    std::atomic<bool> should_stream_;
    
    // Threading
    std::thread connection_thread_;
    std::thread health_thread_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    
    // Callbacks
    CameraStateCallback state_callback_;
    CameraRTPPacketCallback rtp_callback_;
    
    // Configuration
    int connection_timeout_;
    int retry_count_;
    int retry_interval_;
    
    // Statistics
    CameraStats stats_;
    
    // Error handling
    std::string last_error_;
    std::atomic<bool> has_error_;
    
    // Health monitoring
    std::atomic<uint64_t> last_activity_time_;
    std::atomic<bool> health_check_running_;
    int streaming_timeout_; // Timeout in seconds to wait for streaming confirmation
    
    // Fake video data generation
    std::thread fake_video_thread_;
    std::atomic<bool> fake_video_running_{false};
    std::atomic<uint32_t> fake_sequence_number_{0};
};

} // namespace camera
} // namespace camrelay
