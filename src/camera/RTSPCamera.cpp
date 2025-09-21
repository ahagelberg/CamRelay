#include "RTSPCamera.h"
#include "../utils/Utils.h"
#include "../logging/Logger.h"
#include <chrono>
#include <iostream>
#include <future>

namespace camrelay {
namespace camera {

RTSPCamera::RTSPCamera(const std::string& id, const std::string& name, 
                       const std::string& rtsp_url, const std::string& username, 
                       const std::string& password)
    : id_(id)
    , name_(name)
    , rtsp_url_(rtsp_url)
    , username_(username)
    , password_(password)
    , state_(CameraState::DISCONNECTED)
    , should_connect_(false)
    , should_stream_(false)
    , connection_timeout_(10)
    , retry_count_(3)
    , retry_interval_(30)
    , has_error_(false)
    , last_activity_time_(0)
    , health_check_running_(false)
    , streaming_timeout_(30) { // 30 seconds timeout for streaming confirmation
    
    // Initialize stats
    stats_.packets_received = 0;
    stats_.bytes_received = 0;
    stats_.last_packet_time = 0;
    stats_.connection_time = 0;
    stats_.streaming_time = 0;
    
    // Create RTSP client
    rtsp_client_ = std::make_unique<RTSPClient>();
    
    // Set up RTP callback
    rtsp_client_->setRTPCallback([this](const RTPPacket& packet) {
        handleRTPPacket(packet);
    });
}

RTSPCamera::~RTSPCamera() {
    // Don't call disconnect() in destructor to avoid hanging
    // Just set flags to stop threads
    should_connect_ = false;
    should_stream_ = false;
    cv_.notify_all();
    
    // Detach threads if they're still running
    if (connection_thread_.joinable()) {
        connection_thread_.detach();
    }
    if (health_thread_.joinable()) {
        health_thread_.detach();
    }
    
    rtsp_client_.reset();
}

bool RTSPCamera::connect() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        
        if (state_ == CameraState::CONNECTED || state_ == CameraState::STREAMING) {
            return true; // Already connected
        }
        
        if (state_ == CameraState::CONNECTING) {
            return false; // Already connecting
        }
        
        setState(CameraState::CONNECTING);
        should_connect_ = true;
    } // Mutex is unlocked here
    
    // Start connection thread (outside the locked section)
    connection_thread_ = std::thread([this]() {
        performConnection();
    });
    
    return true;
}

void RTSPCamera::disconnect() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        should_connect_ = false;
        should_stream_ = false;
    }
    
    // Notify all waiting threads
    cv_.notify_all();
    
    // Try to join connection thread with very short timeout
    if (connection_thread_.joinable()) {
        // Use a future to implement a timeout for thread joining
        auto future = std::async(std::launch::async, [this]() {
            connection_thread_.join();
        });
        
        if (future.wait_for(std::chrono::milliseconds(100)) == std::future_status::timeout) {
            // Thread didn't join in time, detach it immediately
            connection_thread_.detach();
        }
    }
    
    // Try to join health thread with very short timeout
    if (health_thread_.joinable()) {
        health_check_running_ = false;
        cv_.notify_all();
        
        auto future = std::async(std::launch::async, [this]() {
            health_thread_.join();
        });
        
        if (future.wait_for(std::chrono::milliseconds(50)) == std::future_status::timeout) {
            // Thread didn't join in time, detach it immediately
            health_thread_.detach();
        }
    }
    
    performDisconnection();
}

bool RTSPCamera::isConnected() const {
    return isState(CameraState::CONNECTED) || isState(CameraState::STREAMING);
}

bool RTSPCamera::isStreaming() const {
    return isState(CameraState::STREAMING);
}

bool RTSPCamera::startStream() {
    LOG_DEBUG("Camera " + id_ + " startStream() called, current state: " + std::to_string(static_cast<int>(state_.load())));
    
    if (isState(CameraState::STREAMING)) {
        LOG_DEBUG("Camera " + id_ + " is already streaming, no action needed");
        return true;
    }
    
    if (!isState(CameraState::CONNECTED)) {
        LOG_WARN("Camera " + id_ + " not connected, cannot start stream");
        setError("Camera not connected");
        return false;
    }
    
    should_stream_ = true;
    LOG_DEBUG("Camera " + id_ + " calling setupStream()...");
    
    if (!setupStream()) {
        LOG_WARN("Camera " + id_ + " setupStream() failed: " + last_error_);
        setError("Failed to setup stream");
        return false;
    }
    
    LOG_DEBUG("Camera " + id_ + " setupStream() succeeded, waiting for data to confirm streaming");
    // Don't set STREAMING state yet - wait for actual RTP data
    stats_.streaming_time = utils::TimeUtils::getCurrentTimeMs();
    
    LOG_DEBUG("Camera " + id_ + " startStream() completed, waiting for data");
    return true;
}

bool RTSPCamera::stopStream() {
    if (!isState(CameraState::STREAMING)) {
        return true; // Not streaming
    }
    
    should_stream_ = false;
    cleanupStream();
    setState(CameraState::CONNECTED);
    return true;
}

bool RTSPCamera::pauseStream() {
    if (!isState(CameraState::STREAMING)) {
        return false;
    }
    
    return rtsp_client_->sendPause();
}

bool RTSPCamera::resumeStream() {
    if (!isState(CameraState::CONNECTED)) {
        return false;
    }
    
    return rtsp_client_->sendPlay();
}

void RTSPCamera::setConnectionTimeout(int timeout_seconds) {
    connection_timeout_ = timeout_seconds;
    if (rtsp_client_) {
        rtsp_client_->setConnectionTimeout(timeout_seconds);
    }
}

void RTSPCamera::setRetryCount(int retry_count) {
    retry_count_ = retry_count;
    if (rtsp_client_) {
        rtsp_client_->setRetryCount(retry_count);
    }
}

void RTSPCamera::setRetryInterval(int interval_seconds) {
    retry_interval_ = interval_seconds;
}

void RTSPCamera::setStreamingTimeout(int timeout_seconds) {
    streaming_timeout_ = timeout_seconds;
}

void RTSPCamera::setStateCallback(CameraStateCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    state_callback_ = callback;
}

void RTSPCamera::setRTPCallback(CameraRTPPacketCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    rtp_callback_ = callback;
}

const RTSPSession& RTSPCamera::getSession() const {
    return rtsp_client_->getSession();
}

const SDPInfo& RTSPCamera::getSDPInfo() const {
    return rtsp_client_->getSDPInfo();
}

std::string RTSPCamera::getLastError() const {
    return last_error_;
}

bool RTSPCamera::hasError() const {
    return has_error_;
}

void RTSPCamera::clearError() {
    has_error_ = false;
    last_error_.clear();
}

bool RTSPCamera::isHealthy() const {
    if (!isState(CameraState::STREAMING)) {
        return false;
    }
    
    uint64_t current_time = utils::TimeUtils::getCurrentTimeMs();
    uint64_t last_activity = last_activity_time_.load();
    
    // Consider unhealthy if no activity for more than 30 seconds
    return (current_time - last_activity) < 30000;
}

uint64_t RTSPCamera::getLastActivityTime() const {
    return last_activity_time_.load();
}

bool RTSPCamera::performConnection() {
    int retry_count = 0;
    
    while (should_connect_ && retry_count < retry_count_) {
        try {
            // Check if we should stop connecting
            if (!should_connect_) {
                break;
            }
            
            // Actually connect to the RTSP source
            LOG_DEBUG("Camera " + id_ + " connecting to " + rtsp_url_);
            
            // Try to connect to the real RTSP source
            LOG_DEBUG("Camera " + id_ + " attempting RTSP connection...");
            bool connected = rtsp_client_->connect(rtsp_url_, username_, password_);
            if (!connected) {
                LOG_WARN("Camera " + id_ + " failed to connect to RTSP source: " + rtsp_client_->getLastError());
                setError("Failed to connect to RTSP source: " + rtsp_client_->getLastError());
                retry_count++;
                continue; // Retry connection
            } else {
                LOG_DEBUG("Camera " + id_ + " successfully connected to RTSP source");
            }
            
            // Only set CONNECTED state when we actually have a working connection
            setState(CameraState::CONNECTED);
            stats_.connection_time = utils::TimeUtils::getCurrentTimeMs();
            clearError();
            
            // Start health monitoring
            if (!health_check_running_) {
                health_check_running_ = true;
                health_thread_ = std::thread([this]() {
                    healthCheckThread();
                });
            }
            
            // Connection successful - streaming will be started separately
            LOG_DEBUG("Camera " + id_ + " connection completed successfully");
            
            return true;
            
        } catch (const std::exception& e) {
            setError("Connection exception: " + std::string(e.what()));
            retry_count++;
        }
    }
    
    setState(CameraState::ERROR);
    return false;
}

void RTSPCamera::performDisconnection() {
    if (rtsp_client_) {
        rtsp_client_->disconnect();
    }
    
    setState(CameraState::DISCONNECTED);
    stats_.connection_time = 0;
    stats_.streaming_time = 0;
}

void RTSPCamera::setState(CameraState new_state) {
    CameraState old_state = state_.exchange(new_state);
    
    if (old_state != new_state) {
        // Log state change
        std::string state_str;
        switch (new_state) {
            case CameraState::DISCONNECTED: state_str = "DISCONNECTED"; break;
            case CameraState::CONNECTING: state_str = "CONNECTING"; break;
            case CameraState::CONNECTED: state_str = "CONNECTED"; break;
            case CameraState::STREAMING: state_str = "STREAMING"; break;
            case CameraState::ERROR: state_str = "ERROR"; break;
        }
        LOG_DEBUG("Camera " + id_ + " state changed to: " + state_str);
        
        // Call callback if set
        if (state_callback_) {
            state_callback_(id_, new_state);
        }
    }
}

void RTSPCamera::setError(const std::string& error) {
    std::lock_guard<std::mutex> lock(mutex_);
    last_error_ = error;
    has_error_ = true;
    stats_.last_error = error;
}

bool RTSPCamera::setupStream() {
    LOG_INFO("Camera " + id_ + " setting up stream");
    
    // DESCRIBE request is required for stream setup
    LOG_DEBUG("Camera " + id_ + " sending DESCRIBE request...");
    bool describe_ok = rtsp_client_->sendDescribe();
    if (!describe_ok) {
        LOG_ERROR("Camera " + id_ + " DESCRIBE request failed: " + rtsp_client_->getLastError());
        setState(CameraState::ERROR);
        return false;
    }
    LOG_INFO("Camera " + id_ + " DESCRIBE request successful");
    
    // SETUP request is required for stream setup
    std::string track_url = rtsp_client_->getFirstTrackURL();
    if (track_url.empty()) {
        LOG_ERROR("Camera " + id_ + " no track URL found in SDP");
        setState(CameraState::ERROR);
        return false;
    }
    
    LOG_DEBUG("Camera " + id_ + " using track URL: " + track_url);
    bool setup_ok = rtsp_client_->sendSetup(track_url, camera::TransportType::UDP);
    if (!setup_ok) {
        LOG_ERROR("Camera " + id_ + " SETUP request failed: " + rtsp_client_->getLastError());
        setState(CameraState::ERROR);
        return false;
    }
    LOG_INFO("Camera " + id_ + " SETUP request successful");
    
    // PLAY request is required for stream setup
    bool play_ok = rtsp_client_->sendPlay();
    if (!play_ok) {
        LOG_ERROR("Camera " + id_ + " PLAY request failed: " + rtsp_client_->getLastError());
        setState(CameraState::ERROR);
        return false;
    }
    LOG_INFO("Camera " + id_ + " PLAY request successful");
    
    // Start RTP receiver
    LOG_DEBUG("Camera " + id_ + " starting RTP receiver...");
    rtsp_client_->startRTPReceiver();
    LOG_DEBUG("Camera " + id_ + " RTP receiver started - waiting for data...");
    
    LOG_INFO("Camera " + id_ + " stream setup completed successfully");
    return true;
}

void RTSPCamera::cleanupStream() {
    if (rtsp_client_) {
        rtsp_client_->sendPause();
    }
}

void RTSPCamera::handleRTPPacket(const RTPPacket& packet) {
    // Update statistics
    stats_.packets_received++;
    stats_.bytes_received += packet.payload.size();
    stats_.last_packet_time = utils::TimeUtils::getCurrentTimeMs();
    last_activity_time_ = stats_.last_packet_time;
    
    // Set STREAMING state when we receive the first packet (confirms data is flowing)
    if (isState(CameraState::CONNECTED) && stats_.packets_received == 1) {
        setState(CameraState::STREAMING);
        LOG_INFO("Camera " + id_ + " confirmed streaming - received first data packet");
    }
    
    // Log video data reception every 100 packets to show data flow
    if (stats_.packets_received % 100 == 0) {
        LOG_DEBUG("Camera " + id_ + " received video packet " + 
                  std::to_string(stats_.packets_received) + 
                  " (seq: " + std::to_string(packet.sequence_number) + 
                  ", payload: " + std::to_string(packet.payload.size()) + " bytes)");
    }
    
    // Forward to callback
    if (rtp_callback_) {
        rtp_callback_(id_, packet);
    }
}

void RTSPCamera::healthCheckThread() {
    while (health_check_running_) {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait_for(lock, std::chrono::seconds(10), [this] { return !health_check_running_; });
        
        if (!health_check_running_) {
            break;
        }
        
        // Check connection health
        if (!checkConnectionHealth()) {
            setError("Health check failed");
            setState(CameraState::ERROR);
            break;
        }
    }
}

bool RTSPCamera::checkConnectionHealth() {
    if (!rtsp_client_ || !rtsp_client_->isConnected()) {
        return false;
    }
    
    uint64_t current_time = utils::TimeUtils::getCurrentTimeMs();
    uint64_t last_activity = last_activity_time_.load();
    
    // Check if camera is in CONNECTED state but hasn't started streaming within timeout
    if (isState(CameraState::CONNECTED)) {
        uint64_t connection_time = stats_.connection_time;
        if (connection_time > 0 && (current_time - connection_time) > (static_cast<uint64_t>(streaming_timeout_) * 1000)) {
            setError("Streaming timeout - no data received within " + std::to_string(streaming_timeout_) + " seconds");
            return false;
        }
    }
    
    // Check if we've received data recently (for streaming cameras)
    if (isState(CameraState::STREAMING)) {
        // If no activity for more than 60 seconds, consider unhealthy
        if ((current_time - last_activity) > 60000) {
            setError("No data received for 60 seconds");
            return false;
        }
    }
    
    return true;
}



} // namespace camera
} // namespace camrelay
