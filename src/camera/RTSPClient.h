#pragma once

#include <string>
#include <map>
#include <vector>
#include <memory>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

namespace camrelay {
namespace camera {

// RTSP Authentication types
enum class AuthType {
    NONE,
    BASIC,
    DIGEST
};

// RTSP Transport types
enum class TransportType {
    UDP,
    TCP
};

// RTP packet structure
struct RTPPacket {
    uint8_t version;
    uint8_t padding;
    uint8_t extension;
    uint8_t csrc_count;
    uint8_t marker;
    uint8_t payload_type;
    uint16_t sequence_number;
    uint32_t timestamp;
    uint32_t ssrc;
    std::vector<uint8_t> payload;
    std::vector<uint8_t> extension_data;
    std::vector<uint32_t> csrc_list;
};

// RTSP session information
struct RTSPSession {
    std::string session_id;
    std::string transport;
    std::string server_port;
    std::string client_port;
    std::string ssrc;
    TransportType transport_type;
    int server_rtp_port;
    int server_rtcp_port;
    int client_rtp_port;
    int client_rtcp_port;
};

// Media description from SDP
struct MediaDescription {
    std::string media_type;      // video, audio
    int port;
    std::string protocol;        // RTP/AVP
    std::string format;          // 96, 97, etc.
    std::string control_url;     // track1, track2, etc.
    std::map<std::string, std::string> attributes;
};

// SDP information
struct SDPInfo {
    std::string session_name;
    std::string session_info;
    std::string connection_address;
    int connection_port;
    std::vector<MediaDescription> media_descriptions;
};

// RTSP response
struct RTSPResponse {
    std::string version;
    int status_code;
    std::string reason_phrase;
    std::map<std::string, std::string> headers;
    std::string body;
};

// Callback function types
using RTPPacketCallback = std::function<void(const RTPPacket&)>;
using RTSPResponseCallback = std::function<void(const RTSPResponse&)>;

class RTSPClient {
public:
    RTSPClient();
    ~RTSPClient();
    
    // Disable copy constructor and assignment operator
    RTSPClient(const RTSPClient&) = delete;
    RTSPClient& operator=(const RTSPClient&) = delete;
    
    // Connection management
    bool connect(const std::string& url, const std::string& username = "", const std::string& password = "");
    void disconnect();
    bool isConnected() const;
    
    // RTSP methods
    bool sendOptions();
    bool sendDescribe();
    bool sendSetup(const std::string& track_url, TransportType transport = TransportType::UDP);
    bool sendPlay();
    bool sendPause();
    bool sendTeardown();
    bool sendSetParameter();
    bool sendGetParameter();
    
    // Session management
    const RTSPSession& getSession() const { return session_; }
    const SDPInfo& getSDPInfo() const { return sdp_info_; }
    std::string getFirstTrackURL() const;
    
    // RTP handling
    void setRTPCallback(RTPPacketCallback callback);
    void startRTPReceiver();
    void stopRTPReceiver();
    
    // Keepalive
    void startKeepalive();
    void stopKeepalive();
    
    // Configuration
    void setConnectionTimeout(int timeout_seconds);
    void setRetryCount(int retry_count);
    
    // Status
    std::string getLastError() const { return last_error_; }
    int getLastStatusCode() const { return last_status_code_; }

private:
    // Network operations
    bool createSocket();
    bool connectToServer();
    void closeSocket();
    
    // RTSP protocol
    bool sendRequest(const std::string& method, const std::string& url, 
                    const std::map<std::string, std::string>& headers = {},
                    const std::string& body = "", int retry_count = 0);
    bool receiveResponse(RTSPResponse& response);
    bool parseResponse(const std::string& response_data, RTSPResponse& response);
    
    // Authentication
    bool handleAuthentication(const RTSPResponse& response);
    std::string generateBasicAuth(const std::string& username, const std::string& password);
    std::string generateDigestAuth(const std::string& username, const std::string& password,
                                  const std::string& method, const std::string& uri,
                                  const std::string& realm, const std::string& nonce);
    
    // SDP parsing
    bool parseSDP(const std::string& sdp_data);
    MediaDescription parseMediaDescription(const std::vector<std::string>& lines, size_t& index);
    
    // RTP handling
    void rtpReceiverThread();
    bool parseRTPPacket(const uint8_t* data, size_t length, RTPPacket& packet);
    bool createUDPSockets();
    void closeUDPSockets();
    
    // Utility functions
    std::string extractHeader(const std::map<std::string, std::string>& headers, const std::string& name);
    std::string generateCSeq();
    std::string generateUserAgent();
    
    // Member variables
    std::string server_url_;
    std::string server_host_;
    int server_port_;
    std::string server_path_;
    std::string username_;
    std::string password_;
    AuthType auth_type_;
    
    // Network
    int tcp_socket_;
    int udp_rtp_socket_;
    int udp_rtcp_socket_;
    struct sockaddr_in server_addr_;
    struct sockaddr_in local_rtp_addr_;
    struct sockaddr_in local_rtcp_addr_;
    
    // RTSP state
    std::atomic<bool> connected_;
    std::atomic<bool> playing_;
    std::atomic<bool> should_stop_;
    std::string session_id_;
    int cseq_;
    std::string user_agent_;
    
    // Session information
    RTSPSession session_;
    SDPInfo sdp_info_;
    
    // RTP
    std::thread rtp_thread_;
    std::atomic<bool> rtp_running_;
    RTPPacketCallback rtp_callback_;
    
    // Keepalive
    std::thread keepalive_thread_;
    std::atomic<bool> keepalive_running_;
    int session_timeout_seconds_;
    
    // Configuration
    int connection_timeout_;
    int retry_count_;
    
    // Status
    std::string last_error_;
    int last_status_code_;
    
    // Threading
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    
    // FU-A reassembly
    bool processFUAFragment(const uint8_t* payload, size_t payload_len, uint16_t sequence_number);
    void processCompleteNALUnit(const uint8_t* nal_data, size_t nal_len, uint8_t nal_type);
    
    // Keyframe requests
    void requestKeyframe();
    void sendKeyframeRequest(const std::string& method, const std::string& parameter);
};

} // namespace camera
} // namespace camrelay
