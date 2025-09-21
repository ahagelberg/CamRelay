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
#include <chrono>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

namespace camrelay {
namespace camera {
    class RTSPCamera;
    struct RTPPacket;
}

namespace server {

// Forward declarations
class RTSPServer;
class RTSPClientSession;

// RTSP Request structure
struct RTSPRequest {
    std::string method;
    std::string uri;
    std::string version;
    std::map<std::string, std::string> headers;
    int cseq;
    std::string session;
    std::string transport;
    std::string range;
};

// RTSP Response structure
struct RTSPResponse {
    std::string version;
    int statusCode;
    std::string reasonPhrase;
    std::map<std::string, std::string> headers;
    std::string body;
};

// Client session for RTP streaming
struct ClientSession {
    std::string sessionId;
    std::string cameraId;
    std::string clientIp;
    int clientRtpPort;
    int clientRtcpPort;
    int serverRtpPort;
    int serverRtcpPort;
    int rtpSocket;
    struct sockaddr_in clientRtpAddr;
    struct sockaddr_in clientRtcpAddr;
    std::chrono::steady_clock::time_point lastActivity;
    std::atomic<bool> isActive{false};
    std::atomic<bool> isPlaying{false};
    RTSPClientSession* clientSession = nullptr; // Reference to the RTSP client session
    std::atomic<uint16_t> sequenceNumber{0}; // RTP sequence number for this session
};

// RTSP Server configuration
struct RTSPServerConfig {
    int port = 554;
    std::string serverName = "CamRelay/1.0";
    int clientTimeoutSeconds = 60;
    int maxClients = 100;
};

// Server statistics
struct ServerStats {
    std::chrono::steady_clock::time_point startTime;
    int totalClients{0};
    int activeClients{0};
    uint64_t bytesTransmitted{0};
    uint64_t packetsTransmitted{0};
};

// Callback function types
using ClientConnectedCallback = std::function<void(const std::string& sessionId, const std::string& clientIp)>;
using ClientDisconnectedCallback = std::function<void(const std::string& sessionId, const std::string& clientIp)>;
using StreamRequestCallback = std::function<void(const std::string& sessionId, const std::string& cameraId)>;

// RTSP Server class
class RTSPServer {
public:
    RTSPServer();
    ~RTSPServer();
    
    // Disable copy constructor and assignment operator
    RTSPServer(const RTSPServer&) = delete;
    RTSPServer& operator=(const RTSPServer&) = delete;
    
    // Server management
    bool start(const RTSPServerConfig& config);
    void stop();
    bool isRunning() const;
    
    // Camera management
    void setCameras(const std::vector<std::shared_ptr<camera::RTSPCamera>>& cameras);
    std::shared_ptr<camera::RTSPCamera> getCamera(const std::string& cameraId) const;
    
    // Callback management
    void setClientConnectedCallback(ClientConnectedCallback callback);
    void setClientDisconnectedCallback(ClientDisconnectedCallback callback);
    void setStreamRequestCallback(StreamRequestCallback callback);
    
    // Statistics
    struct ServerStats getStats() const;
    
    // RTP packet forwarding
    void forwardRTPPacket(const std::string& cameraId, const camera::RTPPacket& packet);

    // Session cleanup (needed by RTSPClientSession)
    void cleanupClientSessions(RTSPClientSession* clientSession);

    // Methods needed by RTSPClientSession
    std::string generateSessionId();
    bool parseRequest(const std::string& requestData, RTSPRequest& request);
    std::string buildResponse(const RTSPResponse& response);
    RTSPResponse handleRequest(const RTSPRequest& request, const std::string& clientIp);
    
    // Session management for RTSPClientSession
    void removeActiveSession(const std::string& sessionId);
    
    // RTP fragmentation
    bool sendRTPPacket(int socket, const struct sockaddr_in& clientAddr, 
                      const camera::RTPPacket& packet, std::atomic<uint16_t>& sequenceNumber);

private:
    // RTP packet building helpers
    std::vector<uint8_t> buildRTPHeader(const camera::RTPPacket& packet, uint16_t sequenceNumber, bool isLastFragment = true);
    void buildFU_AHeader(std::vector<uint8_t>& rtpPacket, uint8_t nalType, uint8_t nalNri, bool isFirstFragment, bool isLastFragment);
    bool sendSingleRTPPacket(int socket, const struct sockaddr_in& clientAddr, 
                           const camera::RTPPacket& packet, std::atomic<uint16_t>& sequenceNumber);
    bool sendFragmentedRTPPacket(int socket, const struct sockaddr_in& clientAddr, 
                               const camera::RTPPacket& packet, std::atomic<uint16_t>& sequenceNumber);
    bool sendPacketData(int socket, const struct sockaddr_in& clientAddr, 
                       const std::vector<uint8_t>& packetData, std::atomic<uint16_t>& sequenceNumber);
    // Network operations
    bool createServerSocket();
    void acceptConnections();
    void closeSocket(int socket);
    
    
    // RTSP method handlers
    RTSPResponse handleOptions(const RTSPRequest& request);
    RTSPResponse handleDescribe(const RTSPRequest& request, const std::string& clientIp);
    RTSPResponse handleSetup(const RTSPRequest& request, const std::string& clientIp);
    RTSPResponse handlePlay(const RTSPRequest& request, const std::string& clientIp);
    RTSPResponse handlePause(const RTSPRequest& request, const std::string& clientIp);
    RTSPResponse handleTeardown(const RTSPRequest& request, const std::string& clientIp);
    
    // SDP generation
    std::string generateSDP(const std::string& cameraId, const std::string& serverIp, int serverPort);
    
    // Utility functions
    std::string getLocalIP() const;
    int findAvailablePort(int startPort = 50000) const;
    
    // Member variables
    RTSPServerConfig config_;
    std::atomic<bool> running_{false};
    std::atomic<bool> shouldStop_{false};
    
    // Network
    int serverSocket_;
    struct sockaddr_in serverAddr_;
    
    // Threading
    std::thread acceptThread_;
    // cleanupThread_ removed - sessions are cleaned up immediately on disconnect
    
    // Camera management
    std::vector<std::shared_ptr<camera::RTSPCamera>> cameras_;
    mutable std::mutex camerasMutex_;
    
    // Session management
    std::vector<std::unique_ptr<RTSPClientSession>> clientSessions_;
    std::map<std::string, std::shared_ptr<ClientSession>> activeSessions_;
    mutable std::mutex sessionsMutex_;
    mutable std::mutex activeSessionsMutex_;
    
    // Callbacks
    ClientConnectedCallback clientConnectedCallback_;
    ClientDisconnectedCallback clientDisconnectedCallback_;
    StreamRequestCallback streamRequestCallback_;
    
    // Statistics
    ServerStats stats_;
    mutable std::mutex statsMutex_;
};

// RTSP Client Session class
class RTSPClientSession {
public:
    RTSPClientSession(int clientSocket, const std::string& clientIp, RTSPServer* server);
    ~RTSPClientSession();
    
    // Disable copy constructor and assignment operator
    RTSPClientSession(const RTSPClientSession&) = delete;
    RTSPClientSession& operator=(const RTSPClientSession&) = delete;
    
    // Session management
    void start();
    void stop();
    bool isActive() const;
    
    // Session information
    std::string getSessionId() const;
    std::string getClientIp() const;
    
    // Stream management
    bool createStream(const std::string& cameraId, const std::string& transport, 
                     int clientRtpPort, int clientRtcpPort);
    void destroyStream(const std::string& cameraId);
    
    // RTP streaming
    void startRTPStreaming(std::shared_ptr<ClientSession> session);
    void stopRTPStreaming(std::shared_ptr<ClientSession> session);
    void setClientSession(std::shared_ptr<ClientSession> session);

private:
    // Session thread
    void sessionThread();
    
    // Network operations
    bool receiveRequest(RTSPRequest& request);
    bool sendResponse(const RTSPResponse& response);
    void closeSocket(int socket);
    
    // Cleanup
    void cleanup();
    
    // RTP streaming thread
    void rtpStreamingThread(std::shared_ptr<ClientSession> session);
    
    // Member variables
    int clientSocket_;
    std::string clientIp_;
    std::string sessionId_;
    RTSPServer* server_;
    
    // Threading
    std::thread sessionThread_;
    std::atomic<bool> shouldStop_{false};
    std::atomic<bool> active_{false};
    
    // Stream management
    std::map<std::string, std::shared_ptr<ClientSession>> streams_;
    mutable std::mutex streamsMutex_;
};

} // namespace server
} // namespace camrelay
