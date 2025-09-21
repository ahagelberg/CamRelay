#include "RTSPServer.h"
#include "../utils/Utils.h"
#include "../utils/Constants.h"
#include "../logging/Logger.h"
#include "../camera/RTSPCamera.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/select.h>
#include <random>
#include <future>

namespace camrelay {
namespace server {

RTSPServer::RTSPServer() 
    : serverSocket_(-1) {
    stats_.startTime = std::chrono::steady_clock::now();
}

RTSPServer::~RTSPServer() {
    stop();
}

bool RTSPServer::start(const RTSPServerConfig& config) {
    std::lock_guard<std::mutex> lock(sessionsMutex_);
    
    if (running_) {
        LOG_WARN("RTSP Server is already running");
        return false;
    }
    
    config_ = config;
    shouldStop_ = false;
    
    // Create server socket
    if (!createServerSocket()) {
        LOG_ERROR("Failed to create server socket");
        return false;
    }
    
    // Start accept thread
    acceptThread_ = std::thread([this]() {
        acceptConnections();
    });
    
    // Note: Session cleanup is now handled immediately on disconnect
    // No need for periodic cleanup thread
    
    running_ = true;
    LOG_INFO("RTSP Server started on port " + std::to_string(config_.port));
    
    return true;
}

void RTSPServer::stop() {
    if (!running_) {
        return;
    }
    
    shouldStop_ = true;
    
    // Close server socket to stop accepting new connections
    closeSocket(serverSocket_);
    
    // Stop all client sessions with timeout
    {
        std::lock_guard<std::mutex> lock(sessionsMutex_);
        for (auto& session : clientSessions_) {
            if (session) {
                session->stop();
            }
        }
        clientSessions_.clear();
    }
    
    // Wait for threads to finish with timeout
    if (acceptThread_.joinable()) {
        auto future = std::async(std::launch::async, [this]() {
            acceptThread_.join();
        });
        if (future.wait_for(std::chrono::milliseconds(100)) == std::future_status::timeout) {
            LOG_WARN("Accept thread did not join in time, detaching");
            acceptThread_.detach();
        }
    }
    
    // Cleanup thread removed - sessions are cleaned up immediately on disconnect
    
    running_ = false;
    LOG_INFO("RTSP Server stopped");
}

bool RTSPServer::isRunning() const {
    return running_;
}

void RTSPServer::setCameras(const std::vector<std::shared_ptr<camera::RTSPCamera>>& cameras) {
    std::lock_guard<std::mutex> lock(camerasMutex_);
    cameras_ = cameras;
    LOG_INFO("RTSP Server updated with " + std::to_string(cameras_.size()) + " cameras");
}

std::shared_ptr<camera::RTSPCamera> RTSPServer::getCamera(const std::string& cameraId) const {
    std::lock_guard<std::mutex> lock(camerasMutex_);
    for (const auto& camera : cameras_) {
        if (camera) {
            std::string cameraIdLower = camera->getId();
            std::transform(cameraIdLower.begin(), cameraIdLower.end(), cameraIdLower.begin(), ::tolower);
            std::string requestedIdLower = cameraId;
            std::transform(requestedIdLower.begin(), requestedIdLower.end(), requestedIdLower.begin(), ::tolower);
            
            if (cameraIdLower == requestedIdLower) {
                return camera;
            }
        }
    }
    return nullptr;
}

void RTSPServer::setClientConnectedCallback(ClientConnectedCallback callback) {
    clientConnectedCallback_ = callback;
}

void RTSPServer::setClientDisconnectedCallback(ClientDisconnectedCallback callback) {
    clientDisconnectedCallback_ = callback;
}

void RTSPServer::setStreamRequestCallback(StreamRequestCallback callback) {
    streamRequestCallback_ = callback;
}

ServerStats RTSPServer::getStats() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    return stats_;
}

std::string RTSPServer::generateSessionId() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(100000, 999999);
    return std::to_string(dis(gen));
}

bool RTSPServer::createServerSocket() {
    LOG_DEBUG("Creating server socket on port " + std::to_string(config_.port));
    
    serverSocket_ = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket_ < 0) {
        LOG_ERROR("Failed to create server socket: " + std::string(strerror(errno)));
        return false;
    }
    LOG_DEBUG("Server socket created successfully, fd=" + std::to_string(serverSocket_));
    
    // Set socket options
    int opt = 1;
    if (setsockopt(serverSocket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        LOG_ERROR("Failed to set SO_REUSEADDR: " + std::string(strerror(errno)));
        closeSocket(serverSocket_);
        return false;
    }
    LOG_DEBUG("SO_REUSEADDR set successfully");
    
    // Bind socket
    memset(&serverAddr_, 0, sizeof(serverAddr_));
    serverAddr_.sin_family = AF_INET;
    serverAddr_.sin_addr.s_addr = INADDR_ANY;
    serverAddr_.sin_port = htons(config_.port);
    
    LOG_DEBUG("Attempting to bind to port " + std::to_string(config_.port));
    if (bind(serverSocket_, (struct sockaddr*)&serverAddr_, sizeof(serverAddr_)) < 0) {
        LOG_ERROR("Failed to bind server socket: " + std::string(strerror(errno)) + " (errno=" + std::to_string(errno) + ")");
        closeSocket(serverSocket_);
        return false;
    }
    LOG_DEBUG("Socket bound successfully");
    
    // Listen for connections
    if (listen(serverSocket_, 10) < 0) {
        LOG_ERROR("Failed to listen on server socket: " + std::string(strerror(errno)));
        closeSocket(serverSocket_);
        return false;
    }
    LOG_DEBUG("Socket listening successfully");
    
    return true;
}

void RTSPServer::acceptConnections() {
    LOG_INFO("Accepting RTSP connections on port " + std::to_string(config_.port));
    
    // Set server socket to non-blocking mode
    int flags = fcntl(serverSocket_, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(serverSocket_, F_SETFL, flags | O_NONBLOCK);
    }
    
    while (!shouldStop_) {
        struct sockaddr_in clientAddr;
        socklen_t clientAddrLen = sizeof(clientAddr);
        
        int clientSocket = accept(serverSocket_, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (clientSocket < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // No connection available, sleep briefly and check shouldStop_
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }
            if (errno == EINTR) {
                continue; // Interrupted, continue
            }
            if (!shouldStop_) {
                LOG_ERROR("Failed to accept client connection: " + std::string(strerror(errno)));
            }
            break;
        }
        
        std::string clientIp = inet_ntoa(clientAddr.sin_addr);
        LOG_INFO("New RTSP client connected from " + clientIp + " (socket=" + std::to_string(clientSocket) + ")");
        
        // Create client session
        LOG_DEBUG("Creating RTSP client session for " + clientIp);
        auto session = std::make_unique<RTSPClientSession>(clientSocket, clientIp, this);
        LOG_DEBUG("Starting RTSP client session for " + clientIp);
        session->start();
        LOG_DEBUG("RTSP client session started for " + clientIp);
        
        // Add to sessions list
        {
            std::lock_guard<std::mutex> lock(sessionsMutex_);
            clientSessions_.push_back(std::move(session));
            
            // Update stats
            {
                std::lock_guard<std::mutex> statsLock(statsMutex_);
                stats_.totalClients++;
                stats_.activeClients++;
            }
        }
        
        // Call callback
        if (clientConnectedCallback_) {
            clientConnectedCallback_(clientSessions_.back()->getSessionId(), clientIp);
        }
    }
    
    LOG_INFO("Stopped accepting RTSP connections");
}

void RTSPServer::cleanupClientSessions(RTSPClientSession* clientSession) {
    LOG_DEBUG("Starting cleanup for client session: " + clientSession->getSessionId());
    
    std::lock_guard<std::mutex> lock(sessionsMutex_);
    std::lock_guard<std::mutex> activeLock(activeSessionsMutex_);
    
    int cleanedCount = 0;
    auto activeIt = activeSessions_.begin();
    while (activeIt != activeSessions_.end()) {
        // Find sessions that belong to this specific client session
        if (activeIt->second->clientSession == clientSession) {
            LOG_DEBUG("Cleaning up associated active session: " + activeIt->first + " (camera: " + activeIt->second->cameraId + ")");
            
            // Stop RTP streaming first
            activeIt->second->isPlaying = false;
            activeIt->second->isActive = false;
            
            // Close RTP socket to release the port
            if (activeIt->second->rtpSocket != -1) {
                LOG_DEBUG("Closing RTP socket for session " + activeIt->first);
                close(activeIt->second->rtpSocket);
                activeIt->second->rtpSocket = -1;
                
                // Small delay to ensure OS releases the port
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            
            activeIt = activeSessions_.erase(activeIt);
            cleanedCount++;
        } else {
            ++activeIt;
        }
    }
    
    LOG_DEBUG("Cleaned up " + std::to_string(cleanedCount) + " active sessions for client " + clientSession->getSessionId());
}

bool RTSPServer::parseRequest(const std::string& requestData, RTSPRequest& request) {
    std::istringstream stream(requestData);
    std::string line;
    
    // Parse request line
    if (!std::getline(stream, line)) {
        return false;
    }
    
    std::istringstream requestLine(line);
    requestLine >> request.method >> request.uri >> request.version;
    
    // Parse headers
    while (std::getline(stream, line) && !line.empty() && line != "\r") {
        size_t colonPos = line.find(':');
        if (colonPos != std::string::npos) {
            std::string headerName = utils::StringUtils::trim(line.substr(0, colonPos));
            std::string headerValue = utils::StringUtils::trim(line.substr(colonPos + 1));
            request.headers[utils::StringUtils::toLower(headerName)] = headerValue;
        }
    }
    
    // Parse CSeq
    if (request.headers.count("cseq")) {
        try {
            request.cseq = std::stoi(request.headers["cseq"]);
        } catch (...) {
            request.cseq = 0;
        }
    }
    
    // Parse other important headers
    if (request.headers.count("session")) {
        request.session = request.headers["session"];
        
        // Extract just the session ID part (before any semicolon)
        size_t semicolonPos = request.session.find(';');
        if (semicolonPos != std::string::npos) {
            request.session = request.session.substr(0, semicolonPos);
        }
        
        // Trim whitespace (including newlines) from the session ID
        // Manual trim since StringUtils::trim might not be working properly
        size_t start = request.session.find_first_not_of(" \t\n\r");
        if (start != std::string::npos) {
            size_t end = request.session.find_last_not_of(" \t\n\r");
            request.session = request.session.substr(start, end - start + 1);
        } else {
            request.session.clear();
        }

        LOG_DEBUG("Session ID: '" + request.session + "'");
    }
    if (request.headers.count("transport")) {
        request.transport = request.headers["transport"];
    }
    if (request.headers.count("range")) {
        request.range = request.headers["range"];
    }
    
    return true;
}

std::string RTSPServer::buildResponse(const RTSPResponse& response) {
    std::ostringstream oss;
    
    // Status line
    oss << response.version << " " << response.statusCode << " " << response.reasonPhrase << "\r\n";
    
    // Headers
    for (const auto& header : response.headers) {
        oss << header.first << ": " << header.second << "\r\n";
    }
    
    // End headers
    oss << "\r\n";
    
    // Body
    if (!response.body.empty()) {
        oss << response.body;
    }
    
    return oss.str();
}

RTSPResponse RTSPServer::handleRequest(const RTSPRequest& request, const std::string& clientIp) {
    LOG_DEBUG("Handling RTSP request: " + request.method + " " + request.uri + " from " + clientIp);
    
    if (request.method == "OPTIONS") {
        return handleOptions(request);
    } else if (request.method == "DESCRIBE") {
        return handleDescribe(request, clientIp);
    } else if (request.method == "SETUP") {
        return handleSetup(request, clientIp);
    } else if (request.method == "PLAY") {
        return handlePlay(request, clientIp);
    } else if (request.method == "PAUSE") {
        return handlePause(request, clientIp);
    } else if (request.method == "TEARDOWN") {
        return handleTeardown(request, clientIp);
    } else {
        RTSPResponse response;
        response.version = "RTSP/1.0";
        response.statusCode = 501;
        response.reasonPhrase = "Not Implemented";
        response.headers["CSeq"] = std::to_string(request.cseq);
        return response;
    }
}

RTSPResponse RTSPServer::handleOptions(const RTSPRequest& request) {
    RTSPResponse response;
    response.version = "RTSP/1.0";
    response.statusCode = 200;
    response.reasonPhrase = "OK";
    response.headers["CSeq"] = std::to_string(request.cseq);
    response.headers["Public"] = "OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN";
    response.headers["Server"] = config_.serverName;
    return response;
}

RTSPResponse RTSPServer::handleDescribe(const RTSPRequest& request, const std::string& /* clientIp */) {
    LOG_DEBUG("DESCRIBE request for URI: " + request.uri);
    RTSPResponse response;
    response.version = "RTSP/1.0";
    response.headers["CSeq"] = std::to_string(request.cseq);
    response.headers["Server"] = config_.serverName;
    
    // Extract camera ID from URI (e.g., rtsp://server:port/camera1 -> camera1)
    std::string cameraId;
    size_t lastSlash = request.uri.find_last_of('/');
    if (lastSlash != std::string::npos && lastSlash + 1 < request.uri.length()) {
        cameraId = request.uri.substr(lastSlash + 1);
        // Convert to lowercase for case-insensitive comparison
        std::transform(cameraId.begin(), cameraId.end(), cameraId.begin(), ::tolower);
    }
    
    if (cameraId.empty()) {
        response.statusCode = 400;
        response.reasonPhrase = "Bad Request";
        return response;
    }
    
    // Check if camera exists
    LOG_DEBUG("Looking up camera with ID: " + cameraId);
    auto camera = getCamera(cameraId);
    if (!camera) {
        LOG_WARN("Camera not found: " + cameraId);
        response.statusCode = 404;
        response.reasonPhrase = "Not Found";
        return response;
    }
    LOG_DEBUG("Camera found: " + camera->getId());
    
    // Check if camera is connected and streaming
    LOG_DEBUG("Camera " + cameraId + " status: connected=" + (camera->isConnected() ? "true" : "false") + 
              ", streaming=" + (camera->isStreaming() ? "true" : "false"));
    
    if (!camera->isConnected()) {
        LOG_WARN("Camera " + cameraId + " is not connected: " + camera->getLastError());
        response.statusCode = 503;
        response.reasonPhrase = "Service Unavailable - Camera not connected";
        return response;
    }
    
    if (!camera->isStreaming()) {
        LOG_WARN("Camera " + cameraId + " is not streaming");
        response.statusCode = 503;
        response.reasonPhrase = "Service Unavailable - Camera not streaming";
        return response;
    }
    
    // Generate SDP
    std::string serverIp = getLocalIP();
    response.body = generateSDP(cameraId, serverIp, config_.port);
    
    response.statusCode = 200;
    response.reasonPhrase = "OK";
    response.headers["Content-Type"] = "application/sdp";
    response.headers["Content-Length"] = std::to_string(response.body.length());
    
    LOG_DEBUG("DESCRIBE response: " + std::to_string(response.statusCode) + " " + response.reasonPhrase);
    LOG_DEBUG("SDP content length: " + std::to_string(response.body.length()));
    
    return response;
}

RTSPResponse RTSPServer::handleSetup(const RTSPRequest& request, const std::string& /* clientIp */) {
    RTSPResponse response;
    response.version = "RTSP/1.0";
    response.headers["CSeq"] = std::to_string(request.cseq);
    response.headers["Server"] = config_.serverName;
    
    // Parse transport header
    if (request.transport.empty()) {
        response.statusCode = 400;
        response.reasonPhrase = "Bad Request";
        return response;
    }
    
    // Extract client ports from transport header
    int clientRtpPort = 0, clientRtcpPort = 0;
    size_t clientPortPos = request.transport.find("client_port=");
    if (clientPortPos != std::string::npos) {
        clientPortPos += 12; // Skip "client_port="
        size_t dashPos = request.transport.find('-', clientPortPos);
        if (dashPos != std::string::npos) {
            try {
                clientRtpPort = std::stoi(request.transport.substr(clientPortPos, dashPos - clientPortPos));
                clientRtcpPort = std::stoi(request.transport.substr(dashPos + 1));
            } catch (...) {
                response.statusCode = 400;
                response.reasonPhrase = "Bad Request";
                return response;
            }
        }
    }
    
    // Extract camera ID from URI
    std::string cameraId;
    size_t lastSlash = request.uri.find_last_of('/');
    if (lastSlash != std::string::npos && lastSlash + 1 < request.uri.length()) {
        cameraId = request.uri.substr(lastSlash + 1);
        // Convert to lowercase for case-insensitive comparison
        std::transform(cameraId.begin(), cameraId.end(), cameraId.begin(), ::tolower);
    }
    
    if (cameraId.empty()) {
        response.statusCode = 400;
        response.reasonPhrase = "Bad Request";
        return response;
    }
    
    // Generate session ID for this setup request
    std::string sessionId = generateSessionId();
    
    // Find available server ports
    int serverRtpPort = findAvailablePort();
    int serverRtcpPort = serverRtpPort + 1;
    
    // Create client session
    auto session = std::make_shared<ClientSession>();
    session->sessionId = sessionId;
    session->cameraId = cameraId;
    session->clientRtpPort = clientRtpPort;
    session->clientRtcpPort = clientRtcpPort;
    session->serverRtpPort = serverRtpPort;
    session->serverRtcpPort = serverRtcpPort;
    session->lastActivity = std::chrono::steady_clock::now();
    session->isActive = true;  // Mark session as active
    
    // Set up client addresses
    session->clientRtpAddr.sin_family = AF_INET;
    session->clientRtpAddr.sin_port = htons(clientRtpPort);
    session->clientRtcpAddr.sin_family = AF_INET;
    session->clientRtcpAddr.sin_port = htons(clientRtcpPort);
    
    // Create RTP socket
    session->rtpSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (session->rtpSocket == -1) {
        LOG_ERROR("Failed to create RTP socket: " + std::string(std::strerror(errno)));
        response.statusCode = 500;
        response.reasonPhrase = "Internal Server Error";
        return response;
    }
    
    // Bind RTP socket to server port
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(serverRtpPort);
    
    if (bind(session->rtpSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
        LOG_ERROR("Failed to bind RTP socket to port " + std::to_string(serverRtpPort) + ": " + std::string(std::strerror(errno)));
        close(session->rtpSocket);
        response.statusCode = 500;
        response.reasonPhrase = "Internal Server Error";
        return response;
    }
    
    // Store session
    {
        std::lock_guard<std::mutex> lock(activeSessionsMutex_);
        activeSessions_[sessionId] = session;
    }
    
    // Note: The ClientSession will be linked to the RTSPClientSession
    // when the RTSPClientSession calls setClientSession() during PLAY request
    
    LOG_DEBUG("Created RTSP session " + sessionId + " for camera " + cameraId + 
             " (client: " + std::to_string(clientRtpPort) + ", server: " + std::to_string(serverRtpPort) + ")");
    
    response.statusCode = 200;
    response.reasonPhrase = "OK";
    response.headers["Session"] = sessionId + ";timeout=" + std::to_string(config_.clientTimeoutSeconds);
    response.headers["Transport"] = "RTP/AVP;unicast;client_port=" + 
                                   std::to_string(clientRtpPort) + "-" + std::to_string(clientRtcpPort) + 
                                   ";server_port=" + std::to_string(serverRtpPort) + "-" + std::to_string(serverRtcpPort);
    
    return response;
}

RTSPResponse RTSPServer::handlePlay(const RTSPRequest& request, const std::string& clientIp) {
    LOG_DEBUG("PLAY request from " + clientIp + " for session: '" + request.session + "'");
    
    RTSPResponse response;
    response.version = "RTSP/1.0";
    response.headers["CSeq"] = std::to_string(request.cseq);
    response.headers["Server"] = config_.serverName;
    
    if (request.session.empty()) {
        LOG_WARN("PLAY request with empty session from " + clientIp);
        response.statusCode = 454;
        response.reasonPhrase = "Session Not Found";
        return response;
    }
    
    // Find the session
    std::shared_ptr<ClientSession> session;
    {
        std::lock_guard<std::mutex> lock(activeSessionsMutex_);
        LOG_DEBUG("Looking for session: '" + request.session + "' (length: " + std::to_string(request.session.length()) + ")");
        LOG_DEBUG("Available sessions:");
        for (const auto& [id, sess] : activeSessions_) {
            LOG_DEBUG("  Stored session: '" + id + "'");
        }
        
        auto it = activeSessions_.find(request.session);
        if (it == activeSessions_.end()) {
            LOG_WARN("Session not found: '" + request.session + "' (total active sessions: " + std::to_string(activeSessions_.size()) + ")");
            response.statusCode = 454;
            response.reasonPhrase = "Session Not Found";
            return response;
        }
        session = it->second;
    }
    
    // Set client IP address if not already set
    if (session->clientIp.empty()) {
        session->clientIp = clientIp;
        inet_pton(AF_INET, clientIp.c_str(), &session->clientRtpAddr.sin_addr);
        inet_pton(AF_INET, clientIp.c_str(), &session->clientRtcpAddr.sin_addr);
    }
    
    // Find the RTSPClientSession that's handling this request
    RTSPClientSession* rtspClientSession = nullptr;
    {
        std::lock_guard<std::mutex> lock(sessionsMutex_);
        for (auto& clientSession : clientSessions_) {
            if (clientSession && clientSession->isActive() && clientSession->getClientIp() == clientIp) {
                rtspClientSession = clientSession.get();
                break;
            }
        }
    }
    
    if (!rtspClientSession) {
        LOG_ERROR("No RTSPClientSession found for client " + clientIp);
        response.statusCode = 454;
        response.reasonPhrase = "Session Not Found";
        return response;
    }
    
    // Validate that the session is still active and not being cleaned up
    if (!rtspClientSession->isActive()) {
        LOG_WARN("RTSPClientSession is inactive for client " + clientIp);
        response.statusCode = 454;
        response.reasonPhrase = "Session Not Found";
        return response;
    }
    
    // Link the ClientSession with the RTSPClientSession
    rtspClientSession->setClientSession(session);
    
    // Mark session as playing
    session->isPlaying = true;
    session->lastActivity = std::chrono::steady_clock::now();
    
    // Start RTP streaming
    rtspClientSession->startRTPStreaming(session);
    
    LOG_DEBUG("PLAY successful for session " + session->sessionId + 
             " (camera: " + session->cameraId + ", client: " + clientIp + ")");
    
    response.statusCode = 200;
    response.reasonPhrase = "OK";
    response.headers["Session"] = request.session;
    response.headers["RTP-Info"] = "url=rtsp://" + getLocalIP() + ":" + std::to_string(config_.port) + "/" + session->cameraId;
    
    return response;
}

RTSPResponse RTSPServer::handlePause(const RTSPRequest& request, const std::string& /* clientIp */) {
    RTSPResponse response;
    response.version = "RTSP/1.0";
    response.headers["CSeq"] = std::to_string(request.cseq);
    response.headers["Server"] = config_.serverName;
    
    if (request.session.empty()) {
        response.statusCode = 454;
        response.reasonPhrase = "Session Not Found";
        return response;
    }
    
    response.statusCode = 200;
    response.reasonPhrase = "OK";
    response.headers["Session"] = request.session;
    
    return response;
}

RTSPResponse RTSPServer::handleTeardown(const RTSPRequest& request, const std::string& /* clientIp */) {
    RTSPResponse response;
    response.version = "RTSP/1.0";
    response.headers["CSeq"] = std::to_string(request.cseq);
    response.headers["Server"] = config_.serverName;
    
    if (request.session.empty()) {
        response.statusCode = 454;
        response.reasonPhrase = "Session Not Found";
        return response;
    }
    
    // Remove the session from activeSessions_ immediately
    {
        std::lock_guard<std::mutex> lock(activeSessionsMutex_);
        auto it = activeSessions_.find(request.session);
        if (it != activeSessions_.end()) {
            LOG_DEBUG("TEARDOWN: Removing session " + request.session + " from active sessions");
            
            // Close RTP socket to release the port
            if (it->second->rtpSocket != -1) {
                close(it->second->rtpSocket);
                it->second->rtpSocket = -1;
                
                // Small delay to ensure OS releases the port
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            
            // Mark session as inactive
            it->second->isActive = false;
            it->second->isPlaying = false;
            
            activeSessions_.erase(it);
            LOG_DEBUG("TEARDOWN: Session " + request.session + " removed successfully");
        } else {
            LOG_DEBUG("TEARDOWN: Session " + request.session + " not found in active sessions");
        }
    }
    
    response.statusCode = 200;
    response.reasonPhrase = "OK";
    response.headers["Session"] = request.session;
    
    return response;
}

std::string RTSPServer::generateSDP(const std::string& cameraId, const std::string& serverIp, int serverPort) {
    auto camera = getCamera(cameraId);
    if (!camera) {
        return "";
    }
    
    const auto& sdpInfo = camera->getSDPInfo();
    
    std::ostringstream sdp;
    sdp << "v=0\r\n";
    sdp << "o=- 0 0 IN IP4 " << serverIp << "\r\n";
    sdp << "s=CamRelay Stream\r\n";
    sdp << "c=IN IP4 " << serverIp << "\r\n";
    sdp << "t=0 0\r\n";
    
    // Add media tracks
    for (const auto& media : sdpInfo.media_descriptions) {
        sdp << "m=" << media.media_type << " " << media.port << " " << media.protocol;
        if (!media.format.empty()) {
            sdp << " " << media.format;
        }
        sdp << "\r\n";
        
        // Add RTP map if available in attributes
        if (media.attributes.count("rtpmap")) {
            sdp << "a=rtpmap:" << media.attributes.at("rtpmap") << "\r\n";
        }
        
        sdp << "a=control:rtsp://" << serverIp << ":" << serverPort << "/" << cameraId << "\r\n";
    }
    
    return sdp.str();
}

std::string RTSPServer::getLocalIP() const {
    // Return the server IP address that clients connect to
    // This should be the IP address that clients use to connect to the server
    return "192.168.42.7";
}

int RTSPServer::findAvailablePort(int startPort) const {
    // Try to find an available port by actually testing if it can be bound
    // Limit search to 50 ports to avoid blocking
    for (int port = startPort; port < startPort + 100; port += 2) {
        int testSocket = socket(AF_INET, SOCK_DGRAM, 0);
        if (testSocket == -1) {
            continue;
        }
        
        // Set socket to non-blocking for faster testing
        int flags = fcntl(testSocket, F_GETFL, 0);
        fcntl(testSocket, F_SETFL, flags | O_NONBLOCK);
        
        struct sockaddr_in testAddr;
        testAddr.sin_family = AF_INET;
        testAddr.sin_addr.s_addr = INADDR_ANY;
        testAddr.sin_port = htons(port);
        
        if (bind(testSocket, (struct sockaddr*)&testAddr, sizeof(testAddr)) == 0) {
            close(testSocket);
            LOG_DEBUG("Found available port: " + std::to_string(port));
            return port;
        }
        
        close(testSocket);
    }
    
    // Fallback to simple counter if no port found
    static int portCounter = startPort;
    LOG_WARN("No available ports found in range, using fallback counter");
    return portCounter += 2;
}

void RTSPServer::closeSocket(int socket) {
    if (socket >= 0) {
        close(socket);
    }
}

// RTSPClientSession Implementation
RTSPClientSession::RTSPClientSession(int clientSocket, const std::string& clientIp, RTSPServer* server)
    : clientSocket_(clientSocket), clientIp_(clientIp), server_(server) {
    // sessionId_ will be set by setClientSession() when linked to a ClientSession
    active_ = true;  // Set active immediately so linking works
}

RTSPClientSession::~RTSPClientSession() {
    stop();
}

void RTSPClientSession::start() {
    shouldStop_ = false;
    sessionThread_ = std::thread([this]() {
        sessionThread();
    });
}

void RTSPClientSession::stop() {
    shouldStop_ = true;
    closeSocket(clientSocket_);
    
    if (sessionThread_.joinable()) {
        auto future = std::async(std::launch::async, [this]() {
            sessionThread_.join();
        });
        if (future.wait_for(std::chrono::milliseconds(50)) == std::future_status::timeout) {
            LOG_WARN("Session thread did not join in time, detaching");
            sessionThread_.detach();
        }
    }
    
    cleanup();
    active_ = false;
}

bool RTSPClientSession::isActive() const {
    return active_;
}

std::string RTSPClientSession::getSessionId() const {
    return sessionId_;
}

std::string RTSPClientSession::getClientIp() const {
    return clientIp_;
}

void RTSPClientSession::sessionThread() {
    LOG_DEBUG("RTSP client session started: " + (sessionId_.empty() ? "pending" : sessionId_) + " from " + clientIp_);
    active_ = true;  // Set active flag at the beginning
    
    while (!shouldStop_) {
        RTSPRequest request;
        if (!receiveRequest(request)) {
            // Break on any error (including connection closure)
            LOG_DEBUG("RTSP request reception failed, ending session thread");
            break;
        }
        
        RTSPResponse response = server_->handleRequest(request, clientIp_);
        if (!sendResponse(response)) {
            LOG_DEBUG("RTSP response sending failed, ending session thread");
            break;
        }
    }
    
    LOG_DEBUG("RTSP client session ended: " + sessionId_);
    
    // Clean up associated active sessions immediately
    if (server_) {
        LOG_DEBUG("Calling cleanupClientSessions for " + sessionId_);
        server_->cleanupClientSessions(this);
    }
    
    active_ = false;
    LOG_DEBUG("Session " + sessionId_ + " marked as inactive");
}

bool RTSPClientSession::receiveRequest(RTSPRequest& request) {
    std::string requestData;
    char buffer[4096];
    
    // Set socket timeout
    struct timeval timeout;
    timeout.tv_sec = 30; // Longer timeout to allow clients time to send requests
    timeout.tv_usec = 0;
    setsockopt(clientSocket_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    LOG_DEBUG("Waiting for RTSP request from client " + clientIp_);
    
    while (!shouldStop_) {
        ssize_t received = recv(clientSocket_, buffer, sizeof(buffer) - 1, 0);
        if (received < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Socket timeout - this is normal, just continue waiting
                continue;
            }
            LOG_DEBUG("Socket error receiving from " + clientIp_ + ": " + std::string(strerror(errno)));
            return false; // Real error
        }
        
        if (received == 0) {
            LOG_DEBUG("Connection closed by client " + clientIp_);
            return false; // Connection closed
        }
        
        // Null-terminate the received data
        buffer[received] = '\0';
        
        // Validate received data is printable/ASCII
        bool isValidData = true;
        for (int i = 0; i < received; i++) {
            if (buffer[i] < 32 && buffer[i] != '\r' && buffer[i] != '\n' && buffer[i] != '\t') {
                isValidData = false;
                break;
            }
        }
        
        if (!isValidData) {
            LOG_WARN("Received non-printable data from " + clientIp_ + " (" + std::to_string(received) + " bytes)");
            // Log first few bytes in hex for debugging
            std::string hexData;
            for (int i = 0; i < std::min(static_cast<int>(received), 16); i++) {
                char hex[4];
                snprintf(hex, sizeof(hex), "%02X ", (unsigned char)buffer[i]);
                hexData += hex;
            }
            LOG_WARN("Data (hex): " + hexData);
            return false; // Reject corrupted data
        }
        
        requestData += buffer;
        
        // Extract first line for logging (limit length to prevent log spam)
        std::string bufferStr(buffer, received);
        size_t newlinePos = bufferStr.find('\n');
        std::string firstLine = (newlinePos != std::string::npos) ? bufferStr.substr(0, newlinePos) : bufferStr;
        if (firstLine.length() > 100) {
            firstLine = firstLine.substr(0, 100) + "...";
        }
        LOG_DEBUG("Received " + std::to_string(received) + " bytes from " + clientIp_ + ": " + firstLine);
        
        // Check if we have a complete request
        if (requestData.find("\r\n\r\n") != std::string::npos) {
            LOG_DEBUG("Complete RTSP request received from " + clientIp_);
            break;
        }
        
        // Prevent infinite accumulation of data
        if (requestData.length() > 8192) {
            LOG_ERROR("Request data too large from " + clientIp_ + " (" + std::to_string(requestData.length()) + " bytes)");
            return false;
        }
    }
    
    if (shouldStop_) {
        LOG_DEBUG("Session stopping, not processing request from " + clientIp_);
        return false; // Shutdown requested
    }
    
    LOG_DEBUG("Parsing RTSP request from " + clientIp_);
    return server_->parseRequest(requestData, request);
}

bool RTSPClientSession::sendResponse(const RTSPResponse& response) {
    std::string responseData = server_->buildResponse(response);
    
    LOG_DEBUG("Sending response: " + std::to_string(response.statusCode) + " " + response.reasonPhrase + " (" + std::to_string(responseData.length()) + " bytes)");
    
    ssize_t sent = send(clientSocket_, responseData.c_str(), responseData.length(), 0);
    if (sent != static_cast<ssize_t>(responseData.length())) {
        LOG_WARN("Failed to send complete response: " + std::to_string(sent) + "/" + std::to_string(responseData.length()));
        return false;
    }
    
    LOG_DEBUG("Response sent successfully");
    return true;
}

void RTSPClientSession::cleanup() {
    std::lock_guard<std::mutex> lock(streamsMutex_);
    for (auto& stream : streams_) {
        stopRTPStreaming(stream.second);
        
        // Note: Active sessions are cleaned up by the server's cleanupInactiveSessions()
        // method before this cleanup() is called, so we don't need to remove them here
        LOG_DEBUG("Cleaning up stream: " + stream.second->sessionId);
    }
    streams_.clear();
    
    // Mark session as inactive
    active_ = false;
}

void RTSPClientSession::closeSocket(int socket) {
    if (socket >= 0) {
        close(socket);
    }
}

bool RTSPClientSession::createStream(const std::string& cameraId, const std::string& transport, 
                                   int /* clientRtpPort */, int /* clientRtcpPort */) {
    // This is a placeholder implementation
    // In a real implementation, this would create UDP sockets and set up RTP streaming
    LOG_DEBUG("Creating stream for camera " + cameraId + " with transport " + transport);
    return true;
}

void RTSPClientSession::destroyStream(const std::string& cameraId) {
    // This is a placeholder implementation
    LOG_DEBUG("Destroying stream for camera " + cameraId);
}

void RTSPClientSession::startRTPStreaming(std::shared_ptr<ClientSession> session) {
    LOG_DEBUG("Starting RTP streaming for session " + session->sessionId);
    
    // Start RTP streaming thread
    std::thread rtpThread([this, session]() {
        rtpStreamingThread(session);
    });
    rtpThread.detach(); // Detach the thread to run independently
}

void RTSPClientSession::stopRTPStreaming(std::shared_ptr<ClientSession> session) {
    // This is a placeholder implementation
    LOG_DEBUG("Stopping RTP streaming for session " + session->sessionId);
}

void RTSPClientSession::setClientSession(std::shared_ptr<ClientSession> session) {
    std::lock_guard<std::mutex> lock(streamsMutex_);
    streams_[session->cameraId] = session;
    // Update our session ID to match the ClientSession's session ID
    sessionId_ = session->sessionId;
    // Set the client session reference in the ClientSession
    session->clientSession = this;
}

void RTSPClientSession::rtpStreamingThread(std::shared_ptr<ClientSession> session) {
    LOG_DEBUG("RTP streaming thread started for session " + session->sessionId);
    
    // Keep the streaming thread alive while session is active
    // The actual RTP packet forwarding is handled by forwardRTPPacket()
    // which is called directly from the camera data callback
    while (session->isActive && session->isPlaying && !shouldStop_) {
        // Just keep the session alive - RTP packets are sent via forwardRTPPacket()
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    LOG_DEBUG("RTP streaming thread ended for session " + session->sessionId + 
              " (isActive=" + std::to_string(session->isActive) + 
              ", isPlaying=" + std::to_string(session->isPlaying) + 
              ", shouldStop=" + std::to_string(shouldStop_) + ")");
}

void RTSPServer::removeActiveSession(const std::string& sessionId) {
    std::lock_guard<std::mutex> lock(activeSessionsMutex_);
    auto it = activeSessions_.find(sessionId);
    if (it != activeSessions_.end()) {
        auto session = it->second;
        

        // Stop RTP streaming if it's still active
        if (session->isPlaying) {
            LOG_DEBUG("Stopping RTP streaming for session " + sessionId);
            session->isPlaying = false;
        }
        
        // Close RTP socket to release the port
        if (session->rtpSocket != -1) {
            LOG_DEBUG("Closing RTP socket for session " + sessionId);
            close(session->rtpSocket);
            session->rtpSocket = -1;
            
            // Small delay to ensure OS releases the port
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        // Mark session as inactive
        session->isActive = false;
        
        activeSessions_.erase(it);
        LOG_DEBUG("Removed active session: " + sessionId);
    } else {
        LOG_DEBUG("Session " + sessionId + " not found in active sessions (already removed?)");
    }
}

bool RTSPServer::sendRTPPacket(int socket, const struct sockaddr_in& clientAddr, 
                               const camera::RTPPacket& packet, std::atomic<uint16_t>& sequenceNumber) {
    // Calculate the maximum UDP payload size that can be sent without fragmentation
    const size_t maxUDPPayload = ConfigDefaults::MAX_UDP_PAYLOAD_SIZE;
    const size_t rtpHeaderSize = ConfigDefaults::RTP_HEADER_SIZE;
    const size_t totalPacketSize = rtpHeaderSize + packet.payload.size();
    
    if (totalPacketSize <= maxUDPPayload) {
        // Send as single packet
        return sendSingleRTPPacket(socket, clientAddr, packet, sequenceNumber);
    } else {
        // Fragment using FU-A (H.264 fragmentation)
        return sendFragmentedRTPPacket(socket, clientAddr, packet, sequenceNumber);
    }
}

// RTP packet building helper functions
std::vector<uint8_t> RTSPServer::buildRTPHeader(const camera::RTPPacket& packet, uint16_t sequenceNumber, bool isLastFragment) {
    std::vector<uint8_t> header;
    header.reserve(ConfigDefaults::RTP_HEADER_SIZE);
    
    // RTP Header (12 bytes)
    uint8_t byte1 = (packet.version << 6) | (packet.padding << 5) | (packet.extension << 4) | packet.csrc_count;
    header.push_back(byte1);
    
    // Marker bit only on last fragment
    uint8_t byte2 = (isLastFragment ? packet.marker : 0) << 7 | packet.payload_type;
    header.push_back(byte2);
    
    // Sequence number (big-endian)
    header.push_back((sequenceNumber >> 8) & 0xFF);
    header.push_back(sequenceNumber & 0xFF);
    
    // Timestamp (big-endian)
    header.push_back((packet.timestamp >> 24) & 0xFF);
    header.push_back((packet.timestamp >> 16) & 0xFF);
    header.push_back((packet.timestamp >> 8) & 0xFF);
    header.push_back(packet.timestamp & 0xFF);
    
    // SSRC (big-endian)
    header.push_back((packet.ssrc >> 24) & 0xFF);
    header.push_back((packet.ssrc >> 16) & 0xFF);
    header.push_back((packet.ssrc >> 8) & 0xFF);
    header.push_back(packet.ssrc & 0xFF);
    
    return header;
}

void RTSPServer::buildFU_AHeader(std::vector<uint8_t>& rtpPacket, uint8_t nalType, uint8_t nalNri, bool isFirstFragment, bool isLastFragment) {
    // FU-A header (2 bytes)
    // First byte: FU indicator (F=0, NRI=from original NAL, Type=28 for FU-A)
    uint8_t fuIndicator = nalNri | 28; // NRI from original, Type=28
    rtpPacket.push_back(fuIndicator);
    
    // Second byte: FU header (S=start, E=end, R=reserved, Type=original NAL type)
    uint8_t fuHeader = (isFirstFragment ? 0x80 : 0x00) |  // S bit
                      (isLastFragment ? 0x40 : 0x00) |   // E bit
                      nalType;  // Original NAL type
    rtpPacket.push_back(fuHeader);
}

bool RTSPServer::sendSingleRTPPacket(int socket, const struct sockaddr_in& clientAddr, 
                                    const camera::RTPPacket& packet, std::atomic<uint16_t>& sequenceNumber) {
    uint16_t seq = sequenceNumber.load();
    std::vector<uint8_t> rtpPacket = buildRTPHeader(packet, seq, true);
    
    // Add payload
    rtpPacket.insert(rtpPacket.end(), packet.payload.begin(), packet.payload.end());
    
    // Send packet
    return sendPacketData(socket, clientAddr, rtpPacket, sequenceNumber);
}

bool RTSPServer::sendFragmentedRTPPacket(int socket, const struct sockaddr_in& clientAddr, 
                                        const camera::RTPPacket& packet, std::atomic<uint16_t>& sequenceNumber) {
    const size_t maxUDPPayload = ConfigDefaults::MAX_UDP_PAYLOAD_SIZE;
    const size_t rtpHeaderSize = ConfigDefaults::RTP_HEADER_SIZE;
    const size_t maxRTPPayload = maxUDPPayload - rtpHeaderSize;
    const size_t maxFragmentPayload = maxRTPPayload - ConfigDefaults::FU_A_HEADER_SIZE;
    
    // Check if the packet is too large even for fragmentation
    if (packet.payload.size() > maxFragmentPayload * 1000) { // Reasonable limit
        LOG_ERROR("RTP packet too large for fragmentation: " + std::to_string(packet.payload.size()) + 
                 " bytes (max fragment: " + std::to_string(maxFragmentPayload) + ")");
        return false;
    }
    
    // Validate payload has at least one byte (NAL header)
    if (packet.payload.empty()) {
        LOG_ERROR("Cannot fragment empty RTP payload");
        return false;
    }
    
    // Extract NAL header from the first byte of payload
    const uint8_t* payload = packet.payload.data();
    uint8_t nalHeader = payload[0];
    uint8_t nalType = nalHeader & 0x1F;
    uint8_t nalNri = nalHeader & 0x60;
    
    // Move payload pointer past the NAL header
    payload++;
    size_t remaining = packet.payload.size() - 1;
    
    // Validate we still have data to fragment
    if (remaining == 0) {
        LOG_ERROR("Cannot fragment RTP payload with only NAL header");
        return false;
    }
    
    LOG_DEBUG("Fragmenting RTP packet: payload size=" + std::to_string(packet.payload.size()) + 
             ", max fragment payload=" + std::to_string(maxFragmentPayload));
    
    int fragmentCount = 0;
    bool isFirstFragment = true;
    
    while (remaining > 0) {
        // Calculate fragment size - all fragments contain only data (no NAL header)
        size_t fragmentSize = std::min(remaining, maxFragmentPayload);
        bool isLastFragment = (remaining == fragmentSize);
        
        // Build RTP packet
        uint16_t seq = sequenceNumber.load();
        std::vector<uint8_t> rtpPacket = buildRTPHeader(packet, seq, isLastFragment);
        
        // Add FU-A header
        buildFU_AHeader(rtpPacket, nalType, nalNri, isFirstFragment, isLastFragment);
        
        // Add fragment payload (only data, no NAL header)
        rtpPacket.insert(rtpPacket.end(), payload, payload + fragmentSize);
        
        // Send fragment
        if (!sendPacketData(socket, clientAddr, rtpPacket, sequenceNumber)) {
            LOG_WARN("Failed to send RTP fragment " + std::to_string(fragmentCount + 1));
            break;
        }
        
        fragmentCount++;
        LOG_DEBUG("Sent fragment " + std::to_string(fragmentCount) + 
                 " (size=" + std::to_string(rtpPacket.size()) + 
                 ", remaining=" + std::to_string(remaining - fragmentSize) + 
                 ", S=" + std::to_string(isFirstFragment ? 1 : 0) +
                 ", E=" + std::to_string(isLastFragment ? 1 : 0) + ")");
        
        // Update for next fragment
        payload += fragmentSize;
        remaining -= fragmentSize;
        isFirstFragment = false;
    }
    
    if (fragmentCount > 0) {
        LOG_DEBUG("Successfully fragmented RTP packet into " + std::to_string(fragmentCount) + " fragments");
        return true;
    }
    
    return false;
}

bool RTSPServer::sendPacketData(int socket, const struct sockaddr_in& clientAddr, 
                               const std::vector<uint8_t>& packetData, std::atomic<uint16_t>& sequenceNumber) {
    ssize_t sent = sendto(socket, packetData.data(), packetData.size(), 0,
                        (struct sockaddr*)&clientAddr, sizeof(clientAddr));
    if (sent > 0) {
        sequenceNumber.fetch_add(1);
        return true;
    } else {
        LOG_WARN("Failed to send RTP packet: " + std::string(strerror(errno)));
        return false;
    }
}

// RTSPServer implementation
void RTSPServer::forwardRTPPacket(const std::string& cameraId, const camera::RTPPacket& packet) {
    static std::atomic<int> packetCount{0};
    static std::chrono::steady_clock::time_point lastLogTime = std::chrono::steady_clock::now();
    
    packetCount++;
    
    // Debug: Log every call to forwardRTPPacket (reduced frequency)
    if (packetCount % 100 == 0) {
        LOG_DEBUG("forwardRTPPacket: cameraId=" + cameraId + ", packetCount=" + std::to_string(packetCount) + 
                 ", payload=" + std::to_string(packet.payload.size()) + " bytes");
    }
    
    // Log digest every 5 seconds
    auto now = std::chrono::steady_clock::now();
    if (std::chrono::duration_cast<std::chrono::seconds>(now - lastLogTime).count() >= 5) {
        std::lock_guard<std::mutex> lock(activeSessionsMutex_);
        int playingSessions = 0;
        for (const auto& [sessionId, session] : activeSessions_) {
            if (session->cameraId == cameraId && session->isActive && session->isPlaying) {
                playingSessions++;
            }
        }
        LOG_INFO("RTP Digest: " + std::to_string(packetCount) + " packets for " + cameraId + 
                 ", " + std::to_string(playingSessions) + " playing sessions, " + 
                 std::to_string(activeSessions_.size()) + " total sessions");
        packetCount = 0;
        lastLogTime = now;
    }
    
    std::lock_guard<std::mutex> lock(activeSessionsMutex_);
    
    // Find all active sessions for this camera
    int forwardedCount = 0;
    
    for (auto& [sessionId, session] : activeSessions_) {
        if (session->cameraId == cameraId && session->isActive && session->isPlaying) {
            // Forward the RTP packet to this client
            if (session->rtpSocket != -1) {
                // Use the new sendRTPPacket method with fragmentation support
                bool sent = sendRTPPacket(session->rtpSocket, session->clientRtpAddr, packet, session->sequenceNumber);
                
                if (sent) {
                    forwardedCount++;
                    
                    // Update statistics
                    {
                        std::lock_guard<std::mutex> statsLock(statsMutex_);
                        stats_.bytesTransmitted += packet.payload.size();
                        stats_.packetsTransmitted++;
                    }
                } else {
                    LOG_WARN("Failed to send RTP packet " + std::to_string(packetCount) + " to session " + sessionId + " (seq: " + std::to_string(packet.sequence_number) + ")");
                }
            } else {
                LOG_WARN("Session " + sessionId + " has invalid RTP socket (-1)");
            }
        }
    }
    
    // Debug: Log if no packets were forwarded
    if (forwardedCount == 0) {
        LOG_DEBUG("No active sessions found for camera " + cameraId + " (total sessions: " + std::to_string(activeSessions_.size()) + ")");
    } else {
        // Log RTP packet details every 100 packets for debugging
        static std::atomic<int> debugPacketCount{0};
        
        // Track what happens after packet 600
        static std::atomic<int> packetsAfter600{0};
        static bool packet600Seen{false};
        if (debugPacketCount == 600) {
            packet600Seen = true;
            packetsAfter600 = 0;
            LOG_DEBUG("*** PACKET 600 DETECTED - monitoring next 20 packets ***");
        }
        if (packet600Seen && packetsAfter600 < 20) {
            packetsAfter600++;
            LOG_DEBUG("Packet " + std::to_string(debugPacketCount) + " after packet 600: " + 
                     "forwarded to " + std::to_string(forwardedCount) + " sessions");
        }
        if (debugPacketCount++ % 100 == 0) {
            // Analyze NAL type for debugging
            std::string nalType = "Unknown";
            if (!packet.payload.empty()) {
                uint8_t nalHeader = packet.payload[0];
                uint8_t nalTypeValue = nalHeader & 0x1F;
                switch (nalTypeValue) {
                    case 1: nalType = "P-frame"; break;
                    case 5: nalType = "IDR"; break;
                    case 7: nalType = "SPS"; break;
                    case 8: nalType = "PPS"; break;
                    case 28: nalType = "FU-A"; break;
                    default: nalType = "Type-" + std::to_string(nalTypeValue); break;
                }
            }
            LOG_DEBUG("RTP packet forwarded: original_seq=" + std::to_string(packet.sequence_number) + 
                     ", payload=" + std::to_string(packet.payload.size()) + " bytes, " +
                     "NAL=" + nalType + ", to " + std::to_string(forwardedCount) + " sessions");
        }
        
        // Special debugging around packet 600 - this is the critical packet!
        if (debugPacketCount >= 590 && debugPacketCount <= 610) {
            std::string nalType = "Unknown";
            bool isLastFragment = false;
            if (!packet.payload.empty()) {
                uint8_t nalHeader = packet.payload[0];
                uint8_t nalTypeValue = nalHeader & 0x1F;
                switch (nalTypeValue) {
                    case 1: nalType = "P-frame"; break;
                    case 5: nalType = "IDR"; break;
                    case 7: nalType = "SPS"; break;
                    case 8: nalType = "PPS"; break;
                    case 28: 
                        nalType = "FU-A";
                        // Check if this is the last fragment of a FU-A packet
                        if (packet.payload.size() > 1) {
                            uint8_t fuHeader = packet.payload[1];
                            isLastFragment = (fuHeader & 0x40) != 0; // E bit
                        }
                        break;
                    default: nalType = "Type-" + std::to_string(nalTypeValue); break;
                }
            }
            
            // Highlight packet 600 specifically
            std::string highlight = (debugPacketCount == 600) ? " *** PACKET 600 *** " : "";
            LOG_DEBUG("RTP packet " + std::to_string(debugPacketCount) + highlight + 
                     " forwarded: original_seq=" + std::to_string(packet.sequence_number) + 
                     ", payload=" + std::to_string(packet.payload.size()) + " bytes, " +
                     "NAL=" + nalType + (isLastFragment ? " (LAST)" : "") + 
                     ", to " + std::to_string(forwardedCount) + " sessions");
        }
    }
}

} // namespace server
} // namespace camrelay
