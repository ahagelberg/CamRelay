#include "RTSPClient.h"
#include "../utils/Utils.h"
#include "../utils/Constants.h"
#include "../logging/Logger.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/select.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#include <chrono>

namespace camrelay {
namespace camera {

RTSPClient::RTSPClient() 
    : server_port_(554)
    , auth_type_(AuthType::NONE)
    , tcp_socket_(-1)
    , udp_rtp_socket_(-1)
    , udp_rtcp_socket_(-1)
    , connected_(false)
    , playing_(false)
    , should_stop_(false)
    , cseq_(1)
    , user_agent_("CamRelay/1.0")
    , rtp_running_(false)
    , connection_timeout_(10)
    , retry_count_(3)
    , last_status_code_(0) {
    memset(&server_addr_, 0, sizeof(server_addr_));
    memset(&local_rtp_addr_, 0, sizeof(local_rtp_addr_));
    memset(&local_rtcp_addr_, 0, sizeof(local_rtcp_addr_));
}

RTSPClient::~RTSPClient() {
    // Don't call disconnect() in destructor to avoid hanging
    // Just close sockets and set flags
    should_stop_ = true;
    closeSocket();
    closeUDPSockets();
}

bool RTSPClient::connect(const std::string& url, const std::string& username, const std::string& password) {
    {
        std::unique_lock<std::mutex> lock(mutex_);
        
        if (connected_) {
            last_error_ = "Already connected";
            return false;
        }
        
        // Parse URL
        auto url_components = utils::NetworkUtils::parseUrl(url);
        if (url_components.protocol != "rtsp") {
            last_error_ = "Invalid protocol, expected rtsp://";
            return false;
        }
        
        server_url_ = url;
        server_host_ = url_components.host;
        server_port_ = url_components.port > 0 ? url_components.port : 554;
        server_path_ = url_components.path;
        username_ = url_components.username.empty() ? username : url_components.username;
        password_ = url_components.password.empty() ? password : url_components.password;
        
        // Check if we should stop before starting
        if (should_stop_) {
            last_error_ = "Connection cancelled";
            return false;
        }
    } // Unlock mutex before network operations
    
    // Create TCP socket
    if (!createSocket()) {
        return false;
    }
    
    // Check if we should stop after creating socket
    if (should_stop_) {
        closeSocket();
        last_error_ = "Connection cancelled";
        return false;
    }
    
    // Connect to server (this can take time, so mutex is unlocked)
    if (!connectToServer()) {
        closeSocket();
        return false;
    }
    
    // Check if we should stop after connecting
    if (should_stop_) {
        closeSocket();
        last_error_ = "Connection cancelled";
        return false;
    }
    
    // Lock mutex only for final state updates
    {
        std::unique_lock<std::mutex> lock(mutex_);
        connected_ = true;
        last_error_.clear();
    }
    
    return true;
}

void RTSPClient::disconnect() {
    should_stop_ = true;
    
    // Force close sockets to interrupt any blocking operations
    closeSocket();
    closeUDPSockets();
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (playing_) {
        sendTeardown();
    }
    
    stopRTPReceiver();
    
    connected_ = false;
    playing_ = false;
    session_id_.clear();
    cseq_ = 1;
}

bool RTSPClient::isConnected() const {
    return connected_;
}

bool RTSPClient::sendOptions() {
    if (!connected_) {
        last_error_ = "Not connected";
        return false;
    }
    
    std::map<std::string, std::string> headers;
    headers["CSeq"] = generateCSeq();
    headers["User-Agent"] = generateUserAgent();
    
    return sendRequest("OPTIONS", server_url_, headers, "", 0);
}

bool RTSPClient::sendDescribe() {
    if (!connected_) {
        last_error_ = "Not connected";
        return false;
    }
    
    std::map<std::string, std::string> headers;
    headers["CSeq"] = generateCSeq();
    headers["User-Agent"] = generateUserAgent();
    headers["Accept"] = "application/sdp";
    
    if (!username_.empty()) {
        headers["Authorization"] = generateBasicAuth(username_, password_);
    }
    
    return sendRequest("DESCRIBE", server_url_, headers, "", 0);
}

bool RTSPClient::sendSetup(const std::string& track_url, TransportType transport) {
    if (!connected_) {
        last_error_ = "Not connected";
        return false;
    }
    
    // Create UDP sockets for RTP/RTCP if using UDP
    if (transport == TransportType::UDP && !createUDPSockets()) {
        return false;
    }
    
    std::map<std::string, std::string> headers;
    headers["CSeq"] = generateCSeq();
    headers["User-Agent"] = generateUserAgent();
    
    if (!session_id_.empty()) {
        headers["Session"] = session_id_;
    }
    
    // Generate transport header
    std::ostringstream transport_header;
    transport_header << "RTP/AVP";
    if (transport == TransportType::UDP) {
        transport_header << ";unicast;client_port=" << ntohs(local_rtp_addr_.sin_port) << "-" << ntohs(local_rtcp_addr_.sin_port);
    } else {
        transport_header << "/TCP;unicast;interleaved=0-1";
    }
    headers["Transport"] = transport_header.str();
    
    if (!username_.empty() && auth_type_ == AuthType::DIGEST) {
        // For digest auth, we need to get the realm and nonce from previous responses
        // This is a simplified implementation
        headers["Authorization"] = generateBasicAuth(username_, password_);
    } else if (!username_.empty()) {
        headers["Authorization"] = generateBasicAuth(username_, password_);
    }
    
    LOG_DEBUG("RTSPClient::sendSetup() trying " + std::string(transport == TransportType::UDP ? "UDP" : "TCP") + 
             " transport with header: " + transport_header.str());
    
    bool result = sendRequest("SETUP", track_url, headers, "", 0);
    
    // If UDP failed with "461 Unsupported Transport", try TCP fallback
    if (!result && transport == TransportType::UDP && 
        last_error_.find("461") != std::string::npos) {
        LOG_DEBUG("RTSPClient::sendSetup() UDP transport rejected, falling back to TCP");
        
        // Close UDP sockets
        closeUDPSockets();
        
        // Retry with TCP
        headers["Transport"] = "RTP/AVP/TCP;unicast;interleaved=0-1";
        headers["CSeq"] = generateCSeq(); // New CSeq for retry
        
        LOG_DEBUG("RTSPClient::sendSetup() retrying with TCP transport");
        result = sendRequest("SETUP", track_url, headers, "", 0);
    }
    
    return result;
}

bool RTSPClient::sendPlay() {
    if (!connected_) {
        last_error_ = "Not connected";
        return false;
    }
    
    std::map<std::string, std::string> headers;
    headers["CSeq"] = generateCSeq();
    headers["User-Agent"] = generateUserAgent();
    headers["Session"] = session_id_;
    headers["Range"] = "npt=0.000-";
    
    if (!username_.empty()) {
        headers["Authorization"] = generateBasicAuth(username_, password_);
    }
    
    bool result = sendRequest("PLAY", server_url_, headers, "", 0);
    if (result) {
        playing_ = true;
        startRTPReceiver();
        
        // Request keyframes immediately after starting playback
        requestKeyframe();
    }
    return result;
}

bool RTSPClient::sendPause() {
    if (!connected_) {
        last_error_ = "Not connected";
        return false;
    }
    
    std::map<std::string, std::string> headers;
    headers["CSeq"] = generateCSeq();
    headers["User-Agent"] = generateUserAgent();
    headers["Session"] = session_id_;
    
    if (!username_.empty()) {
        headers["Authorization"] = generateBasicAuth(username_, password_);
    }
    
    bool result = sendRequest("PAUSE", server_url_, headers, "", 0);
    if (result) {
        playing_ = false;
        stopRTPReceiver();
    }
    return result;
}

bool RTSPClient::sendTeardown() {
    if (!connected_) {
        return true; // Already disconnected
    }
    
    std::map<std::string, std::string> headers;
    headers["CSeq"] = generateCSeq();
    headers["User-Agent"] = generateUserAgent();
    headers["Session"] = session_id_;
    
    if (!username_.empty()) {
        headers["Authorization"] = generateBasicAuth(username_, password_);
    }
    
    bool result = sendRequest("TEARDOWN", server_url_, headers, "", 0);
    playing_ = false;
    stopRTPReceiver();
    return result;
}

void RTSPClient::setRTPCallback(RTPPacketCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    rtp_callback_ = callback;
}

void RTSPClient::startRTPReceiver() {
    if (rtp_running_) {
        return;
    }
    
    rtp_running_ = true;
    rtp_thread_ = std::thread(&RTSPClient::rtpReceiverThread, this);
}

void RTSPClient::stopRTPReceiver() {
    if (!rtp_running_) {
        return;
    }
    
    rtp_running_ = false;
    if (rtp_thread_.joinable()) {
        rtp_thread_.join();
    }
}

void RTSPClient::setConnectionTimeout(int timeout_seconds) {
    connection_timeout_ = timeout_seconds;
}

void RTSPClient::setRetryCount(int retry_count) {
    retry_count_ = retry_count;
}

bool RTSPClient::createSocket() {
    tcp_socket_ = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_socket_ < 0) {
        last_error_ = "Failed to create socket: " + std::string(strerror(errno));
        return false;
    }
    
    // Set socket options
    int opt = 1;
    if (setsockopt(tcp_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        last_error_ = "Failed to set socket options: " + std::string(strerror(errno));
        close(tcp_socket_);
        tcp_socket_ = -1;
        return false;
    }
    
    return true;
}

bool RTSPClient::connectToServer() {
    server_addr_.sin_family = AF_INET;
    server_addr_.sin_port = htons(server_port_);
    
    // Try to resolve hostname to IP address
    LOG_DEBUG("RTSPClient: Resolving hostname: " + server_host_);
    struct hostent* host_entry = gethostbyname(server_host_.c_str());
    if (host_entry == nullptr) {
        LOG_DEBUG("RTSPClient: Hostname resolution failed, trying direct IP conversion");
        // If hostname resolution fails, try direct IP conversion
        if (inet_pton(AF_INET, server_host_.c_str(), &server_addr_.sin_addr) <= 0) {
            last_error_ = "Invalid server address: " + server_host_;
            return false;
        }
    } else {
        LOG_DEBUG("RTSPClient: Hostname resolved successfully");
        // Copy the resolved IP address
        memcpy(&server_addr_.sin_addr, host_entry->h_addr_list[0], host_entry->h_length);
    }
    
    // Set socket to non-blocking mode
    int flags = fcntl(tcp_socket_, F_GETFL, 0);
    if (flags < 0) {
        last_error_ = "Failed to get socket flags: " + std::string(strerror(errno));
        return false;
    }
    
    if (fcntl(tcp_socket_, F_SETFL, flags | O_NONBLOCK) < 0) {
        last_error_ = "Failed to set socket non-blocking: " + std::string(strerror(errno));
        return false;
    }
    
    // Attempt connection
    int result = ::connect(tcp_socket_, (struct sockaddr*)&server_addr_, sizeof(server_addr_));
    
    if (result < 0) {
        if (errno == EINPROGRESS) {
            // Connection in progress, wait for completion with timeout
            fd_set write_fds;
            FD_ZERO(&write_fds);
            FD_SET(tcp_socket_, &write_fds);
            
            struct timeval timeout;
            timeout.tv_sec = connection_timeout_;
            timeout.tv_usec = 0;
            
            int select_result = select(tcp_socket_ + 1, nullptr, &write_fds, nullptr, &timeout);
            
            // Check if we should stop during the select wait
            if (should_stop_) {
                fcntl(tcp_socket_, F_SETFL, flags); // Restore original flags
                last_error_ = "Connection cancelled";
                return false;
            }
            
            if (select_result > 0) {
                // Check if connection was successful
                int error = 0;
                socklen_t len = sizeof(error);
                if (getsockopt(tcp_socket_, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
                    last_error_ = "Failed to get socket error: " + std::string(strerror(errno));
                    fcntl(tcp_socket_, F_SETFL, flags); // Restore original flags
                    return false;
                }
                
                if (error != 0) {
                    last_error_ = "Connection failed: " + std::string(strerror(error));
                    fcntl(tcp_socket_, F_SETFL, flags); // Restore original flags
                    return false;
                }
            } else if (select_result == 0) {
                last_error_ = "Connection timeout";
                fcntl(tcp_socket_, F_SETFL, flags); // Restore original flags
                return false;
            } else {
                last_error_ = "Select error: " + std::string(strerror(errno));
                fcntl(tcp_socket_, F_SETFL, flags); // Restore original flags
                return false;
            }
        } else {
            last_error_ = "Failed to connect to server: " + std::string(strerror(errno));
            fcntl(tcp_socket_, F_SETFL, flags); // Restore original flags
            return false;
        }
    }
    
    // Restore blocking mode
    fcntl(tcp_socket_, F_SETFL, flags);
    
    return true;
}

void RTSPClient::closeSocket() {
    if (tcp_socket_ >= 0) {
        close(tcp_socket_);
        tcp_socket_ = -1;
    }
}

bool RTSPClient::sendRequest(const std::string& method, const std::string& url, 
                            const std::map<std::string, std::string>& headers, 
                            const std::string& body, int retry_count) {
    if (tcp_socket_ < 0) {
        last_error_ = "Socket not connected";
        return false;
    }
    
    // Build request
    std::ostringstream request;
    request << method << " " << url << " RTSP/1.0\r\n";
    
    for (const auto& header : headers) {
        request << header.first << ": " << header.second << "\r\n";
    }
    
    if (!body.empty()) {
        request << "Content-Length: " << body.length() << "\r\n";
    }
    
    request << "\r\n";
    if (!body.empty()) {
        request << body;
    }
    
    std::string request_str = request.str();
    
    // Send request
    ssize_t sent = send(tcp_socket_, request_str.c_str(), request_str.length(), 0);
    if (sent < 0) {
        last_error_ = "Failed to send request: " + std::string(strerror(errno));
        return false;
    }
    
    // Receive response
    RTSPResponse response;
    if (!receiveResponse(response)) {
        return false;
    }
    
    // Debug: Show response details
    LOG_DEBUG("RTSPClient::sendRequest() response status: " + std::to_string(response.status_code));
    if (response.status_code == 401) {
        LOG_DEBUG("RTSPClient::sendRequest() 401 Unauthorized - checking for WWW-Authenticate header");
        auto auth_header = response.headers.find("WWW-Authenticate");
        if (auth_header != response.headers.end()) {
            LOG_DEBUG("RTSPClient::sendRequest() WWW-Authenticate: " + auth_header->second);
        } else {
            LOG_DEBUG("RTSPClient::sendRequest() No WWW-Authenticate header found");
        }
    }
    
    // Handle authentication if needed
    if (response.status_code == 401 && !username_.empty()) {
        if (retry_count < 3) {
            if (handleAuthentication(response)) {
                // Add authentication header for retry
                std::map<std::string, std::string> auth_headers = headers;
                std::string auth_header_value;
                if (auth_type_ == AuthType::BASIC) {
                    auth_header_value = generateBasicAuth(username_, password_);
                    LOG_DEBUG("RTSPClient::sendRequest() using BASIC authentication");
                } else if (auth_type_ == AuthType::DIGEST) {
                    // Parse WWW-Authenticate header for digest parameters
                    auto auth_header = response.headers.find("WWW-Authenticate");
                    std::string auth_string = auth_header->second;
                    
                    // Extract realm and nonce from WWW-Authenticate header
                    std::string realm, nonce;
                    size_t realm_pos = auth_string.find("realm=\"");
                    if (realm_pos != std::string::npos) {
                        realm_pos += 7; // Skip "realm=\""
                        size_t realm_end = auth_string.find("\"", realm_pos);
                        if (realm_end != std::string::npos) {
                            realm = auth_string.substr(realm_pos, realm_end - realm_pos);
                        }
                    }
                    
                    size_t nonce_pos = auth_string.find("nonce=\"");
                    if (nonce_pos != std::string::npos) {
                        nonce_pos += 7; // Skip "nonce=\""
                        size_t nonce_end = auth_string.find("\"", nonce_pos);
                        if (nonce_end != std::string::npos) {
                            nonce = auth_string.substr(nonce_pos, nonce_end - nonce_pos);
                        }
                    }
                    
                    auth_header_value = generateDigestAuth(username_, password_, method, url, realm, nonce);
                    LOG_DEBUG("RTSPClient::sendRequest() using DIGEST authentication");
                    LOG_DEBUG("RTSPClient::sendRequest() realm: " + realm + ", nonce: " + nonce);
                }
                auth_headers["Authorization"] = auth_header_value;
                LOG_DEBUG("RTSPClient::sendRequest() Authorization header: " + auth_header_value);
                
                // Retry request with authentication
                LOG_DEBUG("RTSPClient::sendRequest() retrying with authentication (attempt " + std::to_string(retry_count + 1) + ")");
                return sendRequest(method, url, auth_headers, body, retry_count + 1);
            }
        } else {
            LOG_DEBUG("RTSPClient::sendRequest() authentication retry limit reached");
        }
    }
    
    last_status_code_ = response.status_code;
    
    // Handle successful responses
    if (response.status_code >= 200 && response.status_code < 300) {
        // Extract session ID if present
        auto session_header = response.headers.find("Session");
        if (session_header != response.headers.end()) {
            session_id_ = session_header->second;
            // Remove any timeout parameter
            size_t timeout_pos = session_id_.find(';');
            if (timeout_pos != std::string::npos) {
                session_id_ = session_id_.substr(0, timeout_pos);
            }
        }
        
        // Parse SDP if this is a DESCRIBE response
        if (method == "DESCRIBE" && !response.body.empty()) {
            parseSDP(response.body);
        }
        
        // Parse transport information if this is a SETUP response
        if (method == "SETUP") {
            auto transport_header = response.headers.find("Transport");
            if (transport_header != response.headers.end()) {
                // Parse transport header to get server ports
                std::string transport = transport_header->second;
                // This is a simplified parser - in a real implementation,
                // you'd want more robust parsing
                size_t server_port_pos = transport.find("server_port=");
                if (server_port_pos != std::string::npos) {
                    server_port_pos += 12; // Length of "server_port="
                    size_t end_pos = transport.find('-', server_port_pos);
                    if (end_pos != std::string::npos) {
                        session_.server_rtp_port = std::stoi(transport.substr(server_port_pos, end_pos - server_port_pos));
                        session_.server_rtcp_port = std::stoi(transport.substr(end_pos + 1));
                    }
                }
            }
        }
        
        return true;
    }
    
    last_error_ = "RTSP error " + std::to_string(response.status_code) + ": " + response.reason_phrase;
    return false;
}

bool RTSPClient::receiveResponse(RTSPResponse& response) {
    std::string response_data;
    char buffer[4096];
    
    // Set socket timeout for receiving data
    struct timeval timeout;
    timeout.tv_sec = connection_timeout_;
    timeout.tv_usec = 0;
    setsockopt(tcp_socket_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    while (true) {
        ssize_t received = recv(tcp_socket_, buffer, sizeof(buffer) - 1, 0);
        if (received < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                last_error_ = "Receive timeout";
            } else {
                last_error_ = "Failed to receive response: " + std::string(strerror(errno));
            }
            return false;
        }
        
        if (received == 0) {
            last_error_ = "Connection closed by server";
            return false;
        }
        
        buffer[received] = '\0';
        response_data += buffer;
        
        // Check if we have a complete response (ends with \r\n\r\n)
        if (response_data.find("\r\n\r\n") != std::string::npos) {
            break;
        }
    }
    
    return parseResponse(response_data, response);
}

bool RTSPClient::parseResponse(const std::string& response_data, RTSPResponse& response) {
    std::istringstream stream(response_data);
    std::string line;
    
    // Parse status line
    if (!std::getline(stream, line)) {
        last_error_ = "Invalid response format";
        return false;
    }
    
    // Remove \r if present
    if (!line.empty() && line.back() == '\r') {
        line.pop_back();
    }
    
    std::istringstream status_line(line);
    status_line >> response.version >> response.status_code >> response.reason_phrase;
    
    // Parse headers
    while (std::getline(stream, line)) {
        if (line.empty() || line == "\r") {
            break;
        }
        
        // Remove \r if present
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        
        size_t colon_pos = line.find(':');
        if (colon_pos != std::string::npos) {
            std::string name = line.substr(0, colon_pos);
            std::string value = line.substr(colon_pos + 1);
            
            // Trim whitespace
            name = utils::StringUtils::trim(name);
            value = utils::StringUtils::trim(value);
            
            response.headers[name] = value;
        }
    }
    
    // Parse body if present
    std::ostringstream body_stream;
    while (std::getline(stream, line)) {
        body_stream << line << "\n";
    }
    response.body = body_stream.str();
    
    return true;
}

bool RTSPClient::handleAuthentication(const RTSPResponse& response) {
    auto auth_header = response.headers.find("WWW-Authenticate");
    if (auth_header == response.headers.end()) {
        return false;
    }
    
    std::string auth = auth_header->second;
    if (auth.find("Basic") == 0) {
        auth_type_ = AuthType::BASIC;
        return true;
    } else if (auth.find("Digest") == 0) {
        auth_type_ = AuthType::DIGEST;
        return true;
    }
    
    return false;
}

std::string RTSPClient::generateBasicAuth(const std::string& username, const std::string& password) {
    std::string credentials = username + ":" + password;
    return "Basic " + utils::Base64::encode(credentials);
}

std::string RTSPClient::generateDigestAuth(const std::string& username, const std::string& password,
                                          const std::string& method, const std::string& uri,
                                          const std::string& realm, const std::string& nonce) {
    // Generate MD5 hash for digest authentication
    std::string ha1_input = username + ":" + realm + ":" + password;
    std::string ha1 = utils::MD5::hash(ha1_input);
    
    std::string ha2_input = method + ":" + uri;
    std::string ha2 = utils::MD5::hash(ha2_input);
    
    std::string response_input = ha1 + ":" + nonce + ":" + ha2;
    std::string response = utils::MD5::hash(response_input);
    
    return "Digest username=\"" + username + "\", realm=\"" + realm + "\", nonce=\"" + nonce + 
           "\", uri=\"" + uri + "\", response=\"" + response + "\"";
}

std::string RTSPClient::getFirstTrackURL() const {
    if (sdp_info_.media_descriptions.empty()) {
        return "";
    }
    
    const MediaDescription& media = sdp_info_.media_descriptions[0];
    if (media.control_url.empty()) {
        return "";
    }
    
    // If control_url is relative, make it absolute
    if (media.control_url.find("rtsp://") == 0) {
        return media.control_url;
    } else {
        // Make it relative to the server URL
        return server_url_ + "/" + media.control_url;
    }
}

bool RTSPClient::parseSDP(const std::string& sdp_data) {
    std::istringstream stream(sdp_data);
    std::string line;
    std::vector<std::string> lines;
    
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        lines.push_back(line);
    }
    
    size_t index = 0;
    while (index < lines.size()) {
        if (lines[index].find("m=") == 0) {
            sdp_info_.media_descriptions.push_back(parseMediaDescription(lines, index));
        } else if (lines[index].find("c=") == 0) {
            // Parse connection information
            std::string connection = lines[index].substr(2);
            auto parts = utils::StringUtils::split(connection, ' ');
            if (parts.size() >= 3) {
                sdp_info_.connection_address = parts[2];
            }
        } else if (lines[index].find("s=") == 0) {
            sdp_info_.session_name = lines[index].substr(2);
        } else if (lines[index].find("i=") == 0) {
            sdp_info_.session_info = lines[index].substr(2);
        }
        index++;
    }
    
    return true;
}

MediaDescription RTSPClient::parseMediaDescription(const std::vector<std::string>& lines, size_t& index) {
    MediaDescription media;
    
    // Parse m= line
    std::string m_line = lines[index].substr(2);
    auto parts = utils::StringUtils::split(m_line, ' ');
    if (parts.size() >= 4) {
        media.media_type = parts[0];
        media.port = std::stoi(parts[1]);
        media.protocol = parts[2];
        media.format = parts[3];
    }
    
    index++;
    
    // Parse attributes
    while (index < lines.size() && lines[index].find("m=") != 0) {
        if (lines[index].find("a=") == 0) {
            std::string attr = lines[index].substr(2);
            size_t colon_pos = attr.find(':');
            if (colon_pos != std::string::npos) {
                std::string name = attr.substr(0, colon_pos);
                std::string value = attr.substr(colon_pos + 1);
                media.attributes[name] = value;
                
                if (name == "control") {
                    media.control_url = value;
                }
            }
        }
        index++;
    }
    
    return media;
}

void RTSPClient::rtpReceiverThread() {
    if (udp_rtp_socket_ < 0) {
        LOG_DEBUG("RTSPClient::rtpReceiverThread() RTP socket not available");
        return;
    }
    
    LOG_DEBUG("RTSPClient::rtpReceiverThread() started, socket: " + std::to_string(udp_rtp_socket_));
    
    uint8_t buffer[ConfigDefaults::MAX_PACKET_SIZE];
    RTPPacket packet;
    
    // Set socket timeout to 1 second
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(udp_rtp_socket_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    while (rtp_running_) {
        struct sockaddr_in from_addr;
        socklen_t from_len = sizeof(from_addr);
        
        ssize_t received = recvfrom(udp_rtp_socket_, buffer, sizeof(buffer), 0,
                                   (struct sockaddr*)&from_addr, &from_len);
        
        if (received > 0) {
            // Analyze RTP packet structure
            if (received >= 12) {
                uint8_t payload_type = buffer[1] & 0x7F;
                uint16_t sequence_number = (buffer[2] << 8) | buffer[3];
                
                // Check for H.264 payload
                if (payload_type == 96 && received > 16) {
                    uint8_t nal_header = buffer[12];
                    uint8_t nal_type = nal_header & 0x1F;
                    
                    // Track frame statistics
                    static int total_packets = 0;
                    static int idr_frames = 0;
                    static int p_frames = 0;
                    static int fu_fragments = 0;
                    static int sps_frames = 0;
                    static int pps_frames = 0;
                    static int packets_without_idr = 0;
                    static bool idr_seen = false;
                    static int keyframe_request_count = 0;
                    static auto last_report = std::chrono::steady_clock::now();
                    
                    total_packets++;
                    
                    switch (nal_type) {
                        case 7: 
                            sps_frames++;
                            break;
                        case 8: 
                            pps_frames++;
                            break;
                        case 5: 
                            idr_frames++;
                            idr_seen = true;
                            packets_without_idr = 0;
                            keyframe_request_count = 0;
                            break;
                        case 1: 
                            p_frames++;
                            packets_without_idr++;
                            break;
                        case 28: {
                            fu_fragments++;
                            packets_without_idr++;
                            // Check if this FU-A fragment completes an IDR frame
                            bool was_idr = processFUAFragment(buffer + 12, received - 12, sequence_number);
                            if (was_idr) {
                                idr_frames++; // Update the main counter
                                idr_seen = true;
                                packets_without_idr = 0;
                                keyframe_request_count = 0;
                            }
                            break;
                        }
                        default: 
                            break;
                    }
                    
                    // Request keyframes if we haven't seen any IDR frames
                    if (!idr_seen && packets_without_idr > 10 && keyframe_request_count < 5) {
                        LOG_DEBUG("No IDR frames after " + std::to_string(packets_without_idr) + " packets, requesting keyframe (attempt " + std::to_string(keyframe_request_count + 1) + ")");
                        requestKeyframe();
                        keyframe_request_count++;
                        packets_without_idr = 0; // Reset to avoid spam
                    }
                    
                    // Periodic status report every 5 seconds
                    auto now = std::chrono::steady_clock::now();
                    if (std::chrono::duration_cast<std::chrono::seconds>(now - last_report).count() >= 5) {
                        LOG_DEBUG("RTP Stream Status - Packets: " + std::to_string(total_packets) + 
                                 ", IDR: " + std::to_string(idr_frames) + ", P: " + std::to_string(p_frames) + 
                                 ", FU-A: " + std::to_string(fu_fragments) + ", SPS: " + std::to_string(sps_frames) + 
                                 ", PPS: " + std::to_string(pps_frames));
                        last_report = now;
                    }
                }
            }
            
            if (parseRTPPacket(buffer, received, packet)) {
                if (rtp_callback_) {
                    rtp_callback_(packet);
                } else {
                    LOG_WARN("RTP callback is null!");
                }
            } else {
                LOG_DEBUG("Failed to parse RTP packet");
            }
        } else if (received < 0) {
            // Check if it's a timeout error (EAGAIN/EWOULDBLOCK)
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Timeout occurred, continue loop to check rtp_running_
                continue;
            } else {
                // Other error occurred, break the loop
                break;
            }
        }
    }
}

bool RTSPClient::parseRTPPacket(const uint8_t* data, size_t length, RTPPacket& packet) {
    if (length < 12) {
        return false; // RTP header is at least 12 bytes
    }
    
    // Parse RTP header
    packet.version = (data[0] >> 6) & 0x3;
    packet.padding = (data[0] >> 5) & 0x1;
    packet.extension = (data[0] >> 4) & 0x1;
    packet.csrc_count = data[0] & 0xF;
    
    packet.marker = (data[1] >> 7) & 0x1;
    packet.payload_type = data[1] & 0x7F;
    
    packet.sequence_number = (data[2] << 8) | data[3];
    packet.timestamp = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
    packet.ssrc = (data[8] << 24) | (data[9] << 16) | (data[10] << 8) | data[11];
    
    size_t header_size = 12 + (packet.csrc_count * 4);
    
    // Parse extension header if present
    if (packet.extension) {
        if (length < header_size + 4) {
            return false;
        }
        uint16_t extension_length = (data[header_size + 2] << 8) | data[header_size + 3];
        header_size += 4 + (extension_length * 4);
    }
    
    // Parse CSRC list
    packet.csrc_list.clear();
    for (int i = 0; i < packet.csrc_count; i++) {
        uint32_t csrc = (data[12 + i * 4] << 24) | (data[13 + i * 4] << 16) |
                       (data[14 + i * 4] << 8) | data[15 + i * 4];
        packet.csrc_list.push_back(csrc);
    }
    
    // Extract payload
    if (length > header_size) {
        packet.payload.assign(data + header_size, data + length);
    }
    
    return true;
}

bool RTSPClient::createUDPSockets() {
    LOG_DEBUG("RTSPClient::createUDPSockets() creating UDP sockets");
    
    // Create RTP socket
    udp_rtp_socket_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_rtp_socket_ < 0) {
        last_error_ = "Failed to create RTP socket: " + std::string(strerror(errno));
        return false;
    }
    LOG_DEBUG("RTSPClient::createUDPSockets() RTP socket created: " + std::to_string(udp_rtp_socket_));
    
    // Set large receive buffer for RTP packets
    int rcvbuf_size = ConfigDefaults::RECEIVE_BUFFER_SIZE;
    if (setsockopt(udp_rtp_socket_, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size)) < 0) {
        LOG_DEBUG("RTSPClient::createUDPSockets() failed to set RTP socket receive buffer size: " + std::string(strerror(errno)));
    }
    
    // Create RTCP socket
    udp_rtcp_socket_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_rtcp_socket_ < 0) {
        last_error_ = "Failed to create RTCP socket: " + std::string(strerror(errno));
        close(udp_rtp_socket_);
        udp_rtp_socket_ = -1;
        return false;
    }
    
    // Set large receive buffer for RTCP packets
    if (setsockopt(udp_rtcp_socket_, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size)) < 0) {
        LOG_DEBUG("RTSPClient::createUDPSockets() failed to set RTCP socket receive buffer size: " + std::string(strerror(errno)));
    }
    
    // Bind RTP socket
    local_rtp_addr_.sin_family = AF_INET;
    local_rtp_addr_.sin_addr.s_addr = INADDR_ANY;
    local_rtp_addr_.sin_port = 0; // Let system choose port
    
    if (bind(udp_rtp_socket_, (struct sockaddr*)&local_rtp_addr_, sizeof(local_rtp_addr_)) < 0) {
        last_error_ = "Failed to bind RTP socket: " + std::string(strerror(errno));
        closeUDPSockets();
        return false;
    }
    
    // Get the assigned port
    socklen_t addr_len = sizeof(local_rtp_addr_);
    if (getsockname(udp_rtp_socket_, (struct sockaddr*)&local_rtp_addr_, &addr_len) < 0) {
        last_error_ = "Failed to get RTP socket address: " + std::string(strerror(errno));
        closeUDPSockets();
        return false;
    }
    LOG_DEBUG("RTSPClient::createUDPSockets() RTP port: " + std::to_string(ntohs(local_rtp_addr_.sin_port)));
    
    // Bind RTCP socket to next port
    local_rtcp_addr_ = local_rtp_addr_;
    local_rtcp_addr_.sin_port = htons(ntohs(local_rtp_addr_.sin_port) + 1);
    
    if (bind(udp_rtcp_socket_, (struct sockaddr*)&local_rtcp_addr_, sizeof(local_rtcp_addr_)) < 0) {
        last_error_ = "Failed to bind RTCP socket: " + std::string(strerror(errno));
        closeUDPSockets();
        return false;
    }
    
    return true;
}

void RTSPClient::closeUDPSockets() {
    if (udp_rtp_socket_ >= 0) {
        close(udp_rtp_socket_);
        udp_rtp_socket_ = -1;
    }
    
    if (udp_rtcp_socket_ >= 0) {
        close(udp_rtcp_socket_);
        udp_rtcp_socket_ = -1;
    }
}

bool RTSPClient::processFUAFragment(const uint8_t* payload, size_t payload_len, uint16_t sequence_number) {
    if (payload_len < 2) return false; // Need at least FU-A header
    
    // Parse FU-A header
    uint8_t fu_header = payload[0];
    uint8_t fu_indicator = payload[1];
    
    uint8_t start_bit = (fu_indicator >> 7) & 0x1;
    uint8_t end_bit = (fu_indicator >> 6) & 0x1;
    uint8_t nal_type = fu_indicator & 0x1F;
    
    // Reconstruct NAL header
    uint8_t nal_header = (fu_header & 0xE0) | nal_type;
    
    // Get fragment data
    const uint8_t* fragment_data = payload + 2;
    size_t fragment_len = payload_len - 2;
    
    // Static reassembly buffer
    static uint8_t reassembly_buffer[ConfigDefaults::MAX_PACKET_SIZE];
    static size_t reassembly_len = 0;
    static uint8_t current_nal_type = 0;
    static bool reassembly_active = false;
    static uint16_t last_seq = 0;
    
    // Check for sequence discontinuity
    if (reassembly_active && sequence_number != last_seq + 1) {
        LOG_DEBUG("RTSPClient::processFUAFragment() sequence discontinuity: " + std::to_string(last_seq) + " -> " + std::to_string(sequence_number));
        reassembly_active = false;
        reassembly_len = 0;
    }
    
    if (start_bit) {
        // Start of new NAL unit
        reassembly_len = 0;
        current_nal_type = nal_type;
        reassembly_active = true;
        
        // Add NAL header
        reassembly_buffer[0] = nal_header;
        reassembly_len = 1;
        
        // Add fragment data
        if (reassembly_len + fragment_len < sizeof(reassembly_buffer)) {
            memcpy(reassembly_buffer + reassembly_len, fragment_data, fragment_len);
            reassembly_len += fragment_len;
        }
        
        if (end_bit) {
            // Single packet FU-A
            reassembly_active = false;
            
            // Process complete NAL unit
            processCompleteNALUnit(reassembly_buffer, reassembly_len, nal_type);
            return (nal_type == 5); // Return true if this was an IDR frame
        }
    } else if (reassembly_active && nal_type == current_nal_type) {
        // Continuation of current NAL unit
        if (reassembly_len + fragment_len < sizeof(reassembly_buffer)) {
            memcpy(reassembly_buffer + reassembly_len, fragment_data, fragment_len);
            reassembly_len += fragment_len;
        }
        
        if (end_bit) {
            // End of NAL unit
            reassembly_active = false;
            
            // Process complete NAL unit
            processCompleteNALUnit(reassembly_buffer, reassembly_len, nal_type);
            return (nal_type == 5); // Return true if this was an IDR frame
        }
    } else {
        // Invalid fragment - reset reassembly
        reassembly_active = false;
        reassembly_len = 0;
    }
    
    last_seq = sequence_number;
    return false; // No complete frame processed
}

void RTSPClient::processCompleteNALUnit(const uint8_t* nal_data, size_t nal_len, uint8_t nal_type) {
    // Update statistics for reassembled NAL units
    static int reassembled_idr_frames = 0;
    static int reassembled_p_frames = 0;
    static int reassembled_sps_frames = 0;
    static int reassembled_pps_frames = 0;
    
    switch (nal_type) {
        case 5: 
            reassembled_idr_frames++;
            LOG_DEBUG("IDR keyframe received, len=" + std::to_string(nal_len) + " (reassembled #" + std::to_string(reassembled_idr_frames) + ")");
            break;
        case 1: 
            reassembled_p_frames++;
            break;
        case 7: 
            reassembled_sps_frames++;
            break;
        case 8: 
            reassembled_pps_frames++;
            break;
    }
    
    // Update the main statistics counters (these are static in rtpReceiverThread)
    // We need to access them through a different mechanism since they're in a different function
    // For now, we'll just log the reassembled frames separately
    
    // Create RTP packet for the complete NAL unit
    RTPPacket packet;
    packet.version = 2;
    packet.padding = 0;
    packet.extension = 0;
    packet.csrc_count = 0;
    packet.marker = 0;
    packet.payload_type = 96; // H.264
    packet.sequence_number = 0; // Will be set by caller
    packet.timestamp = 0; // Will be set by caller
    packet.ssrc = 0;
    packet.payload.assign(nal_data, nal_data + nal_len);
    
    // Call the RTP callback with the complete NAL unit
    if (rtp_callback_) {
        rtp_callback_(packet);
    }
}

void RTSPClient::requestKeyframe() {
    if (!connected_ || session_id_.empty()) {
        return;
    }
    
    LOG_DEBUG("Requesting keyframe from camera");
    
    // Method 1: SET_PARAMETER with picture_fast_update
    sendKeyframeRequest("SET_PARAMETER", "picture_fast_update");
    
    // Method 2: SET_PARAMETER with keyframe_request
    sendKeyframeRequest("SET_PARAMETER", "keyframe_request");
    
    // Method 3: GET_PARAMETER to trigger keyframe
    sendKeyframeRequest("GET_PARAMETER", "picture_fast_update");
    
    // Method 4: Additional keyframe request with different parameter
    sendKeyframeRequest("SET_PARAMETER", "force_idr");
    
    // Method 5: Try to trigger keyframe with different approach
    sendKeyframeRequest("SET_PARAMETER", "idr");
}

void RTSPClient::sendKeyframeRequest(const std::string& method, const std::string& parameter) {
    if (!connected_ || session_id_.empty()) {
        return;
    }
    
    std::map<std::string, std::string> headers;
    headers["CSeq"] = generateCSeq();
    headers["User-Agent"] = generateUserAgent();
    headers["Session"] = session_id_;
    headers["Content-Type"] = "text/parameters";
    headers["Content-Length"] = std::to_string(parameter.length());
    
    if (!username_.empty() && auth_type_ == AuthType::DIGEST) {
        headers["Authorization"] = generateBasicAuth(username_, password_);
    } else if (!username_.empty()) {
        headers["Authorization"] = generateBasicAuth(username_, password_);
    }
    
    // Send the request silently
    
    // Send the request (we don't care about the response for keyframe requests)
    sendRequest(method, server_url_, headers, parameter, 0);
}

std::string RTSPClient::extractHeader(const std::map<std::string, std::string>& headers, const std::string& name) {
    auto it = headers.find(name);
    return (it != headers.end()) ? it->second : "";
}

std::string RTSPClient::generateCSeq() {
    return std::to_string(cseq_++);
}

std::string RTSPClient::generateUserAgent() {
    return user_agent_;
}

} // namespace camera
} // namespace camrelay
