#include "Utils.h"
#include <algorithm>
#include <cctype>
#include <sstream>
#include <chrono>
#include <thread>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <filesystem>
#include <fstream>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

namespace camrelay {
namespace utils {

// String utility functions
std::string StringUtils::trim(const std::string& str) {
    size_t first = str.find_first_not_of(' ');
    if (first == std::string::npos) {
        return "";
    }
    size_t last = str.find_last_not_of(' ');
    return str.substr(first, (last - first + 1));
}

std::string StringUtils::toLower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

std::string StringUtils::toUpper(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::toupper);
    return result;
}

std::vector<std::string> StringUtils::split(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::stringstream ss(str);
    std::string token;
    
    while (std::getline(ss, token, delimiter)) {
        tokens.push_back(token);
    }
    
    return tokens;
}

bool StringUtils::startsWith(const std::string& str, const std::string& prefix) {
    return str.size() >= prefix.size() && str.compare(0, prefix.size(), prefix) == 0;
}

bool StringUtils::endsWith(const std::string& str, const std::string& suffix) {
    return str.size() >= suffix.size() && str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::string StringUtils::replace(const std::string& str, const std::string& from, const std::string& to) {
    std::string result = str;
    size_t pos = 0;
    while ((pos = result.find(from, pos)) != std::string::npos) {
        result.replace(pos, from.length(), to);
        pos += to.length();
    }
    return result;
}

bool StringUtils::isEmpty(const std::string& str) {
    return str.empty() || std::all_of(str.begin(), str.end(), ::isspace);
}

// Time utility functions
std::string TimeUtils::getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    oss << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return oss.str();
}

uint64_t TimeUtils::getCurrentTimeMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string TimeUtils::formatDuration(std::chrono::milliseconds duration) {
    auto hours = std::chrono::duration_cast<std::chrono::hours>(duration);
    auto minutes = std::chrono::duration_cast<std::chrono::minutes>(duration % std::chrono::hours(1));
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration % std::chrono::minutes(1));
    auto ms = duration % std::chrono::seconds(1);
    
    std::ostringstream oss;
    if (hours.count() > 0) {
        oss << hours.count() << "h ";
    }
    if (minutes.count() > 0) {
        oss << minutes.count() << "m ";
    }
    oss << seconds.count() << "." << std::setfill('0') << std::setw(3) << ms.count() << "s";
    return oss.str();
}

void TimeUtils::sleepMs(uint32_t milliseconds) {
    std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}

// Network utility functions
NetworkUtils::URLComponents NetworkUtils::parseUrl(const std::string& url) {
    URLComponents components;
    
    // Find protocol
    size_t protocolEnd = url.find("://");
    if (protocolEnd != std::string::npos) {
        components.protocol = url.substr(0, protocolEnd);
        protocolEnd += 3;
    } else {
        protocolEnd = 0;
    }
    
    // Find host and port
    size_t pathStart = url.find('/', protocolEnd);
    std::string hostPort;
    if (pathStart != std::string::npos) {
        hostPort = url.substr(protocolEnd, pathStart - protocolEnd);
        components.path = url.substr(pathStart);
    } else {
        hostPort = url.substr(protocolEnd);
        components.path = "/";
    }
    
    // Check for authentication
    size_t atPos = hostPort.find('@');
    if (atPos != std::string::npos) {
        std::string auth = hostPort.substr(0, atPos);
        size_t colonPos = auth.find(':');
        if (colonPos != std::string::npos) {
            components.username = auth.substr(0, colonPos);
            components.password = auth.substr(colonPos + 1);
        } else {
            components.username = auth;
        }
        hostPort = hostPort.substr(atPos + 1);
    }
    
    // Parse host and port
    size_t colonPos = hostPort.find(':');
    if (colonPos != std::string::npos) {
        components.host = hostPort.substr(0, colonPos);
        try {
            components.port = std::stoi(hostPort.substr(colonPos + 1));
        } catch (...) {
            components.port = 0;
        }
    } else {
        components.host = hostPort;
        components.port = 0;
    }
    
    return components;
}

bool NetworkUtils::isPortAvailable(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return false;
    }
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    int result = bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    close(sock);
    
    return result == 0;
}

std::string NetworkUtils::getLocalIP() {
    struct ifaddrs *ifaddr, *ifa;
    std::string localIP = "127.0.0.1";
    
    if (getifaddrs(&ifaddr) == -1) {
        return localIP;
    }
    
    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        
        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in* addr_in = (struct sockaddr_in*)ifa->ifa_addr;
            std::string ip = inet_ntoa(addr_in->sin_addr);
            
            // Skip loopback and prefer non-127.0.0.1 addresses
            if (ip != "127.0.0.1" && ip.substr(0, 3) != "169") {
                localIP = ip;
                break;
            }
        }
    }
    
    freeifaddrs(ifaddr);
    return localIP;
}

bool NetworkUtils::isValidIP(const std::string& ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) != 0;
}

bool NetworkUtils::isValidPort(int port) {
    return port > 0 && port <= 65535;
}

bool NetworkUtils::isValidIPAddress(const std::string& ip) {
    // Simple IPv4 validation
    std::vector<std::string> parts = StringUtils::split(ip, '.');
    if (parts.size() != 4) {
        return false;
    }
    
    for (const auto& part : parts) {
        try {
            int num = std::stoi(part);
            if (num < 0 || num > 255) {
                return false;
            }
        } catch (...) {
            return false;
        }
    }
    
    return true;
}

// File system utility functions
bool FileUtils::fileExists(const std::string& path) {
    return std::filesystem::exists(path) && std::filesystem::is_regular_file(path);
}

bool FileUtils::directoryExists(const std::string& path) {
    return std::filesystem::exists(path) && std::filesystem::is_directory(path);
}

bool FileUtils::createDirectory(const std::string& path) {
    try {
        return std::filesystem::create_directories(path);
    } catch (...) {
        return false;
    }
}

size_t FileUtils::getFileSize(const std::string& path) {
    try {
        return std::filesystem::file_size(path);
    } catch (...) {
        return 0;
    }
}

std::string FileUtils::readFile(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return "";
    }
    
    std::ostringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

bool FileUtils::writeFile(const std::string& path, const std::string& content) {
    std::ofstream file(path);
    if (!file.is_open()) {
        return false;
    }
    
    file << content;
    return file.good();
}

std::string FileUtils::getDirectory(const std::string& filePath) {
    size_t pos = filePath.find_last_of('/');
    if (pos != std::string::npos) {
        return filePath.substr(0, pos);
    }
    return "";
}

std::string FileUtils::getFilename(const std::string& filePath) {
    size_t pos = filePath.find_last_of('/');
    if (pos != std::string::npos) {
        return filePath.substr(pos + 1);
    }
    return filePath;
}

// Base64 encoding/decoding
std::string Base64::encode(const std::string& input) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input.c_str(), input.length());
    BIO_flush(bio);
    
    BIO_get_mem_ptr(bio, &bufferPtr);
    std::string result(bufferPtr->data, bufferPtr->length);
    
    BIO_free_all(bio);
    return result;
}

std::string Base64::decode(const std::string& input) {
    BIO *bio, *b64;
    
    int decodeLen = (input.length() * 3) / 4;
    char* buffer = new char[decodeLen + 1];
    
    bio = BIO_new_mem_buf(input.c_str(), input.length());
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int length = BIO_read(bio, buffer, input.length());
    buffer[length] = '\0';
    
    std::string result(buffer);
    delete[] buffer;
    
    BIO_free_all(bio);
    return result;
}

// MD5 hash function
std::string MD5::hash(const std::string& input) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return "";
    }
    
    if (EVP_DigestInit_ex(ctx, EVP_md5(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }
    
    if (EVP_DigestUpdate(ctx, input.c_str(), input.length()) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }
    
    if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }
    
    EVP_MD_CTX_free(ctx);
    
    std::ostringstream oss;
    for (unsigned int i = 0; i < digest_len; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    }
    
    return oss.str();
}

// Configuration validation utilities
bool ConfigValidator::isValidRTSPUrl(const std::string& url) {
    return StringUtils::startsWith(url, "rtsp://") && url.length() > 7;
}

bool ConfigValidator::isValidLogLevel(const std::string& level) {
    std::string lowerLevel = StringUtils::toLower(level);
    return lowerLevel == "trace" || lowerLevel == "debug" || 
           lowerLevel == "info" || lowerLevel == "warn" || 
           lowerLevel == "error" || lowerLevel == "critical";
}

bool ConfigValidator::isValidPortRange(int minPort, int maxPort) {
    return minPort > 0 && maxPort <= 65535 && minPort <= maxPort;
}

bool ConfigValidator::isValidMemorySize(int sizeMb) {
    return sizeMb > 0 && sizeMb <= 10240; // Max 10GB
}

bool ConfigValidator::isValidTimeout(int timeoutSeconds) {
    return timeoutSeconds > 0 && timeoutSeconds <= 3600; // Max 1 hour
}


} // namespace utils
} // namespace camrelay
