/**
 * @file stream_utils.c
 * @brief Utility functions for stream management
 */

#define _POSIX_C_SOURCE 200809L
#include "stream/stream_utils.h"
#include "logging/logger.h"
#include <time.h>
#include <string.h>
#include <openssl/evp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>

/**
 * @brief Get current timestamp in milliseconds
 */
uint64_t get_timestamp_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/**
 * @brief Get stream state string
 */
const char *stream_manager_state_to_string(stream_state_t state) {
    switch (state) {
        case STREAM_STATE_DISCONNECTED: return "DISCONNECTED";
        case STREAM_STATE_CONNECTING: return "CONNECTING";
        case STREAM_STATE_CONNECTED: return "CONNECTED";
        case STREAM_STATE_STREAMING: return "STREAMING";
        case STREAM_STATE_ERROR: return "ERROR";
        case STREAM_STATE_RECONNECTING: return "RECONNECTING";
        default: return "UNKNOWN";
    }
}

/**
 * @brief Convert bytes to hex string
 */
void bytes_to_hex(const unsigned char *bytes, size_t len, char *hex) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + (i * 2), "%02x", bytes[i]);
    }
    hex[len * 2] = '\0';
}

/**
 * @brief Generate MD5 hash using EVP interface
 */
void md5_hash(const char *input, char *output) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        logger_error("Failed to create MD context");
        return;
    }
    
    if (EVP_DigestInit_ex(mdctx, EVP_md5(), NULL) != 1) {
        logger_error("Failed to initialize MD5 digest");
        EVP_MD_CTX_free(mdctx);
        return;
    }
    
    if (EVP_DigestUpdate(mdctx, input, strlen(input)) != 1) {
        logger_error("Failed to update MD5 digest");
        EVP_MD_CTX_free(mdctx);
        return;
    }
    
    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        logger_error("Failed to finalize MD5 digest");
        EVP_MD_CTX_free(mdctx);
        return;
    }
    
    EVP_MD_CTX_free(mdctx);
    bytes_to_hex(hash, hash_len, output);
}

/**
 * @brief Parse WWW-Authenticate header for Digest authentication
 */
int parse_digest_challenge(const char *auth_header, char *realm, char *nonce) {
    if (!auth_header || !realm || !nonce) return -1;
    
    /* Look for realm= */
    const char *realm_start = strstr(auth_header, "realm=\"");
    if (realm_start) {
        realm_start += 7; /* Skip 'realm="' */
        const char *realm_end = strchr(realm_start, '"');
        if (realm_end) {
            size_t realm_len = realm_end - realm_start;
            strncpy(realm, realm_start, realm_len);
            realm[realm_len] = '\0';
        }
    }
    
    /* Look for nonce= */
    const char *nonce_start = strstr(auth_header, "nonce=\"");
    if (nonce_start) {
        nonce_start += 7; /* Skip 'nonce="' */
        const char *nonce_end = strchr(nonce_start, '"');
        if (nonce_end) {
            size_t nonce_len = nonce_end - nonce_start;
            strncpy(nonce, nonce_start, nonce_len);
            nonce[nonce_len] = '\0';
        }
    }
    
    return 0;
}

/**
 * @brief Generate Digest authentication response
 */
int generate_digest_response(const char *username, const char *password, 
                           const char *realm, const char *nonce, 
                           const char *method, const char *uri, 
                           char *response) {
    if (!username || !password || !realm || !nonce || !method || !uri || !response) {
        return -1;
    }
    
    /* HA1 = MD5(username:realm:password) */
    char ha1_input[512];
    snprintf(ha1_input, sizeof(ha1_input), "%s:%s:%s", username, realm, password);
    char ha1[33];
    md5_hash(ha1_input, ha1);
    
    /* HA2 = MD5(method:uri) */
    char ha2_input[512];
    snprintf(ha2_input, sizeof(ha2_input), "%s:%s", method, uri);
    char ha2[33];
    md5_hash(ha2_input, ha2);
    
    /* Response = MD5(HA1:nonce:HA2) */
    char response_input[512];
    snprintf(response_input, sizeof(response_input), "%s:%s:%s", ha1, nonce, ha2);
    char digest_response[33];
    md5_hash(response_input, digest_response);
    
    /* Build Authorization header */
    snprintf(response, 1024,
        "Authorization: Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\"\r\n",
        username, realm, nonce, uri, digest_response);
    
    return 0;
}

/**
 * @brief Create UDP sockets for RTP/RTCP
 */
int create_udp_sockets(stream_connection_t *conn) {
    if (!conn) return -1;
    
    /* Create RTP socket */
    conn->rtp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (conn->rtp_socket < 0) {
        logger_error("Failed to create RTP socket: %s", strerror(errno));
        return -1;
    }
    
    /* Set large receive buffer for RTP packets */
    int rcvbuf_size = 65536;
    if (setsockopt(conn->rtp_socket, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size)) < 0) {
        logger_warn("Failed to set RTP socket receive buffer size: %s", strerror(errno));
    }
    
    /* Create RTCP socket */
    conn->rtcp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (conn->rtcp_socket < 0) {
        logger_error("Failed to create RTCP socket: %s", strerror(errno));
        close(conn->rtp_socket);
        return -1;
    }
    
    /* Set large receive buffer for RTCP packets */
    if (setsockopt(conn->rtcp_socket, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size)) < 0) {
        logger_warn("Failed to set RTCP socket receive buffer size: %s", strerror(errno));
    }
    
    /* Bind RTP socket to any available port */
    struct sockaddr_in local_addr = {0};
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    local_addr.sin_port = 0; /* Let system choose port */
    
    if (bind(conn->rtp_socket, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        logger_error("Failed to bind RTP socket: %s", strerror(errno));
        close(conn->rtp_socket);
        close(conn->rtcp_socket);
        return -1;
    }
    
    /* Get the assigned port */
    socklen_t addr_len = sizeof(local_addr);
    if (getsockname(conn->rtp_socket, (struct sockaddr*)&local_addr, &addr_len) < 0) {
        logger_error("Failed to get RTP socket port: %s", strerror(errno));
        close(conn->rtp_socket);
        close(conn->rtcp_socket);
        return -1;
    }
    conn->client_port = ntohs(local_addr.sin_port);
    
    /* Bind RTCP socket to next port */
    local_addr.sin_port = htons(conn->client_port + 1);
    if (bind(conn->rtcp_socket, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        logger_error("Failed to bind RTCP socket: %s", strerror(errno));
        close(conn->rtp_socket);
        close(conn->rtcp_socket);
        return -1;
    }
    
    
    return 0;
}

/**
 * @brief Close UDP sockets
 */
void close_udp_sockets(stream_connection_t *conn) {
    if (!conn) return;
    
    if (conn->rtp_socket >= 0) {
        close(conn->rtp_socket);
        conn->rtp_socket = -1;
    }
    
    if (conn->rtcp_socket >= 0) {
        close(conn->rtcp_socket);
        conn->rtcp_socket = -1;
    }
    
}

/**
 * @brief Analyze received data to determine if it's video, audio, or control data
 */
void analyze_received_data(const uint8_t *data, size_t len, int packet_num) {
    (void)packet_num; /* Suppress unused parameter warning */
    if (len < 12) {
        logger_warn("*** DATA TOO SHORT *** %zd bytes (minimum 12 for RTP)", len);
        return;
    }
    
    /* Check RTP header */
    uint8_t version = (data[0] >> 6) & 0x3;
    
    if (version != 2) {
        logger_warn("  *** INVALID RTP VERSION *** Expected 2, got %d", version);
    }
    
}

/**
 * @brief Process RTP packet from UDP transport
 */
void process_rtp_packet(stream_connection_t *stream, const uint8_t *data, size_t len) {
    if (!stream || !data || len < 12) return;
    
    /* Update statistics */
    stream->stats.bytes_received += len;
    stream->stats.packets_received++;
    stream->stats.last_packet_time = get_timestamp_ms();
    
    /* Analyze received data */
    if (stream->stats.packets_received <= 20) {
        analyze_received_data(data, len, (int)stream->stats.packets_received);
    }
    
    /* Call global data callback if registered */
    stream_manager_t *manager = stream->manager;
    if (manager && manager->data_callback) {
        pthread_mutex_lock(&manager->mutex);
        if (manager->data_callback) {
            manager->data_callback(stream->name, data, len, manager->callback_user_data);
        }
        pthread_mutex_unlock(&manager->mutex);
    }
    
    /* Track H.264 frame types for keyframe detection */
    if (len >= 12) {
        uint8_t payload_type = data[1] & 0x7F;
        
        if (payload_type == 96 && len > 16) {
            uint8_t nal_header = data[12];
            uint8_t nal_type = nal_header & 0x1F;
            
            if (nal_type == 5) { /* IDR frame */
            } else if (nal_type == 7) { /* SPS */
            } else if (nal_type == 8) { /* PPS */
            }
        }
    }
}

/**
 * @brief Check if SDP supports UDP transport
 */
bool sdp_supports_udp_transport(const char *sdp_content) {
    if (!sdp_content) return false;
    
    /* Look for UDP transport in SDP */
    const char *udp_transport = strstr(sdp_content, "RTP/AVP");
    if (udp_transport) {
        return true;
    }
    
    /* Also check for RTP/AVP/UDP explicitly */
    const char *udp_explicit = strstr(sdp_content, "RTP/AVP/UDP");
    if (udp_explicit) {
        return true;
    }
    
    return false;
}

/**
 * @brief Parse SDP content to extract the best video track URL
 */
int parse_sdp_tracks(const char *sdp_content, char *video_track_url, size_t url_size) {
    if (!sdp_content || !video_track_url) return -1;
    
    
    /* Find SDP start */
    const char *sdp_start = strstr(sdp_content, "v=0");
    if (!sdp_start) {
        logger_error("*** SDP ERROR *** No SDP content found (no 'v=0' line)");
        return -1;
    }
    
    /* Find all video tracks and analyze them */
    const char *search_ptr = sdp_start; /* Start from SDP beginning */
    int track_count = 0;
    int best_track = -1;
    int best_payload_type = -1;
    char best_track_url[512] = {0};
    
    
    while ((search_ptr = strstr(search_ptr, "m=video")) != NULL) {
        track_count++;
        
        /* Find the end of this track section */
        const char *next_track = strstr(search_ptr + 1, "m=");
        const char *track_end = next_track ? next_track : strstr(search_ptr, "\r\n\r\n");
        if (!track_end) track_end = search_ptr + strlen(search_ptr);
        
        /* Extract the track section */
        size_t track_section_len = track_end - search_ptr;
        char track_section[1024];
        if (track_section_len >= sizeof(track_section)) {
            track_section_len = sizeof(track_section) - 1;
        }
        strncpy(track_section, search_ptr, track_section_len);
        track_section[track_section_len] = '\0';
        
        
        /* Parse payload types from m=video line */
        const char *m_line = strstr(track_section, "m=video");
        if (m_line) {
            /* Extract payload types: m=video 0 33 36 61 96 */
            char payload_types[256];
            const char *payload_start = strchr(m_line, ' ');
            if (payload_start) {
                payload_start++; /* Skip first space */
                const char *payload_end = strchr(payload_start, '\r');
                if (!payload_end) payload_end = strchr(payload_start, '\n');
                if (payload_end) {
                    size_t payload_len = payload_end - payload_start;
                    if (payload_len < sizeof(payload_types)) {
                        strncpy(payload_types, payload_start, payload_len);
                        payload_types[payload_len] = '\0';
                        
                        /* Find the best payload type (prefer 33, 36, 61 over 96) */
                        int current_best_pt = -1;
                        if (strstr(payload_types, "33")) current_best_pt = 33;
                        else if (strstr(payload_types, "36")) current_best_pt = 36;
                        else if (strstr(payload_types, "61")) current_best_pt = 61;
                        else if (strstr(payload_types, "96")) current_best_pt = 96;
                        
                        if (current_best_pt > 0) {
                            
                            /* Check if this is better than our current best */
                            if (best_payload_type == -1 || 
                                (current_best_pt == 33 && best_payload_type != 33) ||
                                (current_best_pt == 36 && best_payload_type != 33 && best_payload_type != 36) ||
                                (current_best_pt == 61 && best_payload_type == 96)) {
                                
                                best_track = track_count;
                                best_payload_type = current_best_pt;
                                
                                /* Extract control URL for this track */
                                const char *control_line = strstr(track_section, "a=control:");
                                if (control_line) {
    const char *track_start = control_line + 10; /* Skip "a=control:" */
    const char *track_end = strchr(track_start, '\r');
    if (!track_end) track_end = strchr(track_start, '\n');
                                    if (track_end) {
                                        size_t track_len = track_end - track_start;
                                        if (track_len < sizeof(best_track_url)) {
                                            strncpy(best_track_url, track_start, track_len);
                                            best_track_url[track_len] = '\0';
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        search_ptr++; /* Move past this match to find next one */
    }
    
    
    if (track_count == 0) {
        logger_error("*** NO VIDEO TRACKS FOUND *** Camera may not be offering video streams");
        logger_error("*** SDP CONTENT PREVIEW *** %.200s", sdp_start);
        return -1;
    }
    
    if (best_track == -1) {
        logger_warn("*** NO SUITABLE VIDEO TRACK *** Found %d tracks but none were suitable", track_count);
        return -1;
    }
    
    
    /* Copy the best track URL */
    if (strlen(best_track_url) >= url_size) {
        logger_warn("Track URL too long");
        return -1;
    }
    
    /* Copy track URL with proper bounds checking */
    size_t copy_len = strlen(best_track_url);
    if (copy_len >= url_size) {
        copy_len = url_size - 1;
    }
    memcpy(video_track_url, best_track_url, copy_len);
    video_track_url[copy_len] = '\0';
    
    /* Handle different track URL formats */
    if (strstr(video_track_url, "trackID=") == video_track_url) {
        /* Format: trackID=1 - need to construct proper URL */
        return 1; /* Special return code for trackID format */
    } else if (video_track_url[0] == '/') {
        /* Format: /track1 - relative path */
        return 0;
    } else if (strstr(video_track_url, "rtsp://") == video_track_url) {
        /* Format: rtsp://... - full URL */
        return 0;
    } else {
        /* Unknown format */
        logger_warn("Unknown track URL format: %s", video_track_url);
        return -1;
    }
}

/**
 * @brief Find stream by name
 */
stream_connection_t *find_stream(stream_manager_t *manager, const char *stream_name) {
    if (!manager || !stream_name) return NULL;
    
    for (uint16_t i = 0; i < manager->stream_count; i++) {
        if (strcmp(manager->streams[i].name, stream_name) == 0) {
            return &manager->streams[i];
        }
    }
    return NULL;
}

/**
 * @brief Parse RTSP URL
 */
int parse_rtsp_url(const char *url, char *host, size_t host_size, 
                   uint16_t *port, char *path, size_t path_size) {
    if (!url || !host || !port || !path) return -1;
    
    /* Parse rtsp://host:port/path */
    if (strncmp(url, "rtsp://", 7) != 0) {
        logger_error("Invalid RTSP URL format: %s", url);
        return -1;
    }
    
    const char *start = url + 7; /* Skip "rtsp://" */
    const char *port_start = strchr(start, ':');
    const char *path_start = strchr(start, '/');
    
    if (!path_start) {
        logger_error("No path in RTSP URL: %s", url);
        return -1;
    }
    
    /* Extract host */
    size_t host_len = (port_start ? port_start : path_start) - start;
    if (host_len >= host_size) {
        logger_error("Host name too long in RTSP URL: %s", url);
        return -1;
    }
    strncpy(host, start, host_len);
    host[host_len] = '\0';
    
    /* Extract port */
    if (port_start && port_start < path_start) {
        char port_str[16];
        size_t port_len = path_start - port_start - 1;
        if (port_len >= sizeof(port_str)) {
            logger_error("Port too long in RTSP URL: %s", url);
            return -1;
        }
        strncpy(port_str, port_start + 1, port_len);
        port_str[port_len] = '\0';
        *port = (uint16_t)atoi(port_str);
    } else {
        *port = 554; /* Default RTSP port */
    }
    
    /* Extract path */
    size_t path_len = strlen(path_start);
    if (path_len >= path_size) {
        logger_error("Path too long in RTSP URL: %s", url);
        return -1;
    }
    strcpy(path, path_start);
    
    return 0;
}

/**
 * @brief Connect to RTSP server
 */
int connect_rtsp_server(const char *host, uint16_t port, int *socket_fd) {
    struct sockaddr_in server_addr;
    struct hostent *server;
    
    *socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (*socket_fd < 0) {
        logger_error("Failed to create socket: %s", strerror(errno));
        return -1;
    }
    
    server = gethostbyname(host);
    if (!server) {
        logger_error("Failed to resolve host: %s", host);
        close(*socket_fd);
        return -1;
    }
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr_list[0], server->h_length);
    
    if (connect(*socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        logger_error("Failed to connect to %s:%d: %s", host, port, strerror(errno));
        close(*socket_fd);
        return -1;
    }
    
    return 0;
}

/**
 * @brief Send RTSP request
 */
int send_rtsp_request(int socket_fd, const char *method, const char *url, 
                     const char *username, const char *password, 
                     const char *realm, const char *nonce, int cseq,
                     const char *additional_headers) {
    char request[2048];
    char auth_header[1024] = {0};
    
    /* Build authentication header if credentials provided */
    if (username && password && strlen(username) > 0 && strlen(password) > 0) {
        if (realm && nonce && strlen(realm) > 0 && strlen(nonce) > 0) {
            /* Use Digest authentication */
            char digest_response[1024];
            if (generate_digest_response(username, password, realm, nonce, method, url, digest_response) == 0) {
                strcpy(auth_header, digest_response);
            }
        } else {
            /* Fallback to Basic authentication */
            char credentials[128];
            snprintf(credentials, sizeof(credentials), "%s:%s", username, password);
            snprintf(auth_header, sizeof(auth_header), "Authorization: Basic %s\r\n", credentials);
        }
    }
    
    snprintf(request, sizeof(request),
        "%s %s RTSP/1.0\r\n"
        "CSeq: %d\r\n"
        "User-Agent: CamRelay/1.0\r\n"
        "%s"
        "%s"
        "\r\n",
        method, url, cseq, auth_header, additional_headers ? additional_headers : "");
    
    ssize_t sent = send(socket_fd, request, strlen(request), 0);
    if (sent < 0) {
        logger_error("Failed to send RTSP request: %s", strerror(errno));
        return -1;
    }
    
    return 0;
}

/**
 * @brief Process FU-A fragmentation unit packet
 */
void process_fu_a_packet(stream_connection_t *stream, const uint8_t *rtp_packet, size_t rtp_len) {
    if (rtp_len < 14) return; /* Need at least RTP header + FU-A header */
    
    uint8_t *payload = (uint8_t *)rtp_packet + 12; /* Skip RTP header */
    size_t payload_len = rtp_len - 12;
    
    if (payload_len < 2) return; /* Need FU-A header */
    
    /* Parse FU-A header */
    uint8_t fu_header = payload[0];
    uint8_t fu_indicator = payload[1];
    
    uint8_t start_bit = (fu_indicator >> 7) & 0x1;
    uint8_t end_bit = (fu_indicator >> 6) & 0x1;
    uint8_t nal_type = fu_indicator & 0x1F;
    
    /* Reconstruct NAL header */
    uint8_t nal_header = (fu_header & 0xE0) | nal_type;
    
    /* Get fragment data */
    uint8_t *fragment_data = payload + 2;
    size_t fragment_len = payload_len - 2;
    
    /* Store fragment in reassembly buffer */
    static uint8_t reassembly_buffer[65536];
    static size_t reassembly_len = 0;
    static uint8_t current_nal_type = 0;
    static bool reassembly_active = false;
    
    if (start_bit) {
        /* Start of new NAL unit */
        reassembly_len = 0;
        current_nal_type = nal_type;
        reassembly_active = true;
        
        /* Add NAL header */
        reassembly_buffer[0] = nal_header;
        reassembly_len = 1;
        
        /* Add fragment data */
        if (reassembly_len + fragment_len < sizeof(reassembly_buffer)) {
            memcpy(reassembly_buffer + reassembly_len, fragment_data, fragment_len);
            reassembly_len += fragment_len;
        }
        
        if (end_bit) {
            /* Single packet FU-A */
            reassembly_active = false;
            
            /* Send complete NAL unit */
            stream_manager_t *manager = stream->manager;
            if (manager && manager->data_callback) {
                pthread_mutex_lock(&manager->mutex);
                if (manager->data_callback) {
                    size_t total_size = 12 + reassembly_len;
                    manager->data_callback(stream->name, rtp_packet, total_size, manager->callback_user_data);
                }
                pthread_mutex_unlock(&manager->mutex);
            }
        }
    } else if (reassembly_active && nal_type == current_nal_type) {
        /* Continuation of current NAL unit */
        if (reassembly_len + fragment_len < sizeof(reassembly_buffer)) {
            memcpy(reassembly_buffer + reassembly_len, fragment_data, fragment_len);
            reassembly_len += fragment_len;
        }
        
        if (end_bit) {
            /* End of NAL unit */
            reassembly_active = false;
            
            /* Send complete NAL unit */
            stream_manager_t *manager = stream->manager;
            if (manager && manager->data_callback) {
                pthread_mutex_lock(&manager->mutex);
                if (manager->data_callback) {
                    size_t total_size = 12 + reassembly_len;
                    manager->data_callback(stream->name, rtp_packet, total_size, manager->callback_user_data);
                }
                pthread_mutex_unlock(&manager->mutex);
            }
        }
    } else {
        /* Invalid fragment - reset reassembly */
        reassembly_active = false;
        reassembly_len = 0;
    }
}
