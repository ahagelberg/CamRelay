/**
 * @file stream_utils.h
 * @brief Utility functions for stream management
 */

#ifndef STREAM_UTILS_H
#define STREAM_UTILS_H

#include <stdint.h>
#include <stddef.h>
#include "stream_manager.h"

/**
 * @brief Get current timestamp in milliseconds
 * @return Current timestamp in milliseconds
 */
uint64_t get_timestamp_ms(void);

/**
 * @brief Get stream state string
 * @param state Stream state
 * @return String representation of state
 */
const char *stream_manager_state_to_string(stream_state_t state);

/**
 * @brief Convert bytes to hex string
 * @param bytes Input bytes
 * @param len Number of bytes
 * @param hex Output hex string (must be at least len*2+1 bytes)
 */
void bytes_to_hex(const unsigned char *bytes, size_t len, char *hex);

/**
 * @brief Generate MD5 hash using EVP interface
 * @param input Input string
 * @param output Output hex string (must be at least 33 bytes)
 */
void md5_hash(const char *input, char *output);

/**
 * @brief Parse WWW-Authenticate header for Digest authentication
 * @param auth_header Authentication header string
 * @param realm Output realm string
 * @param nonce Output nonce string
 * @return 0 on success, -1 on error
 */
int parse_digest_challenge(const char *auth_header, char *realm, char *nonce);

/**
 * @brief Generate Digest authentication response
 * @param username Username for authentication
 * @param password Password for authentication
 * @param realm Authentication realm
 * @param nonce Authentication nonce
 * @param method HTTP method (e.g., "DESCRIBE")
 * @param uri Request URI
 * @param response Output response string
 * @return 0 on success, -1 on error
 */
int generate_digest_response(const char *username, const char *password, 
                           const char *realm, const char *nonce, 
                           const char *method, const char *uri, 
                           char *response);

/**
 * @brief Create UDP sockets for RTP/RTCP
 * @param conn Stream connection structure
 * @return 0 on success, -1 on error
 */
int create_udp_sockets(stream_connection_t *conn);

/**
 * @brief Close UDP sockets
 * @param conn Stream connection structure
 */
void close_udp_sockets(stream_connection_t *conn);

/**
 * @brief Analyze received data to determine if it's video, audio, or control data
 * @param data Received data buffer
 * @param len Length of data
 * @param packet_num Packet number for logging
 */
void analyze_received_data(const uint8_t *data, size_t len, int packet_num);

/**
 * @brief Process RTP packet from UDP transport
 * @param stream Stream connection structure
 * @param data RTP packet data
 * @param len Length of packet data
 */
void process_rtp_packet(stream_connection_t *stream, const uint8_t *data, size_t len);

/**
 * @brief Check if SDP supports UDP transport
 * @param sdp_content SDP content string
 * @return true if UDP transport is supported, false otherwise
 */
bool sdp_supports_udp_transport(const char *sdp_content);

/**
 * @brief Parse SDP content to extract the best video track URL
 * @param sdp_content SDP content string
 * @param video_track_url Output buffer for track URL
 * @param url_size Size of output buffer
 * @return 0 on success, 1 for trackID format, -1 on error
 */
int parse_sdp_tracks(const char *sdp_content, char *video_track_url, size_t url_size);

/**
 * @brief Find stream by name
 * @param manager Stream manager
 * @param stream_name Name of stream to find
 * @return Pointer to stream connection or NULL if not found
 */
stream_connection_t *find_stream(stream_manager_t *manager, const char *stream_name);

/**
 * @brief Parse RTSP URL
 * @param url RTSP URL to parse
 * @param host Output buffer for host name
 * @param host_size Size of host buffer
 * @param port Output port number
 * @param path Output buffer for path
 * @param path_size Size of path buffer
 * @return 0 on success, -1 on error
 */
int parse_rtsp_url(const char *url, char *host, size_t host_size, 
                   uint16_t *port, char *path, size_t path_size);

/**
 * @brief Connect to RTSP server
 * @param host Server hostname
 * @param port Server port
 * @param socket_fd Output socket file descriptor
 * @return 0 on success, -1 on error
 */
int connect_rtsp_server(const char *host, uint16_t port, int *socket_fd);

/**
 * @brief Send RTSP request
 * @param socket_fd Socket file descriptor
 * @param method RTSP method (OPTIONS, DESCRIBE, SETUP, PLAY, etc.)
 * @param url Request URL
 * @param username Username for authentication
 * @param password Password for authentication
 * @param realm Digest authentication realm
 * @param nonce Digest authentication nonce
 * @param cseq CSeq number
 * @param additional_headers Additional headers to include
 * @return 0 on success, -1 on error
 */
int send_rtsp_request(int socket_fd, const char *method, const char *url, 
                     const char *username, const char *password, 
                     const char *realm, const char *nonce, int cseq,
                     const char *additional_headers);

/**
 * @brief Process FU-A fragmentation unit packet
 * @param stream Stream connection
 * @param rtp_packet RTP packet data
 * @param rtp_len RTP packet length
 */
void process_fu_a_packet(stream_connection_t *stream, const uint8_t *rtp_packet, size_t rtp_len);

#endif /* STREAM_UTILS_H */
