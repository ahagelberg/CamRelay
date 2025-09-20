/**
 * @file stream_manager.c
 * @brief Stream manager implementation for RTSP source connections
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include "stream/stream_manager.h"
#include "stream/stream_utils.h"
#include "logging/logger.h"
#include "error/error_handler.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <errno.h>
#include <openssl/evp.h>
#include <sys/select.h>


/**
 * @brief Process FU-A fragmentation unit packet for reassembly
 */
















/**
 * @brief Stream processing thread
 */
static void *stream_thread(void *arg) {
    stream_connection_t *stream = (stream_connection_t *)arg;
    char host[256];
    uint16_t port;
    char path[256];
    int socket_fd = -1;
    char realm[256] = {0};
    char nonce[256] = {0};
    int cseq = 1;
    
    
    /* Parse RTSP URL */
    if (parse_rtsp_url(stream->rtsp_url, host, sizeof(host), &port, path, sizeof(path)) != 0) {
        logger_error("Failed to parse RTSP URL for stream '%s': %s", stream->name, stream->rtsp_url);
        stream->state = STREAM_STATE_ERROR;
        return NULL;
    }
    
    /* Connect to RTSP server */
    if (connect_rtsp_server(host, port, &socket_fd) != 0) {
        logger_error("Failed to connect to RTSP server for stream '%s'", stream->name);
        stream->state = STREAM_STATE_ERROR;
        return NULL;
    }
    
    stream->socket_fd = socket_fd;
    stream->state = STREAM_STATE_CONNECTED;
    stream->stats.connection_time = get_timestamp_ms();
    
    /* Send OPTIONS request */
    if (send_rtsp_request(socket_fd, "OPTIONS", stream->rtsp_url, 
                         stream->username, stream->password, NULL, NULL, cseq++, NULL) != 0) {
        logger_error("Failed to send OPTIONS request for stream '%s'", stream->name);
        stream->state = STREAM_STATE_ERROR;
        close(socket_fd);
        return NULL;
    }
    
    /* Read OPTIONS response */
    char response[1024];
    ssize_t bytes_read = recv(socket_fd, response, sizeof(response) - 1, 0);
    if (bytes_read <= 0) {
        logger_error("Failed to read OPTIONS response from '%s': %s", stream->name, strerror(errno));
        stream->state = STREAM_STATE_ERROR;
        close(socket_fd);
        return NULL;
    }
    response[bytes_read] = '\0';
    
    /* Send DESCRIBE request */
    if (send_rtsp_request(socket_fd, "DESCRIBE", stream->rtsp_url, 
                         stream->username, stream->password, NULL, NULL, cseq++, NULL) != 0) {
        logger_error("Failed to send DESCRIBE request for stream '%s'", stream->name);
        stream->state = STREAM_STATE_ERROR;
        close(socket_fd);
        return NULL;
    }
    
    /* Read DESCRIBE response */
    char describe_response[2048];
    ssize_t desc_bytes = recv(socket_fd, describe_response, sizeof(describe_response) - 1, 0);
    if (desc_bytes <= 0) {
        logger_error("Failed to read DESCRIBE response from '%s': %s", stream->name, strerror(errno));
        stream->state = STREAM_STATE_ERROR;
        close(socket_fd);
        return NULL;
    }
    describe_response[desc_bytes] = '\0';
    
    /* Check if authentication is required */
    if (strstr(describe_response, "401 Unauthorized") != NULL) {
        logger_info("Stream '%s' requires authentication", stream->name);
        
        /* Parse WWW-Authenticate header for Digest challenge */
        char *auth_line = strstr(describe_response, "WWW-Authenticate:");
        if (auth_line) {
            char *auth_start = strchr(auth_line, ':');
            if (auth_start) {
                auth_start++; /* Skip the ':' */
                char *auth_end = strstr(auth_start, "\r\n");
                if (!auth_end) auth_end = strstr(auth_start, "\n");
                if (auth_end) {
                    *auth_end = '\0';
                    if (parse_digest_challenge(auth_start, realm, nonce) == 0) {
                        
                        /* Retry DESCRIBE with authentication */
                        if (send_rtsp_request(socket_fd, "DESCRIBE", stream->rtsp_url, 
                                             stream->username, stream->password, realm, nonce, cseq++, NULL) != 0) {
                            logger_error("Failed to send authenticated DESCRIBE request for stream '%s'", stream->name);
                            stream->state = STREAM_STATE_ERROR;
                            close(socket_fd);
                            return NULL;
                        }
                        
                        /* Read authenticated DESCRIBE response */
                        desc_bytes = recv(socket_fd, describe_response, sizeof(describe_response) - 1, 0);
                        if (desc_bytes > 0) {
                            describe_response[desc_bytes] = '\0';
                            
                            if (strstr(describe_response, "200 OK") == NULL) {
                                logger_error("Authenticated DESCRIBE failed for stream '%s': %.200s", stream->name, describe_response);
                                stream->state = STREAM_STATE_ERROR;
                                close(socket_fd);
                                return NULL;
                            }
                            
                            /* Log full SDP content for debugging */
                            char *sdp_start = strstr(describe_response, "v=0");
                            if (sdp_start) {
                                
                                /* Count total m=video lines in SDP */
                                int total_video_tracks = 0;
                                char *search_ptr = sdp_start;
                                while ((search_ptr = strstr(search_ptr, "m=video")) != NULL) {
                                    total_video_tracks++;
                                    search_ptr++;
                                }
                                
                                /* Analyze what media types are offered */
                                if (strstr(sdp_start, "m=video")) {
                                } else {
                                    logger_warn("*** SDP PROBLEM *** No video track found in SDP!");
                                }
                                
                                if (strstr(sdp_start, "m=audio")) {
                                }
                                
                                /* Check for H.264 payload type */
                                if (strstr(sdp_start, "rtpmap:96 H264")) {
                                } else {
                                    logger_warn("*** SDP PROBLEM *** No H.264 rtpmap found!");
                                }
                                
                                /* Count video tracks in SDP */
                                int video_track_count = 0;
                                char *track_ptr = sdp_start;
                                while ((track_ptr = strstr(track_ptr, "m=video")) != NULL) {
                                    video_track_count++;
                                    track_ptr++;
                                }
                                
                                if (video_track_count > 1) {
                                    logger_warn("*** MULTIPLE VIDEO TRACKS *** Found %d video tracks in SDP", video_track_count);
                                    logger_warn("*** We might be using the wrong track! ***");
                                }
                                
                                /* Detailed SDP track analysis */
                                track_ptr = strstr(sdp_start, "m=video");
                                if (track_ptr) {
                                    /* char *next_track = strstr(track_ptr + 1, "m="); */
                                    /* size_t track_len = next_track ? (size_t)(next_track - track_ptr) : strlen(track_ptr); */
                                    
                                    
                                    /* Look for profile-level-id which indicates video quality/type */
                                    if (strstr(track_ptr, "profile-level-id")) {
                                    } else {
                                        logger_error("*** SDP PROBLEM *** No profile-level-id - might be audio-only or preview!");
                                    }
                                    
                                    /* Check for sprop-parameter-sets */
                                    if (strstr(track_ptr, "sprop-parameter-sets")) {
                                        
                                        /* Extract and decode the parameter sets */
                                        char *sprop_start = strstr(track_ptr, "sprop-parameter-sets=");
                                        if (sprop_start) {
                                            sprop_start += strlen("sprop-parameter-sets=");
                                            char *sprop_end = strstr(sprop_start, ";");
                                            if (!sprop_end) sprop_end = strstr(sprop_start, "\r");
                                            if (!sprop_end) sprop_end = strstr(sprop_start, "\n");
                                            
                                            if (sprop_end) {
                                                size_t sprop_len = sprop_end - sprop_start;
                                                char sprop_data[256];
                                                if (sprop_len < sizeof(sprop_data)) {
                                                    memcpy(sprop_data, sprop_start, sprop_len);
                                                    sprop_data[sprop_len] = '\0';
                                                    
                                                    
                                                    /* Parse comma-separated parameter sets */
                                                    char *pps_ptr = strchr(sprop_data, ',');
                                                    
                                                    if (pps_ptr) {
                                                        *pps_ptr = '\0';
                                                        pps_ptr++;
                                                        
                                                    }
                                                }
                                            }
                                        }
                                    } else {
                                        logger_warn("*** SDP *** No sprop-parameter-sets - inline parameter delivery expected");
                                    }
                                } else {
                                    logger_error("*** CRITICAL *** No video track in SDP after DESCRIBE!");
                                }
                            }
                        } else {
                            logger_error("Failed to read authenticated DESCRIBE response from '%s'", stream->name);
                            stream->state = STREAM_STATE_ERROR;
                            close(socket_fd);
                            return NULL;
                        }
                    } else {
                        logger_error("Failed to parse Digest challenge for stream '%s'", stream->name);
                        stream->state = STREAM_STATE_ERROR;
                        close(socket_fd);
                        return NULL;
                    }
                }
            }
        } else {
            logger_error("No WWW-Authenticate header found in 401 response for stream '%s'", stream->name);
            stream->state = STREAM_STATE_ERROR;
            close(socket_fd);
            return NULL;
        }
    } else if (strstr(describe_response, "200 OK") == NULL) {
        logger_error("DESCRIBE request failed for stream '%s': %.200s", stream->name, describe_response);
        stream->state = STREAM_STATE_ERROR;
        close(socket_fd);
        return NULL;
    }
    
    /* Check if SDP supports UDP transport */
    stream->use_udp_transport = sdp_supports_udp_transport(describe_response);
    
    /* Force UDP transport for cameras that work with VLC but don't advertise it in SDP */
    if (!stream->use_udp_transport) {
        stream->use_udp_transport = true;
    }
    
    
    /* Parse SDP content to extract track URLs */
    char video_track_url[512] = {0};
    int parse_result = parse_sdp_tracks(describe_response, video_track_url, sizeof(video_track_url));
    
    /* Build full track URL based on parsing result */
    char setup_url[1024];
    if (parse_result == 1) {
        /* trackID format - construct track-specific URL */
        char *content_base = strstr(describe_response, "Content-Base:");
        if (content_base) {
            char *base_start = strchr(content_base, ':');
            if (base_start) {
                base_start++; /* Skip the ':' */
                while (*base_start == ' ' || *base_start == '\t') base_start++; /* Skip whitespace */
                char *base_end = strchr(base_start, '\r');
                if (!base_end) base_end = strchr(base_start, '\n');
                if (base_end) {
                    size_t base_len = base_end - base_start;
                    char base_url[512];
                    if (base_len < sizeof(base_url)) {
                        strncpy(base_url, base_start, base_len);
                        base_url[base_len] = '\0';
                        
                        /* Remove trailing slash if present */
                        if (base_url[strlen(base_url) - 1] == '/') {
                            base_url[strlen(base_url) - 1] = '\0';
                        }
                        
                        /* Add track ID as path parameter */
                        int setup_len = snprintf(setup_url, sizeof(setup_url), "%s/%s", base_url, video_track_url);
                        if (setup_len >= (int)sizeof(setup_url)) {
                            logger_error("Setup URL too long");
                            stream->state = STREAM_STATE_ERROR;
                            close(socket_fd);
                            return NULL;
                        }
                    } else {
                        logger_warn("Content-Base URL too long, using original URL");
                        strncpy(setup_url, stream->rtsp_url, sizeof(setup_url) - 1);
                        setup_url[sizeof(setup_url) - 1] = '\0';
                    }
                } else {
                    logger_warn("Invalid Content-Base format, using original URL");
                    strncpy(setup_url, stream->rtsp_url, sizeof(setup_url) - 1);
                    setup_url[sizeof(setup_url) - 1] = '\0';
                }
            } else {
                logger_warn("No Content-Base value found, using original URL");
                strncpy(setup_url, stream->rtsp_url, sizeof(setup_url) - 1);
                setup_url[sizeof(setup_url) - 1] = '\0';
            }
        } else {
            strncpy(setup_url, stream->rtsp_url, sizeof(setup_url) - 1);
            setup_url[sizeof(setup_url) - 1] = '\0';
        }
    } else if (parse_result == 0) {
        /* Normal track URL format */
        if (video_track_url[0] == '/') {
            /* Relative path - build full URL */
            char base_url[512];
            int base_len = snprintf(base_url, sizeof(base_url), "rtsp://%s:%d", host, port);
            if (base_len >= (int)sizeof(base_url)) {
                logger_error("Base URL too long for host: %s", host);
                stream->state = STREAM_STATE_ERROR;
                close(socket_fd);
                return NULL;
            }
            int setup_len = snprintf(setup_url, sizeof(setup_url), "%s%s", base_url, video_track_url);
            if (setup_len >= (int)sizeof(setup_url)) {
                logger_error("Setup URL too long");
                stream->state = STREAM_STATE_ERROR;
                close(socket_fd);
                return NULL;
            }
        } else if (strstr(video_track_url, "rtsp://") == video_track_url) {
            /* Already a full URL */
            strncpy(setup_url, video_track_url, sizeof(setup_url) - 1);
            setup_url[sizeof(setup_url) - 1] = '\0';
        } else {
            /* Use base URL */
            strncpy(setup_url, stream->rtsp_url, sizeof(setup_url) - 1);
            setup_url[sizeof(setup_url) - 1] = '\0';
        }
    } else {
        /* Parse failed, use base URL */
        logger_warn("Failed to parse SDP tracks, using base URL for SETUP");
        strncpy(setup_url, stream->rtsp_url, sizeof(setup_url) - 1);
        setup_url[sizeof(setup_url) - 1] = '\0';
    }
    
    
    /* Prepare Transport header for SETUP based on SDP analysis */
    char transport_header[256];
    if (stream->use_udp_transport) {
        /* Create UDP sockets for RTP/RTCP */
        if (create_udp_sockets(stream) != 0) {
            logger_error("Failed to create UDP sockets for stream '%s'", stream->name);
            stream->state = STREAM_STATE_ERROR;
            close(socket_fd);
            return NULL;
        }
        
        /* Use UDP transport */
        snprintf(transport_header, sizeof(transport_header),
            "Transport: RTP/AVP;unicast;client_port=%d-%d\r\n",
            stream->client_port, stream->client_port + 1);
        
    } else {
        /* Use TCP interleaved transport */
    snprintf(transport_header, sizeof(transport_header),
        "Transport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n");
    
    }
    
    /* Send SETUP request with Transport header */
    if (send_rtsp_request(socket_fd, "SETUP", setup_url, 
                         stream->username, stream->password, realm, nonce, cseq++, transport_header) != 0) {
        logger_error("Failed to send SETUP request for stream '%s'", stream->name);
        stream->state = STREAM_STATE_ERROR;
        close(socket_fd);
        return NULL;
    }
    
    /* Prepare buffers for RTP data processing */
    uint8_t buffer[65536]; /* Much larger buffer for RTP data and reassembly */
    uint8_t incomplete_buffer[65536]; /* Buffer for incomplete frames */
    size_t incomplete_bytes = 0;
    
    /* Read SETUP response and extract session ID */
    char setup_response[4096]; /* Increased buffer size */
    char original_response[4096]; /* Backup of original response for debugging */
    ssize_t setup_bytes = 0;
    ssize_t total_bytes = 0;
    
    /* Read complete RTSP response (may require multiple recv calls) */
    while (total_bytes < (ssize_t)(sizeof(setup_response) - 1)) {
        ssize_t bytes_read = recv(socket_fd, setup_response + total_bytes, 
                                 sizeof(setup_response) - 1 - total_bytes, 0);
        if (bytes_read <= 0) {
        logger_error("Failed to read SETUP response from '%s': %s", stream->name, strerror(errno));
        stream->state = STREAM_STATE_ERROR;
        close(socket_fd);
        return NULL;
    }
        total_bytes += bytes_read;
        setup_response[total_bytes] = '\0';
        
        /* Check if we have a complete RTSP response (ends with \r\n\r\n) */
        if (total_bytes >= 4 && 
            setup_response[total_bytes-4] == '\r' && 
            setup_response[total_bytes-3] == '\n' && 
            setup_response[total_bytes-2] == '\r' && 
            setup_response[total_bytes-1] == '\n') {
            break;
        }
        
    }
    setup_bytes = total_bytes;
    
    /* Check if this is RTSP response or RTP data */
    if (setup_response[0] == '$') {
        /* Camera started sending RTP data immediately after SETUP - this is normal! */
        
        /* Put the RTP data back into our buffer for processing */
        memcpy(buffer, setup_response, setup_bytes);
        incomplete_bytes = setup_bytes;
        
        /* Assume TCP interleaved was accepted since we got RTP data */
        
        /* Analyze the first RTP packet to see what we're getting */
        if (setup_bytes >= 4) {
            uint16_t frame_length = (setup_response[2] << 8) | setup_response[3];
            
            if (frame_length < 100) {
                logger_warn("*** SUSPICIOUS *** First RTP packet is very small: %d bytes", frame_length);
                logger_warn("*** This might be control data, not video frames ***");
            }
        }
    } else {
        /* This is an RTSP response */
        
        /* Save the original response for debugging */
        memcpy(original_response, setup_response, setup_bytes);
        original_response[setup_bytes] = '\0';
        
        /* Check if UDP transport was rejected and fall back to TCP */
        if (stream->use_udp_transport && strstr(setup_response, "461 Unsupported Transport") != NULL) {
            logger_warn("*** UDP TRANSPORT REJECTED *** Camera doesn't support UDP, falling back to TCP");
            close_udp_sockets(stream);
            stream->use_udp_transport = false;
            
            /* Retry SETUP with TCP interleaved */
            snprintf(transport_header, sizeof(transport_header),
                "Transport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n");
            
            if (send_rtsp_request(socket_fd, "SETUP", setup_url, 
                                 stream->username, stream->password, realm, nonce, cseq++, transport_header) != 0) {
                logger_error("Failed to send TCP SETUP request for stream '%s'", stream->name);
                stream->state = STREAM_STATE_ERROR;
                close(socket_fd);
                return NULL;
            }
            
            /* Read TCP SETUP response */
            setup_bytes = recv(socket_fd, setup_response, sizeof(setup_response) - 1, 0);
            if (setup_bytes <= 0) {
                logger_error("Failed to read TCP SETUP response from '%s': %s", stream->name, strerror(errno));
                stream->state = STREAM_STATE_ERROR;
                close(socket_fd);
                return NULL;
            }
            setup_response[setup_bytes] = '\0';
        } else {
            /* UDP transport was accepted - check if response was modified */
            if (memcmp(original_response, setup_response, setup_bytes) != 0) {
                logger_error("*** RESPONSE MODIFIED *** Original response was changed!");
                logger_error("*** ORIGINAL RESPONSE ***:\n%.400s", original_response);
                logger_error("*** CURRENT RESPONSE ***:\n%.400s", setup_response);
            } else {
            }
        }
        
        /* Analyze what transport the camera accepted */
        if (strstr(setup_response, "Transport:") || strstr(setup_response, "transport:")) {
            if (strstr(setup_response, "interleaved")) {
                stream->use_udp_transport = false;
            } else if (strstr(setup_response, "client_port") && strstr(setup_response, "server_port")) {
                stream->use_udp_transport = true;
                
                /* Parse server ports from response */
                char *server_port_start = strstr(setup_response, "server_port=");
                if (server_port_start) {
                    server_port_start += 12; /* Skip "server_port=" */
                    char *server_port_end = strchr(server_port_start, ';');
                    if (!server_port_end) server_port_end = strchr(server_port_start, '\r');
                    if (!server_port_end) server_port_end = strchr(server_port_start, '\n');
                    if (server_port_end) {
                        *server_port_end = '\0';
                        int rtp_port, rtcp_port;
                        if (sscanf(server_port_start, "%d-%d", &rtp_port, &rtcp_port) == 2) {
                            stream->server_rtp_addr.sin_family = AF_INET;
                            stream->server_rtp_addr.sin_port = htons(rtp_port);
                            stream->server_rtp_addr.sin_addr.s_addr = inet_addr(host);
                            
                            stream->server_rtcp_addr.sin_family = AF_INET;
                            stream->server_rtcp_addr.sin_port = htons(rtcp_port);
                            stream->server_rtcp_addr.sin_addr.s_addr = inet_addr(host);
                            
                        }
                    }
                }
            } else if (strstr(setup_response, "client_port")) {
                logger_error("*** TRANSPORT MISMATCH *** Camera wants UDP but we requested TCP!");
                logger_error("*** This might explain P-frame-only stream - degraded fallback mode ***");
                logger_error("*** VLC probably uses UDP transport for full video ***");
                logger_error("*** SOLUTION: Need to implement UDP transport support ***");
            } else {
                logger_warn("*** UNKNOWN TRANSPORT *** Camera response unclear");
            }
        } else {
            logger_warn("*** NO TRANSPORT INFO *** Camera didn't specify transport in SETUP response");
        }
        
        /* Check for any error conditions in the response */
        if (strstr(setup_response, "406 Not Acceptable")) {
            logger_error("*** SETUP ERROR *** Camera rejected our transport request");
            logger_error("*** This might be why we're not getting proper video data ***");
        } else if (strstr(setup_response, "461 Unsupported Transport")) {
            logger_error("*** SETUP ERROR *** Camera doesn't support our transport method");
            logger_error("*** Need to try different transport options ***");
        }
    }
    
    /* Only check for 200 OK if we got an RTSP response, not RTP data */
    if (setup_response[0] != '$' && strstr(setup_response, "200 OK") == NULL) {
        logger_error("SETUP request failed for stream '%s': %.400s", stream->name, setup_response);
        stream->state = STREAM_STATE_ERROR;
        close(socket_fd);
        return NULL;
    }
    
    /* Extract session ID from SETUP response (only if we got RTSP response) */
    
    
    if (setup_response[0] != '$') {
        char *session_line = strstr(setup_response, "Session:");
        if (session_line) {
        } else {
            /* Try with original response if current response doesn't have Session */
            char *original_session_line = strstr(original_response, "Session:");
            if (original_session_line) {
                /* Use original response for session extraction */
                memcpy(setup_response, original_response, setup_bytes);
                setup_response[setup_bytes] = '\0';
                session_line = strstr(setup_response, "Session:");
            }
        }
        
        if (session_line) {
            char *session_start = strchr(session_line, ':');
            if (session_start) {
                session_start++; /* Skip the ':' */
                char *session_end = strchr(session_start, '\r');
                if (!session_end) session_end = strchr(session_start, '\n');
                if (session_end) {
                    size_t session_len = session_end - session_start;
                    if (session_len < sizeof(stream->session_id)) {
                        strncpy(stream->session_id, session_start, session_len);
                        stream->session_id[session_len] = '\0';
                        
                        /* Trim whitespace from session ID */
                        char *trim_start = stream->session_id;
                        while (*trim_start == ' ' || *trim_start == '\t') trim_start++;
                        char *trim_end = stream->session_id + strlen(stream->session_id) - 1;
                        while (trim_end > trim_start && (*trim_end == ' ' || *trim_end == '\t' || *trim_end == '\r' || *trim_end == '\n')) {
                            *trim_end = '\0';
                            trim_end--;
                        }
                        if (trim_start != stream->session_id) {
                            memmove(stream->session_id, trim_start, strlen(trim_start) + 1);
                        }
                        
                    }
                }
            }
        } else {
            logger_error("*** DEBUGGING SESSION EXTRACTION *** 'Session:' not found in SETUP response!");
            logger_error("*** SETUP RESPONSE CONTENT ***: %.200s", setup_response);
        }
    } else {
        /* No session ID available when camera sends RTP immediately */
    }
    
    /* Prepare Session header for PLAY if we have one */
    char session_header[256] = {0};
    if (strlen(stream->session_id) > 0) {
        snprintf(session_header, sizeof(session_header),
            "Session: %s\r\n"
            "Range: npt=0.000-\r\n", stream->session_id);
    } else {
        logger_error("*** PLAY REQUEST ERROR *** No session ID available!");
        logger_error("*** This will cause 'Session Not Found' error ***");
    }
    
    /* Send PLAY request with session ID */
    if (send_rtsp_request(socket_fd, "PLAY", setup_url, 
                         stream->username, stream->password, realm, nonce, cseq++, session_header) != 0) {
        logger_error("Failed to send PLAY request for stream '%s'", stream->name);
        stream->state = STREAM_STATE_ERROR;
        close(socket_fd);
        return NULL;
    }
    
    /* Read PLAY response - but camera might start sending RTP data immediately */
    char play_response[1024];
    ssize_t play_bytes = recv(socket_fd, play_response, sizeof(play_response) - 1, 0);
    if (play_bytes <= 0) {
        logger_error("Failed to read PLAY response from '%s': %s", stream->name, strerror(errno));
        stream->state = STREAM_STATE_ERROR;
        close(socket_fd);
        return NULL;
    }
    play_response[play_bytes] = '\0';
    
    /* Check if this is RTSP response or RTP data */
    if (play_response[0] == '$') {
        /* Camera started sending RTP data immediately - PLAY was successful */
        
        /* Put the RTP data back into our buffer for processing */
        memcpy(buffer, play_response, play_bytes);
        incomplete_bytes = play_bytes;
    } else {
        /* This is an RTSP response */
        
        if (strstr(play_response, "200 OK") == NULL) {
            logger_error("PLAY request failed for stream '%s': %.200s", stream->name, play_response);
            stream->state = STREAM_STATE_ERROR;
            close(socket_fd);
            return NULL;
        }
    }
    stream->state = STREAM_STATE_STREAMING;
    
    /* Immediately request keyframes using multiple methods - this is what VLC does */
    
    /* Method 1: SET_PARAMETER with picture_fast_update */
    char keyframe_request1[512];
    snprintf(keyframe_request1, sizeof(keyframe_request1),
        "SET_PARAMETER %s RTSP/1.0\r\n"
        "CSeq: %d\r\n"
        "Session: %s\r\n"
        "Content-Type: text/parameters\r\n"
        "Content-Length: 20\r\n"
        "\r\n"
        "picture_fast_update\r\n",
        stream->rtsp_url, cseq++, stream->session_id);
    
    send(socket_fd, keyframe_request1, strlen(keyframe_request1), 0);
    
    /* Method 2: SET_PARAMETER with different parameter */
    char keyframe_request2[512];
    snprintf(keyframe_request2, sizeof(keyframe_request2),
        "SET_PARAMETER %s RTSP/1.0\r\n"
        "CSeq: %d\r\n"
        "Session: %s\r\n"
        "Content-Type: text/parameters\r\n"
        "Content-Length: 15\r\n"
        "\r\n"
        "keyframe_request\r\n",
        stream->rtsp_url, cseq++, stream->session_id);
    
    send(socket_fd, keyframe_request2, strlen(keyframe_request2), 0);
    
    /* Method 3: GET_PARAMETER to trigger keyframe */
    char keyframe_request3[512];
    snprintf(keyframe_request3, sizeof(keyframe_request3),
        "GET_PARAMETER %s RTSP/1.0\r\n"
        "CSeq: %d\r\n"
        "Session: %s\r\n"
        "Content-Type: text/parameters\r\n"
        "Content-Length: 20\r\n"
        "\r\n"
        "picture_fast_update\r\n",
        stream->rtsp_url, cseq++, stream->session_id);
    
    send(socket_fd, keyframe_request3, strlen(keyframe_request3), 0);
    
    /* Method 4: RTCP PLI packet */
    uint8_t pli_packet[] = {
        '$', 1, 0, 12,
        0x81, 0xCE, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    send(socket_fd, pli_packet, sizeof(pli_packet), 0);
    
    /* Method 5: Additional keyframe request with different parameter */
    char keyframe_request5[512];
    snprintf(keyframe_request5, sizeof(keyframe_request5),
        "SET_PARAMETER %s RTSP/1.0\r\n"
        "CSeq: %d\r\n"
        "Session: %s\r\n"
        "Content-Type: text/parameters\r\n"
        "Content-Length: 12\r\n"
        "\r\n"
        "force_idr\r\n",
        stream->rtsp_url, cseq++, stream->session_id);
    
    send(socket_fd, keyframe_request5, strlen(keyframe_request5), 0);
    
    /* Method 6: Try to trigger keyframe with different approach */
    char keyframe_request6[512];
    snprintf(keyframe_request6, sizeof(keyframe_request6),
        "SET_PARAMETER %s RTSP/1.0\r\n"
        "CSeq: %d\r\n"
        "Session: %s\r\n"
        "Content-Type: text/parameters\r\n"
        "Content-Length: 8\r\n"
        "\r\n"
        "idr\r\n",
        stream->rtsp_url, cseq++, stream->session_id);
    
    send(socket_fd, keyframe_request6, strlen(keyframe_request6), 0);
    
    /* Read any responses */
    char keyframe_response[1024];
    ssize_t keyframe_bytes = recv(socket_fd, keyframe_response, sizeof(keyframe_response) - 1, 0);
    if (keyframe_bytes > 0) {
        keyframe_response[keyframe_bytes] = '\0';
    } else {
        logger_warn("*** NO RESPONSE TO KEYFRAME REQUESTS *** Camera may not support these methods");
    }
    
    /* Initialize timeout tracking */
    uint64_t last_data_time = get_timestamp_ms();
    const uint64_t STREAM_TIMEOUT_MS = 30000; /* 30 seconds timeout */
    
    /* Initialize data quality tracking */
    uint32_t consecutive_corrupted_packets = 0;
    const uint32_t MAX_CORRUPTED_PACKETS = 10;
    
    while (!stream->should_stop && stream->state == STREAM_STATE_STREAMING) {
        /* Check for stream timeout */
        uint64_t current_time = get_timestamp_ms();
        if (current_time - last_data_time > STREAM_TIMEOUT_MS) {
            logger_warn("Stream '%s' timeout - no data received for %lu ms", 
                       stream->name, current_time - last_data_time);
            logger_info("Stream '%s' disconnecting due to timeout", stream->name);
            break;
        }
        
        if (stream->use_udp_transport) {
            /* UDP transport - read from RTP socket */
            struct sockaddr_in from_addr;
            socklen_t from_len = sizeof(from_addr);
            ssize_t bytes_read = recvfrom(stream->rtp_socket, buffer, sizeof(buffer), MSG_DONTWAIT,
                                        (struct sockaddr*)&from_addr, &from_len);
            if (bytes_read > 0) {
                /* Process UDP RTP packet */
                last_data_time = get_timestamp_ms(); /* Update timeout */
                process_rtp_packet(stream, buffer, bytes_read);
            } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                logger_error("UDP receive error for stream '%s': %s", stream->name, strerror(errno));
                break;
            }
        } else {
            /* TCP interleaved transport - read from RTSP socket */
            ssize_t bytes_read = recv(socket_fd, buffer + incomplete_bytes, 
                                     sizeof(buffer) - incomplete_bytes, MSG_DONTWAIT);
            if (bytes_read > 0) {
                /* Update timeout when data is received */
                last_data_time = get_timestamp_ms();
                
                /* Check for corrupted data - if we receive binary data when expecting RTSP */
                if (bytes_read > 0 && buffer[0] < 32) {
                    consecutive_corrupted_packets++;
                    if (consecutive_corrupted_packets >= MAX_CORRUPTED_PACKETS) {
                        logger_error("Stream '%s' receiving corrupted data (%d consecutive corrupted packets), disconnecting", 
                                   stream->name, consecutive_corrupted_packets);
                        break;
                    }
                    /* Skip this corrupted data */
                    continue;
                } else {
                    consecutive_corrupted_packets = 0; /* Reset counter on good data */
                }
                
                /* Add new data to any incomplete data from previous reads */
                ssize_t total_bytes = bytes_read + incomplete_bytes;
                incomplete_bytes = 0; /* Reset for this processing cycle */
            
            /* Check if this is interleaved data (starts with $) or raw RTP */
            if (buffer[0] == '$' && total_bytes >= 4) {
                /* Interleaved format: $<channel><length><data> */
                uint8_t *data_ptr = buffer;
                ssize_t remaining = total_bytes;
                
                while (remaining >= 4) {
                    if (data_ptr[0] == '$') {
                        uint8_t channel = data_ptr[1];
                        uint16_t frame_length = (data_ptr[2] << 8) | data_ptr[3];
                        
                        if (remaining >= (ssize_t)(4 + frame_length)) {
                            if (channel == 0) { /* RTP data channel */
                                /* Update statistics */
                                stream->stats.bytes_received += frame_length;
                                stream->stats.packets_received++;
                                stream->stats.last_packet_time = get_timestamp_ms();
                                
                                /* Process RTP packet - handle FU-A reassembly if needed */
                                uint8_t *rtp_payload = data_ptr + 4;
                                size_t rtp_payload_len = frame_length;
                                
                                /* Check if this is an FU-A packet that needs reassembly */
                                if (rtp_payload_len > 12) {
                                    uint8_t *payload = rtp_payload + 12; /* Skip RTP header */
                                    size_t payload_len = rtp_payload_len - 12;
                                    
                                    if (payload_len > 0) {
                                        uint8_t nal_header = payload[0];
                                        uint8_t nal_type = nal_header & 0x1F;
                                        
                                        if (nal_type == 28) { /* FU-A fragmentation unit */
                                            /* Process FU-A packet for reassembly */
                                            process_fu_a_packet(stream, rtp_payload, rtp_payload_len);
                                        } else {
                                            /* Regular NAL unit - send directly */
                                stream_manager_t *manager = stream->manager;
                                if (manager && manager->data_callback) {
                                    pthread_mutex_lock(&manager->mutex);
                                    if (manager->data_callback) {
                                                    manager->data_callback(stream->name, rtp_payload, rtp_payload_len, manager->callback_user_data);
                                    }
                                    pthread_mutex_unlock(&manager->mutex);
                                }
                                        }
                                    }
                                    } else {
                                    /* Call global data callback if registered */
                                    stream_manager_t *manager = stream->manager;
                                    if (manager && manager->data_callback) {
                                        pthread_mutex_lock(&manager->mutex);
                                        if (manager->data_callback) {
                                            manager->data_callback(stream->name, data_ptr + 4, frame_length, manager->callback_user_data);
                                        }
                                        pthread_mutex_unlock(&manager->mutex);
                                    }
                                }
                                
                                /* Analyze received data to understand what we're actually getting */
                                if (stream->stats.packets_received <= 20) {
                                    analyze_received_data(data_ptr + 4, frame_length, (int)stream->stats.packets_received);
                                    
                                    /* Special analysis for the first few packets to verify the fix */
                                    if (stream->stats.packets_received <= 5) {
                                    uint8_t *rtp_data = data_ptr + 4;
                                        if (frame_length >= 12) {
                                    uint8_t payload_type = rtp_data[1] & 0x7F;
                                            
                                            if (payload_type == 33 || payload_type == 36 || payload_type == 61) {
                                    } else if (payload_type == 96) {
                                                logger_warn("*** STILL GETTING PT=96 *** P-frame fragments - may need different approach");
                                            }
                                        }
                                    }
                                }
                                
                                /* Track stream statistics and discontinuities */
                                    static uint16_t last_seq = 0;
                                    static uint32_t last_ts = 0;
                                    static bool first_packet = true;
                                static bool sps_seen = false, pps_seen = false, idr_seen = false;
                                static int packets_without_idr = 0;
                                
                                /* Store SPS/PPS data for injection to clients */
                                static uint8_t sps_data[256];
                                static uint8_t pps_data[256];
                                static size_t sps_size = 0;
                                static size_t pps_size = 0;
                                static bool sps_stored = false;
                                static bool pps_stored = false;
                                
                                if (frame_length >= 12) {
                                    uint8_t *rtp_data = data_ptr + 4;
                                    uint8_t payload_type = rtp_data[1] & 0x7F;
                                    uint16_t seq_num = (rtp_data[2] << 8) | rtp_data[3];
                                    uint32_t timestamp = (rtp_data[4] << 24) | (rtp_data[5] << 16) | (rtp_data[6] << 8) | rtp_data[7];
                                    
                                    /* Track stream discontinuities */
                                    if (!first_packet) {
                                        uint16_t seq_diff = seq_num - last_seq;
                                        uint32_t ts_diff = timestamp - last_ts;
                                        
                                        if (seq_diff > 100 || ts_diff > 1000000) {
                                            logger_warn("*** STREAM DISCONTINUITY *** seq jump: %d->%d, ts jump: %u->%u", 
                                                       last_seq, seq_num, last_ts, timestamp);
                                        }
                                    }
                                    
                                    last_seq = seq_num;
                                    last_ts = timestamp;
                                    first_packet = false;
                                    
                                    /* Track critical H.264 frame types */
                                    if (payload_type == 96 && frame_length > 16) {
                                        uint8_t nal_header = rtp_data[12];
                                        uint8_t nal_type = nal_header & 0x1F;
                                        
                                        switch (nal_type) {
                                            case 7: /* SPS */
                                                sps_seen = true;
                                                if (!sps_stored && frame_length > 12) {
                                                    size_t payload_len = frame_length - 12;
                                                    if (payload_len <= sizeof(sps_data)) {
                                                        memcpy(sps_data, rtp_data + 12, payload_len);
                                                        sps_size = payload_len;
                                                        sps_stored = true;
                                                    }
                                                }
                                                break;
                                            case 8: /* PPS */
                                                pps_seen = true;
                                                if (!pps_stored && frame_length > 12) {
                                                    size_t payload_len = frame_length - 12;
                                                    if (payload_len <= sizeof(pps_data)) {
                                                        memcpy(pps_data, rtp_data + 12, payload_len);
                                                        pps_size = payload_len;
                                                        pps_stored = true;
                                                    }
                                                }
                                                break;
                                            case 5: /* IDR */
                                                idr_seen = true;
                                                packets_without_idr = 0;
                                                break;
                                            case 1: /* P-frame */
                                                packets_without_idr++;
                                                break;
                                        }
                                        
                                        /* Inject SPS/PPS to clients if we have them stored */
                                        if (sps_stored && pps_stored) {
                                            /* Create RTP packets for SPS and PPS */
                                            uint8_t sps_rtp[256];
                                            uint8_t pps_rtp[256];
                                            
                                            /* Create SPS RTP packet */
                                            if (sps_size > 0) {
                                                /* RTP header (12 bytes) */
                                                sps_rtp[0] = 0x80; /* V=2, P=0, X=0, CC=0 */
                                                sps_rtp[1] = 0x60; /* M=0, PT=96 (H.264) */
                                                sps_rtp[2] = 0x00; /* Sequence number high */
                                                sps_rtp[3] = 0x01; /* Sequence number low */
                                                sps_rtp[4] = 0x00; /* Timestamp high */
                                                sps_rtp[5] = 0x00; /* Timestamp mid-high */
                                                sps_rtp[6] = 0x00; /* Timestamp mid-low */
                                                sps_rtp[7] = 0x00; /* Timestamp low */
                                                sps_rtp[8] = 0x00; /* SSRC high */
                                                sps_rtp[9] = 0x00; /* SSRC mid-high */
                                                sps_rtp[10] = 0x00; /* SSRC mid-low */
                                                sps_rtp[11] = 0x01; /* SSRC low */
                                                
                                                /* Copy SPS data */
                                                memcpy(sps_rtp + 12, sps_data, sps_size);
                                                
                                                /* Send to clients via data callback */
                                                stream_manager_t *manager = stream->manager;
                                                if (manager && manager->data_callback) {
                                                    manager->data_callback(stream->name, sps_rtp, 12 + sps_size, manager->callback_user_data);
                                                }
                                            }
                                            
                                            /* Create PPS RTP packet */
                                            if (pps_size > 0) {
                                                /* RTP header (12 bytes) */
                                                pps_rtp[0] = 0x80; /* V=2, P=0, X=0, CC=0 */
                                                pps_rtp[1] = 0x60; /* M=0, PT=96 (H.264) */
                                                pps_rtp[2] = 0x00; /* Sequence number high */
                                                pps_rtp[3] = 0x02; /* Sequence number low */
                                                pps_rtp[4] = 0x00; /* Timestamp high */
                                                pps_rtp[5] = 0x00; /* Timestamp mid-high */
                                                pps_rtp[6] = 0x00; /* Timestamp mid-low */
                                                pps_rtp[7] = 0x00; /* Timestamp low */
                                                pps_rtp[8] = 0x00; /* SSRC high */
                                                pps_rtp[9] = 0x00; /* SSRC mid-high */
                                                pps_rtp[10] = 0x00; /* SSRC mid-low */
                                                pps_rtp[11] = 0x01; /* SSRC low */
                                                
                                                /* Copy PPS data */
                                                memcpy(pps_rtp + 12, pps_data, pps_size);
                                                
                                                /* Send to clients via data callback */
                                                stream_manager_t *manager = stream->manager;
                                                if (manager && manager->data_callback) {
                                                    manager->data_callback(stream->name, pps_rtp, 12 + pps_size, manager->callback_user_data);
                                                }
                                            }
                                            
                                        }
                                        
                                        /* Send aggressive keyframe requests if no IDR frames */
                                        if (!idr_seen && packets_without_idr > 0 && packets_without_idr % 5 == 0) {
                                            logger_warn("*** STILL NO IDR *** %d P-frames received, sending aggressive keyframe requests", packets_without_idr);
                                            
                                            /* Method 1: RTCP PLI packet */
                                            uint8_t pli_packet[] = {
                                                '$', 1, 0, 12,
                                                0x81, 0xCE, 0x00, 0x02,
                                                0x00, 0x00, 0x00, 0x00,
                                                0x00, 0x00, 0x00, 0x00
                                            };
                                            send(socket_fd, pli_packet, sizeof(pli_packet), 0);
                                            
                                            /* Method 2: SET_PARAMETER request for keyframe */
                                            char keyframe_request[512];
                                            snprintf(keyframe_request, sizeof(keyframe_request),
                                                "SET_PARAMETER %s RTSP/1.0\r\n"
                                                "CSeq: %d\r\n"
                                                "Session: %s\r\n"
                                                "Content-Type: text/parameters\r\n"
                                                "Content-Length: 20\r\n"
                                                "\r\n"
                                                "picture_fast_update\r\n",
                                                stream->rtsp_url, cseq++, stream->session_id);
                                            
                                            send(socket_fd, keyframe_request, strlen(keyframe_request), 0);
                                            
                                            /* Method 3: Try different parameter name */
                                            char keyframe_request2[512];
                                            snprintf(keyframe_request2, sizeof(keyframe_request2),
                                                "SET_PARAMETER %s RTSP/1.0\r\n"
                                                "CSeq: %d\r\n"
                                                "Session: %s\r\n"
                                                "Content-Type: text/parameters\r\n"
                                                "Content-Length: 15\r\n"
                                                "\r\n"
                                                "keyframe_request\r\n",
                                                stream->rtsp_url, cseq++, stream->session_id);
                                            
                                            send(socket_fd, keyframe_request2, strlen(keyframe_request2), 0);
                                            
                                        }
                                        
                                        /* If we've tried many times and still no IDR, try restarting the stream */
                                        if (!idr_seen && packets_without_idr > 50) {
                                            logger_error("*** STREAM RESTART *** No IDR frames after %d packets, restarting stream", packets_without_idr);
                                            
                                            /* Send TEARDOWN to restart */
                                            char teardown_request[512];
                                            snprintf(teardown_request, sizeof(teardown_request),
                                                "TEARDOWN %s RTSP/1.0\r\n"
                                                "CSeq: %d\r\n"
                                                "Session: %s\r\n"
                                                "\r\n",
                                                stream->rtsp_url, cseq++, stream->session_id);
                                            
                                            send(socket_fd, teardown_request, strlen(teardown_request), 0);
                                            close(socket_fd);
                                            stream->state = STREAM_STATE_DISCONNECTED;
                                            return NULL; /* This will cause the thread to restart */
                                        }
                                        
                                        /* Warn about missing critical frames */
                                        if (stream->stats.packets_received == 25) {
                                            logger_error("*** ANALYSIS *** SPS=%s, PPS=%s, IDR=%s after 25 packets", 
                                                        sps_seen ? "YES" : "NO", pps_seen ? "YES" : "NO", idr_seen ? "YES" : "NO");
                                            if (!idr_seen) {
                                                logger_error("*** CRITICAL *** No IDR keyframes! VLC cannot decode P-frames without keyframes!");
                                                logger_error("*** TRYING STREAM RESTART *** This might force the camera to send keyframes");
                                                
                                                /* Try to restart the stream by sending TEARDOWN and reconnecting */
                                                char teardown_request[512];
                                                snprintf(teardown_request, sizeof(teardown_request),
                                                    "TEARDOWN %s RTSP/1.0\r\n"
                                                    "CSeq: %d\r\n"
                                                    "Session: %s\r\n"
                                                    "\r\n",
                                                    stream->rtsp_url, cseq++, stream->session_id);
                                                
                                                send(socket_fd, teardown_request, strlen(teardown_request), 0);
                                                
                                                /* Close and reconnect */
                                                close(socket_fd);
                                                stream->state = STREAM_STATE_DISCONNECTED;
                                                return NULL; /* This will cause the thread to restart */
                                            }
                                        }
                                    }
                                    
                                    /* Flag large packets that should be video frames */
                                    if (frame_length > 500) {
                                    }
                                } else {
                                }
                            } else if (channel == 1) { /* RTCP control channel */
                                /* Update statistics for RTCP */
                                stream->stats.bytes_received += frame_length;
                                
                                /* Log RTCP packets occasionally */
                                static int rtcp_count = 0;
                                rtcp_count++;
                                if (rtcp_count <= 5 || rtcp_count % 50 == 0) {
                                }
                            }
                            
                            /* Move to next frame */
                            data_ptr += 4 + frame_length;
                            remaining -= 4 + frame_length;
                        } else {
                            /* Incomplete frame - save for next read */
                            if (remaining > 0 && remaining < (ssize_t)sizeof(incomplete_buffer)) {
                                memcpy(incomplete_buffer, data_ptr, remaining);
                                incomplete_bytes = remaining;
                                /* Copy incomplete data back to beginning of buffer */
                                memcpy(buffer, incomplete_buffer, incomplete_bytes);
                            }
                            break;
                        }
                    } else {
                        break;
                    }
                }
            } else {
                /* Assume raw RTP data - validate RTP header */
                if (total_bytes >= 12 && (buffer[0] & 0xC0) == 0x80) { /* RTP version 2 */
                    /* Update statistics */
                    stream->stats.bytes_received += total_bytes;
                    stream->stats.packets_received++;
                    stream->stats.last_packet_time = get_timestamp_ms();
                    
                    /* Process RTP packet - handle FU-A reassembly if needed */
                    if (total_bytes > 12) {
                        uint8_t *payload = buffer + 12; /* Skip RTP header */
                        size_t payload_len = total_bytes - 12;
                        
                        if (payload_len > 0) {
                            uint8_t nal_header = payload[0];
                            uint8_t nal_type = nal_header & 0x1F;
                            
                            if (nal_type == 28) { /* FU-A fragmentation unit */
                                /* Process FU-A packet for reassembly */
                                process_fu_a_packet(stream, buffer, total_bytes);
                            } else {
                                /* Regular NAL unit - send directly */
                                stream_manager_t *manager = stream->manager;
                                if (manager && manager->data_callback) {
                                    pthread_mutex_lock(&manager->mutex);
                                    if (manager->data_callback) {
                                        manager->data_callback(stream->name, buffer, total_bytes, manager->callback_user_data);
                                    }
                                    pthread_mutex_unlock(&manager->mutex);
                                }
                            }
                        }
                    } else {
                    /* Call global data callback if registered */
                    stream_manager_t *manager = stream->manager;
                    if (manager && manager->data_callback) {
                        pthread_mutex_lock(&manager->mutex);
                        if (manager->data_callback) {
                            manager->data_callback(stream->name, buffer, total_bytes, manager->callback_user_data);
                        }
                        pthread_mutex_unlock(&manager->mutex);
                        }
                    }
                    
                    /* Analyze raw RTP packets */
                    if (stream->stats.packets_received <= 20) {
                        analyze_received_data(buffer, total_bytes, (int)stream->stats.packets_received);
                    }
                    
                    /* Log periodic statistics with data rate */
                    if (stream->stats.packets_received % 100 == 0) {
                        uint64_t current_time = get_timestamp_ms();
                        uint64_t elapsed_ms = current_time - stream->stats.connection_time;
                        double elapsed_sec = elapsed_ms / 1000.0;
                        double bytes_per_sec = elapsed_sec > 0 ? stream->stats.bytes_received / elapsed_sec : 0;
                        double kbps = bytes_per_sec * 8 / 1000.0;
                        
                                   
                        if (kbps < 100) {
                            logger_error("*** CRITICAL *** %.2f kbps is FAR too low for video! Expected 1000+ kbps", kbps);
                            logger_error("*** This appears to be CONTROL DATA ONLY, not video frames ***");
                            logger_error("*** Camera may not be configured to send video or wrong RTSP endpoint ***");
                            logger_error("*** TROUBLESHOOTING: Try different RTSP URLs:");
                            logger_error("  - rtsp://192.168.42.cam/stream1");
                            logger_error("  - rtsp://192.168.42.cam/video1");
                            logger_error("  - rtsp://192.168.42.cam/h264");
                            logger_error("  - rtsp://192.168.42.cam/live.sdp");
                            logger_error("  - rtsp://192.168.42.cam/media/video1");
                        } else if (kbps < 500) {
                            logger_warn("*** LOW BITRATE *** %.2f kbps might be very low quality video", kbps);
                        } else {
                        }
                    }
                } else {
                    /* Not RTP data - only log occasionally */
                    static int non_rtp_count = 0;
                    non_rtp_count++;
                    if (non_rtp_count <= 5 || non_rtp_count % 50 == 0) {
                    }
                }
            }
            } else if (bytes_read == 0) {
                logger_warn("Stream '%s' connection closed by server", stream->name);
                break;
            } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* No data available, sleep briefly to prevent CPU spinning */
                usleep(10000); /* 10ms */
            } else {
                logger_error("Stream '%s' read error: %s", stream->name, strerror(errno));
                break;
            }
        } /* End of TCP interleaved transport else block */
    }
    
    close(socket_fd);
    stream->socket_fd = -1;
    
    /* Close UDP sockets if they were created */
    if (stream->use_udp_transport) {
        close_udp_sockets(stream);
    }
    
    /* Update stream state and connection count */
    pthread_mutex_lock(&stream->mutex);
    stream->state = STREAM_STATE_DISCONNECTED;
    stream->active = false;
    pthread_mutex_unlock(&stream->mutex);
    
    /* Update manager connection count with proper locking */
    pthread_mutex_lock(&stream->manager->mutex);
    stream->manager->active_connections--;
    logger_info("Stream '%s' connection count: %d/%d (decremented)", stream->name,
               stream->manager->active_connections, stream->manager->max_connections);
    pthread_mutex_unlock(&stream->manager->mutex);
    
    logger_info("Stream '%s' thread ended", stream->name);
    return NULL;
}

/**
 * @brief Create stream manager
 */
stream_manager_t *stream_manager_create(config_t *config) {
    if (!config) {
        logger_error("Stream manager creation failed: NULL configuration");
        return NULL;
    }
    
    stream_manager_t *manager = calloc(1, sizeof(stream_manager_t));
    if (!manager) {
        logger_error("Stream manager creation failed: memory allocation error");
        return NULL;
    }
    
    manager->config = config;
    manager->stream_count = config->stream_count;
    manager->max_connections = config->max_camera_connections;
    manager->active_connections = 0;
    manager->running = false;
    
    if (pthread_mutex_init(&manager->mutex, NULL) != 0) {
        logger_error("Failed to initialize stream manager mutex");
        free(manager);
        return NULL;
    }
    
    /* Allocate stream connections */
    if (manager->stream_count > 0) {
        manager->streams = calloc(manager->stream_count, sizeof(stream_connection_t));
        if (!manager->streams) {
            logger_error("Failed to allocate memory for %d streams", manager->stream_count);
            pthread_mutex_destroy(&manager->mutex);
            free(manager);
            return NULL;
        }
        
        /* Initialize stream connections */
        for (uint16_t i = 0; i < manager->stream_count; i++) {
            stream_connection_t *stream = &manager->streams[i];
            const stream_config_t *config_stream = &config->streams[i];
            
            strncpy(stream->name, config_stream->name, sizeof(stream->name) - 1);
            stream->name[sizeof(stream->name) - 1] = '\0';
            
            strncpy(stream->rtsp_url, config_stream->rtsp_url, sizeof(stream->rtsp_url) - 1);
            stream->rtsp_url[sizeof(stream->rtsp_url) - 1] = '\0';
            
            strncpy(stream->username, config_stream->username, sizeof(stream->username) - 1);
            stream->username[sizeof(stream->username) - 1] = '\0';
            
            strncpy(stream->password, config_stream->password, sizeof(stream->password) - 1);
            stream->password[sizeof(stream->password) - 1] = '\0';
            
            stream->auth_required = config_stream->auth_required;
            stream->state = STREAM_STATE_DISCONNECTED;
            stream->socket_fd = -1;
            stream->rtp_socket = -1;
            stream->rtcp_socket = -1;
            stream->use_udp_transport = false;
            stream->active = false;
            stream->manager = manager;  /* Set manager reference */
            stream->should_stop = false;
            
            if (pthread_mutex_init(&stream->mutex, NULL) != 0) {
                logger_error("Failed to initialize mutex for stream '%s'", stream->name);
                /* Cleanup already initialized streams */
                for (uint16_t j = 0; j < i; j++) {
                    pthread_mutex_destroy(&manager->streams[j].mutex);
                }
                free(manager->streams);
                pthread_mutex_destroy(&manager->mutex);
                free(manager);
                return NULL;
            }
        }
    }
    
    logger_info("Stream manager created with %d streams", manager->stream_count);
    return manager;
}

/**
 * @brief Destroy stream manager
 */
void stream_manager_destroy(stream_manager_t *manager) {
    if (!manager) return;
    
    logger_info("Destroying stream manager...");
    
    /* Stop all streams */
    stream_manager_stop(manager);
    
    /* Cleanup streams */
    if (manager->streams) {
        for (uint16_t i = 0; i < manager->stream_count; i++) {
            stream_connection_t *stream = &manager->streams[i];
            pthread_mutex_destroy(&stream->mutex);
        }
        free(manager->streams);
    }
    
    pthread_mutex_destroy(&manager->mutex);
    free(manager);
    logger_info("Stream manager destroyed");
}

/**
 * @brief Start stream manager
 */
int stream_manager_start(stream_manager_t *manager) {
    if (!manager) {
        logger_error("Stream manager start failed: NULL manager");
        return -1;
    }
    
    if (manager->running) {
        logger_warn("Stream manager already running");
        return 0;
    }
    
    logger_info("Starting stream manager...");
    
    pthread_mutex_lock(&manager->mutex);
    manager->running = true;
    pthread_mutex_unlock(&manager->mutex);
    
    /* Connect to all configured streams */
    for (uint16_t i = 0; i < manager->stream_count; i++) {
        stream_connection_t *stream = &manager->streams[i];
        logger_info("Connecting to stream '%s'", stream->name);
        
        if (stream_manager_connect_stream(manager, stream->name) != 0) {
            logger_error("Failed to connect to stream '%s'", stream->name);
        } else {
            logger_info("Successfully initiated connection to stream '%s'", stream->name);
        }
    }
    
    logger_info("Stream manager started with %d streams", manager->stream_count);
    return 0;
}

/**
 * @brief Stop stream manager
 */
int stream_manager_stop(stream_manager_t *manager) {
    if (!manager) {
        logger_error("Stream manager stop failed: NULL manager");
        return -1;
    }
    
    if (!manager->running) {
        logger_warn("Stream manager not running");
        return 0;
    }
    
    logger_info("Stopping stream manager...");
    
    pthread_mutex_lock(&manager->mutex);
    manager->running = false;
    
    /* Stop all active streams */
    for (uint16_t i = 0; i < manager->stream_count; i++) {
        stream_connection_t *stream = &manager->streams[i];
        if (stream->active) {
            stream->should_stop = true;
            if (stream->socket_fd >= 0) {
                close(stream->socket_fd);
                stream->socket_fd = -1;
            }
        }
    }
    pthread_mutex_unlock(&manager->mutex);
    
    /* Wait for threads to finish */
    for (uint16_t i = 0; i < manager->stream_count; i++) {
        stream_connection_t *stream = &manager->streams[i];
        if (stream->active) {
            pthread_join(stream->thread, NULL);
            stream->active = false;
        }
    }
    
    logger_info("Stream manager stopped");
    return 0;
}

/**
 * @brief Connect to a specific stream
 */
int stream_manager_connect_stream(stream_manager_t *manager, const char *stream_name) {
    if (!manager || !stream_name) {
        logger_error("Stream connect failed: NULL parameter");
        return -1;
    }
    
    stream_connection_t *stream = find_stream(manager, stream_name);
    if (!stream) {
        logger_error("Stream not found: %s", stream_name);
        return -1;
    }
    
    pthread_mutex_lock(&stream->mutex);
    
    if (stream->active) {
        logger_warn("Stream '%s' is already active", stream_name);
        pthread_mutex_unlock(&stream->mutex);
        return 0;
    }
    
    if (manager->active_connections >= manager->max_connections) {
        logger_error("Maximum connections reached (%d/%d), cannot connect stream '%s'", 
                    manager->active_connections, manager->max_connections, stream_name);
        pthread_mutex_unlock(&stream->mutex);
        return -1;
    }
    
    stream->should_stop = false;
    stream->state = STREAM_STATE_CONNECTING;
    
    if (pthread_create(&stream->thread, NULL, stream_thread, stream) != 0) {
        logger_error("Failed to create thread for stream '%s': %s", stream_name, strerror(errno));
        stream->state = STREAM_STATE_ERROR;
        pthread_mutex_unlock(&stream->mutex);
        return -1;
    }
    
    stream->active = true;
    manager->active_connections++;
    
    logger_info("Stream '%s' connection count: %d/%d", stream_name, 
               manager->active_connections, manager->max_connections);
    
    pthread_mutex_unlock(&stream->mutex);
    
    logger_info("Connecting to stream '%s'", stream_name);
    return 0;
}

/**
 * @brief Disconnect a specific stream
 */
int stream_manager_disconnect_stream(stream_manager_t *manager, const char *stream_name) {
    if (!manager || !stream_name) {
        logger_error("Stream disconnect failed: NULL parameter");
        return -1;
    }
    
    stream_connection_t *stream = find_stream(manager, stream_name);
    if (!stream) {
        logger_error("Stream not found: %s", stream_name);
        return -1;
    }
    
    pthread_mutex_lock(&stream->mutex);
    
    if (!stream->active) {
        logger_warn("Stream '%s' is not active", stream_name);
        pthread_mutex_unlock(&stream->mutex);
        return 0;
    }
    
    stream->should_stop = true;
    if (stream->socket_fd >= 0) {
        close(stream->socket_fd);
        stream->socket_fd = -1;
    }
    
    pthread_mutex_unlock(&stream->mutex);
    
    /* Wait for thread to finish */
    pthread_join(stream->thread, NULL);
    
    pthread_mutex_lock(&stream->mutex);
    stream->active = false;
    stream->state = STREAM_STATE_DISCONNECTED;
    pthread_mutex_unlock(&stream->mutex);
    
    /* Note: active_connections is decremented by the stream thread when it exits */
    
    logger_info("Disconnected stream '%s'", stream_name);
    return 0;
}

/**
 * @brief Check if stream is connected
 */
bool stream_manager_is_stream_connected(stream_manager_t *manager, const char *stream_name) {
    if (!manager || !stream_name) return false;
    
    stream_connection_t *stream = find_stream(manager, stream_name);
    if (!stream) return false;
    
    pthread_mutex_lock(&stream->mutex);
    bool connected = (stream->state == STREAM_STATE_STREAMING && stream->active);
    pthread_mutex_unlock(&stream->mutex);
    
    return connected;
}

/**
 * @brief Check stream health and reconnect if needed
 */
int stream_manager_check_and_reconnect_stream(stream_manager_t *manager, const char *stream_name) {
    if (!manager || !stream_name) return -1;
    
    stream_connection_t *stream = find_stream(manager, stream_name);
    if (!stream) return -1;
    
    pthread_mutex_lock(&stream->mutex);
    bool needs_reconnect = (!stream->active || stream->state != STREAM_STATE_STREAMING);
    
    /* Also check if stream has been inactive for too long (indicates corruption) */
    if (!needs_reconnect && stream->active && stream->state == STREAM_STATE_STREAMING) {
        uint64_t current_time = get_timestamp_ms();
        uint64_t time_since_last_packet = current_time - stream->stats.last_packet_time;
        
        /* If no data received for more than 10 seconds, consider stream unhealthy */
        if (time_since_last_packet > 10000) {
            logger_warn("Stream '%s' appears unhealthy - no data for %lu ms, forcing reconnection", 
                       stream_name, time_since_last_packet);
            needs_reconnect = true;
        }
    }
    pthread_mutex_unlock(&stream->mutex);
    
    if (needs_reconnect) {
        logger_info("Stream '%s' needs reconnection, attempting to reconnect...", stream_name);
        
        /* Force disconnect first if stream is in a bad state */
        if (stream->active) {
            logger_info("Force disconnecting unhealthy stream '%s' before reconnection", stream_name);
            stream_manager_disconnect_stream(manager, stream_name);
        }
        
        return stream_manager_connect_stream(manager, stream_name);
    }
    
    return 0; /* Stream is healthy */
}

/**
 * @brief Get stream statistics
 */
int stream_manager_get_stream_stats(stream_manager_t *manager, const char *stream_name, 
                                   stream_stats_t *stats) {
    if (!manager || !stream_name || !stats) {
        logger_error("Stream stats failed: NULL parameter");
        return -1;
    }
    
    stream_connection_t *stream = find_stream(manager, stream_name);
    if (!stream) {
        logger_error("Stream not found: %s", stream_name);
        return -1;
    }
    
    pthread_mutex_lock(&stream->mutex);
    *stats = stream->stats;
    pthread_mutex_unlock(&stream->mutex);
    
    return 0;
}

/**
 * @brief Set data callback for stream
 */
int stream_manager_set_data_callback(stream_manager_t *manager, const char *stream_name,
                                    void (*callback)(const char *stream_name, const void *data, size_t len),
                                    void *user_data) {
    if (!manager || !stream_name) {
        logger_error("Stream callback failed: NULL parameter");
        return -1;
    }
    
    stream_connection_t *stream = find_stream(manager, stream_name);
    if (!stream) {
        logger_error("Stream not found: %s", stream_name);
        return -1;
    }
    
    pthread_mutex_lock(&stream->mutex);
    stream->data_callback = callback;
    stream->callback_data = user_data;
    pthread_mutex_unlock(&stream->mutex);
    
    return 0;
}

/**
 * @brief Get stream manager statistics
 */
int stream_manager_get_stats(stream_manager_t *manager, uint16_t *total_streams,
                            uint16_t *active_streams, uint64_t *total_bytes) {
    if (!manager) {
        logger_error("Manager stats failed: NULL manager");
        return -1;
    }
    
    pthread_mutex_lock(&manager->mutex);
    
    if (total_streams) *total_streams = manager->stream_count;
    if (active_streams) *active_streams = manager->active_connections;
    
    uint64_t bytes = 0;
    if (total_bytes) {
        for (uint16_t i = 0; i < manager->stream_count; i++) {
            bytes += manager->streams[i].stats.bytes_received;
        }
        *total_bytes = bytes;
    }
    
    pthread_mutex_unlock(&manager->mutex);
    
    return 0;
}

/**
 * @brief Register global data callback for all streams
 */
int stream_manager_register_data_callback(stream_manager_t *manager, stream_data_callback_t callback, void *user_data) {
    if (!manager) {
        logger_error("Callback registration failed: NULL manager");
        return -1;
    }
    
    pthread_mutex_lock(&manager->mutex);
    manager->data_callback = callback;
    manager->callback_user_data = user_data;
    pthread_mutex_unlock(&manager->mutex);
    
    logger_info("Registered global data callback for stream manager");
    return 0;
}

/**
 * @brief Reconnect all streams
 */
int stream_manager_reconnect_all(stream_manager_t *manager) {
    if (!manager) {
        logger_error("Reconnect all failed: NULL manager");
        return -1;
    }
    
    logger_info("Reconnecting all streams...");
    
    for (uint16_t i = 0; i < manager->stream_count; i++) {
        stream_connection_t *stream = &manager->streams[i];
        if (stream->active) {
            stream_manager_disconnect_stream(manager, stream->name);
            usleep(100000); /* 100ms delay between reconnects */
            stream_manager_connect_stream(manager, stream->name);
        }
    }
    
    logger_info("Reconnect all completed");
    return 0;
}
