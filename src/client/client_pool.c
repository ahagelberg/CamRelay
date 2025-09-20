/**
 * @file client_pool.c
 * @brief Client pool implementation for handling multiple RTSP clients
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include "client/client_pool.h"
#include "stream/stream_manager.h"
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
#include <sys/select.h>

/**
 * @brief Get client state string
 */
const char *client_pool_state_to_string(client_state_t state) {
    switch (state) {
        case CLIENT_STATE_DISCONNECTED: return "DISCONNECTED";
        case CLIENT_STATE_CONNECTING: return "CONNECTING";
        case CLIENT_STATE_CONNECTED: return "CONNECTED";
        case CLIENT_STATE_PLAYING: return "PLAYING";
        case CLIENT_STATE_PAUSED: return "PAUSED";
        case CLIENT_STATE_ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

/**
 * @brief Get client request type string
 */
const char *client_pool_request_to_string(client_request_t request) {
    switch (request) {
        case CLIENT_REQUEST_OPTIONS: return "OPTIONS";
        case CLIENT_REQUEST_DESCRIBE: return "DESCRIBE";
        case CLIENT_REQUEST_SETUP: return "SETUP";
        case CLIENT_REQUEST_PLAY: return "PLAY";
        case CLIENT_REQUEST_PAUSE: return "PAUSE";
        case CLIENT_REQUEST_TEARDOWN: return "TEARDOWN";
        case CLIENT_REQUEST_UNKNOWN: return "UNKNOWN";
        default: return "UNKNOWN";
    }
}

/**
 * @brief Get current timestamp in milliseconds
 */
static uint64_t get_timestamp_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/**
 * @brief Generate unique client ID
 */
static void generate_client_id(char *client_id, size_t size, const char *client_ip, uint16_t port) {
    snprintf(client_id, size, "%s:%d", client_ip, port);
}

/**
 * @brief Parse RTSP request
 */
static client_request_t parse_rtsp_request(const char *request) {
    if (!request) return CLIENT_REQUEST_UNKNOWN;
    
    if (strncmp(request, "OPTIONS", 7) == 0) return CLIENT_REQUEST_OPTIONS;
    if (strncmp(request, "DESCRIBE", 8) == 0) return CLIENT_REQUEST_DESCRIBE;
    if (strncmp(request, "SETUP", 5) == 0) return CLIENT_REQUEST_SETUP;
    if (strncmp(request, "PLAY", 4) == 0) return CLIENT_REQUEST_PLAY;
    if (strncmp(request, "PAUSE", 5) == 0) return CLIENT_REQUEST_PAUSE;
    if (strncmp(request, "TEARDOWN", 8) == 0) return CLIENT_REQUEST_TEARDOWN;
    
    return CLIENT_REQUEST_UNKNOWN;
}

/**
 * @brief Extract stream name from RTSP URL
 */
static int extract_stream_name(const char *rtsp_url, char *stream_name, size_t size) {
    if (!rtsp_url || !stream_name) return -1;
    
    /* Parse rtsp://server:port/stream_name */
    const char *start = strrchr(rtsp_url, '/');
    if (!start) return -1;
    
    start++; /* Skip the '/' */
    const char *end = strchr(start, ' ');
    if (!end) end = start + strlen(start);
    
    size_t len = end - start;
    if (len >= size) return -1;
    
    strncpy(stream_name, start, len);
    stream_name[len] = '\0';
    
    return 0;
}

/**
 * @brief Extract CSeq from RTSP request
 */
static int extract_cseq(const char *request) {
    const char *cseq_line = strstr(request, "CSeq:");
    if (!cseq_line) {
        logger_warn("No CSeq found in RTSP request");
        return 1; /* Default fallback */
    }
    
    cseq_line += 5; /* Skip "CSeq:" */
    while (*cseq_line == ' ' || *cseq_line == '\t') cseq_line++; /* Skip whitespace */
    
    int cseq = atoi(cseq_line);
    return cseq > 0 ? cseq : 1;
}

/**
 * @brief Send RTSP response
 */
static int send_rtsp_response(int socket_fd, int status_code, const char *status_text,
                               const char *headers, const char *body, int cseq) {
    char response[2048];
    int len = snprintf(response, sizeof(response),
        "RTSP/1.0 %d %s\r\n"
        "CSeq: %d\r\n"
        "Server: CamRelay/1.0\r\n"
        "%s"
        "\r\n%s",
        status_code, status_text ? status_text : "OK", cseq,
        headers ? headers : "",
        body ? body : "");
    
    if (len >= (int)sizeof(response)) {
        logger_error("RTSP response too long");
        return -1;
    }
    
    ssize_t sent = send(socket_fd, response, len, 0);
    if (sent < 0) {
        logger_error("Failed to send RTSP response: %s", strerror(errno));
        return -1;
    }
    
    return 0;
}

/**
 * @brief Handle RTSP OPTIONS request
 */
static int handle_options_request(client_connection_t *client, const char *request) {
    
    int cseq = extract_cseq(request);
    const char *headers = "Public: OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN\r\n";
    return send_rtsp_response(client->socket_fd, 200, "OK", headers, NULL, cseq);
}

/**
 * @brief Handle RTSP DESCRIBE request
 */
static int handle_describe_request(client_connection_t *client, const char *request) {
    
    /* Extract stream name from request */
    char rtsp_url[256];
    if (sscanf(request, "DESCRIBE %s RTSP/1.0", rtsp_url) != 1) {
        logger_error("Failed to parse DESCRIBE request: %s", request);
        int cseq = extract_cseq(request);
        return send_rtsp_response(client->socket_fd, 400, "Bad Request", NULL, NULL, cseq);
    }
    
    if (extract_stream_name(rtsp_url, client->requested_stream, sizeof(client->requested_stream)) != 0) {
        logger_error("Failed to extract stream name from: %s", rtsp_url);
        int cseq = extract_cseq(request);
        return send_rtsp_response(client->socket_fd, 400, "Bad Request", NULL, NULL, cseq);
    }
    
    /* Map generic stream names to actual stream names */
    if (strcmp(client->requested_stream, "stream=0") == 0) {
        strncpy(client->requested_stream, "Bunnycam2", sizeof(client->requested_stream) - 1);
        client->requested_stream[sizeof(client->requested_stream) - 1] = '\0';
    } else if (strcmp(client->requested_stream, "bunnycam2") == 0) {
        strncpy(client->requested_stream, "Bunnycam2", sizeof(client->requested_stream) - 1);
        client->requested_stream[sizeof(client->requested_stream) - 1] = '\0';
    } else if (strcmp(client->requested_stream, "track0") == 0) {
        strncpy(client->requested_stream, "Bunnycam2", sizeof(client->requested_stream) - 1);
        client->requested_stream[sizeof(client->requested_stream) - 1] = '\0';
    }
    
    /* Generate SDP content with proper H.264 parameters */
    char sdp_content[1024];
    /* Use server address (192.168.42.7) instead of client address */
    snprintf(sdp_content, sizeof(sdp_content),
        "v=0\r\n"
        "o=- 2890844526 2890844526 IN IP4 192.168.42.7\r\n"
        "s=H.264 Video Stream\r\n"
        "c=IN IP4 192.168.42.7\r\n"
        "t=0 0\r\n"
        "a=tool:CamRelay 1.0\r\n"
        "a=type:broadcast\r\n"
        "a=control:*\r\n"
        "a=range:npt=0-\r\n"
        "m=video 0 RTP/AVP 96\r\n"
        "c=IN IP4 192.168.42.7\r\n"
        "b=AS:5000\r\n"
        "a=rtpmap:96 H264/90000\r\n"
        "a=fmtp:96 packetization-mode=1;profile-level-id=420020;sprop-parameter-sets=Z0IAH6zAUAW7AQEBAg==,aM48gA==\r\n"
        "a=control:track0\r\n");
    
    const char *headers = "Content-Type: application/sdp\r\n"
                         "Content-Length: %d\r\n";
    
    char header_buf[256];
    snprintf(header_buf, sizeof(header_buf), headers, (int)strlen(sdp_content));
    
    int cseq = extract_cseq(request);
    return send_rtsp_response(client->socket_fd, 200, "OK", header_buf, sdp_content, cseq);
}

/**
 * @brief Handle RTSP SETUP request
 */
static int handle_setup_request(client_connection_t *client, const char *request) {
    
    /* Extract stream name from request for later use */
    char rtsp_url[256];
    if (sscanf(request, "SETUP %s RTSP/1.0", rtsp_url) == 1) {
        if (extract_stream_name(rtsp_url, client->requested_stream, sizeof(client->requested_stream)) == 0) {
            /* Map generic stream names to actual stream names */
            if (strcmp(client->requested_stream, "bunnycam2") == 0) {
                strncpy(client->requested_stream, "Bunnycam2", sizeof(client->requested_stream) - 1);
                client->requested_stream[sizeof(client->requested_stream) - 1] = '\0';
            } else if (strcmp(client->requested_stream, "track0") == 0) {
                strncpy(client->requested_stream, "Bunnycam2", sizeof(client->requested_stream) - 1);
                client->requested_stream[sizeof(client->requested_stream) - 1] = '\0';
            }
        }
    }
    
    /* Generate session ID */
    snprintf(client->session_id, sizeof(client->session_id), "session_%ld", time(NULL));
    
    /* Extract transport information */
    const char *transport = strstr(request, "Transport:");
    if (transport) {
        
        /* Parse client_port from Transport header */
        const char *client_port_str = strstr(transport, "client_port=");
        if (client_port_str) {
            client_port_str += 12; /* Skip "client_port=" */
            int port = atoi(client_port_str);
            if (port > 0 && port < 65536) {
                client->rtp_port = (uint16_t)port;
            }
        }
    }
    
    char headers[512];
    snprintf(headers, sizeof(headers), 
        "Session: %s\r\n"
        "Transport: RTP/AVP;unicast;destination=%s;client_port=%d-%d\r\n",
        client->session_id, client->client_ip, client->rtp_port, client->rtp_port + 1);
    
    int cseq = extract_cseq(request);
    return send_rtsp_response(client->socket_fd, 200, "OK", headers, NULL, cseq);
}

/**
 * @brief Handle RTSP PLAY request
 */
static int handle_play_request(client_connection_t *client, const char *request) {
    (void)request; /* Suppress unused parameter warning */
    
    /* Extract stream name from request if not already set */
    if (strlen(client->requested_stream) == 0) {
        char rtsp_url[256];
        if (sscanf(request, "PLAY %s RTSP/1.0", rtsp_url) == 1) {
            if (extract_stream_name(rtsp_url, client->requested_stream, sizeof(client->requested_stream)) != 0) {
                logger_warn("Failed to extract stream name from PLAY request: %s", rtsp_url);
            }
        }
    }
    
    /* Map generic stream names to actual stream names */
    if (strcmp(client->requested_stream, "stream=0") == 0) {
        strncpy(client->requested_stream, "Bunnycam2", sizeof(client->requested_stream) - 1);
        client->requested_stream[sizeof(client->requested_stream) - 1] = '\0';
    } else if (strcmp(client->requested_stream, "track0") == 0) {
        strncpy(client->requested_stream, "Bunnycam2", sizeof(client->requested_stream) - 1);
        client->requested_stream[sizeof(client->requested_stream) - 1] = '\0';
    }
    
    
    /* Associate with stream */
    strncpy(client->stream_name, client->requested_stream, sizeof(client->stream_name) - 1);
    client->stream_name[sizeof(client->stream_name) - 1] = '\0';
    client->state = CLIENT_STATE_PLAYING;
    
    /* Log that we need SPS/PPS/IDR for proper H.264 decoding */
    logger_info("Client %s:%d started PLAY for stream '%s' - will monitor for SPS/PPS/IDR frames", 
               client->client_ip, client->rtp_port, client->stream_name);
    
    /* Mark client as needing SPS/PPS injection */
    client->needs_sps_pps = true;
    
    /* Connect to stream manager to get video data */
    client_pool_t *pool = (client_pool_t *)client->callback_data;
    if (pool && pool->stream_manager) {
        /* Check stream health and reconnect if needed */
        if (stream_manager_check_and_reconnect_stream(pool->stream_manager, client->stream_name) == 0) {
            client->stream_connected = true;
            logger_info("*** STREAM CONNECTION *** Successfully connected client to stream '%s'", client->stream_name);
        } else {
            logger_error("*** STREAM CONNECTION FAILED *** Could not connect to stream '%s'", client->stream_name);
            client->stream_connected = false;
        }
    } else {
        logger_error("*** MISSING STREAM MANAGER *** Cannot connect client to stream");
        client->stream_connected = false;
    }
    
    int cseq = extract_cseq(request);
    return send_rtsp_response(client->socket_fd, 200, "OK", NULL, NULL, cseq);
}

/**
 * @brief Handle RTSP PAUSE request
 */
static int handle_pause_request(client_connection_t *client, const char *request) {
    (void)request; /* Suppress unused parameter warning */
    
    client->state = CLIENT_STATE_PAUSED;
    
    int cseq = extract_cseq(request);
    return send_rtsp_response(client->socket_fd, 200, "OK", NULL, NULL, cseq);
}

/**
 * @brief Handle RTSP TEARDOWN request
 */
static int handle_teardown_request(client_connection_t *client, const char *request) {
    (void)request; /* Suppress unused parameter warning */
    
    client->state = CLIENT_STATE_DISCONNECTED;
    
    int cseq = extract_cseq(request);
    return send_rtsp_response(client->socket_fd, 200, "OK", NULL, NULL, cseq);
}

/**
 * @brief Handle RTSP request
 */
static int handle_rtsp_request(client_connection_t *client, const char *request) {
    client_request_t req_type = parse_rtsp_request(request);
    
    client->stats.request_count++;
    client->stats.last_activity = get_timestamp_ms();
    
    switch (req_type) {
        case CLIENT_REQUEST_OPTIONS:
            return handle_options_request(client, request);
        case CLIENT_REQUEST_DESCRIBE:
            return handle_describe_request(client, request);
        case CLIENT_REQUEST_SETUP:
            return handle_setup_request(client, request);
        case CLIENT_REQUEST_PLAY:
            return handle_play_request(client, request);
        case CLIENT_REQUEST_PAUSE:
            return handle_pause_request(client, request);
        case CLIENT_REQUEST_TEARDOWN:
            return handle_teardown_request(client, request);
        default:
            logger_warn("Unknown RTSP request from %s: %.100s", client->client_ip, request);
            int cseq = extract_cseq(request);
            return send_rtsp_response(client->socket_fd, 501, "Not Implemented", NULL, NULL, cseq);
    }
}

/**
 * @brief Client handling thread
 */
static void *client_thread(void *arg) {
    client_connection_t *client = (client_connection_t *)arg;
    char buffer[2048];
    ssize_t bytes_read;
    
    logger_info("Client thread started for %s", client->client_ip);
    
    client->state = CLIENT_STATE_CONNECTED;
    client->stats.connection_time = get_timestamp_ms();
    
    while (!client->should_stop && client->state != CLIENT_STATE_DISCONNECTED) {
        /* Read RTSP request */
        bytes_read = recv(client->socket_fd, buffer, sizeof(buffer) - 1, 0);
        if (bytes_read <= 0) {
            if (bytes_read == 0) {
                logger_info("Client %s disconnected", client->client_ip);
            } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* Timeout occurred, continue to check should_stop */
                continue;
            } else {
                logger_error("Error reading from client %s: %s", client->client_ip, strerror(errno));
            }
            break;
        }
        
        buffer[bytes_read] = '\0';
        
        /* Validate RTSP request format */
        if (bytes_read < 4 || buffer[0] < 32 || buffer[0] > 126) {
            logger_warn("Invalid RTSP request from %s: received %zd bytes starting with 0x%02x", 
                       client->client_ip, bytes_read, (unsigned char)buffer[0]);
            client->stats.error_count++;
            
            /* If we receive too many corrupted requests, disconnect the client */
            if (client->stats.error_count > 10) {
                logger_error("Too many corrupted requests from %s, disconnecting client", client->client_ip);
                break;
            }
            continue;
        }
        
        /* Handle RTSP request */
        if (handle_rtsp_request(client, buffer) != 0) {
            logger_error("Failed to handle RTSP request from %s", client->client_ip);
            client->stats.error_count++;
        }
    }
    
    /* Cleanup UDP socket if open */
    if (client->udp_socket >= 0) {
        close(client->udp_socket);
        client->udp_socket = -1;
    }
    
    /* Disconnect from stream if connected */
    if (client->stream_connected && strlen(client->stream_name) > 0) {
        client_pool_t *pool = (client_pool_t *)client->callback_data;
        if (pool && pool->stream_manager) {
            /* Check if any other clients are watching this stream */
            bool other_clients_watching = false;
            pthread_mutex_lock(&pool->mutex);
            for (uint16_t i = 0; i < pool->max_clients; i++) {
                if (pool->clients[i].active && 
                    pool->clients[i].stream_connected &&
                    strcmp(pool->clients[i].stream_name, client->stream_name) == 0 &&
                    &pool->clients[i] != client) {
                    other_clients_watching = true;
                    break;
                }
            }
            pthread_mutex_unlock(&pool->mutex);
            
            /* Only disconnect stream if no other clients are watching */
            if (!other_clients_watching) {
                logger_info("No other clients watching stream '%s', disconnecting", client->stream_name);
                stream_manager_disconnect_stream(pool->stream_manager, client->stream_name);
            } else {
                logger_info("Other clients still watching stream '%s', keeping connection", client->stream_name);
            }
        }
    }
    
    logger_info("Client thread ended for %s", client->client_ip);
    return NULL;
}

/**
 * @brief Stream health check thread
 */
static void *health_check_thread(void *arg) {
    client_pool_t *pool = (client_pool_t *)arg;
    
    logger_info("Stream health check thread started");
    
    while (!pool->should_stop) {
        /* Sleep for 10 seconds between health checks to allow proper cleanup */
        sleep(10);
        
        if (pool->should_stop) break;
        
        /* Check health of all active streams */
        pthread_mutex_lock(&pool->mutex);
        for (uint16_t i = 0; i < pool->max_clients; i++) {
            if (pool->clients[i].active && 
                pool->clients[i].stream_connected &&
                strlen(pool->clients[i].stream_name) > 0) {
                
                /* Check if stream is still healthy */
                if (!stream_manager_is_stream_connected(pool->stream_manager, pool->clients[i].stream_name)) {
                    logger_warn("Stream '%s' is no longer connected, attempting to reconnect...", 
                               pool->clients[i].stream_name);
                    
                    /* Try to reconnect the stream */
                    if (stream_manager_check_and_reconnect_stream(pool->stream_manager, pool->clients[i].stream_name) == 0) {
                        logger_info("Successfully reconnected stream '%s'", pool->clients[i].stream_name);
                    } else {
                        logger_error("Failed to reconnect stream '%s'", pool->clients[i].stream_name);
                        pool->clients[i].stream_connected = false;
                    }
                } else {
                    /* Stream appears connected, but check if it's actually healthy */
                    if (stream_manager_check_and_reconnect_stream(pool->stream_manager, pool->clients[i].stream_name) != 0) {
                        logger_warn("Stream '%s' health check failed, marking as disconnected", 
                                   pool->clients[i].stream_name);
                        pool->clients[i].stream_connected = false;
                    }
                }
            }
        }
        pthread_mutex_unlock(&pool->mutex);
    }
    
    logger_info("Stream health check thread ended");
    return NULL;
}

/**
 * @brief Accept thread
 */
static void *accept_thread(void *arg) {
    client_pool_t *pool = (client_pool_t *)arg;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_socket;
    char client_ip[INET_ADDRSTRLEN];
    
    logger_info("Accept thread started on port %d", pool->listen_port);
    
    while (!pool->should_stop) {
        client_socket = accept(pool->listen_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* Timeout occurred, continue to check should_stop */
                continue;
            }
            logger_error("Failed to accept client connection: %s", strerror(errno));
            continue;
        }
        
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        uint16_t client_port = ntohs(client_addr.sin_port);
        
        logger_info("New client connection from %s:%d", client_ip, client_port);
        
        /* Add client to pool */
        if (client_pool_add_client(pool, client_socket, client_ip, client_port) != 0) {
            logger_error("Failed to add client %s:%d", client_ip, client_port);
            close(client_socket);
        }
    }
    
    logger_info("Accept thread ended");
    return NULL;
}

/**
 * @brief Create client pool
 */
client_pool_t *client_pool_create(config_t *config, stream_manager_t *stream_manager) {
    if (!config || !stream_manager) {
        logger_error("Client pool creation failed: NULL parameter");
        return NULL;
    }
    
    client_pool_t *pool = calloc(1, sizeof(client_pool_t));
    if (!pool) {
        logger_error("Client pool creation failed: memory allocation error");
        return NULL;
    }
    
    pool->config = config;
    pool->stream_manager = stream_manager;
    pool->listen_port = config->listen_port;
    pool->max_clients = config->max_clients;
    pool->active_clients = 0;
    pool->running = false;
    pool->should_stop = false;
    
    if (pthread_mutex_init(&pool->mutex, NULL) != 0) {
        logger_error("Failed to initialize client pool mutex");
        free(pool);
        return NULL;
    }
    
    /* Allocate client connections */
    pool->clients = calloc(pool->max_clients, sizeof(client_connection_t));
    if (!pool->clients) {
        logger_error("Failed to allocate memory for %d clients", pool->max_clients);
        pthread_mutex_destroy(&pool->mutex);
        free(pool);
        return NULL;
    }
    
    /* Initialize client connections */
    for (uint16_t i = 0; i < pool->max_clients; i++) {
        client_connection_t *client = &pool->clients[i];
        client->socket_fd = -1;
        client->udp_socket = -1;
        client->last_seq_num = 0;
        client->needs_sps_pps = false;
        client->state = CLIENT_STATE_DISCONNECTED;
        client->active = false;
        client->should_stop = false;
        
        if (pthread_mutex_init(&client->mutex, NULL) != 0) {
            logger_error("Failed to initialize mutex for client %d", i);
            /* Cleanup already initialized clients */
            for (uint16_t j = 0; j < i; j++) {
                pthread_mutex_destroy(&pool->clients[j].mutex);
            }
            free(pool->clients);
            pthread_mutex_destroy(&pool->mutex);
            free(pool);
            return NULL;
        }
    }
    
    logger_info("Client pool created with %d max clients on port %d", pool->max_clients, pool->listen_port);
    return pool;
}

/**
 * @brief Destroy client pool
 */
void client_pool_destroy(client_pool_t *pool) {
    if (!pool) return;
    
    logger_info("Destroying client pool...");
    
    /* Stop pool */
    client_pool_stop(pool);
    
    /* Cleanup clients */
    if (pool->clients) {
        for (uint16_t i = 0; i < pool->max_clients; i++) {
            client_connection_t *client = &pool->clients[i];
            pthread_mutex_destroy(&client->mutex);
        }
        free(pool->clients);
    }
    
    pthread_mutex_destroy(&pool->mutex);
    free(pool);
    logger_info("Client pool destroyed");
}

/**
 * @brief Start client pool
 */
int client_pool_start(client_pool_t *pool) {
    if (!pool) {
        logger_error("Client pool start failed: NULL pool");
        return -1;
    }
    
    if (pool->running) {
        logger_warn("Client pool already running");
        return 0;
    }
    
    logger_info("Starting client pool on port %d...", pool->listen_port);
    
    /* Create listening socket */
    pool->listen_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (pool->listen_socket < 0) {
        logger_error("Failed to create listening socket: %s", strerror(errno));
        return -1;
    }
    
    /* Set socket options */
    int opt = 1;
    if (setsockopt(pool->listen_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        logger_error("Failed to set socket options: %s", strerror(errno));
        close(pool->listen_socket);
        return -1;
    }
    
    /* Set accept timeout to allow checking should_stop flag */
    struct timeval timeout;
    timeout.tv_sec = 1;  /* 1 second timeout */
    timeout.tv_usec = 0;
    if (setsockopt(pool->listen_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        logger_error("Failed to set accept timeout: %s", strerror(errno));
        close(pool->listen_socket);
        return -1;
    }
    
    /* Bind socket */
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(pool->listen_port);
    
    if (bind(pool->listen_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        logger_error("Failed to bind socket to port %d: %s", pool->listen_port, strerror(errno));
        close(pool->listen_socket);
        return -1;
    }
    
    /* Start listening */
    if (listen(pool->listen_socket, 10) < 0) {
        logger_error("Failed to listen on socket: %s", strerror(errno));
        close(pool->listen_socket);
        return -1;
    }
    
    pool->running = true;
    pool->should_stop = false;
    
    /* Start accept thread */
    if (pthread_create(&pool->accept_thread, NULL, accept_thread, pool) != 0) {
        logger_error("Failed to create accept thread: %s", strerror(errno));
        close(pool->listen_socket);
        pool->running = false;
        return -1;
    }
    
    /* Start health check thread */
    if (pthread_create(&pool->health_check_thread, NULL, health_check_thread, pool) != 0) {
        logger_error("Failed to create health check thread: %s", strerror(errno));
        pool->should_stop = true;
        pthread_join(pool->accept_thread, NULL);
        close(pool->listen_socket);
        pool->running = false;
        return -1;
    }
    
    logger_info("Client pool started successfully on port %d", pool->listen_port);
    return 0;
}

/**
 * @brief Stop client pool
 */
int client_pool_stop(client_pool_t *pool) {
    if (!pool) {
        logger_error("Client pool stop failed: NULL pool");
        return -1;
    }
    
    if (!pool->running) {
        logger_warn("Client pool not running");
        return 0;
    }
    
    logger_info("Stopping client pool...");
    
    pool->should_stop = true;
    
    /* Close listening socket */
    if (pool->listen_socket >= 0) {
        close(pool->listen_socket);
        pool->listen_socket = -1;
    }
    
    /* Wait for accept thread */
    pthread_join(pool->accept_thread, NULL);
    
    /* Wait for health check thread */
    pthread_join(pool->health_check_thread, NULL);
    
    /* Stop all active clients */
    pthread_mutex_lock(&pool->mutex);
    for (uint16_t i = 0; i < pool->max_clients; i++) {
        client_connection_t *client = &pool->clients[i];
        if (client->active) {
            client->should_stop = true;
            if (client->socket_fd >= 0) {
                close(client->socket_fd);
                client->socket_fd = -1;
            }
            if (client->udp_socket >= 0) {
                close(client->udp_socket);
                client->udp_socket = -1;
            }
        }
    }
    pthread_mutex_unlock(&pool->mutex);
    
    /* Wait for client threads */
    for (uint16_t i = 0; i < pool->max_clients; i++) {
        client_connection_t *client = &pool->clients[i];
        if (client->active) {
            pthread_join(client->thread, NULL);
            client->active = false;
        }
    }
    
    pool->running = false;
    logger_info("Client pool stopped");
    return 0;
}

/**
 * @brief Add client connection
 */
int client_pool_add_client(client_pool_t *pool, int socket_fd, 
                           const char *client_ip, uint16_t client_port) {
    if (!pool || !client_ip) {
        logger_error("Add client failed: NULL parameter");
        return -1;
    }
    
    pthread_mutex_lock(&pool->mutex);
    
    if (pool->active_clients >= pool->max_clients) {
        logger_error("Maximum clients reached (%d), rejecting %s:%d", 
                    pool->max_clients, client_ip, client_port);
        pthread_mutex_unlock(&pool->mutex);
        return -1;
    }
    
    /* Find free client slot */
    client_connection_t *client = NULL;
    for (uint16_t i = 0; i < pool->max_clients; i++) {
        if (!pool->clients[i].active) {
            client = &pool->clients[i];
            break;
        }
    }
    
    if (!client) {
        logger_error("No free client slots available");
        pthread_mutex_unlock(&pool->mutex);
        return -1;
    }
    
    /* Initialize client */
    client->socket_fd = socket_fd;
    client->udp_socket = -1;
    client->last_seq_num = 0;
    client->needs_sps_pps = false;
    strncpy(client->client_ip, client_ip, sizeof(client->client_ip) - 1);
    client->client_ip[sizeof(client->client_ip) - 1] = '\0';
    client->client_port = client_port;
    client->rtp_port = 0; /* Will be set during SETUP */
    client->state = CLIENT_STATE_CONNECTING;
    client->active = true;
    client->should_stop = false;
    client->callback_data = pool; /* Set pool reference for stream manager access */
    
    /* Set recv timeout to allow checking should_stop flag */
    struct timeval timeout;
    timeout.tv_sec = 1;  /* 1 second timeout */
    timeout.tv_usec = 0;
    if (setsockopt(client->socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        logger_warn("Failed to set recv timeout for client %s: %s", client_ip, strerror(errno));
    }
    
    /* Clear any pending data in the socket buffer */
    char clear_buffer[1024];
    int cleared_bytes = 0;
    while (recv(client->socket_fd, clear_buffer, sizeof(clear_buffer), MSG_DONTWAIT) > 0) {
        cleared_bytes += sizeof(clear_buffer);
    }
    if (cleared_bytes > 0) {
        logger_info("Cleared %d bytes of stale data from client socket %s:%d", 
                   cleared_bytes, client_ip, client_port);
    }
    
    /* Start client thread */
    if (pthread_create(&client->thread, NULL, client_thread, client) != 0) {
        logger_error("Failed to create client thread for %s:%d: %s", 
                    client_ip, client_port, strerror(errno));
        client->active = false;
        pthread_mutex_unlock(&pool->mutex);
        return -1;
    }
    
    pool->active_clients++;
    pthread_mutex_unlock(&pool->mutex);
    
    logger_info("Added client %s:%d (total: %d)", client_ip, client_port, pool->active_clients);
    return 0;
}

/**
 * @brief Remove client connection
 */
int client_pool_remove_client(client_pool_t *pool, const char *client_id) {
    if (!pool || !client_id) {
        logger_error("Remove client failed: NULL parameter");
        return -1;
    }
    
    pthread_mutex_lock(&pool->mutex);
    
    /* Find client by ID */
    client_connection_t *client = NULL;
    for (uint16_t i = 0; i < pool->max_clients; i++) {
        char client_id_buf[64];
        generate_client_id(client_id_buf, sizeof(client_id_buf), 
                          pool->clients[i].client_ip, pool->clients[i].client_port);
        if (strcmp(client_id_buf, client_id) == 0) {
            client = &pool->clients[i];
            break;
        }
    }
    
    if (!client || !client->active) {
        logger_warn("Client %s not found or not active", client_id);
        pthread_mutex_unlock(&pool->mutex);
        return -1;
    }
    
    /* Stop client */
    client->should_stop = true;
    if (client->socket_fd >= 0) {
        close(client->socket_fd);
        client->socket_fd = -1;
    }
    if (client->udp_socket >= 0) {
        close(client->udp_socket);
        client->udp_socket = -1;
    }
    
    pool->active_clients--;
    pthread_mutex_unlock(&pool->mutex);
    
    /* Wait for thread to finish */
    pthread_join(client->thread, NULL);
    
    pthread_mutex_lock(&pool->mutex);
    client->active = false;
    client->state = CLIENT_STATE_DISCONNECTED;
    pthread_mutex_unlock(&pool->mutex);
    
    logger_info("Removed client %s (remaining: %d)", client_id, pool->active_clients);
    return 0;
}

/**
 * @brief Get client by ID
 */
client_connection_t *client_pool_get_client(client_pool_t *pool, const char *client_id) {
    if (!pool || !client_id) return NULL;
    
    pthread_mutex_lock(&pool->mutex);
    
    for (uint16_t i = 0; i < pool->max_clients; i++) {
        char client_id_buf[64];
        generate_client_id(client_id_buf, sizeof(client_id_buf), 
                          pool->clients[i].client_ip, pool->clients[i].client_port);
        if (strcmp(client_id_buf, client_id) == 0 && pool->clients[i].active) {
            pthread_mutex_unlock(&pool->mutex);
            return &pool->clients[i];
        }
    }
    
    pthread_mutex_unlock(&pool->mutex);
    return NULL;
}

/**
 * @brief Get client statistics
 */
int client_pool_get_client_stats(client_pool_t *pool, const char *client_id, 
                                 client_stats_t *stats) {
    if (!pool || !client_id || !stats) {
        logger_error("Client stats failed: NULL parameter");
        return -1;
    }
    
    client_connection_t *client = client_pool_get_client(pool, client_id);
    if (!client) {
        logger_error("Client not found: %s", client_id);
        return -1;
    }
    
    pthread_mutex_lock(&client->mutex);
    *stats = client->stats;
    pthread_mutex_unlock(&client->mutex);
    
    return 0;
}

/**
 * @brief Get pool statistics
 */
int client_pool_get_stats(client_pool_t *pool, uint16_t *total_clients,
                          uint16_t *active_clients, uint64_t *total_bytes) {
    if (!pool) {
        logger_error("Pool stats failed: NULL pool");
        return -1;
    }
    
    pthread_mutex_lock(&pool->mutex);
    
    if (total_clients) *total_clients = pool->max_clients;
    if (active_clients) *active_clients = pool->active_clients;
    
    uint64_t bytes = 0;
    if (total_bytes) {
        for (uint16_t i = 0; i < pool->max_clients; i++) {
            if (pool->clients[i].active) {
                bytes += pool->clients[i].stats.bytes_sent;
            }
        }
        *total_bytes = bytes;
    }
    
    pthread_mutex_unlock(&pool->mutex);
    
    return 0;
}

/**
 * @brief Broadcast data to all clients
 */
int client_pool_broadcast(client_pool_t *pool, const void *data, size_t len) {
    if (!pool || !data || len == 0) return 0;
    
    int sent_count = 0;
    
    pthread_mutex_lock(&pool->mutex);
    
    for (uint16_t i = 0; i < pool->max_clients; i++) {
        client_connection_t *client = &pool->clients[i];
        if (client->active && client->state == CLIENT_STATE_PLAYING) {
            ssize_t sent = send(client->socket_fd, data, len, 0);
            if (sent > 0) {
                client->stats.bytes_sent += sent;
                client->stats.packets_sent++;
                sent_count++;
            }
        }
    }
    
    pthread_mutex_unlock(&pool->mutex);
    
    return sent_count;
}

/**
 * @brief Broadcast data to clients of specific stream
 */
int client_pool_broadcast_stream(client_pool_t *pool, const char *stream_name,
                                 const void *data, size_t len) {
    if (!pool || !stream_name || !data || len == 0) return 0;
    
    int sent_count = 0;
    
    pthread_mutex_lock(&pool->mutex);
    
    /* Debug: Count clients */
    int total_clients = 0, active_clients = 0, playing_clients = 0, matching_stream_clients = 0;
    for (uint16_t i = 0; i < pool->max_clients; i++) {
        client_connection_t *client = &pool->clients[i];
        total_clients++;
        if (client->active) {
            active_clients++;
            if (client->state == CLIENT_STATE_PLAYING) {
                playing_clients++;
                if (strcmp(client->stream_name, stream_name) == 0) {
                    matching_stream_clients++;
                }
            }
        }
    }
    
    
    for (uint16_t i = 0; i < pool->max_clients; i++) {
        client_connection_t *client = &pool->clients[i];
        if (client->active && client->state == CLIENT_STATE_PLAYING &&
            strcmp(client->stream_name, stream_name) == 0) {
            
            /* Send RTP data to client's UDP port if specified */
            if (client->rtp_port > 0) {
                /* Create persistent UDP socket if not already created */
                if (client->udp_socket < 0) {
                    client->udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
                    if (client->udp_socket >= 0) {
                        /* Set up client address for future use */
                        memset(&client->client_addr, 0, sizeof(client->client_addr));
                        client->client_addr.sin_family = AF_INET;
                        client->client_addr.sin_port = htons(client->rtp_port);
                        inet_pton(AF_INET, client->client_ip, &client->client_addr.sin_addr);
                    } else {
                        logger_error("Failed to create UDP socket for client %s:%d: %s", 
                                   client->client_ip, client->rtp_port, strerror(errno));
                    }
                }
                
                if (client->udp_socket >= 0) {
                    /* Send SPS/PPS if client needs it and this is the first RTP packet */
                    /* DISABLED: Camera is now sending real SPS/PPS - no synthetic injection needed */
                    if (false && client->needs_sps_pps && client->stats.packets_sent == 0 && len >= 12) {
                        /* Extract timestamp from the real RTP packet for synchronization */
                        uint32_t real_timestamp = ((uint8_t*)data)[4] << 24 | ((uint8_t*)data)[5] << 16 | 
                                                 ((uint8_t*)data)[6] << 8 | ((uint8_t*)data)[7];
                        uint32_t real_ssrc = ((uint8_t*)data)[8] << 24 | ((uint8_t*)data)[9] << 16 | 
                                            ((uint8_t*)data)[10] << 8 | ((uint8_t*)data)[11];
                        logger_info("*** Injecting SPS/PPS for new client %s:%d ***", client->client_ip, client->rtp_port);
                        
                        /* Create synthetic SPS packet */
                        uint8_t sps_packet[64];
                        memset(sps_packet, 0, sizeof(sps_packet));
                        
                        /* RTP header for SPS */
                        sps_packet[0] = 0x80;  /* V=2, P=0, X=0, CC=0 */
                        sps_packet[1] = 0x60;  /* M=0, PT=96 */
                        sps_packet[2] = (client->last_seq_num >> 8) & 0xFF;
                        sps_packet[3] = client->last_seq_num & 0xFF;
                        /* Use real timestamp - 3 for SPS */
                        uint32_t sps_ts = real_timestamp - 3;
                        sps_packet[4] = (sps_ts >> 24) & 0xFF; sps_packet[5] = (sps_ts >> 16) & 0xFF; 
                        sps_packet[6] = (sps_ts >> 8) & 0xFF; sps_packet[7] = sps_ts & 0xFF;
                        /* Use real SSRC */
                        sps_packet[8] = (real_ssrc >> 24) & 0xFF; sps_packet[9] = (real_ssrc >> 16) & 0xFF; 
                        sps_packet[10] = (real_ssrc >> 8) & 0xFF; sps_packet[11] = real_ssrc & 0xFF;
                        /* NAL header for SPS (type 7) */
                        sps_packet[12] = 0x67; /* NAL type 7 (SPS) */
                        /* Minimal SPS data */
                        sps_packet[13] = 0x42; sps_packet[14] = 0x00; sps_packet[15] = 0x20;
                        sps_packet[16] = 0x95; sps_packet[17] = 0xa0; sps_packet[18] = 0xf0;
                        sps_packet[19] = 0x44; sps_packet[20] = 0xfc; sps_packet[21] = 0xb8;
                        sps_packet[22] = 0x0a; sps_packet[23] = 0x80;
                        
                        sendto(client->udp_socket, sps_packet, 24, 0, 
                               (struct sockaddr*)&client->client_addr, sizeof(client->client_addr));
                        client->last_seq_num++;
                        logger_info("*** Sent synthetic SPS packet (seq=%d) ***", client->last_seq_num - 1);
                        
                        /* Create synthetic PPS packet */
                        uint8_t pps_packet[32];
                        memset(pps_packet, 0, sizeof(pps_packet));
                        
                        /* RTP header for PPS */
                        pps_packet[0] = 0x80;  /* V=2, P=0, X=0, CC=0 */
                        pps_packet[1] = 0x60;  /* M=0, PT=96 */
                        pps_packet[2] = (client->last_seq_num >> 8) & 0xFF;
                        pps_packet[3] = client->last_seq_num & 0xFF;
                        /* Use real timestamp - 2 for PPS */
                        uint32_t pps_ts = real_timestamp - 2;
                        pps_packet[4] = (pps_ts >> 24) & 0xFF; pps_packet[5] = (pps_ts >> 16) & 0xFF; 
                        pps_packet[6] = (pps_ts >> 8) & 0xFF; pps_packet[7] = pps_ts & 0xFF;
                        /* Use real SSRC */
                        pps_packet[8] = (real_ssrc >> 24) & 0xFF; pps_packet[9] = (real_ssrc >> 16) & 0xFF; 
                        pps_packet[10] = (real_ssrc >> 8) & 0xFF; pps_packet[11] = real_ssrc & 0xFF;
                        /* NAL header for PPS (type 8) */
                        pps_packet[12] = 0x68; /* NAL type 8 (PPS) */
                        /* Minimal PPS data */
                        pps_packet[13] = 0xce; pps_packet[14] = 0x3c; pps_packet[15] = 0x80;
                        
                        sendto(client->udp_socket, pps_packet, 16, 0, 
                               (struct sockaddr*)&client->client_addr, sizeof(client->client_addr));
                        client->last_seq_num++;
                        logger_info("*** Sent synthetic PPS packet (seq=%d) ***", client->last_seq_num - 1);
                        
                        /* Create synthetic IDR I-frame packet */
                        uint8_t idr_packet[128];
                        memset(idr_packet, 0, sizeof(idr_packet));
                        
                        /* RTP header for IDR */
                        idr_packet[0] = 0x80;  /* V=2, P=0, X=0, CC=0 */
                        idr_packet[1] = 0xE0;  /* M=1, PT=96 (marker bit set for frame end) */
                        idr_packet[2] = (client->last_seq_num >> 8) & 0xFF;
                        idr_packet[3] = client->last_seq_num & 0xFF;
                        /* Use real timestamp - 1 for IDR */
                        uint32_t idr_ts = real_timestamp - 1;
                        idr_packet[4] = (idr_ts >> 24) & 0xFF; idr_packet[5] = (idr_ts >> 16) & 0xFF; 
                        idr_packet[6] = (idr_ts >> 8) & 0xFF; idr_packet[7] = idr_ts & 0xFF;
                        /* Use real SSRC */
                        idr_packet[8] = (real_ssrc >> 24) & 0xFF; idr_packet[9] = (real_ssrc >> 16) & 0xFF; 
                        idr_packet[10] = (real_ssrc >> 8) & 0xFF; idr_packet[11] = real_ssrc & 0xFF;
                        /* NAL header for IDR I-frame (type 5) */
                        idr_packet[12] = 0x65; /* NAL type 5 (IDR) */
                        /* Minimal I-frame data (black frame) */
                        idr_packet[13] = 0x88; idr_packet[14] = 0x84; idr_packet[15] = 0x00;
                        idr_packet[16] = 0x00; idr_packet[17] = 0x03; idr_packet[18] = 0x00;
                        idr_packet[19] = 0x00; idr_packet[20] = 0x03; idr_packet[21] = 0x00;
                        idr_packet[22] = 0x00; idr_packet[23] = 0x03; idr_packet[24] = 0x00;
                        idr_packet[25] = 0x32; idr_packet[26] = 0x20; idr_packet[27] = 0x00;
                        
                        sendto(client->udp_socket, idr_packet, 28, 0, 
                               (struct sockaddr*)&client->client_addr, sizeof(client->client_addr));
                        client->last_seq_num++;
                        logger_info("*** Sent synthetic IDR I-frame packet (seq=%d) ***", client->last_seq_num - 1);
                        
                        client->needs_sps_pps = false;
                        logger_info("*** SPS/PPS/IDR injection completed for client %s:%d ***", client->client_ip, client->rtp_port);
                    }
                    
                    /* Validate and potentially fix RTP packet */
                    uint8_t rtp_buffer[2048];
                    uint8_t *rtp_data;
                    size_t rtp_len = len;
                    
                    /* Copy data to modifiable buffer if needed */
                    if (len <= sizeof(rtp_buffer)) {
                        memcpy(rtp_buffer, data, len);
                        rtp_data = rtp_buffer;
                    } else {
                        rtp_data = (uint8_t *)data; /* Fallback for large packets */
                    }
                    
                    if (len >= 12 && (rtp_data[0] & 0xC0) == 0x80) {
                        /* Valid RTP packet - update sequence number if needed */
                        uint16_t seq_num = (rtp_data[2] << 8) | rtp_data[3];
                        uint8_t payload_type = rtp_data[1] & 0x7F;
                        
                        /* Log detailed RTP info for some packets */
                        if (client->stats.packets_sent <= 20 || client->stats.packets_sent % 50 == 0) {
                            if (client->stats.packets_sent == 10) {
                            }
                        }
                        
                        /* Analyze packet sizes to detect if we're getting real video */
                        static int large_packet_count = 0;
                        static int total_analyzed = 0;
                        
                        if (len > 500) large_packet_count++;  /* Real video frames are usually >500 bytes */
                        total_analyzed++;
                        
                        if (total_analyzed == 100) {
                            double large_percentage = (large_packet_count * 100.0) / total_analyzed;
                            if (large_percentage < 10) {
                                logger_error("*** PACKET SIZE ANALYSIS *** Only %.1f%% of packets >500 bytes - NOT video data!", large_percentage);
                                logger_error("*** Receiving control/parameter data only, no actual video frames ***");
                            } else {
                                logger_info("*** PACKET SIZE ANALYSIS *** %.1f%% of packets >500 bytes - looks like video data", large_percentage);
                            }
                        }

                        /* Check for SPS/PPS/I-frame and warn if missing */
                        if (payload_type == 96 && len > 12) {
                            uint8_t nal_header = rtp_data[12];
                            uint8_t nal_type = nal_header & 0x1F;
                            
                            /* Track critical NAL unit types per client */
                            static bool real_sps_seen = false, real_pps_seen = false, real_idr_seen = false;
                            static bool synthetic_sent = false;
                            /* static int warning_count = 0; */
                            static int total_packets = 0;
                            
                            total_packets++;
                            
                            if (nal_type == 7) {
                                real_sps_seen = true;
                            } else if (nal_type == 8) {
                                real_pps_seen = true;
                            } else if (nal_type == 5) {
                                real_idr_seen = true;
                            }
                            
                            /* Check if we sent synthetic frames */
                            if (client->stats.packets_sent >= 3 && !synthetic_sent) {
                                synthetic_sent = true; /* Assume we sent SPS/PPS/IDR if packets were sent */
                            }
                            
                            /* Status reporting and IDR waiting message */
                            if (total_packets == 5) {
                                          
                                if (real_sps_seen && real_pps_seen && !real_idr_seen) {
                                }
                            }
                            
                            /* Request IDR if we have SPS/PPS but no IDR after many packets */
                            if (real_sps_seen && real_pps_seen && !real_idr_seen && total_packets == 50) {
                                logger_warn("*** Have SPS+PPS but no IDR after %d packets - Camera may need keyframe request ***", total_packets);
                                logger_info("*** Try restarting camera stream or check camera settings for keyframe interval ***");
                            }
                            
                            /* Report when we have everything needed */
                            if (real_sps_seen && real_pps_seen && real_idr_seen && total_packets <= 20) {
                                logger_info("*** PERFECT! Camera sent SPS+PPS+IDR - VLC should now display video! ***");
                            }
                        }
                        
                        /* Always update sequence number to maintain continuity with synthetic packets */
                        uint16_t expected_seq = client->last_seq_num + 1;
                        if (seq_num != expected_seq) {
                            /* Update sequence number to maintain continuity */
                            rtp_data[2] = (expected_seq >> 8) & 0xFF;
                            rtp_data[3] = expected_seq & 0xFF;
                            seq_num = expected_seq;
                        }
                        client->last_seq_num = seq_num;
                    }
                    
                    /* Optional: dump first few packets to hex for analysis */
                    if (client->stats.packets_sent <= 3) {
                        char hex_dump[256];
                        size_t dump_len = rtp_len > 32 ? 32 : rtp_len;
                        for (size_t i = 0; i < dump_len; i++) {
                            sprintf(hex_dump + i*3, "%02x ", rtp_data[i]);
                        }
                    }
                    
                    ssize_t sent = sendto(client->udp_socket, rtp_data, rtp_len, 0, 
                                        (struct sockaddr*)&client->client_addr, sizeof(client->client_addr));
                    
                    if (sent > 0) {
                        client->stats.bytes_sent += sent;
                        client->stats.packets_sent++;
                        sent_count++;
                        
                        /* Log only first few packets and periodic stats */
                        if (client->stats.packets_sent <= 5) {
                        } else if (client->stats.packets_sent % 100 == 0) {
                            logger_info("*** STREAMING STATUS: %d packets (%llu bytes) sent to VLC client %s:%d ***", 
                                       (int)client->stats.packets_sent, 
                                       (unsigned long long)client->stats.bytes_sent,
                                       client->client_ip, client->rtp_port);
                        }
                    } else {
                        logger_error("*** CRITICAL: Failed to send UDP packet to %s:%d: %s ***", 
                                   client->client_ip, client->rtp_port, strerror(errno));
                    }
                }
            } else {
                /* Fallback: send over TCP connection */
                ssize_t sent = send(client->socket_fd, data, len, 0);
                if (sent > 0) {
                    client->stats.bytes_sent += sent;
                    client->stats.packets_sent++;
                    sent_count++;
                }
            }
        }
    }
    
    pthread_mutex_unlock(&pool->mutex);
    
    return sent_count;
}

/**
 * @brief Send data to clients of specific stream (alias for broadcast_stream)
 */
int client_pool_send_to_stream_clients(client_pool_t *pool, const char *stream_name,
                                      const void *data, size_t len) {
    return client_pool_broadcast_stream(pool, stream_name, data, len);
}

/**
 * @brief Register stream data callback
 */
int client_pool_register_stream_callback(client_pool_t *pool, 
                                       void (*callback)(const char *stream_name, const void *data, size_t len),
                                       void *user_data) {
    if (!pool) {
        logger_error("Callback registration failed: NULL pool");
        return -1;
    }
    
    pthread_mutex_lock(&pool->mutex);
    pool->stream_data_callback = callback;
    pool->stream_callback_data = user_data;
    pthread_mutex_unlock(&pool->mutex);
    
    logger_info("Registered stream data callback for client pool");
    return 0;
}

