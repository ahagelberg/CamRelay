/**
 * @file stream_manager.h
 * @brief Stream manager for RTSP source connections
 * 
 * Manages connections to RTSP source cameras, handles authentication,
 * and provides stream data to client pool.
 */

#ifndef STREAM_MANAGER_H
#define STREAM_MANAGER_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Include config parser for complete type definitions */
#include "config/config_parser.h"

/**
 * @brief RTP packet header structure
 */
typedef struct {
    uint8_t version:2;      /**< RTP version (2) */
    uint8_t padding:1;      /**< Padding flag */
    uint8_t extension:1;    /**< Extension flag */
    uint8_t csrc_count:4;   /**< CSRC count */
    uint8_t marker:1;       /**< Marker bit */
    uint8_t payload_type:7; /**< Payload type */
    uint16_t sequence;      /**< Sequence number */
    uint32_t timestamp;     /**< Timestamp */
    uint32_t ssrc;          /**< SSRC */
} __attribute__((packed)) rtp_header_t;

/**
 * @brief RTP packet structure
 */
typedef struct {
    rtp_header_t header;    /**< RTP header */
    uint8_t payload[];      /**< Payload data */
} rtp_packet_t;

/**
 * @brief Stream data callback function type
 * @param stream_name Name of the stream
 * @param data RTP packet data
 * @param size Size of the data
 * @param user_data User data passed to callback
 */
typedef void (*stream_data_callback_t)(const char *stream_name, const uint8_t *data, size_t size, void *user_data);

/**
 * @brief Stream connection states
 */
typedef enum {
    STREAM_STATE_DISCONNECTED = 0,
    STREAM_STATE_CONNECTING,
    STREAM_STATE_CONNECTED,
    STREAM_STATE_STREAMING,
    STREAM_STATE_ERROR,
    STREAM_STATE_RECONNECTING
} stream_state_t;

/**
 * @brief Stream statistics
 */
typedef struct stream_stats_s {
    uint64_t bytes_received;
    uint64_t packets_received;
    uint64_t frames_received;
    uint64_t connection_time;
    uint64_t last_packet_time;
    uint32_t reconnect_attempts;
    uint32_t error_count;
} stream_stats_t;

/**
 * @brief Stream connection structure
 */
typedef struct stream_connection_s {
    char name[64];                  /**< Stream name */
    char rtsp_url[256];            /**< RTSP URL */
    char username[64];              /**< Username for authentication */
    char password[64];              /**< Password for authentication */
    bool auth_required;             /**< Whether authentication is required */
    
    stream_state_t state;           /**< Current connection state */
    stream_stats_t stats;           /**< Stream statistics */
    
    int socket_fd;                  /**< Socket file descriptor */
    pthread_t thread;               /**< Stream processing thread */
    pthread_mutex_t mutex;          /**< Thread synchronization */
    
    bool active;                    /**< Whether stream is active */
    bool should_stop;               /**< Stop flag for thread */
    
    struct stream_manager_s *manager; /**< Reference to parent manager */
    
    /* RTSP session data */
    char session_id[64];            /**< RTSP session ID */
    uint16_t client_port;           /**< Client RTP port */
    uint16_t server_port;           /**< Server RTP port */
    
    /* UDP transport support */
    int rtp_socket;                 /**< UDP socket for RTP */
    int rtcp_socket;                /**< UDP socket for RTCP */
    struct sockaddr_in server_rtp_addr;  /**< Server RTP address */
    struct sockaddr_in server_rtcp_addr; /**< Server RTCP address */
    bool use_udp_transport;         /**< Whether to use UDP transport */
    
    /* Callback for data */
    void (*data_callback)(const char *stream_name, const void *data, size_t len);
    void *callback_data;            /**< User data for callback */
} stream_connection_t;

/**
 * @brief Stream manager structure
 */
typedef struct stream_manager_s {
    config_t *config;               /**< Configuration */
    stream_connection_t *streams;   /**< Array of stream connections */
    uint16_t stream_count;          /**< Number of streams */
    
    pthread_mutex_t mutex;          /**< Manager synchronization */
    bool running;                   /**< Manager running state */
    
    /* Resource management */
    uint32_t max_connections;       /**< Maximum concurrent connections */
    uint32_t active_connections;    /**< Current active connections */
    
    /* Global data callback */
    stream_data_callback_t data_callback;  /**< Global data callback function */
    void *callback_user_data;              /**< User data for callback */
} stream_manager_t;

/**
 * @brief Create stream manager
 * 
 * @param config Configuration to use
 * @return New stream manager or NULL on error
 */
stream_manager_t *stream_manager_create(config_t *config);

/**
 * @brief Destroy stream manager
 * 
 * @param manager Stream manager to destroy
 */
void stream_manager_destroy(stream_manager_t *manager);

/**
 * @brief Start stream manager
 * 
 * @param manager Stream manager to start
 * @return 0 on success, -1 on error
 */
int stream_manager_start(stream_manager_t *manager);

/**
 * @brief Stop stream manager
 * 
 * @param manager Stream manager to stop
 * @return 0 on success, -1 on error
 */
int stream_manager_stop(stream_manager_t *manager);

/**
 * @brief Connect to a specific stream
 * 
 * @param manager Stream manager
 * @param stream_name Name of stream to connect
 * @return 0 on success, -1 on error
 */
int stream_manager_connect_stream(stream_manager_t *manager, const char *stream_name);

/**
 * @brief Disconnect a specific stream
 * 
 * @param manager Stream manager
 * @param stream_name Name of stream to disconnect
 * @return 0 on success, -1 on error
 */
int stream_manager_disconnect_stream(stream_manager_t *manager, const char *stream_name);

/**
 * @brief Check if stream is connected
 * 
 * @param manager Stream manager
 * @param stream_name Name of stream to check
 * @return true if connected, false otherwise
 */
bool stream_manager_is_stream_connected(stream_manager_t *manager, const char *stream_name);

/**
 * @brief Check stream health and reconnect if needed
 * 
 * @param manager Stream manager
 * @param stream_name Name of stream to check
 * @return 0 on success, -1 on error
 */
int stream_manager_check_and_reconnect_stream(stream_manager_t *manager, const char *stream_name);

/**
 * @brief Get stream statistics
 * 
 * @param manager Stream manager
 * @param stream_name Name of stream
 * @param stats Output statistics structure
 * @return 0 on success, -1 on error
 */
int stream_manager_get_stream_stats(stream_manager_t *manager, const char *stream_name, 
                                   stream_stats_t *stats);

/**
 * @brief Set data callback for stream
 * 
 * @param manager Stream manager
 * @param stream_name Name of stream
 * @param callback Callback function
 * @param user_data User data for callback
 * @return 0 on success, -1 on error
 */
int stream_manager_set_data_callback(stream_manager_t *manager, const char *stream_name,
                                    void (*callback)(const char *stream_name, const void *data, size_t len),
                                    void *user_data);

/**
 * @brief Get stream manager statistics
 * 
 * @param manager Stream manager
 * @param total_streams Output total streams
 * @param active_streams Output active streams
 * @param total_bytes Output total bytes received
 * @return 0 on success, -1 on error
 */
int stream_manager_get_stats(stream_manager_t *manager, uint16_t *total_streams,
                            uint16_t *active_streams, uint64_t *total_bytes);

/**
 * @brief Reconnect all streams
 * 
 * @param manager Stream manager
 * @return 0 on success, -1 on error
 */
int stream_manager_reconnect_all(stream_manager_t *manager);

/**
 * @brief Get stream state string
 * 
 * @param state Stream state
 * @return String representation of state
 */
const char *stream_manager_state_to_string(stream_state_t state);

/**
 * @brief Register global data callback for all streams
 * @param manager Stream manager instance
 * @param callback Callback function to call when data is received
 * @param user_data User data to pass to callback
 * @return 0 on success, -1 on error
 */
int stream_manager_register_data_callback(stream_manager_t *manager, stream_data_callback_t callback, void *user_data);

#endif /* STREAM_MANAGER_H */
