/**
 * @file client_pool.h
 * @brief Client pool for handling multiple RTSP clients
 * 
 * Manages incoming client connections, handles RTSP requests,
 * and relays stream data to multiple clients.
 */

#ifndef CLIENT_POOL_H
#define CLIENT_POOL_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <netinet/in.h>

/* Forward declarations */
typedef struct config_s config_t;
typedef struct stream_manager_s stream_manager_t;

/**
 * @brief Client connection states
 */
typedef enum {
    CLIENT_STATE_DISCONNECTED = 0,
    CLIENT_STATE_CONNECTING,
    CLIENT_STATE_CONNECTED,
    CLIENT_STATE_PLAYING,
    CLIENT_STATE_PAUSED,
    CLIENT_STATE_ERROR
} client_state_t;

/**
 * @brief Client request types
 */
typedef enum {
    CLIENT_REQUEST_OPTIONS = 0,
    CLIENT_REQUEST_DESCRIBE,
    CLIENT_REQUEST_SETUP,
    CLIENT_REQUEST_PLAY,
    CLIENT_REQUEST_PAUSE,
    CLIENT_REQUEST_TEARDOWN,
    CLIENT_REQUEST_UNKNOWN
} client_request_t;

/**
 * @brief Client statistics
 */
typedef struct client_stats_s {
    uint64_t bytes_sent;
    uint64_t packets_sent;
    uint64_t connection_time;
    uint64_t last_activity;
    uint32_t request_count;
    uint32_t error_count;
} client_stats_t;

/**
 * @brief Client connection structure
 */
typedef struct client_connection_s {
    int socket_fd;                  /**< Client socket file descriptor */
    char client_ip[INET_ADDRSTRLEN]; /**< Client IP address */
    uint16_t client_port;           /**< Client port */
    
    client_state_t state;           /**< Current client state */
    client_stats_t stats;           /**< Client statistics */
    
    pthread_t thread;               /**< Client handling thread */
    pthread_mutex_t mutex;          /**< Thread synchronization */
    
    bool active;                    /**< Whether client is active */
    bool should_stop;               /**< Stop flag for thread */
    
    /* RTSP session data */
    char session_id[64];            /**< RTSP session ID */
    char user_agent[128];           /**< Client user agent */
    char requested_stream[64];      /**< Requested stream name */
    
    /* Stream association */
    char stream_name[64];           /**< Associated stream name */
    bool stream_connected;          /**< Whether associated stream is connected */
    uint16_t rtp_port;              /**< Client RTP port for UDP transmission */
    
    /* UDP socket for RTP transmission */
    int udp_socket;                 /**< Persistent UDP socket for RTP */
    struct sockaddr_in client_addr; /**< Client address for UDP transmission */
    uint16_t last_seq_num;          /**< Last RTP sequence number sent */
    bool needs_sps_pps;             /**< Whether client needs SPS/PPS injection */
    
    /* Callback for stream data */
    void (*data_callback)(const char *client_id, const void *data, size_t len);
    void *callback_data;            /**< User data for callback */
} client_connection_t;

/**
 * @brief Client pool structure
 */
typedef struct client_pool_s {
    config_t *config;               /**< Configuration */
    stream_manager_t *stream_manager; /**< Stream manager reference */
    
    int listen_socket;              /**< Listening socket */
    uint16_t listen_port;           /**< Listening port */
    
    client_connection_t *clients;   /**< Array of client connections */
    uint16_t max_clients;           /**< Maximum clients */
    uint16_t active_clients;        /**< Current active clients */
    
    pthread_t accept_thread;        /**< Accept thread */
    pthread_mutex_t mutex;          /**< Pool synchronization */
    
    bool running;                   /**< Pool running state */
    bool should_stop;               /**< Stop flag */
    
    /* Stream data callback */
    void (*stream_data_callback)(const char *stream_name, const void *data, size_t len);
    void *stream_callback_data;     /**< User data for stream callback */
} client_pool_t;

/**
 * @brief Create client pool
 * 
 * @param config Configuration to use
 * @param stream_manager Stream manager reference
 * @return New client pool or NULL on error
 */
client_pool_t *client_pool_create(config_t *config, stream_manager_t *stream_manager);

/**
 * @brief Destroy client pool
 * 
 * @param pool Client pool to destroy
 */
void client_pool_destroy(client_pool_t *pool);

/**
 * @brief Start client pool
 * 
 * @param pool Client pool to start
 * @return 0 on success, -1 on error
 */
int client_pool_start(client_pool_t *pool);

/**
 * @brief Stop client pool
 * 
 * @param pool Client pool to stop
 * @return 0 on success, -1 on error
 */
int client_pool_stop(client_pool_t *pool);

/**
 * @brief Add client connection
 * 
 * @param pool Client pool
 * @param socket_fd Client socket
 * @param client_ip Client IP address
 * @param client_port Client port
 * @return 0 on success, -1 on error
 */
int client_pool_add_client(client_pool_t *pool, int socket_fd, 
                           const char *client_ip, uint16_t client_port);

/**
 * @brief Remove client connection
 * 
 * @param pool Client pool
 * @param client_id Client identifier
 * @return 0 on success, -1 on error
 */
int client_pool_remove_client(client_pool_t *pool, const char *client_id);

/**
 * @brief Get client by ID
 * 
 * @param pool Client pool
 * @param client_id Client identifier
 * @return Client connection or NULL if not found
 */
client_connection_t *client_pool_get_client(client_pool_t *pool, const char *client_id);

/**
 * @brief Get client statistics
 * 
 * @param pool Client pool
 * @param client_id Client identifier
 * @param stats Output statistics structure
 * @return 0 on success, -1 on error
 */
int client_pool_get_client_stats(client_pool_t *pool, const char *client_id, 
                                 client_stats_t *stats);

/**
 * @brief Get pool statistics
 * 
 * @param pool Client pool
 * @param total_clients Output total clients
 * @param active_clients Output active clients
 * @param total_bytes Output total bytes sent
 * @return 0 on success, -1 on error
 */
int client_pool_get_stats(client_pool_t *pool, uint16_t *total_clients,
                          uint16_t *active_clients, uint64_t *total_bytes);

/**
 * @brief Broadcast data to all clients
 * 
 * @param pool Client pool
 * @param data Data to broadcast
 * @param len Data length
 * @return Number of clients data was sent to
 */
int client_pool_broadcast(client_pool_t *pool, const void *data, size_t len);

/**
 * @brief Broadcast data to clients of specific stream
 * 
 * @param pool Client pool
 * @param stream_name Stream name
 * @param data Data to broadcast
 * @param len Data length
 * @return Number of clients data was sent to
 */
int client_pool_broadcast_stream(client_pool_t *pool, const char *stream_name,
                                 const void *data, size_t len);

/**
 * @brief Get client state string
 * 
 * @param state Client state
 * @return String representation of state
 */
const char *client_pool_state_to_string(client_state_t state);

/**
 * @brief Get client request type string
 * 
 * @param request Client request type
 * @return String representation of request
 */
const char *client_pool_request_to_string(client_request_t request);

/**
 * @brief Send data to clients of specific stream
 * @param pool Client pool instance
 * @param stream_name Name of the stream
 * @param data Data to send
 * @param len Length of data
 * @return Number of clients data was sent to
 */
int client_pool_send_to_stream_clients(client_pool_t *pool, const char *stream_name,
                                      const void *data, size_t len);

/**
 * @brief Register stream data callback
 * @param pool Client pool instance
 * @param callback Callback function for stream data
 * @param user_data User data for callback
 * @return 0 on success, -1 on error
 */
int client_pool_register_stream_callback(client_pool_t *pool, 
                                       void (*callback)(const char *stream_name, const void *data, size_t len),
                                       void *user_data);

#endif /* CLIENT_POOL_H */
