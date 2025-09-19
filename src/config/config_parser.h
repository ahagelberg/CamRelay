/**
 * @file config_parser.h
 * @brief Configuration parsing and management
 * 
 * Handles loading, parsing, and validation of configuration files
 * in various formats (JSON, INI, plain text).
 */

#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

#include <stdint.h>
#include <stdbool.h>

/**
 * @brief Stream configuration structure
 */
typedef struct stream_config_s {
    char name[64];              /**< Stream name */
    char camera_id[64];         /**< Camera identifier */
    char rtsp_url[256];         /**< RTSP URL */
    char username[64];          /**< Username for authentication */
    char password[64];          /**< Password for authentication */
    bool auth_required;         /**< Whether authentication is required */
    uint16_t max_clients;       /**< Maximum clients for this stream */
} stream_config_t;

/**
 * @brief Main configuration structure
 */
typedef struct config_s {
    uint16_t listen_port;           /**< Listening port for clients */
    uint16_t max_clients;           /**< Maximum total clients */
    uint32_t max_memory_mb;         /**< Maximum memory usage in MB */
    uint8_t max_cpu_percent;        /**< Maximum CPU usage percentage */
    uint8_t max_camera_connections; /**< Maximum camera connections */
    char log_level[16];             /**< Log level */
    char config_file[256];          /**< Configuration file path */
    
    stream_config_t *streams;       /**< Array of stream configurations */
    uint16_t stream_count;          /**< Number of streams */
    
    /* Resource limits */
    uint32_t max_bandwidth_per_stream; /**< Max bandwidth per stream in kbps */
    uint32_t connection_timeout_ms;    /**< Connection timeout in milliseconds */
    uint32_t reconnection_delay_ms;    /**< Reconnection delay in milliseconds */
    uint8_t max_reconnection_attempts; /**< Maximum reconnection attempts */
} config_t;

/**
 * @brief Load configuration from file
 * 
 * @param filename Configuration file path
 * @return Configuration structure or NULL on error
 */
config_t *config_load(const char *filename);

/**
 * @brief Free configuration structure
 * 
 * @param config Configuration to free
 */
void config_free(config_t *config);

/**
 * @brief Validate configuration
 * 
 * @param config Configuration to validate
 * @return 0 on success, -1 on error
 */
int config_validate(const config_t *config);

/**
 * @brief Get default configuration
 * 
 * @return Default configuration structure
 */
config_t *config_get_defaults(void);

/**
 * @brief Print configuration (for debugging)
 * 
 * @param config Configuration to print
 */
void config_print(const config_t *config);

/**
 * @brief Save configuration to file
 * 
 * @param config Configuration to save
 * @param filename Output file path
 * @return 0 on success, -1 on error
 */
int config_save(const config_t *config, const char *filename);

/**
 * @brief Reload configuration from file
 * 
 * @param config Existing configuration to update
 * @param filename Configuration file path
 * @return 0 on success, -1 on error
 */
int config_reload(config_t *config, const char *filename);

#endif /* CONFIG_PARSER_H */
