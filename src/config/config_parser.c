/**
 * @file config_parser.c
 * @brief Configuration parsing and management implementation using cJSON
 */

#include "config/config_parser.h"
#include "logging/logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <cjson/cJSON.h>

/**
 * @brief Parse stream configuration from JSON object
 */
static int parse_stream_config(cJSON *stream_obj, stream_config_t *stream) {
    if (!stream_obj || !cJSON_IsObject(stream_obj)) {
        logger_error("Stream configuration is not a valid JSON object");
        return -1;
    }
    
    
    /* Initialize with defaults */
    memset(stream, 0, sizeof(stream_config_t));
    stream->max_clients = 4;
    stream->auth_required = false;
    
    /* Parse name (required) */
    cJSON *name_item = cJSON_GetObjectItem(stream_obj, "name");
    if (!name_item || !cJSON_IsString(name_item)) {
        logger_error("Stream configuration missing required 'name' field or not a string");
        return -1;
    }
    strncpy(stream->name, name_item->valuestring, sizeof(stream->name) - 1);
    stream->name[sizeof(stream->name) - 1] = '\0';
    
    /* Parse camera_id (optional) */
    cJSON *camera_item = cJSON_GetObjectItem(stream_obj, "camera_id");
    if (camera_item && cJSON_IsString(camera_item)) {
        strncpy(stream->camera_id, camera_item->valuestring, sizeof(stream->camera_id) - 1);
        stream->camera_id[sizeof(stream->camera_id) - 1] = '\0';
    } else {
        logger_warn("Stream '%s' missing camera_id field", stream->name);
    }
    
    /* Parse rtsp_url (required) */
    cJSON *url_item = cJSON_GetObjectItem(stream_obj, "rtsp_url");
    if (!url_item || !cJSON_IsString(url_item)) {
        logger_error("Stream '%s' missing required 'rtsp_url' field or not a string", stream->name);
        return -1;
    }
    strncpy(stream->rtsp_url, url_item->valuestring, sizeof(stream->rtsp_url) - 1);
    stream->rtsp_url[sizeof(stream->rtsp_url) - 1] = '\0';
    
    /* Parse username (optional) */
    cJSON *user_item = cJSON_GetObjectItem(stream_obj, "username");
    if (user_item && cJSON_IsString(user_item)) {
        strncpy(stream->username, user_item->valuestring, sizeof(stream->username) - 1);
        stream->username[sizeof(stream->username) - 1] = '\0';
        stream->auth_required = true;
    }
    
    /* Parse password (optional) */
    cJSON *pass_item = cJSON_GetObjectItem(stream_obj, "password");
    if (pass_item && cJSON_IsString(pass_item)) {
        strncpy(stream->password, pass_item->valuestring, sizeof(stream->password) - 1);
        stream->password[sizeof(stream->password) - 1] = '\0';
        stream->auth_required = true;
    }
    
    /* Parse max_clients (optional) */
    cJSON *max_item = cJSON_GetObjectItem(stream_obj, "max_clients");
    if (max_item && cJSON_IsNumber(max_item)) {
        int max_clients = (int)max_item->valuedouble;
        if (max_clients > 0 && max_clients <= 1000) {
            stream->max_clients = (uint16_t)max_clients;
            logger_debug("Stream '%s' max_clients set to %d", stream->name, max_clients);
        } else {
            logger_warn("Stream '%s' invalid max_clients value: %d (using default: 4)", 
                       stream->name, max_clients);
        }
    } else if (max_item && !cJSON_IsNumber(max_item)) {
        logger_warn("Stream '%s' max_clients is not a number (using default: 4)", stream->name);
    }
    
    logger_info("Parsed stream '%s': %s (auth: %s)", 
               stream->name, stream->rtsp_url, 
               stream->auth_required ? "yes" : "no");
    return 0;
}

/**
 * @brief Parse streams array from JSON
 */
static int parse_streams_array(cJSON *json, config_t *config) {
    cJSON *streams_array = cJSON_GetObjectItem(json, "streams");
    if (!streams_array) {
        logger_warn("No 'streams' array found in configuration");
        config->streams = NULL;
        config->stream_count = 0;
        return 0; /* Not an error - streams are optional */
    }
    
    if (!cJSON_IsArray(streams_array)) {
        logger_error("'streams' field is not an array");
        return -1;
    }
    
    int array_size = cJSON_GetArraySize(streams_array);
    
    if (array_size <= 0) {
        config->streams = NULL;
        config->stream_count = 0;
        logger_info("No streams configured");
        return 0;
    }
    
    config->streams = calloc(array_size, sizeof(stream_config_t));
    if (!config->streams) {
        logger_error("Failed to allocate memory for %d streams", array_size);
        return -1;
    }
    
    config->stream_count = 0;
    
    for (int i = 0; i < array_size; i++) {
        cJSON *stream_obj = cJSON_GetArrayItem(streams_array, i);
        if (!stream_obj) {
            logger_error("Failed to get stream object at index %d", i);
            continue;
        }
        
        
        if (parse_stream_config(stream_obj, &config->streams[config->stream_count]) == 0) {
            config->stream_count++;
        } else {
            logger_error("Failed to parse stream %d", i);
        }
    }
    
    if (config->stream_count == 0) {
        logger_warn("No valid streams found in configuration");
    }
    
    logger_info("Successfully parsed %d out of %d streams", config->stream_count, array_size);
    return 0;
}

/**
 * @brief Load configuration from file
 */
config_t *config_load(const char *filename) {
    if (!filename) {
        logger_error("Config filename is NULL");
        return NULL;
    }
    
    logger_info("Loading configuration from %s", filename);
    
    FILE *file = fopen(filename, "r");
    if (!file) {
        logger_error("Failed to open config file %s: %s", filename, strerror(errno));
        return NULL;
    }
    
    /* Read entire file */
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    if (file_size <= 0) {
        logger_error("Config file %s is empty or invalid size: %ld", filename, file_size);
        fclose(file);
        return NULL;
    }
    
    if (file_size > 1024 * 1024) { /* 1MB limit */
        logger_error("Config file %s is too large: %ld bytes (max 1MB)", filename, file_size);
        fclose(file);
        return NULL;
    }
    
    char *json_data = malloc(file_size + 1);
    if (!json_data) {
        logger_error("Failed to allocate memory for config file: %s", strerror(errno));
        fclose(file);
        return NULL;
    }
    
    size_t bytes_read = fread(json_data, 1, file_size, file);
    fclose(file);
    
    if (bytes_read != (size_t)file_size) {
        logger_error("Failed to read entire config file %s: read %zu of %ld bytes", 
                    filename, bytes_read, file_size);
        free(json_data);
        return NULL;
    }
    
    json_data[file_size] = '\0';
    
    /* Parse JSON */
    cJSON *json = cJSON_Parse(json_data);
    free(json_data);
    
    if (!json) {
        const char *error_ptr = cJSON_GetErrorPtr();
        logger_error("Failed to parse JSON configuration: %s", 
                    error_ptr ? error_ptr : "Unknown JSON error");
        return NULL;
    }
    
    
    /* Allocate config structure */
    config_t *config = calloc(1, sizeof(config_t));
    if (!config) {
        logger_error("Failed to allocate memory for configuration structure");
        cJSON_Delete(json);
        return NULL;
    }
    
    /* Set defaults */
    config->listen_port = 8554;
    config->max_clients = 16;
    config->max_memory_mb = 512;
    config->max_cpu_percent = 80;
    config->max_camera_connections = 8;
    config->max_bandwidth_per_stream = 2048; /* 2 Mbps */
    config->connection_timeout_ms = 30000;   /* 30 seconds */
    config->reconnection_delay_ms = 5000;    /* 5 seconds */
    config->max_reconnection_attempts = 3;
    strcpy(config->log_level, "info");
    strcpy(config->config_file, filename);
    
    /* Parse JSON values */
    cJSON *port_item = cJSON_GetObjectItem(json, "listen_port");
    if (port_item && cJSON_IsNumber(port_item)) {
        int port = (int)port_item->valuedouble;
        if (port > 0 && port <= 65535) {
            config->listen_port = (uint16_t)port;
        } else {
            logger_warn("Invalid listen_port value: %d (using default: 8554)", port);
        }
    } else if (port_item && !cJSON_IsNumber(port_item)) {
        logger_warn("listen_port is not a number (using default: 8554)");
    }
    
    cJSON *clients_item = cJSON_GetObjectItem(json, "max_clients");
    if (clients_item && cJSON_IsNumber(clients_item)) {
        int clients = (int)clients_item->valuedouble;
        if (clients > 0 && clients <= 1000) {
            config->max_clients = (uint16_t)clients;
        } else {
            logger_warn("Invalid max_clients value: %d (using default: 16)", clients);
        }
    } else if (clients_item && !cJSON_IsNumber(clients_item)) {
        logger_warn("max_clients is not a number (using default: 16)");
    }
    
    cJSON *memory_item = cJSON_GetObjectItem(json, "max_memory_mb");
    if (memory_item && cJSON_IsNumber(memory_item)) {
        int memory = (int)memory_item->valuedouble;
        if (memory > 0 && memory <= 8192) {
            config->max_memory_mb = (uint32_t)memory;
        } else {
            logger_warn("Invalid max_memory_mb value: %d (using default: 512)", memory);
        }
    } else if (memory_item && !cJSON_IsNumber(memory_item)) {
        logger_warn("max_memory_mb is not a number (using default: 512)");
    }
    
    cJSON *log_item = cJSON_GetObjectItem(json, "log_level");
    if (log_item && cJSON_IsString(log_item)) {
        strncpy(config->log_level, log_item->valuestring, sizeof(config->log_level) - 1);
        config->log_level[sizeof(config->log_level) - 1] = '\0';
    } else if (log_item && !cJSON_IsString(log_item)) {
        logger_warn("log_level is not a string (using default: 'info')");
    }
    
    /* Parse streams */
    if (parse_streams_array(json, config) != 0) {
        logger_error("Failed to parse streams configuration");
        cJSON_Delete(json);
        config_free(config);
        return NULL;
    }
    
    cJSON_Delete(json);
    
    /* Validate configuration */
    if (config_validate(config) != 0) {
        logger_error("Configuration validation failed");
        config_free(config);
        return NULL;
    }
    
    logger_info("Configuration loaded successfully from %s", filename);
    return config;
}

/**
 * @brief Free configuration structure
 */
void config_free(config_t *config) {
    if (!config) return;
    
    if (config->streams) {
        free(config->streams);
    }
    
    free(config);
}

/**
 * @brief Validate configuration
 */
int config_validate(const config_t *config) {
    if (!config) {
        logger_error("Configuration is NULL");
        return -1;
    }
    
    
    /* Validate port */
    if (config->listen_port == 0) {
        logger_error("Invalid listen port: %d", config->listen_port);
        return -1;
    }
    
    /* Validate limits */
    if (config->max_clients == 0 || config->max_clients > 1000) {
        logger_error("Invalid max_clients: %d", config->max_clients);
        return -1;
    }
    
    if (config->max_memory_mb == 0 || config->max_memory_mb > 8192) {
        logger_error("Invalid max_memory_mb: %d", config->max_memory_mb);
        return -1;
    }
    
    /* Validate streams */
    for (uint16_t i = 0; i < config->stream_count; i++) {
        const stream_config_t *stream = &config->streams[i];
        
        if (strlen(stream->name) == 0) {
            logger_error("Stream %d has empty name", i);
            return -1;
        }
        
        if (strlen(stream->rtsp_url) == 0) {
            logger_error("Stream '%s' has empty RTSP URL", stream->name);
            return -1;
        }
        
        if (stream->max_clients == 0) {
            logger_error("Stream '%s' has invalid max_clients: %d", stream->name, stream->max_clients);
            return -1;
        }
    }
    
    logger_info("Configuration validation passed");
    return 0;
}

/**
 * @brief Get default configuration
 */
config_t *config_get_defaults(void) {
    config_t *config = calloc(1, sizeof(config_t));
    if (!config) return NULL;
    
    config->listen_port = 8554;
    config->max_clients = 16;
    config->max_memory_mb = 512;
    config->max_cpu_percent = 80;
    config->max_camera_connections = 8;
    config->max_bandwidth_per_stream = 2048;
    config->connection_timeout_ms = 30000;
    config->reconnection_delay_ms = 5000;
    config->max_reconnection_attempts = 3;
    strcpy(config->log_level, "info");
    config->streams = NULL;
    config->stream_count = 0;
    
    return config;
}

/**
 * @brief Print configuration (for debugging)
 */
void config_print(const config_t *config) {
    if (!config) {
        printf("Configuration: NULL\n");
        return;
    }
    
    printf("Configuration:\n");
    printf("  Listen Port: %d\n", config->listen_port);
    printf("  Max Clients: %d\n", config->max_clients);
    printf("  Max Memory: %d MB\n", config->max_memory_mb);
    printf("  Max CPU: %d%%\n", config->max_cpu_percent);
    printf("  Log Level: %s\n", config->log_level);
    printf("  Streams: %d\n", config->stream_count);
    
    for (uint16_t i = 0; i < config->stream_count; i++) {
        const stream_config_t *stream = &config->streams[i];
        printf("    Stream %d: %s\n", i, stream->name);
        printf("      Camera ID: %s\n", stream->camera_id);
        printf("      RTSP URL: %s\n", stream->rtsp_url);
        printf("      Auth Required: %s\n", stream->auth_required ? "Yes" : "No");
        if (stream->auth_required) {
            printf("      Username: %s\n", stream->username);
        }
        printf("      Max Clients: %d\n", stream->max_clients);
    }
}

/**
 * @brief Save configuration to file
 */
int config_save(const config_t *config, const char *filename) {
    if (!config || !filename) {
        logger_error("config_save: NULL parameter");
        return -1;
    }
    
    cJSON *json = cJSON_CreateObject();
    if (!json) {
        logger_error("Failed to create JSON object");
        return -1;
    }
    
    /* Add basic configuration */
    cJSON_AddNumberToObject(json, "listen_port", config->listen_port);
    cJSON_AddNumberToObject(json, "max_clients", config->max_clients);
    cJSON_AddNumberToObject(json, "max_memory_mb", config->max_memory_mb);
    cJSON_AddStringToObject(json, "log_level", config->log_level);
    
    /* Add streams array */
    cJSON *streams_array = cJSON_CreateArray();
    if (!streams_array) {
        logger_error("Failed to create streams array");
        cJSON_Delete(json);
        return -1;
    }
    
    for (uint16_t i = 0; i < config->stream_count; i++) {
        const stream_config_t *stream = &config->streams[i];
        cJSON *stream_obj = cJSON_CreateObject();
        if (!stream_obj) {
            logger_error("Failed to create stream object %d", i);
            continue;
        }
        
        cJSON_AddStringToObject(stream_obj, "name", stream->name);
        cJSON_AddStringToObject(stream_obj, "camera_id", stream->camera_id);
        cJSON_AddStringToObject(stream_obj, "rtsp_url", stream->rtsp_url);
        
        if (stream->auth_required) {
            cJSON_AddStringToObject(stream_obj, "username", stream->username);
            cJSON_AddStringToObject(stream_obj, "password", stream->password);
        }
        
        cJSON_AddNumberToObject(stream_obj, "max_clients", stream->max_clients);
        cJSON_AddItemToArray(streams_array, stream_obj);
    }
    
    cJSON_AddItemToObject(json, "streams", streams_array);
    
    /* Write to file */
    char *json_string = cJSON_Print(json);
    if (!json_string) {
        logger_error("Failed to generate JSON string");
        cJSON_Delete(json);
        return -1;
    }
    
    FILE *file = fopen(filename, "w");
    if (!file) {
        logger_error("Failed to open file for writing: %s", strerror(errno));
        free(json_string);
        cJSON_Delete(json);
        return -1;
    }
    
    size_t json_len = strlen(json_string);
    size_t written = fwrite(json_string, 1, json_len, file);
    fclose(file);
    free(json_string);
    cJSON_Delete(json);
    
    if (written != json_len) {
        logger_error("Failed to write entire configuration to file");
        return -1;
    }
    
    logger_info("Configuration saved to %s", filename);
    return 0;
}

/**
 * @brief Reload configuration from file
 */
int config_reload(config_t *config, const char *filename) {
    if (!config || !filename) {
        logger_error("config_reload: NULL parameter");
        return -1;
    }
    
    config_t *new_config = config_load(filename);
    if (!new_config) {
        return -1;
    }
    
    /* Free old streams */
    if (config->streams) {
        free(config->streams);
    }
    
    /* Copy new configuration */
    *config = *new_config;
    
    /* Don't free new_config since we copied the data */
    free(new_config);
    
    logger_info("Configuration reloaded from %s", filename);
    return 0;
}