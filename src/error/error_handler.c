/**
 * @file error_handler.c
 * @brief Centralized error handling implementation for CamRelay
 */

#define _POSIX_C_SOURCE 200809L
#include "error/error_handler.h"
#include "logging/logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <pthread.h>

/* Global error handler state */
static struct {
    error_callback_t callback;
    error_t last_error;
    uint32_t total_errors;
    uint32_t critical_errors;
    uint32_t recoverable_errors;
    bool error_state;
    pthread_mutex_t mutex;
} error_state = {
    .callback = NULL,
    .total_errors = 0,
    .critical_errors = 0,
    .recoverable_errors = 0,
    .error_state = false
};

/**
 * @brief Get current timestamp
 */
static uint64_t get_timestamp(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/**
 * @brief Get error type string
 */
const char *error_type_to_string(error_type_t type) {
    switch (type) {
        case ERROR_TYPE_NETWORK: return "NETWORK";
        case ERROR_TYPE_CAMERA: return "CAMERA";
        case ERROR_TYPE_CLIENT: return "CLIENT";
        case ERROR_TYPE_RESOURCE: return "RESOURCE";
        case ERROR_TYPE_CONFIG: return "CONFIG";
        case ERROR_TYPE_SYSTEM: return "SYSTEM";
        default: return "UNKNOWN";
    }
}

/**
 * @brief Get error severity string
 */
const char *error_severity_to_string(error_severity_t severity) {
    switch (severity) {
        case ERROR_SEVERITY_LOW: return "LOW";
        case ERROR_SEVERITY_MEDIUM: return "MEDIUM";
        case ERROR_SEVERITY_HIGH: return "HIGH";
        case ERROR_SEVERITY_CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

/**
 * @brief Initialize error handling system
 */
int error_handler_init(void) {
    if (pthread_mutex_init(&error_state.mutex, NULL) != 0) {
        return -1;
    }
    
    memset(&error_state.last_error, 0, sizeof(error_t));
    error_state.total_errors = 0;
    error_state.critical_errors = 0;
    error_state.recoverable_errors = 0;
    error_state.error_state = false;
    
    logger_info("Error handling system initialized");
    return 0;
}

/**
 * @brief Cleanup error handling system
 */
void error_handler_cleanup(void) {
    pthread_mutex_destroy(&error_state.mutex);
    logger_info("Error handling system cleaned up");
}

/**
 * @brief Register error callback
 */
int error_handler_register_callback(error_callback_t callback) {
    pthread_mutex_lock(&error_state.mutex);
    error_state.callback = callback;
    pthread_mutex_unlock(&error_state.mutex);
    return 0;
}

/**
 * @brief Report an error
 */
void error_report(error_type_t type, error_severity_t severity, int code,
                  const char *source, const char *format, ...) {
    error_t error;
    va_list args;
    
    /* Initialize error structure */
    error.type = type;
    error.severity = severity;
    error.code = code;
    error.timestamp = get_timestamp();
    error.recoverable = (severity != ERROR_SEVERITY_CRITICAL);
    
    strncpy(error.source, source ? source : "unknown", sizeof(error.source) - 1);
    error.source[sizeof(error.source) - 1] = '\0';
    
    /* Format error message */
    va_start(args, format);
    vsnprintf(error.message, sizeof(error.message), format, args);
    va_end(args);
    
    /* Update statistics */
    pthread_mutex_lock(&error_state.mutex);
    error_state.last_error = error;
    error_state.total_errors++;
    
    if (severity == ERROR_SEVERITY_CRITICAL) {
        error_state.critical_errors++;
        error_state.error_state = true;
    }
    
    if (error.recoverable) {
        error_state.recoverable_errors++;
    }
    
    /* Log the error */
    switch (severity) {
        case ERROR_SEVERITY_LOW:
            logger_debug("Error [%s:%s] %s: %s", 
                        error_type_to_string(type),
                        error_severity_to_string(severity),
                        error.source, error.message);
            break;
        case ERROR_SEVERITY_MEDIUM:
            logger_warn("Error [%s:%s] %s: %s", 
                       error_type_to_string(type),
                       error_severity_to_string(severity),
                       error.source, error.message);
            break;
        case ERROR_SEVERITY_HIGH:
            logger_error("Error [%s:%s] %s: %s", 
                        error_type_to_string(type),
                        error_severity_to_string(severity),
                        error.source, error.message);
            break;
        case ERROR_SEVERITY_CRITICAL:
            logger_fatal("Error [%s:%s] %s: %s", 
                        error_type_to_string(type),
                        error_severity_to_string(severity),
                        error.source, error.message);
            break;
    }
    
    /* Call registered callback if available */
    if (error_state.callback) {
        error_state.callback(&error);
    }
    
    pthread_mutex_unlock(&error_state.mutex);
}

/**
 * @brief Report a recoverable error
 */
void error_report_recoverable(error_type_t type, int code, const char *source,
                              const char *format, ...) {
    va_list args;
    va_start(args, format);
    
    /* Create a temporary error for logging */
    error_t error;
    error.type = type;
    error.severity = ERROR_SEVERITY_MEDIUM;
    error.code = code;
    error.timestamp = get_timestamp();
    error.recoverable = true;
    
    strncpy(error.source, source ? source : "unknown", sizeof(error.source) - 1);
    error.source[sizeof(error.source) - 1] = '\0';
    
    vsnprintf(error.message, sizeof(error.message), format, args);
    va_end(args);
    
    /* Report as medium severity recoverable error */
    error_report(type, ERROR_SEVERITY_MEDIUM, code, source, "%s", error.message);
}

/**
 * @brief Report a critical error
 */
void error_report_critical(error_type_t type, int code, const char *source,
                           const char *format, ...) {
    va_list args;
    va_start(args, format);
    
    /* Create a temporary error for logging */
    error_t error;
    error.type = type;
    error.severity = ERROR_SEVERITY_CRITICAL;
    error.code = code;
    error.timestamp = get_timestamp();
    error.recoverable = false;
    
    strncpy(error.source, source ? source : "unknown", sizeof(error.source) - 1);
    error.source[sizeof(error.source) - 1] = '\0';
    
    vsnprintf(error.message, sizeof(error.message), format, args);
    va_end(args);
    
    /* Report as critical error */
    error_report(type, ERROR_SEVERITY_CRITICAL, code, source, "%s", error.message);
}

/**
 * @brief Get error statistics
 */
void error_get_stats(uint32_t *total_errors, uint32_t *critical_errors,
                     uint32_t *recoverable_errors) {
    pthread_mutex_lock(&error_state.mutex);
    
    if (total_errors) {
        *total_errors = error_state.total_errors;
    }
    if (critical_errors) {
        *critical_errors = error_state.critical_errors;
    }
    if (recoverable_errors) {
        *recoverable_errors = error_state.recoverable_errors;
    }
    
    pthread_mutex_unlock(&error_state.mutex);
}

/**
 * @brief Clear error statistics
 */
void error_clear_stats(void) {
    pthread_mutex_lock(&error_state.mutex);
    
    error_state.total_errors = 0;
    error_state.critical_errors = 0;
    error_state.recoverable_errors = 0;
    error_state.error_state = false;
    
    pthread_mutex_unlock(&error_state.mutex);
    
    logger_info("Error statistics cleared");
}

/**
 * @brief Check if system is in error state
 */
bool error_is_error_state(void) {
    bool error_state_flag;
    
    pthread_mutex_lock(&error_state.mutex);
    error_state_flag = error_state.error_state;
    pthread_mutex_unlock(&error_state.mutex);
    
    return error_state_flag;
}

/**
 * @brief Get last error
 */
const error_t *error_get_last(void) {
    const error_t *last_error = NULL;
    
    pthread_mutex_lock(&error_state.mutex);
    if (error_state.total_errors > 0) {
        last_error = &error_state.last_error;
    }
    pthread_mutex_unlock(&error_state.mutex);
    
    return last_error;
}
