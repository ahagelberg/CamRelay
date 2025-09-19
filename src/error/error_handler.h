/**
 * @file error_handler.h
 * @brief Centralized error handling for CamRelay
 * 
 * Provides error handling, recovery mechanisms, and
 * camera health monitoring.
 */

#ifndef ERROR_HANDLER_H
#define ERROR_HANDLER_H

#include <stdint.h>
#include <stdbool.h>

/**
 * @brief Error types
 */
typedef enum {
    ERROR_TYPE_NETWORK = 0,
    ERROR_TYPE_CAMERA,
    ERROR_TYPE_CLIENT,
    ERROR_TYPE_RESOURCE,
    ERROR_TYPE_CONFIG,
    ERROR_TYPE_SYSTEM
} error_type_t;

/**
 * @brief Error severity levels
 */
typedef enum {
    ERROR_SEVERITY_LOW = 0,
    ERROR_SEVERITY_MEDIUM,
    ERROR_SEVERITY_HIGH,
    ERROR_SEVERITY_CRITICAL
} error_severity_t;

/**
 * @brief Error structure
 */
typedef struct error_s {
    error_type_t type;           /**< Error type */
    error_severity_t severity;   /**< Error severity */
    int code;                    /**< Error code */
    char message[256];           /**< Error message */
    char source[64];             /**< Error source */
    uint64_t timestamp;          /**< Error timestamp */
    bool recoverable;            /**< Whether error is recoverable */
} error_t;

/**
 * @brief Error callback function type
 */
typedef void (*error_callback_t)(const error_t *error);

/**
 * @brief Initialize error handling system
 * 
 * @return 0 on success, -1 on error
 */
int error_handler_init(void);

/**
 * @brief Cleanup error handling system
 */
void error_handler_cleanup(void);

/**
 * @brief Register error callback
 * 
 * @param callback Function to call on errors
 * @return 0 on success, -1 on error
 */
int error_handler_register_callback(error_callback_t callback);

/**
 * @brief Report an error
 * 
 * @param type Error type
 * @param severity Error severity
 * @param code Error code
 * @param source Error source
 * @param format Printf-style format string
 * @param ... Format arguments
 */
void error_report(error_type_t type, error_severity_t severity, int code,
                  const char *source, const char *format, ...);

/**
 * @brief Report a recoverable error
 * 
 * @param type Error type
 * @param code Error code
 * @param source Error source
 * @param format Printf-style format string
 * @param ... Format arguments
 */
void error_report_recoverable(error_type_t type, int code, const char *source,
                              const char *format, ...);

/**
 * @brief Report a critical error
 * 
 * @param type Error type
 * @param code Error code
 * @param source Error source
 * @param format Printf-style format string
 * @param ... Format arguments
 */
void error_report_critical(error_type_t type, int code, const char *source,
                           const char *format, ...);

/**
 * @brief Get error statistics
 * 
 * @param total_errors Output total error count
 * @param critical_errors Output critical error count
 * @param recoverable_errors Output recoverable error count
 */
void error_get_stats(uint32_t *total_errors, uint32_t *critical_errors,
                     uint32_t *recoverable_errors);

/**
 * @brief Clear error statistics
 */
void error_clear_stats(void);

/**
 * @brief Check if system is in error state
 * 
 * @return true if in error state, false otherwise
 */
bool error_is_error_state(void);

/**
 * @brief Get last error
 * 
 * @return Last error or NULL if none
 */
const error_t *error_get_last(void);

/**
 * @brief Get error type string
 * 
 * @param type Error type
 * @return String representation
 */
const char *error_type_to_string(error_type_t type);

/**
 * @brief Get error severity string
 * 
 * @param severity Error severity
 * @return String representation
 */
const char *error_severity_to_string(error_severity_t severity);

#endif /* ERROR_HANDLER_H */
