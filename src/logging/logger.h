/**
 * @file logger.h
 * @brief Logging system for CamRelay
 * 
 * Provides structured logging with different levels and
 * optional file output for daemon operation.
 */

#ifndef LOGGER_H
#define LOGGER_H

#include <stdarg.h>
#include <stdbool.h>

/**
 * @brief Log levels
 */
typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_FATAL
} log_level_t;

/**
 * @brief Initialize logging system
 * 
 * @param level_str Log level string ("debug", "info", "warn", "error")
 * @param log_file Optional log file path (NULL for stdout)
 * @return 0 on success, -1 on error
 */
int logger_init(const char *level_str);

/**
 * @brief Initialize logging with file output
 * 
 * @param level_str Log level string
 * @param log_file Log file path
 * @return 0 on success, -1 on error
 */
int logger_init_file(const char *level_str, const char *log_file);

/**
 * @brief Cleanup logging system
 */
void logger_cleanup(void);

/**
 * @brief Set log level
 * 
 * @param level New log level
 */
void logger_set_level(log_level_t level);

/**
 * @brief Get current log level
 * 
 * @return Current log level
 */
log_level_t logger_get_level(void);

/**
 * @brief Log a debug message
 * 
 * @param format Printf-style format string
 * @param ... Format arguments
 */
void logger_debug(const char *format, ...);

/**
 * @brief Log an info message
 * 
 * @param format Printf-style format string
 * @param ... Format arguments
 */
void logger_info(const char *format, ...);

/**
 * @brief Log a warning message
 * 
 * @param format Printf-style format string
 * @param ... Format arguments
 */
void logger_warn(const char *format, ...);

/**
 * @brief Log an error message
 * 
 * @param format Printf-style format string
 * @param ... Format arguments
 */
void logger_error(const char *format, ...);

/**
 * @brief Log a fatal error message
 * 
 * @param format Printf-style format string
 * @param ... Format arguments
 */
void logger_fatal(const char *format, ...);

/**
 * @brief Log a message with specific level
 * 
 * @param level Log level
 * @param format Printf-style format string
 * @param ... Format arguments
 */
void logger_log(log_level_t level, const char *format, ...);

/**
 * @brief Log a message with specific level and va_list
 * 
 * @param level Log level
 * @param format Printf-style format string
 * @param args va_list arguments
 */
void logger_vlog(log_level_t level, const char *format, va_list args);

/**
 * @brief Enable/disable colored output
 * 
 * @param enabled true to enable colors, false to disable
 */
void logger_set_colors(bool enabled);

/**
 * @brief Enable/disable timestamps
 * 
 * @param enabled true to enable timestamps, false to disable
 */
void logger_set_timestamps(bool enabled);

/**
 * @brief Get log level string
 * 
 * @param level Log level
 * @return String representation of log level
 */
const char *logger_level_to_string(log_level_t level);

/**
 * @brief Parse log level from string
 * 
 * @param str Log level string
 * @return Log level or LOG_LEVEL_INFO on error
 */
log_level_t logger_string_to_level(const char *str);

#endif /* LOGGER_H */
