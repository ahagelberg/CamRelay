/**
 * @file logger.c
 * @brief Logging system implementation for CamRelay
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include "logging/logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <stdarg.h>
#include <unistd.h>

/* Global logger state */
static struct {
    log_level_t level;
    bool colors_enabled;
    bool timestamps_enabled;
    FILE *output_file;
} logger_state = {
    .level = LOG_LEVEL_INFO,
    .colors_enabled = true,
    .timestamps_enabled = true,
    .output_file = NULL
};

/* Color codes for terminal output */
static const char *color_codes[] = {
    "\033[0m",    /* RESET */
    "\033[36m",   /* DEBUG - cyan */
    "\033[32m",   /* INFO - green */
    "\033[33m",   /* WARN - yellow */
    "\033[31m",   /* ERROR - red */
    "\033[35m"    /* FATAL - magenta */
};

/* Log level strings */
static const char *level_strings[] = {
    "DEBUG",
    "INFO",
    "WARN",
    "ERROR",
    "FATAL"
};

/**
 * @brief Get current timestamp string
 */
static void get_timestamp(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", tm_info);
}

/**
 * @brief Parse log level from string
 */
log_level_t logger_string_to_level(const char *str) {
    if (!str) return LOG_LEVEL_INFO;
    
    if (strcasecmp(str, "debug") == 0) return LOG_LEVEL_DEBUG;
    if (strcasecmp(str, "info") == 0) return LOG_LEVEL_INFO;
    if (strcasecmp(str, "warn") == 0) return LOG_LEVEL_WARN;
    if (strcasecmp(str, "error") == 0) return LOG_LEVEL_ERROR;
    if (strcasecmp(str, "fatal") == 0) return LOG_LEVEL_FATAL;
    
    return LOG_LEVEL_INFO;
}

/**
 * @brief Convert log level to string
 */
const char *logger_level_to_string(log_level_t level) {
    if (level >= 0 && level < 5) {
        return level_strings[level];
    }
    return "UNKNOWN";
}

/**
 * @brief Initialize logging system
 */
int logger_init(const char *level_str) {
    if (level_str) {
        logger_state.level = logger_string_to_level(level_str);
    }
    
    /* Check if we're running in a terminal */
    logger_state.colors_enabled = isatty(STDOUT_FILENO);
    
    return 0;
}

/**
 * @brief Initialize logging with file output
 */
int logger_init_file(const char *level_str, const char *log_file) {
    if (logger_init(level_str) != 0) {
        return -1;
    }
    
    if (log_file) {
        logger_state.output_file = fopen(log_file, "a");
        if (!logger_state.output_file) {
            return -1;
        }
        logger_state.colors_enabled = false; /* No colors in file */
    }
    
    return 0;
}

/**
 * @brief Cleanup logging system
 */
void logger_cleanup(void) {
    if (logger_state.output_file) {
        fclose(logger_state.output_file);
        logger_state.output_file = NULL;
    }
}

/**
 * @brief Set log level
 */
void logger_set_level(log_level_t level) {
    logger_state.level = level;
}

/**
 * @brief Get current log level
 */
log_level_t logger_get_level(void) {
    return logger_state.level;
}

/**
 * @brief Enable/disable colored output
 */
void logger_set_colors(bool enabled) {
    logger_state.colors_enabled = enabled;
}

/**
 * @brief Enable/disable timestamps
 */
void logger_set_timestamps(bool enabled) {
    logger_state.timestamps_enabled = enabled;
}

/**
 * @brief Log a message with specific level and va_list
 */
void logger_vlog(log_level_t level, const char *format, va_list args) {
    if (level < logger_state.level) {
        return;
    }
    
    FILE *output = logger_state.output_file ? logger_state.output_file : stdout;
    char timestamp[32] = {0};
    
    /* Get timestamp if enabled */
    if (logger_state.timestamps_enabled) {
        get_timestamp(timestamp, sizeof(timestamp));
    }
    
    /* Print with colors and timestamp if enabled */
    if (logger_state.colors_enabled && !logger_state.output_file) {
        fprintf(output, "%s[%s] %s: %s",
                color_codes[level + 1],
                timestamp[0] ? timestamp : "",
                logger_level_to_string(level),
                color_codes[0]);
    } else {
        fprintf(output, "[%s] %s: ",
                timestamp[0] ? timestamp : "",
                logger_level_to_string(level));
    }
    
    vfprintf(output, format, args);
    fprintf(output, "\n");
    fflush(output);
}

/**
 * @brief Log a message with specific level
 */
void logger_log(log_level_t level, const char *format, ...) {
    va_list args;
    va_start(args, format);
    logger_vlog(level, format, args);
    va_end(args);
}

/**
 * @brief Log a debug message
 */
void logger_debug(const char *format, ...) {
    va_list args;
    va_start(args, format);
    logger_vlog(LOG_LEVEL_DEBUG, format, args);
    va_end(args);
}

/**
 * @brief Log an info message
 */
void logger_info(const char *format, ...) {
    va_list args;
    va_start(args, format);
    logger_vlog(LOG_LEVEL_INFO, format, args);
    va_end(args);
}

/**
 * @brief Log a warning message
 */
void logger_warn(const char *format, ...) {
    va_list args;
    va_start(args, format);
    logger_vlog(LOG_LEVEL_WARN, format, args);
    va_end(args);
}

/**
 * @brief Log an error message
 */
void logger_error(const char *format, ...) {
    va_list args;
    va_start(args, format);
    logger_vlog(LOG_LEVEL_ERROR, format, args);
    va_end(args);
}

/**
 * @brief Log a fatal error message
 */
void logger_fatal(const char *format, ...) {
    va_list args;
    va_start(args, format);
    logger_vlog(LOG_LEVEL_FATAL, format, args);
    va_end(args);
}
