/**
 * @file main.c
 * @brief CamRelay - Lightweight RTSP Relay for Linux
 * 
 * Main entry point for the CamRelay daemon.
 * Handles command line arguments, configuration loading,
 * and coordinates all system components.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <getopt.h>

#include "core/controller.h"
#include "config/config_parser.h"
#include "logging/logger.h"
#include "error/error_handler.h"

/* Global variables for signal handling */
static volatile sig_atomic_t running = 1;
static controller_t *g_controller = NULL;

/**
 * @brief Signal handler for graceful shutdown
 */
static void signal_handler(int sig) {
    switch (sig) {
        case SIGINT:
        case SIGTERM:
            logger_info("Received signal %d, initiating graceful shutdown...", sig);
            running = 0;
            if (g_controller) {
                controller_shutdown(g_controller);
            }
            break;
        case SIGHUP:
            logger_info("Received SIGHUP, reloading configuration...");
            // TODO: Implement configuration reload
            break;
        default:
            logger_warn("Received unexpected signal %d", sig);
            break;
    }
}

/**
 * @brief Setup signal handlers
 */
static int setup_signals(void) {
    struct sigaction sa;
    
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        logger_error("Failed to setup SIGINT handler: %s", strerror(errno));
        return -1;
    }
    
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        logger_error("Failed to setup SIGTERM handler: %s", strerror(errno));
        return -1;
    }
    
    if (sigaction(SIGHUP, &sa, NULL) == -1) {
        logger_warn("Failed to setup SIGHUP handler: %s", strerror(errno));
        // SIGHUP is optional, don't fail
    }
    
    return 0;
}

/**
 * @brief Print usage information
 */
static void print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS]\n", program_name);
    printf("\n");
    printf("Options:\n");
    printf("  -c, --config FILE    Configuration file (default: /etc/camrelay.conf)\n");
    printf("  -d, --daemon         Run as daemon\n");
    printf("  -p, --pid-file FILE  PID file location (default: /var/run/camrelay.pid)\n");
    printf("  -l, --log-level LEVEL Log level (debug, info, warn, error)\n");
    printf("  -h, --help           Show this help message\n");
    printf("  -v, --version        Show version information\n");
    printf("  -t, --test           Test mode - connect to streams and exit\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -c /etc/camrelay.conf -d\n", program_name);
    printf("  %s --config ./camrelay.conf --log-level debug\n", program_name);
}

/**
 * @brief Print version information
 */
static void print_version(void) {
    printf("CamRelay v0.1.0\n");
    printf("Lightweight RTSP Relay for Linux\n");
    printf("Built on %s %s\n", __DATE__, __TIME__);
}

/**
 * @brief Daemonize the process
 */
static int daemonize(const char *pid_file) {
    pid_t pid, sid;
    FILE *fp;
    
    /* Fork off the parent process */
    pid = fork();
    if (pid < 0) {
        logger_error("Failed to fork: %s", strerror(errno));
        return -1;
    }
    
    /* If we got a good PID, then we can exit the parent process */
    if (pid > 0) {
        exit(0);
    }
    
    /* Change the file mode mask */
    umask(0);
    
    /* Create a new SID for the child process */
    sid = setsid();
    if (sid < 0) {
        logger_error("Failed to create new session: %s", strerror(errno));
        return -1;
    }
    
    /* Change the current working directory */
    if (chdir("/") < 0) {
        logger_error("Failed to change directory: %s", strerror(errno));
        return -1;
    }
    
    /* Close out the standard file descriptors */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    /* Write PID file */
    if (pid_file) {
        fp = fopen(pid_file, "w");
        if (fp) {
            fprintf(fp, "%d\n", getpid());
            fclose(fp);
        }
    }
    
    return 0;
}

/**
 * @brief Main entry point
 */
int main(int argc, char *argv[]) {
    const char *config_file = "/etc/camrelay.conf";
    const char *pid_file = "/var/run/camrelay.pid";
    const char *log_level = "info";
    int daemon_mode = 0;
    int opt;
    
    /* Parse command line arguments */
    while ((opt = getopt(argc, argv, "c:dp:l:hvt")) != -1) {
        switch (opt) {
            case 'c':
                config_file = optarg;
                break;
            case 'd':
                daemon_mode = 1;
                break;
            case 'p':
                pid_file = optarg;
                break;
            case 'l':
                log_level = optarg;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            case 'v':
                print_version();
                return 0;
            case 't':
                /* Test mode - connect to streams and exit */
                logger_info("Running in test mode - will attempt to connect to all streams");
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    /* Initialize logging system */
    if (logger_init(log_level) != 0) {
        fprintf(stderr, "Failed to initialize logging system\n");
        return 1;
    }
    
    logger_info("Starting CamRelay v0.1.0");
    
    /* Setup signal handlers */
    if (setup_signals() != 0) {
        logger_error("Failed to setup signal handlers");
        return 1;
    }
    
    /* Daemonize if requested */
    if (daemon_mode) {
        if (daemonize(pid_file) != 0) {
            logger_error("Failed to daemonize process");
            return 1;
        }
        logger_info("Running as daemon with PID %d", getpid());
    }
    
    /* Load configuration */
    logger_info("Loading configuration from: %s", config_file);
    config_t *config = config_load(config_file);
    if (!config) {
        logger_error("Failed to load configuration from %s", config_file);
        logger_error("Please check that the file exists and contains valid JSON");
        logger_error("Use -h for help or see config/camrelay.json.example for format");
        return 1;
    }
    
    /* Initialize error handling */
    if (error_handler_init() != 0) {
        logger_error("Failed to initialize error handling");
        config_free(config);
        return 1;
    }
    
    /* Create and initialize controller */
    g_controller = controller_create(config);
    if (!g_controller) {
        logger_error("Failed to create controller");
        config_free(config);
        return 1;
    }
    
    /* Start the controller */
    if (controller_start(g_controller) != 0) {
        logger_error("Failed to start controller");
        controller_destroy(g_controller);
        config_free(config);
        return 1;
    }
    
    logger_info("CamRelay started successfully");
    
    /* Test mode - attempt to connect to all streams */
    if (opt == 't') {
        logger_info("Test mode: Attempting to connect to all configured streams...");
        
        /* Wait for connection attempts to complete */
        sleep(3);
        
        logger_info("Test mode completed");
        controller_destroy(g_controller);
        config_free(config);
        error_handler_cleanup();
        logger_cleanup();
        return 0;
    }
    
    /* Main event loop */
    while (running) {
        if (controller_process(g_controller) != 0) {
            logger_error("Controller processing failed");
            break;
        }
        usleep(100000); /* 100ms sleep to allow connection threads to show output */
    }
    
    /* Cleanup */
    logger_info("Shutting down CamRelay...");
    controller_destroy(g_controller);
    config_free(config);
    error_handler_cleanup();
    logger_cleanup();
    
    /* Remove PID file if we created it */
    if (daemon_mode && pid_file) {
        unlink(pid_file);
    }
    
    logger_info("CamRelay shutdown complete");
    return 0;
}
