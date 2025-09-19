/**
 * @file controller.h
 * @brief Main controller for CamRelay system
 * 
 * The controller coordinates all system components including
 * stream management, client handling, and resource management.
 */

#ifndef CONTROLLER_H
#define CONTROLLER_H

#include <stdint.h>
#include <stdbool.h>

/* Forward declarations */
typedef struct config_s config_t;
typedef struct stream_manager_s stream_manager_t;
typedef struct client_pool_s client_pool_t;
typedef struct resource_manager_s resource_manager_t;

/**
 * @brief Controller structure
 */
typedef struct controller_s {
    config_t *config;                    /**< Configuration */
    stream_manager_t *stream_manager;    /**< Stream management */
    client_pool_t *client_pool;          /**< Client handling */
    resource_manager_t *resource_mgr;    /**< Resource management */
    bool running;                        /**< Running state */
    uint64_t start_time;                 /**< Start timestamp */
} controller_t;

/**
 * @brief Create a new controller instance
 * 
 * @param config Configuration to use
 * @return New controller instance or NULL on error
 */
controller_t *controller_create(config_t *config);

/**
 * @brief Destroy a controller instance
 * 
 * @param controller Controller to destroy
 */
void controller_destroy(controller_t *controller);

/**
 * @brief Start the controller
 * 
 * @param controller Controller to start
 * @return 0 on success, -1 on error
 */
int controller_start(controller_t *controller);

/**
 * @brief Stop the controller
 * 
 * @param controller Controller to stop
 * @return 0 on success, -1 on error
 */
int controller_stop(controller_t *controller);

/**
 * @brief Process controller events (main loop)
 * 
 * @param controller Controller to process
 * @return 0 on success, -1 on error
 */
int controller_process(controller_t *controller);

/**
 * @brief Shutdown the controller gracefully
 * 
 * @param controller Controller to shutdown
 */
void controller_shutdown(controller_t *controller);

/**
 * @brief Get controller statistics
 * 
 * @param controller Controller instance
 * @param stats Output statistics structure
 * @return 0 on success, -1 on error
 */
int controller_get_stats(controller_t *controller, void *stats);

/**
 * @brief Check if controller is running
 * 
 * @param controller Controller instance
 * @return true if running, false otherwise
 */
bool controller_is_running(controller_t *controller);

#endif /* CONTROLLER_H */
