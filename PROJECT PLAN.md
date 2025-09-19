# Project Plan: Lightweight RTSP Relay for Linux

## Overview

Develop a lightweight Linux program to receive multiple RTSP video streams from network cameras and rebroadcast them to multiple clients. The program should minimize resource usage by only pulling from a camera's RTSP stream when at least one client is actively viewing the relay stream. The solution should run on Debian/Ubuntu with minimal external dependencies.

---

## Goals

- **Receive multiple live RTSP streams** from network cameras.
- **Re-broadcast each stream to multiple clients** (unicast/multicast).
- **On-demand streaming:** Only connect to the source camera when there are active clients.
- **Lightweight:** Minimal memory and CPU usage.
- **Minimal dependencies:** Prefer standard C/C++ and POSIX APIs; avoid heavyweight FFMPEG if possible; use only essential external libraries.
- **Support authentication for camera streams:** Allow passing usernames and passwords (or other credentials) for RTSP camera sources that require authentication.
- **Run as a background service** (daemon).
- **Configurable via file or command-line.**

---

## High-Level Architecture

**Single Process Design:** The program runs as a single process with threading for client handling.

- **Main Controller:** Central coordinator managing all components and resource limits.
- **Listener/Controller:** Handles client connections and stream requests.
- **Stream Manager:** Manages source RTSP connections (with authentication support) and relays data to clients; starts/stops source streams as needed.
- **Client Handler Pool:** One thread per client for simplicity; manages individual client sessions, relaying data from the Stream Manager.
- **Configuration Module:** Parses and validates configuration with sane defaults for missing parameters.
- **Logging/Stats Module:** Provides basic logging and connection statistics.
- **Resource Manager:** Enforces configurable resource limits (max clients, memory, CPU).

---

## Resource Limits & Configuration

- **Configurable Limits:**
  - Maximum number of concurrent clients
  - Maximum memory usage (in MB)
  - Maximum CPU usage percentage
  - Maximum number of concurrent camera connections
  - Maximum bandwidth per stream
- **Default Values:**
  - Max clients: 16
  - Max memory: 512 MB
  - Max CPU: 80%
  - Max camera connections: 8
- **Configuration Validation:**
  - Verify all required fields on startup
  - Use sane defaults for missing optional parameters
  - Validate RTSP URLs and authentication credentials
  - Check resource limit values for reasonableness

---

## Key Features

1. **Stream Multiplexing:** Efficiently relay each camera stream to multiple clients without duplicating source connections.
2. **On-Demand Source Pull:** Only connect to a source camera when at least one client requests the stream; disconnect when all clients leave.
3. **Protocol Support:** Support RTSP 1.0 and 2.0 over TCP (primary) and UDP for both source and client.
4. **Codec Support:** Primary support for H.264 video codec; H.265 support planned for future versions.
5. **Web Browser Compatibility:** Broadcast protocol suitable for viewing in web browsers using existing or custom client.
6. **Authentication Support:** Allow configuration of username/password (or other credentials) for each RTSP source stream.
7. **Multiple Streams per Camera:** Support multiple RTSP streams from a single camera/source.
8. **Minimal Dependencies:** 
    - Use system sockets, select/poll.
    - Optionally use `live555` or `librist` (very lightweight) for RTSP/RTP parsing if needed.
9. **Configurable:** Camera list (with authentication), listening port, max clients, logging level, resource limits.
10. **Configuration Validation:** Verify config file on startup with sane defaults for missing parameters.
11. **Error Handling:** Camera offline events terminate client connections (with configurable strategies).
12. **Graceful Shutdown:** Clean up all sockets and resources on exit.

---

## Error Handling & Camera Offline Scenarios

- **Camera Offline Detection:**
  - Monitor RTSP connection health
  - Implement configurable timeout values
  - Detect network disconnections and authentication failures
- **Client Connection Termination:**
  - Immediately terminate client connections when source camera goes offline
  - Send appropriate error messages to clients
  - Log offline events for monitoring
- **Recovery Strategies:**
  - Automatic reconnection attempts with exponential backoff
  - Configurable retry intervals and maximum retry attempts
  - Graceful degradation when cameras are unavailable
- **Future Enhancement Options:**
  - Fallback to secondary camera streams
  - Cached frame display during outages
  - Client notification of stream status changes

---

## Project Phases & Milestones

### Phase 1: Design & Research
- Research lightweight RTSP/RTP handling libraries and authentication handling.
- Investigate system socket programming for streaming.
- Design configuration format (JSON or simple plain text file), including authentication fields and resource limits.
- Research web browser compatibility requirements for RTSP streaming.
- **Deliverable:** Design document, tech stack selection, configuration schema.

### Phase 2: Core Relay Implementation
- Implement configuration parser with validation and defaults (including parsing authentication info).
- Implement client listener (TCP primary, UDP fallback).
- Implement single-stream relay (with authentication) to one client.
- Implement basic error handling for camera offline scenarios.
- **Deliverable:** Proof-of-concept: relay single camera (with/without authentication) to single client.

### Phase 3: Multi-Client & Multi-Stream Support
- Implement one-thread-per-client model for simplicity.
- Manage multiple client connections per stream.
- Manage multiple streams from different cameras (with individualized authentication).
- Support multiple streams per camera/source.
- Implement on-demand source connect/disconnect logic.
- **Deliverable:** Relay multiple cameras (with authentication) to multiple clients, with on-demand logic.

### Phase 4: Robustness & Optimization
- Add timeout handling, error recovery, reconnection logic.
- Implement configurable resource limits (max clients, memory, CPU).
- Add camera offline handling with client connection termination.
- Optimize for low memory/CPU footprint.
- Add basic logging and stats.
- **Deliverable:** Robust, efficient service with logging and resource management.

### Phase 5: Packaging & Documentation
- Create systemd service file for easy daemonization.
- Write user guide and configuration instructions.
- Provide example configuration files with all options.
- Test web browser compatibility.
- **Deliverable:** Ready-to-use package with docs.

### Phase 6: Future Enhancements (Optional)
- Add H.265 codec support.
- Implement configuration reload without restart.
- Add advanced security features.
- **Deliverable:** Enhanced features for future releases.

---

## Tech Stack & Dependencies

- **Language:** C or C++
- **Process Model:** Single process with pthreads for client handling
- **RTSP/RTP:** 
    - Option 1: Use [live555](http://www.live555.com/liveMedia/) (very lightweight, pure C++ RTSP library with authentication support).
    - Option 2: Write minimal RTSP/RTP parser (if avoiding all external libs), including authentication logic.
- **Protocol Support:** RTSP 1.0 and 2.0, TCP primary, UDP fallback
- **Codec Support:** H.264 (primary), H.265 (future)
- **Build System:** Makefile or CMake
- **No GUI:** CLI only
- **Other:** POSIX sockets, pthreads/epoll/select

---

## Risks & Mitigations

- **RTSP Complexity and Authentication:** Use live555 or similar for protocol and authentication handling to avoid reimplementing the protocol.
- **Resource Leaks:** Careful management of sockets and threads; implement configurable resource limits.
- **Camera Compatibility:** Test with various brands/models of network cameras (with and without authentication).
- **Thread Management:** One thread per client may scale poorly; monitor performance and consider thread pools for future optimization.
- **Camera Offline Handling:** Implement robust error handling and client notification strategies.
- **Web Browser Compatibility:** Ensure RTSP streams are accessible via web browsers through appropriate protocols.

---

## Deliverables

- Source code (well-commented, modular).
- Example configuration (with authentication options).
- Build instructions.
- Systemd service file.
- User documentation.

---

## Stretch Goals

- Web interface for monitoring/management.
- Per-stream bandwidth limiting.
- Simple access control for clients.

---

## Example Configuration (JSON)

{
  "listen_port": 8554,
  "max_clients": 16,
  "max_memory_mb": 512,
  "log_level": "info",
  "streams": [
    {
      "name": "cam1_main",
      "camera_id": "cam1",
      "rtsp_url": "rtsp://192.168.1.100:554/stream1",
      "username": "admin",
      "password": "mypassword"
    },
    {
      "name": "cam1_sub",
      "camera_id": "cam1",
      "rtsp_url": "rtsp://192.168.1.100:554/stream2",
      "username": "admin",
      "password": "mypassword"
    },
    {
      "name": "cam2_main",
      "camera_id": "cam2",
      "rtsp_url": "rtsp://192.168.1.101:554/stream"
    }
  ]
}

### Example Configuration (plain text, alternative)

listen_port=8554
max_clients=16
max_memory_mb=512
log_level=info

[stream]
camera_id=cam1
name=cam1_main
rtsp_url=rtsp://192.168.1.100:554/stream1
username=admin
password=mypassword

[stream]
camera_id=cam1
name=cam1_sub
rtsp_url=rtsp://192.168.1.100:554/stream2
username=admin
password=mypassword

[stream]
camera_id=cam2
name=cam2_main
rtsp_url=rtsp://192.168.1.101:554/stream

---

## References

- [live555 Streaming Media](http://www.live555.com/liveMedia/)
- [RFC 2326 RTSP](https://datatracker.ietf.org/doc/html/rfc2326)
- [POSIX Sockets Programming](https://beej.us/guide/bgnet/)