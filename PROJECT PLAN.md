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

- **Listener/Controller:** Handles client connections and stream requests.
- **Stream Manager:** Manages source RTSP connections (with authentication support) and relays data to clients; starts/stops source streams as needed.
- **Client Handler:** Manages individual client sessions, relaying data from the Stream Manager.
- **Configuration Module:** Parses configuration (list of camera URLs, authentication info, ports, etc.).
- **Logging/Stats Module:** Provides basic logging and connection statistics.

---

## Key Features

1. **Stream Multiplexing:** Efficiently relay each camera stream to multiple clients without duplicating source connections.
2. **On-Demand Source Pull:** Only connect to a source camera when at least one client requests the stream; disconnect when all clients leave.
3. **Protocol Support:** Support RTSP/RTP over UDP/TCP for both source and client.
4. **Authentication Support:** Allow configuration of username/password (or other credentials) for each RTSP source stream.
5. **Minimal Dependencies:** 
    - Use system sockets, select/poll.
    - Optionally use `live555` or `librist` (very lightweight) for RTSP/RTP parsing if needed.
6. **Configurable:** Camera list (with authentication), listening port, max clients, logging level.
7. **Graceful Shutdown:** Clean up all sockets and resources on exit.

---

## Project Phases & Milestones

### Phase 1: Design & Research
- Research lightweight RTSP/RTP handling libraries and authentication handling.
- Investigate system socket programming for streaming.
- Design configuration format (JSON or simple plain text file), including authentication fields.
- **Deliverable:** Design document, tech stack selection.

### Phase 2: Core Relay Implementation
- Implement configuration parser (including parsing authentication info).
- Implement client listener (TCP/UDP sockets).
- Implement single-stream relay (with authentication) to one client.
- **Deliverable:** Proof-of-concept: relay single camera (with/without authentication) to single client.

### Phase 3: Multi-Client & Multi-Stream Support
- Manage multiple client connections per stream.
- Manage multiple streams from different cameras (with individualized authentication).
- Implement on-demand source connect/disconnect logic.
- **Deliverable:** Relay multiple cameras (with authentication) to multiple clients, with on-demand logic.

### Phase 4: Robustness & Optimization
- Add timeout handling, error recovery, reconnection logic.
- Optimize for low memory/CPU footprint.
- Add basic logging and stats.
- **Deliverable:** Robust, efficient service with logging.

### Phase 5: Packaging & Documentation
- Create systemd service file for easy daemonization.
- Write user guide and configuration instructions.
- Provide example configuration files.
- **Deliverable:** Ready-to-use package with docs.

---

## Tech Stack & Dependencies

- **Language:** C or C++
- **RTSP/RTP:** 
    - Option 1: Use [live555](http://www.live555.com/liveMedia/) (very lightweight, pure C++ RTSP library with authentication support).
    - Option 2: Write minimal RTSP/RTP parser (if avoiding all external libs), including authentication logic.
- **Build System:** Makefile or CMake
- **No GUI:** CLI only
- **Other:** POSIX sockets, pthreads/epoll/select

---

## Risks & Mitigations

- **RTSP Complexity and Authentication:** Use live555 or similar for protocol and authentication handling to avoid reimplementing the protocol.
- **Resource Leaks:** Careful management of sockets and threads.
- **Camera Compatibility:** Test with various brands/models of network cameras (with and without authentication).

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
  "streams": [
    {
      "name": "cam1",
      "rtsp_url": "rtsp://192.168.1.100:554/stream",
      "username": "admin",
      "password": "mypassword"
    },
    {
      "name": "cam2",
      "rtsp_url": "rtsp://192.168.1.101:554/stream"
      // No authentication needed
    }
  ],
  "log_level": "info"
}

### Example Configuration (plain text, alternative)

listen_port=8554
max_clients=16
log_level=info

[stream]
name=cam1
rtsp_url=rtsp://192.168.1.100:554/stream
username=admin
password=mypassword

[stream]
name=cam2
rtsp_url=rtsp://192.168.1.101:554/stream

---

## References

- [live555 Streaming Media](http://www.live555.com/liveMedia/)
- [RFC 2326 RTSP](https://datatracker.ietf.org/doc/html/rfc2326)
- [POSIX Sockets Programming](https://beej.us/guide/bgnet/)