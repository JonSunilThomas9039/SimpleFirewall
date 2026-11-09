# XDP eBPF Whitelist Firewall Daemon

### High-Performance Kernel-Level Packet Filtering Using eBPF, XDP, and systemd

![Linux](https://img.shields.io/badge/Platform-Linux-blue?logo=linux)
![eBPF](https://img.shields.io/badge/Technology-eBPF-orange)
![XDP](https://img.shields.io/badge/Packet%20Processing-XDP-green)
![Language](https://img.shields.io/badge/Language-C-blue?logo=c)
![Service](https://img.shields.io/badge/Service-systemd-red?logo=systemd)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## 1. Project Overview

The **XDP eBPF Whitelist Firewall Daemon** is a Linux-based network security application that implements high-performance packet filtering using **Extended Berkeley Packet Filter (eBPF)** and **eXpress Data Path (XDP)**.

Unlike conventional firewall implementations that evaluate packets after they have progressed through portions of the Linux networking stack, this project uses XDP to inspect incoming packets at an earlier stage of network processing.

The firewall attaches an eBPF program to a network interface, allowing packet-filtering decisions to be executed directly within the Linux kernel.

Its filtering configuration is maintained in user space and transferred into kernel-space eBPF maps. This allows the firewall to enforce IP-based blocking and port-based whitelisting without embedding individual filtering rules directly into the eBPF program.

The application is also designed to operate as a persistent background service through `systemd`, providing automatic startup, service supervision, and controlled shutdown.

### Primary Objectives

- Implement kernel-level packet filtering using eBPF and XDP.
- Reduce packet-processing overhead by evaluating traffic before normal network-stack processing.
- Implement IP-based blacklist filtering.
- Implement port-based whitelist filtering.
- Separate firewall configuration from kernel-level filtering logic.
- Use eBPF maps to exchange filtering rules between user space and kernel space.
- Deploy the firewall as a persistent Linux daemon.
- Implement graceful termination and XDP program detachment.
- Verify packet-filtering behavior through network traffic testing.

---

## 2. Project Architecture

The firewall follows a two-component architecture consisting of a user-space management application and a kernel-space packet-filtering program.

### 2.1 High-Level Architecture

```text
                    USER SPACE
         ┌──────────────────────────────┐
         │       systemd Service       │
         │                              │
         │    xdp-firewall.service      │
         └──────────────┬───────────────┘
                        │
                        ▼
         ┌──────────────────────────────┐
         │     C Firewall Loader        │
         │                              │
         │  ebpf_whitelist_loader.c     │
         │                              │
         │  - Load eBPF object          │
         │  - Read configuration       │
         │  - Populate eBPF maps        │
         │  - Attach XDP program        │
         │  - Handle system signals    │
         └──────────────┬───────────────┘
                        │
                        │ libbpf
                        ▼
                 KERNEL SPACE
         ┌──────────────────────────────┐
         │          eBPF Maps           │
         │                              │
         │  - IP Blacklist              │
         │  - Port Whitelist            │
         └──────────────┬───────────────┘
                        │
                        ▼
         ┌──────────────────────────────┐
         │       XDP eBPF Program       │
         │                              │
         │  - Parse Ethernet header     │
         │  - Parse IPv4 header         │
         │  - Inspect source IP         │
         │  - Inspect destination port  │
         │  - Apply filtering rules     │
         └──────────────┬───────────────┘
                        │
                        ▼
                   XDP ACTION
              ┌─────────┴─────────┐
              │                   │
              ▼                   ▼
          XDP_DROP             XDP_PASS
              │                   │
              ▼                   ▼
        Packet Discarded    Linux Network Stack
```

### 2.2 User-Space Component

The user-space loader is responsible for initializing, configuring, and managing the firewall.

Its responsibilities include:

1. Loading the compiled eBPF object (`.bpf.o`).
2. Identifying the network interface on which the firewall should operate.
3. Reading IP blacklist and port whitelist configuration files.
4. Populating the corresponding eBPF maps.
5. Attaching the XDP program to the network interface.
6. Maintaining the daemon lifecycle.
7. Handling termination signals.
8. Detaching the XDP program during graceful shutdown.

The loader uses **libbpf**, a library that provides APIs for loading and interacting with eBPF programs and maps.

### 2.3 Kernel-Space Component

The kernel-space component contains the actual packet-filtering logic.

Once attached to the network interface, the XDP program is invoked for incoming packets and evaluates them against the configured filtering rules.

The program operates using eBPF maps populated by the user-space loader.

This separation provides several advantages:

- Filtering logic remains inside the kernel.
- Configuration can be maintained independently of the compiled eBPF program.
- Packet filtering does not require continuous communication with the user-space daemon.
- The kernel can continue processing packets even when the loader is sleeping.

---

## 3. Technologies and Tools

| Technology | Purpose |
|---|---|
| C | User-space firewall loader |
| eBPF | Kernel-executed filtering logic |
| XDP | Early packet-processing and filtering hook |
| libbpf | eBPF object loading and map management |
| Clang / LLVM | eBPF program compilation |
| GCC | User-space C compilation |
| Linux Kernel | eBPF execution environment |
| systemd | Daemon lifecycle management |
| Kali Linux | Development and testing environment |

### Why eBPF and XDP?

Traditional firewall implementations generally operate through the Linux networking framework. Depending on the filtering mechanism and packet path, packets may undergo additional processing before reaching the firewall rules.

XDP provides an earlier interception point.

With native driver-mode XDP, packets can be inspected directly within the network driver's receive path, before the conventional network stack processes them.

This makes XDP particularly useful for:

- High-speed packet filtering.
- DDoS mitigation.
- Network traffic classification.
- Early packet dropping.
- Network security enforcement.
- High-performance networking applications.

---

## 4. Firewall Filtering Mechanism

The firewall implements two primary filtering mechanisms.

### 4.1 IP Blacklisting

The IP blacklist contains addresses that are explicitly prohibited from communicating with the protected system.

The configuration is maintained in:

`/etc/IP_blacklist.txt`

Example:

```text
192.168.1.100
10.0.0.25
172.16.0.50
```

During initialization, the user-space loader reads the configured addresses and inserts them into the corresponding eBPF map.

When an incoming IPv4 packet reaches the XDP program:

1. The Ethernet header is inspected.
2. The program identifies whether the packet contains IPv4 traffic.
3. The IPv4 header is parsed.
4. The source IP address is extracted.
5. The source address is checked against the blacklist map.
6. If a match is found, the packet is discarded using `XDP_DROP`.

This prevents packets originating from explicitly blocked addresses from progressing into the normal Linux network stack.

### 4.2 Port Whitelisting

The port whitelist defines the permitted destination ports for incoming traffic.

The configuration is maintained in:

`/etc/Port_whitelist.txt`

Example:

```text
443
80
22
```

The firewall uses the configured port values to determine whether incoming TCP traffic should be permitted.

The filtering workflow is:

1. Identify the packet's network-layer protocol.
2. Verify that the packet contains supported TCP traffic.
3. Parse the TCP header.
4. Extract the destination port.
5. Check whether the destination port exists in the whitelist map.
6. Permit or discard the packet according to the filtering policy.

For example:

| Incoming Traffic | Expected Action |
|---|---|
| TCP destination port 443 | XDP_PASS |
| TCP destination port 80 | XDP_PASS |
| TCP destination port 22 | XDP_PASS |
| TCP destination port 8080 | XDP_DROP |
| Blacklisted source IP | XDP_DROP |

**Important:** The final filtering behavior depends on the exact order of checks and default policy implemented in the BPF source code. The table assumes that blacklist checks take priority over port authorization and that non-whitelisted TCP traffic is dropped.

### 4.3 XDP Actions

The firewall primarily relies on two XDP return actions.

| Action | Description |
|---|---|
| `XDP_PASS` | Allows the packet to continue through the normal Linux networking stack. |
| `XDP_DROP` | Discards the packet immediately at the XDP processing stage. |

Other XDP actions exist, including `XDP_TX` and `XDP_REDIRECT`, but they are not required for the current implementation.

---

## 5. eBPF Maps and Dynamic Configuration

One of the central architectural decisions was to avoid hardcoding filtering rules into the kernel program.

Instead, the firewall uses eBPF maps as a shared data structure between user space and kernel space.

### Configuration Flow

```text
       IP_blacklist.txt
              |
              ▼
       User-Space Loader
              |
              ▼
       Parse IP Addresses
              |
              ▼
       IP Blacklist Map
              |
              |
              ▼
       Kernel-Space XDP
              ▲
              |
              |
       Port Whitelist Map
              ▲
              |
       Parse Port Numbers
              ▲
              |
       User-Space Loader
              ▲
              |
       Port_whitelist.txt
```

### Advantages of Using eBPF Maps

- Filtering rules are separated from packet-processing logic.
- Configuration can be changed without recompiling the eBPF program.
- Lookup operations can be performed directly in kernel space.
- User-space and kernel-space components can share filtering information efficiently.
- The architecture can be extended to support additional filtering criteria.

In the current design, configuration files are loaded during daemon initialization. Changing a configuration file does not automatically update the kernel maps unless the loader is restarted or an explicit configuration-reload mechanism is implemented.

---

## 6. Daemon Lifecycle and Event Loop

A significant aspect of this project is the separation between packet processing and daemon management.

Once the eBPF program is successfully attached, the kernel independently handles incoming packets.

The user-space loader does not need to continuously monitor traffic or poll network sockets.

### 6.1 The Main Event Loop

The daemon uses a loop conceptually similar to:

```c
while (keep_running) {
    pause();
}
```

The purpose of this loop is to keep the user-space process alive while avoiding unnecessary CPU consumption.

### How Does Packet Processing Continue?

A natural question arises:

**If the user-space process is sleeping, how does the firewall continue inspecting packets?**

The answer lies in the execution model of eBPF.

When the loader attaches the XDP program to a network interface, the Linux kernel takes responsibility for executing the program whenever an applicable packet arrives.

The user-space process is no longer required for individual packet-filtering decisions.

Consequently:

- The daemon can remain idle.
- Incoming packets continue to trigger kernel-side XDP execution.
- eBPF map lookups continue independently of the loader's event loop.
- The user-space process wakes when an appropriate signal interrupts `pause()`.

The daemon's low idle CPU consumption should not be confused with zero CPU usage by the firewall as a whole. Kernel CPU resources are still consumed when packets are processed.

### 6.2 Signal Handling

The daemon implements graceful termination using operating-system signals.

The two primary signals are:

| Signal | Trigger |
|---|---|
| `SIGINT` | Ctrl+C during manual execution |
| `SIGTERM` | Normal service termination through systemd |

When a termination signal is received:

1. The signal handler updates the daemon's termination flag.
2. The interrupted `pause()` returns.
3. The main event loop exits.
4. The loader executes its cleanup routine.
5. The XDP program is detached from the network interface.
6. Allocated user-space resources are released.
7. The process terminates.

This approach prevents the normal shutdown process from leaving an attached XDP program behind.

Signal handlers should remain minimal and use signal-safe operations. The actual detachment and resource cleanup should happen in the normal execution context rather than directly inside the signal handler.

---

## 7. systemd Integration

The firewall is deployed as a systemd-managed background service.

This allows it to operate independently of an interactive terminal session and automatically initialize during system startup.

### 7.1 Service Configuration

The service configuration is stored at:

`/etc/systemd/system/xdp-firewall.service`

```ini
[Unit]
Description=XDP eBPF Whitelist Firewall Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ebpf_whitelist_loader eth0
Restart=on-failure
KillSignal=SIGTERM

[Install]
WantedBy=multi-user.target
```

### Explanation of Service Directives

| Directive | Purpose |
|---|---|
| `Description` | Identifies the firewall service. |
| `After=network.target` | Orders service startup after the network target. |
| `Type=simple` | Treats the launched process as the main service process. |
| `ExecStart` | Specifies the firewall loader and target interface. |
| `Restart=on-failure` | Restarts the service after an unsuccessful termination. |
| `KillSignal=SIGTERM` | Sends SIGTERM during normal service shutdown. |
| `WantedBy=multi-user.target` | Allows the service to start during normal multi-user boot. |

**Note:** `network.target` does not guarantee that the target interface is fully configured or operational. A production deployment should also verify interface availability and consider `network-online.target` where appropriate.

### 7.2 Installing and Enabling the Service

Reload the systemd configuration:

```bash
sudo systemctl daemon-reload
```

Enable automatic startup:

```bash
sudo systemctl enable xdp-firewall.service
```

Start the firewall:

```bash
sudo systemctl start xdp-firewall.service
```

Check service status:

```bash
sudo systemctl status xdp-firewall.service
```

Stop the firewall:

```bash
sudo systemctl stop xdp-firewall.service
```

Restart the firewall:

```bash
sudo systemctl restart xdp-firewall.service
```

---

## 8. Development Challenges and Solutions

During implementation, several operational issues emerged that required changes to the loader and service configuration.

### 8.1 Relative Path Resolution Failures

**Problem:**

During manual execution, the loader successfully located its configuration files and compiled eBPF object using relative paths.

However, when executed through systemd, the same paths failed with `ENOENT` errors.

**Root Cause:**

The working directory of a systemd service is not necessarily the directory from which the application was originally launched.

Without an explicitly configured working directory, relative paths may resolve somewhere unexpected.

For example:

```c
IP_blacklist.txt
Port_whitelist.txt
ebpf_whitelists.bpf.o
```

These paths worked during manual execution but failed under the service environment.

**Solution:**

The loader was modified to reference files through absolute paths.

```text
/etc/IP_blacklist.txt
/etc/Port_whitelist.txt
/etc/ebpf_whitelists.bpf.o
```

The corresponding files were placed in their expected locations.

This removed the dependency on the process's current working directory.

### 8.2 systemd Start-Limit-Hit

**Problem:**

Repeated service initialization failures caused systemd to stop attempting automatic restarts.

The service entered a failed state and displayed a start-limit-related error.

**Root Cause:**

The `Restart=on-failure` directive caused repeated restart attempts.

systemd eventually applied its start-rate limiting mechanism to prevent an endlessly restarting service from consuming system resources.

**Solution:**

After correcting the underlying configuration issue, the failed service state was reset:

```bash
sudo systemctl reset-failed xdp-firewall.service
```

The service could then be started again:

```bash
sudo systemctl start xdp-firewall.service
```

This addressed the service-management issue after the original initialization problem was resolved.

### 8.3 Persistent XDP Attachment

**Problem:**

Terminating the user-space loader without detaching its XDP program can leave the program attached to the network interface.

This is particularly important because the kernel-side program is not automatically dependent on the continued existence of the original user-space process.

**Solution:**

The loader incorporates signal handling and a cleanup routine to detach the XDP program during normal termination.

For unexpected process termination, service crashes, or forced kills, additional recovery mechanisms are recommended. A robust production implementation should verify interface attachment state during startup and provide an explicit recovery or cleanup path.

---

## 9. Repository Structure

The project follows a compact structure containing the user-space loader, compiled eBPF object, configuration files, and systemd service definition.

```text
SimpleFirewall/
│
├── ebpf_whitelist_loader.c
│   └── User-space firewall loader
│       - eBPF object loading
│       - Interface identification
│       - Configuration parsing
│       - eBPF map population
│       - XDP attachment
│       - Signal handling
│       - Resource cleanup
│
├── ebpf_whitelists.bpf.o
│   └── Compiled eBPF/XDP program
│
├── IP_blacklist.txt
│   └── Configuration file containing blocked IP addresses
│
├── Port_whitelist.txt
│   └── Configuration file containing permitted destination ports
│
└── xdp-firewall.service
    └── systemd daemon configuration
```

---

## 10. Installation and Compilation

The following instructions describe the setup process on a Debian-based Linux distribution such as Kali Linux.

### 10.1 Prerequisites

Update the package repositories:

```bash
sudo apt update
```

Install the required development dependencies:

```bash
sudo apt install -y \
    build-essential \
    libbpf-dev \
    clang \
    llvm \
    bpftool \
    linux-headers-$(uname -r)
```

The project requires a compatible Linux kernel with BPF and XDP support.

Native driver-mode XDP availability also depends on the network interface driver and hardware.

### 10.2 Compile the eBPF Program

The kernel-space program must first be compiled into an eBPF object file.

A typical compilation command is:

```bash
clang -O2 -g -target bpf \
    -c ebpf_whitelists.bpf.c \
    -o ebpf_whitelists.bpf.o
```

The exact compiler target and architecture settings may need adjustment depending on the system.

### 10.3 Compile the User-Space Loader

Compile the C loader and link it against libbpf:

```bash
gcc -O2 ebpf_whitelist_loader.c \
    -o ebpf_whitelist_loader \
    -lbpf
```

If the source uses additional dependencies, their corresponding libraries must also be linked.

### 10.4 Install the Files

Copy the user-space binary:

```bash
sudo cp ebpf_whitelist_loader /usr/local/bin/
```

Copy the compiled eBPF object:

```bash
sudo cp ebpf_whitelists.bpf.o /etc/
```

Copy the configuration files:

```bash
sudo cp IP_blacklist.txt Port_whitelist.txt /etc/
```

Set appropriate file permissions:

```bash
sudo chmod 755 /usr/local/bin/ebpf_whitelist_loader

sudo chmod 644 /etc/ebpf_whitelists.bpf.o
sudo chmod 640 /etc/IP_blacklist.txt
sudo chmod 640 /etc/Port_whitelist.txt
```

The firewall should run with sufficient privileges to load and attach the eBPF program and access its required resources.

---

## 11. Testing and Verification

Testing focused on verifying whether the firewall correctly distinguishes permitted and prohibited network traffic.

### 11.1 HTTPS Traffic Testing

A local HTTP server was used to test TCP traffic over destination port 443.

The port was added to the whitelist:

```text
443
```

The expected result was:

- Incoming TCP traffic directed to port 443 passes the XDP filtering stage.
- The packet continues through the normal Linux networking stack.
- The application listening on port 443 can process the connection, provided other network and application requirements are satisfied.

### 11.2 ICMP Testing

ICMP traffic was tested using the `ping` utility.

The objective was to verify that ICMP packets were not permitted by the implemented TCP port-whitelist policy.

Since ICMP does not use TCP destination ports, it does not qualify for authorization through the TCP port whitelist.

The observed behavior was consistent with the implemented filtering policy.

**Important:** This result depends on the actual protocol-handling and default-action logic in the BPF program. ICMP blocking should not be assumed unless it is explicitly implemented and verified in the source code.

### 11.3 Daemon Logging

The service's runtime logs can be inspected using:

```bash
sudo journalctl -u xdp-firewall.service
```

Follow logs in real time:

```bash
sudo journalctl -u xdp-firewall.service -f
```

View the latest 50 entries:

```bash
sudo journalctl -u xdp-firewall.service -n 50
```

### 11.4 Inspecting XDP Attachments

The current XDP attachment can be inspected using:

```bash
ip -details link show eth0
```

The output can indicate whether an XDP program is attached to the interface and may identify its attachment mode.

The `bpftool` utility can also be used to inspect loaded BPF programs and maps:

```bash
sudo bpftool prog show
```

```bash
sudo bpftool map show
```

Replace `eth0` with the actual interface name where necessary.

---

## 12. Security Considerations and Limitations

Although the current implementation provides a functional foundation for kernel-level packet filtering, several aspects should be considered before deploying it in a production environment.

### Current Implementation Scope

- IPv4-based IP blacklist filtering.
- TCP destination-port whitelisting.
- Configuration loaded during initialization.
- XDP-based early packet filtering.
- User-space daemon lifecycle management.
- systemd service integration.

### Current Limitations

**1. IPv4-only filtering**

IPv6 traffic requires separate parsing and filtering logic. An IPv4-only implementation should not be considered a complete network firewall.

**2. TCP-specific port filtering**

TCP and UDP use separate transport-layer headers. UDP traffic requires its own parsing and authorization rules.

**3. No automatic configuration reload**

Changes to the configuration files are not automatically reflected in the kernel maps unless an explicit reload mechanism is implemented.

**4. Limited observability**

The current design does not necessarily provide detailed packet counters, dropped-packet statistics, or structured security event reporting.

**5. XDP attachment dependencies**

Native XDP requires driver support. Generic XDP and hardware-offloaded XDP have different execution characteristics and capabilities.

**6. Connection-state awareness**

The current filtering approach is primarily packet-based. It should not be treated as a stateful connection-tracking firewall.

**7. Management-plane exposure**

The firewall must be designed carefully to avoid accidentally blocking SSH, management traffic, DNS, DHCP, or other services needed to administer the machine.

**8. Shutdown and recovery**

Graceful signal handling addresses normal shutdown. Additional safeguards are necessary for crashes, forced termination, interface changes, and stale XDP attachments.

### Recommended Production Improvements

- Add IPv6 filtering.
- Add UDP port whitelisting.
- Implement dynamic configuration updates through map operations.
- Introduce packet counters and per-rule statistics.
- Add structured logging and monitoring.
- Implement a health-check mechanism.
- Add explicit XDP attachment-state validation.
- Support multiple network interfaces.
- Introduce configurable default policies.
- Add rate limiting and connection-aware filtering where appropriate.
- Harden the systemd service using dedicated users, capabilities, and filesystem restrictions where compatible with the BPF loading requirements.

---

## 13. Future Development Roadmap

The project can be extended into a more comprehensive Linux network security platform.

| Development Phase | Proposed Enhancement |
|---|---|
| Phase 1 | Current IP blacklist and TCP port whitelist |
| Phase 2 | IPv6 and UDP filtering |
| Phase 3 | Dynamic eBPF map updates |
| Phase 4 | Packet statistics and monitoring |
| Phase 5 | Multi-interface firewall management |
| Phase 6 | Rate limiting and DDoS mitigation |
| Phase 7 | Stateful connection tracking |
| Phase 8 | Centralized configuration and management interface |

The longer-term objective would be to build a configurable, high-performance network security system that combines kernel-level packet filtering with user-space management and monitoring.

---

## 14. Learning Outcomes

This project provided practical exposure to several important Linux systems and networking concepts.

### Kernel and Operating System Concepts

- Linux kernel networking architecture.
- Kernel-space versus user-space execution.
- eBPF program loading and execution.
- XDP packet-processing lifecycle.
- Kernel data structures and eBPF maps.
- Signal handling and process lifecycle management.

### Network Security Concepts

- Packet inspection and filtering.
- IP-based access control.
- TCP destination-port authorization.
- Early packet dropping.
- Network interface attachment.
- Firewall policy enforcement.

### Linux Administration and Systems Programming

- C-based systems programming.
- libbpf integration.
- Clang and LLVM compilation.
- systemd service configuration.
- Linux process management.
- Service logging and troubleshooting.
- Resource cleanup and graceful termination.

---

## 15. Conclusion

The **XDP eBPF Whitelist Firewall Daemon** demonstrates how modern Linux kernel technologies can be used to implement efficient network packet filtering.

By combining eBPF, XDP, libbpf, and systemd, the project establishes a separation between packet-processing logic and firewall management.

The kernel independently executes filtering rules for incoming traffic, while the user-space daemon handles configuration loading, initialization, service management, and lifecycle control.

The implementation provides a foundation for exploring high-performance networking, Linux kernel programming, and network security engineering.

More importantly, it demonstrates how programmable kernel-level networking can be used to build lightweight and extensible security infrastructure.

---

## 16. License

This project is intended for educational and research purposes.

---

## 17. Author

**Project:** XDP eBPF Whitelist Firewall Daemon  
**Platform:** Kali Linux  
**Primary Language:** C  
**Core Technologies:** eBPF, XDP, libbpf, systemd

