# mdnsreflect
**A unidirectional mDNS (Bonjour/Avahi) and Lutron discovery reflector**

`mdnsreflect` bridges service discovery packets from a trusted "Source"
network (e.g., Ethernet VLAN) to a "Target" network (e.g., IoT/WiFi VLAN). It
is designed to work where standard reflectors fail: in complex Linux gateway
environments where kernel routing loops and cross-talk often cause multicast
storms.

## Key Features

* **Unidirectional Reflection:** Listens on a specific "Source" interface and publishes strictly to a "Target" interface.
* **Loop Prevention:** Uses robust socket binding (`SO_BINDTODEVICE`) and service aliasing to prevent network loops and self-reflection.
* **Lutron Support:** Includes a dedicated reflector for the Lutron discovery protocol (UDP 2647).
* **Daemon & Client Modes:** Runs as a system service with a UNIX domain socket for real-time status querying and management.
* **Dual-Stack:** Supports IPv4 and IPv6 (Lutron is IPv4 only).

## Requirements

* **Operating System:** Linux (Required for `SO_BINDTODEVICE` support).
* **Privileges:** Root or `CAP_NET_RAW` capability (Required to bind sockets to hardware devices).
* **Python:** 3.8 or newer.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/gutschke/mdnsreflect.git](https://github.com/gutschke/mdnsreflect.git)
    cd mdnsreflect
    ```

2.  **Install Python dependencies:**
    ```bash
    python3 -m venv venv
    venv/bin/pip3 install zeroconf pyroute2
    ln -s python3 venv/bin/mdnsreflect
    ```

3.  **Install the manual page (optional):**
    ```bash
    cp mdnsreflect.8 /usr/share/man/man8/
    mandb
    ```

## Usage

For a complete reference of all command-line arguments, please refer to the manual page:
```bash
man mdnsreflect
```

## Quick Start

### Start the daemon (IPv4 only, standard services):
```bash
mdnsreflect --source eth0 --target wlan0
```
### Start with IPv6 and Lutron discovery enabled:
```bash
mdnsreflect -s eth0 -t wlan0 --ip-mode both --lutron
```
### Reflect ONLY printers (IPP):
```bash
mdnsreflect --no-defaults --add _ipp._tcp.local.
```

## Client Commands

You can query the running daemon using the client commands (no root required
if the socket permissions allow):
## Check Daemon Status:
```bash
mdnsreflect --status
```
## List Reflected Services:
```bash
mdnsreflect --list-services
```
