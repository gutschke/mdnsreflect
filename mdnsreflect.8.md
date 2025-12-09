# mdnsreflect(8) - A unidirectional mDNS (Bonjour/Avahi) and Lutron discovery reflector.

1.0, December 2025

```
mdnsreflect [-a|--add TYPE] [--daemon] [-e|--exclude TYPE] [--ip-mode {v4,v6,both}] [--json] [--list-services [FILTER]] [--lutron] [--no-defaults] [--resolve-host HOSTNAME] [-s|--source IFACE] [--socket PATH] [--status] [-t|--target IFACE]
```


<a name="description"></a>

# Description

**mdnsreflect**
is a Python-based utility designed to bridge multicast discovery traffic between two distinct network interfaces (e.g., Ethernet and WiFi). Unlike full mDNS repeaters, it is designed to be lightweight, unidirectional, and highly configurable.

It operates by listening for service advertisements on the
**Source**
interface and re-publishing them onto the
**Target**
interface using the python-zeroconf library.

It also includes support for the proprietary Lutron integration protocol (UDP 2647).


<a name="modes"></a>

# Modes

The program runs in two mutually exclusive modes:

* **Daemon Mode**  
  The default mode when interfaces are specified. It creates a reflector process that runs indefinitely. It binds a UNIX domain socket (default: _/run/mdnsreflect/mdnsreflect.sock_) to allow for status queries.
* **Client Mode**  
  Triggered by flags such as **--status** or **--list-services**. In this mode, the program connects to the running daemon's socket, retrieves information, prints it to stdout, and exits.
  

<a name="options"></a>

# Options


<a name="daemon-configuration"></a>

### Daemon Configuration


* **-s&nbsp;**_IFACE_**, --source **_IFACE_  
  The network interface to listen on (e.g., _eth0_).
* **-t&nbsp;**_IFACE_**, --target **_IFACE_  
  The network interface to publish to (e.g., _wlan0_).
* **--daemon**  
  Explicitly triggers daemon mode. If no other arguments are provided, defaults to _eth0_ and _wlan0_.
* **--ip-mode&nbsp;**_MODE_  
  Sets the IP protocol mode. _MODE_ can be **v4** (default), **v6**, or **both**.
* **--lutron**  
  Enables reflection for the Lutron integration protocol (Multicast 224.0.37.42:2647). This runs in a separate blocking I/O loop alongside the mDNS threads. Note: Lutron reflection is currently IPv4 only.
  

<a name="service-management"></a>

### Service Management


* **-a&nbsp;**_TYPE_**, --add **_TYPE_  
  Add a specific service type to the reflection list (e.g., _\_ssh.\_tcp.local._). Can be used multiple times.
* **-e&nbsp;**_TYPE_**, --exclude **_TYPE_  
  Exclude a specific service type from the default list.
* **--no-defaults**  
  Start with an empty list of services. You must use **--add** to define what to reflect.
  

<a name="client-ipc-options"></a>

### Client & IPC Options


* **--status**  
  Queries the running daemon for uptime, configuration, and service count.
* **--list-services**_ [FILTER]_  
  Lists all currently reflected services. An optional text _FILTER_ can be provided (case-insensitive).
* **--resolve-host**_ HOSTNAME_  
  Queries the daemon's cache to resolve a _.local_ hostname to an IP address.
* **--socket**_ PATH_  
  Path to the UNIX domain socket. Default: _/run/mdnsreflect/mdnsreflect.sock_.
* **--json**  
  Output client results in JSON format for scripting.
  

<a name="edge-cases-and-behavior"></a>

# Edge Cases and Behavior

**mdnsreflect**
includes specific logic to handle the complexities of mDNS on Linux.


<a name="1-service-aliasing-the-mangled-name"></a>

### 1. Service Aliasing (The "Mangled Name")

On Linux, multicast sockets often suffer from "Cross-Talk," where a socket bound to _wlan0_ hears packets arriving on _eth0_. This causes the reflector to see the service it is trying to publish as a conflict.

To resolve this, if a name conflict is detected, the daemon automatically renames the service and hostname:  
Original: _MyPrinter.\_ipp.\_tcp.local._  
Reflected: _MyPrinter (Reflect).\_ipp.\_tcp.local._  
Hostname: _printer-reflector.local._

This ensures the reflected service is unique and robust against network loops.


<a name="2-root-privileges-so_bindtodevice"></a>

### 2. Root Privileges (SO_BINDTODEVICE)

To mitigate the cross-talk mentioned above, the daemon attempts to bind sockets strictly to the hardware device using the **SO\_BINDTODEVICE** socket option.

This requires **root** privileges or the **CAP\_NET\_RAW** capability. If run as a standard user without capabilities, the daemon will warn about "Leakage" and fall back to the Aliasing strategy described above.


<a name="3-zombie-records"></a>

### 3. Zombie Records

If a service disappears abruptly, "Zombie" records (TTL=0) may linger in the cache. The daemon detects this state. If a conflict is caused by a Zombie record, the daemon waits 2.5 seconds for the internal cache cleaner to run, then retries the registration automatically.


<a name="examples"></a>

# Examples

**Start the daemon (IPv4 only, standard services):**  
.in +4
$ sudo mdnsreflect --source eth0 --target wlan0
.in

**Start with IPv6 and Lutron support:**  
.in +4
$ sudo mdnsreflect -s eth0 -t wlan0 --ip-mode both --lutron
.in

**Reflect ONLY printers (IPP):**  
.in +4
$ sudo mdnsreflect -s eth0 -t wlan0 --no-defaults --add _ipp._tcp.local.
.in

**Check status (Client Mode):**  
.in +4
$ mdnsreflect --status
.in

**List all Google Cast devices in JSON:**  
.in +4
$ mdnsreflect --list-services googlecast --json
.in


<a name="files"></a>

# Files


* _/run/mdnsreflect/mdnsreflect.sock_  
  Recommended location for the IPC socket when running via systemd.
* _/etc/systemd/system/mdnsreflect.service_  
  Typical location for the systemd unit file.
  

<a name="exit-status"></a>

# Exit Status


* **0**
  Success.
* **1**
  Error (e.g., Missing arguments, permission denied, or daemon not running).
  

<a name="bugs"></a>

# Bugs

Lutron reflection currently does not support IPv6.  
If **zeroconf** receives a packet from the source network that has the same IP as the target interface (e.g., via a network bridge), it will be ignored to prevent loops.
