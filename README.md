# mdnsreflect

**A robust, unidirectional mDNS and Lutron discovery reflector for segmented
Linux networks.**

If you have ever moved your IoT devices, printers, or media players to a
separate VLAN only to find that discovery protocols stopped working—or worse,
that enabling a standard reflector caused a multicast storm—`mdnsreflect` is
the tool designed to solve that specific problem.

Unlike general-purpose reflectors (like `avahi-daemon`'s reflector mode),
`mdnsreflect` is engineered for complex Linux gateway environments where kernel
routing loops, interface cross-talk, and aggressive client caching often break
standard discovery mechanisms.

## The Problem: Why Standard Reflectors Fail

On a multi-interface Linux gateway, multicast packets received on one interface
(e.g., `eth0`) are often visible to sockets bound to another (e.g., `wlan0`)
due to how the Linux kernel handles multicast routing. This leads to
**Cross-Talk**.

When a standard reflector sees a packet on the "target" interface that *it just
sent* from the "source" interface, it often interprets this as a new device or
a name conflict. This results in:
* **Infinite Loops:** Packets are reflected back and forth until the network
  saturates.
* **Name Conflict Storms:** Devices constantly rename themselves (e.g.,
  `MyPrinter (2)` ... `MyPrinter (9000)`).
* **Ghost Services:** Devices appear and disappear randomly as the reflector
  fights the kernel.

## The Solution: How mdnsreflect Works

`mdnsreflect` is a specialized, unidirectional bridge that uses two specific
strategies to guarantee stability:

1.  **Strict Socket Binding (`SO_BINDTODEVICE`):**
    It monkey-patches the underlying Python networking library to enforce
    `SO_BINDTODEVICE` on every socket. This physically prevents the reflector
    from hearing its own traffic or traffic bleeding over from other interfaces
    via internal routing, eliminating the root cause of loops.

2.  **Intelligent Aliasing:**
    If a legitimate name conflict occurs (e.g., a dual-homed device), it
    prevents loops by acting as a proxy: it renames the reflected service (e.g.
    `MyPrinter (Reflect)`) and spoofs the hostname (`printer-reflector.local`).
    This allows the service to coexist on both networks simultaneously without
    confusing clients.

## Capabilities

* **Unidirectional Reflection:** Explicitly defined "source" (IoT/WiFi)
  and "target" (trusted/wired) roles prevent accidental leakage.
* **Lutron Support:** Includes a dedicated reflector for the proprietary Lutron
  integration protocol (UDP 2647), bridging Caséta and RadioA2 hubs across
  subnets.
* **Chromebook Scanner Fix:** Includes a specialized "watchdog" mode to
  force-refresh scanner advertisements, fixing a known issue where ChromeOS
  loses track of scanners after sleep.
* **Client & Daemon Architecture:** Runs as a systemd service, but provides a
  CLI tool to query the live internal state, resolve `.local` hostnames, and
  dump JSON for scripting.

## System Requirements

* **Linux Kernel:** Essential for `SO_BINDTODEVICE` support.
* **Systemd:** Used for process management and capability bounding
  (`CAP_NET_RAW`).
* **Python 3.8+:** Required for the runtime environment.

## Installation

The provided installer handles dependency checking, virtual environment
creation, and systemd registration.

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/gutschke/mdnsreflect.git](https://github.com/gutschke/mdnsreflect.git)
    cd mdnsreflect
    ```

2.  **Run the installer:**
    ```bash
    sudo ./install.sh
    ```
    This will install the application (defaulting to
    `/usr/local/lib/mdnsreflect`), build the local environment, and install the
    `mdnsreflect` manual page.

## Configuration

After installation, you must configure the daemon to use your specific network
interfaces.

1.  **Edit the service file:**
    ```bash
    sudo systemctl edit --full mdnsreflect.service
    ```

2.  **Modify the ExecStart line:**
    Locate the `ExecStart` line and update the arguments for your network:
    * Set `--source` to your IoT/WiFi interface (e.g., `wlan0`).
    * Set `--target` to your trusted/wired interface (e.g., `eth0`).
    * Add `--lutron` if you need to discover Lutron hubs.
    * Add `--ip-mode both` if you need IPv6 support.

    *Example:*
    ```ini
    ExecStart=/usr/local/lib/mdnsreflect/venv/bin/mdnsreflect /usr/local/lib/mdnsreflect/mdnsreflect.py --source wlan0 --target eth0 --lutron --daemon
    ```

3.  **Restart the service:**
    ```bash
    sudo systemctl restart mdnsreflect
    ```

## Usage

For a comprehensive list of all available flags, refer to the
[manual page](mdnsreflect.8.md):
```bash
man mdnsreflect
```

## Client Commands
mdnsreflect includes a client mode to query the running daemon. You do not need
`root` privileges for these commands if your user has access to the socket.

## Check Status & Configuration:

```bash
mdnsreflect --status
```

### List Reflected Services:

```bash
mdnsreflect --list-services
```

Tip: Add --json to any client command for scriptable output.

## Troubleshooting Lutron Discovery

If Lutron devices appear initially but stop working after a few minutes, your
network switch is likely timing out the multicast subscription. Disabling
IGMP Snooping on the switch can help.

Force IGMPv2: Many IoT devices prefer IGMPv2. Set
net.ipv4.conf.eth0.force_igmp_version=2` via `sysctl`.

Disable RP Filter: Ensure Reverse Path Filtering is not silently dropping
asymmetric multicast packets (`net.ipv4.conf.all.rp_filter=0`).

## License
MIT License.
