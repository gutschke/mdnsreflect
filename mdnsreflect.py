import argparse
import json
import logging
import os
import select
import socket
import sys
import threading
import time
from contextlib import contextmanager
from pyroute2 import IPRoute
from zeroconf import NonUniqueNameException, ServiceBrowser, ServiceInfo, \
                     ServiceListener, Zeroconf

# Logging setup
# Logs go to stderr so they don't pollute JSON output on stdout
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger(__name__)

# Defaults
DEFAULT_SOCKET_NAME = '/run/mdnsreflect/mdnsreflect.sock'
DEFAULT_SOURCE = 'eth0'
DEFAULT_TARGET = 'wlan0'

LUTRON_ADDR = '224.0.37.42'
LUTRON_PORT = 2647

DEFAULT_SERVICES = {
    '_googlecast._tcp.local.',
    '_airplay._tcp.local.',
    '_raop._tcp.local.',
    '_spotify-connect._tcp.local.',
    '_ipp._tcp.local.',
    '_ipps._tcp.local.',
    '_pdl-datastream._tcp.local.',
    '_uscan._tcp.local.',
    '_uscans._tcp.local.',
    '_http._tcp.local.',
    '_ssh._tcp.local.',
    '_matter._tcp.local.',
    '_matterc._udp.local.',
    '_smb._tcp.local.',
    '_afpovertcp._tcp.local.'
}

# Fix up Zeroconf:
# The "zeroconf" Python library is almost perfect for what we need, but it was
# obviously not written with reflector's in mind. When listening for incoming
# packages, it doesn't have the ability to bind to a network interface. And in
# the case of a reflector, that means that the "source" network interface hears
# all the reflected traffic outputted on the "target" network interface. That
# breaks the internal state maintained by "zeroconf". Until there is a better
# API for this use case, we resort to monkey patching the networking layer.
import zeroconf._utils
_patch_context = threading.local()
_patch_context.active_interface = None
_original_new_socket = zeroconf._utils.net.new_socket
IP_TO_IFACE_MAP = { }

def patched_new_socket(*args, **kwargs):
    # Create the socket using the original logic
    s = _original_new_socket(*args, **kwargs)
    # Check context to see if we are inside "with InterfaceContext(...)" blocks.
    target_iface = getattr(_patch_context, 'active_interface', None)
    if not target_iface:
        bind_addr = kwargs.get('bind_addr')
        if bind_addr and bind_addr in IP_TO_IFACE_MAP:
            target_iface = IP_TO_IFACE_MAP[bind_addr]
    if target_iface:
        try:
            SO_BINDTODEVICE = 25
            s.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE,
                         target_iface.encode('utf-8'))
            logger.info(f'🔒 Secure Binding: Socket bound strictly to '
                        f'{target_iface}')
        except PermissionError:
            logger.warning(f'⚠️  ROOT REQUIRED: Cannot bind socket to '
                           f'{target_iface}. Reflected services will be '
                           f'renamed.')
        except Exception as e:
            logger.error(f'❌ Socket Bind Error: {e}')
    return s
zeroconf._utils.net.new_socket = patched_new_socket

@contextmanager
def InterfaceContext(iface_name):
    """Context manager to set the active interface for the monkey patch"""
    old_iface = getattr(_patch_context, 'active_interface', None)
    _patch_context.active_interface = iface_name
    try:
        yield
    finally:
        _patch_context.active_interface = old_iface

# Helper functions
def ip_bytes_to_str(ip_bytes):
    if len(ip_bytes) == 4:
        return socket.inet_ntop(socket.AF_INET, ip_bytes)
    elif len(ip_bytes) == 16:
        return socket.inet_ntop(socket.AF_INET6, ip_bytes)
    return str(ip_bytes)

def get_ip_addresses(ifname, mode):
    ips = []
    families = []

    if mode in ['v4', 'both']:
        families.append(socket.AF_INET)
    if mode in ['v6', 'both']:
        families.append(socket.AF_INET6)

    try:
        with IPRoute() as ip:
            idxs = ip.link_lookup(ifname=ifname)
            if not idxs:
                logger.error(f'❌ Interface "{ifname}" not found.')
                return []
            idx = idxs[0]

            for family in families:
                records = ip.get_addr(index=idx, family=family)
                for addr in records:
                    for attr, value in addr['attrs']:
                        if attr == 'IFA_ADDRESS':
                            # Skip IPv6 link-local
                            if (family == socket.AF_INET6 and
                                    value.startswith('fe80')):
                                continue
                            ips.append(value)
                            IP_TO_IFACE_MAP[value] = ifname
    except Exception as e:
        logger.error(f'❌ Error getting IPs for "{ifname}": {e}')

    return ips

# IPC server ("daemon" side)
class IPCServer:
    def __init__(self, listener, socket_path, start_time, config):
        self.listener = listener
        self.socket_path = socket_path
        self.start_time = start_time
        self.config = config
        self.running = True

    def handle_client(self, conn):
        try:
            data = conn.recv(4096).decode('utf-8')
            if not data:
                return
            request = json.loads(data)
            response = {}

            if request['cmd'] == 'status':
                uptime = time.time() - self.start_time
                response = {
                    'status': 'ok',
                    'running': True,
                    'uptime_seconds': round(uptime, 2),
                    'service_count': len(self.listener.reflected_services),
                    'config': self.config
                }

            elif request['cmd'] == 'list':
                services_out = []
                f_str = request.get('filter', '').lower()

                for name, info in self.listener.reflected_services.items():
                    if f_str and f_str not in name.lower():
                        continue

                    ips = [ip_bytes_to_str(a) for a in info.addresses]
                    services_out.append({
                        'name': name,
                        'server': info.server,
                        'ips': ips,
                        'port': info.port,
                        'type': info.type
                    })
                response = {'status': 'ok', 'data': services_out}

            elif request['cmd'] == 'resolve':
                target = request.get('hostname', '').lower()
                if not target.endswith('.'):
                    target += '.'

                found = None
                for info in self.listener.reflected_services.values():
                    if info.server.lower() == target:
                        found = [ip_bytes_to_str(a) for a in info.addresses]
                        break

                if found:
                    response = {'status': 'ok', 'ips': found}
                else:
                    msg = 'Hostname not found'
                    response = {'status': 'error', 'message': msg}

            else:
                response = {'status': 'error', 'message': 'Unknown command'}

            conn.sendall(json.dumps(response).encode('utf-8'))
        except Exception as e:
            logger.error(f'❌ IPC Error: {e}')
        finally:
            conn.close()

    def run(self):
        if os.path.exists(self.socket_path):
            try:
                os.remove(self.socket_path)
            except OSError:
                logger.error(f'❌ Cannot remove old socket: {self.socket_path}')
                return

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            server.bind(self.socket_path)
            server.listen(1)
            os.chmod(self.socket_path, 0o600)
        except Exception as e:
            logger.critical(f'❌ Failed to bind IPC socket: {e}')
            return

        while self.running:
            try:
                conn, _ = server.accept()
                t = threading.Thread(target=self.handle_client, args=(conn,))
                t.start()
            except OSError:
                break
        server.close()

    def stop(self):
        self.running = False
        try:
            c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            c.connect(self.socket_path)
            c.close()
        except Exception:
            pass
        if os.path.exists(self.socket_path):
            os.remove(self.socket_path)

# Reflector listener
class ReflectorListener(ServiceListener):
    def __init__(self, target_zc, source_zc, target_iface_name, my_ips):
        self.target_zc = target_zc
        self.source_zc = source_zc
        self.target_iface_name = target_iface_name
        self.reflected_services = {}

        # Convert all our IPs (strings) to binary bytes for fast comparison
        self.my_ips = set()
        for ip in my_ips:
            try:
                if ':' in ip:
                    self.my_ips.add(socket.inet_pton(socket.AF_INET6, ip))
                else:
                    self.my_ips.add(socket.inet_aton(ip))
            except Exception:
                pass

    def format_identity(self, name, info=None):
        if not info: return name
        ips = [ip_bytes_to_str(addr) for addr in info.addresses]
        ip_str = ', '.join(ips) if ips else 'Unknown-IP'
        return f'"{info.server.rstrip(".")}" ({ip_str})' if info.server else ip_str

    def dump_conflict_info(self, name, hostname):
        '''Inspects cache for both service name and hostname conflicts.'''
        now = time.time()
        details = []

        # Check service name
        if hasattr(self.target_zc.cache, 'cache'):
            records = self.target_zc.cache.cache.get(name, [])
            for r in records:
                rem = int(r.get_remaining_ttl(now))
                details.append(f'[Service] {r.name} TTL:{rem}s')

            # Check hostname (the likely culprit for IPP/IPPS)
            if hostname:
                records = self.target_zc.cache.cache.get(hostname, [])
                for r in records:
                    rem = int(r.get_remaining_ttl(now))
                    # Check type safely
                    rtype = 'Unknown'
                    if r.type == 1: rtype = 'A'
                    elif r.type == 28: rtype = 'AAAA'
                    elif r.type == 33: rtype = 'SRV'

                    details.append(f'[Hostname] {r.name} [{rtype}] TTL:{rem}s')

        return details if details else [
            '<No records found for name or hostname>']

    def add_service(self, zc, type_, name):
        try:
            info = self.source_zc.get_service_info(type_, name)
        except Exception as e:
            logger.error(f'❌ Failed to resolve info for {name}: {e}')
            return
        if not info: return

        # Loop prevention
        for addr in info.addresses:
            if addr in self.my_ips: return

        ident = self.format_identity(name, info)
        friendly = type_.split('.')[0].replace('_', '')

        logger.info(f'🔎 Found [{friendly}] on source: {ident}')

        # Direct reflection
        try:
            self.target_zc.register_service(info)
            logger.info(f'📢 Reflected {ident}')
            self.reflected_services[name] = info # Track original info
            return
        except NonUniqueNameException:
            conflicts = self.dump_conflict_info(name, info.server)
            logger.warning(f'⚠️  Conflict for {ident}.')
            for c in conflicts: logger.warning(f'    CACHE: {c}')

        # Alias / rename
        logger.info(f'    Action: Attempting to reflect with aliased name...')

        try:
            # Generate unique service name
            original_instance = name.split('.')[0]
            new_instance = f'{original_instance} (Reflect)'
            new_name = name.replace(original_instance, new_instance)

            # Generate unique hostname
            if info.server:
                host_base = info.server.split('.')[0]
                new_server = f'{host_base}-reflector.local.'
            else:
                new_server = info.server

            # Create new ServiceInfo object
            new_info = ServiceInfo(
                type_,
                new_name,
                addresses=info.addresses,
                port=info.port,
                weight=info.weight,
                priority=info.priority,
                properties=info.properties,
                server=new_server
            )

            # Register the alias
            self.target_zc.register_service(new_info)
            # Store new info mapped to old name key
            self.reflected_services[name] = new_info

            logger.info(f'✅ Aliased success: Reflected as "{new_instance}"')
            logger.info(f'    Hostname alias: {new_server}')

        except Exception as e:
            logger.error(f'❌ Alias failed: {e}')

    def update_service(self, zc, type_, name):
        # This method is required by the abstract base class.
        # It handles TXT record updates (like a song change on Spotify).
        # For a simple reflector, we can often ignore it, or log it.
        pass

    def remove_service(self, zc, type_, name):
        # We stored the REGISTERED info (either original or alias) in the dict
        # under the ORIGINAL name key.
        info = self.reflected_services.get(name)
        if info:
            try:
                self.target_zc.unregister_service(info)
                logger.info(f'🔇 Withdrew: {info.name}')
                del self.reflected_services[name]
            except Exception as e:
                logger.error(f'❌ Withdraw error: {e}')

# Client (QUERY) functions
def send_ipc_command(payload, socket_path, json_mode):
    if not os.path.exists(socket_path):
        if json_mode:
            err = {'running': False, 'error': 'Socket file not found'}
            # We add socket path to error to help debug
            err['socket'] = socket_path
            print(json.dumps(err))
        else:
            print('❌ Daemon is not running (Socket file not found).')
        return

    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.connect(socket_path)
        client.sendall(json.dumps(payload).encode('utf-8'))
        response_data = client.recv(32768)
        response = json.loads(response_data.decode('utf-8'))

        # JSON output mode
        if json_mode:
            print(json.dumps(response, indent=2))
            return

        # Human readable mode
        if response.get('status') == 'error':
            print(f'❌ Error: {response.get("message")}')
            return

        if payload['cmd'] == 'status':
            cfg = response['config']
            uptime = response['uptime_seconds']
            print(f'✅ Daemon is RUNNING (Uptime: {uptime}s)')
            print(f'   Services reflected: {response["service_count"]}')
            print(f'   Source: {cfg["source"]} | Target: {cfg["target"]}')
            lutron_status = "Enabled" if cfg.get('lutron') else "Disabled"
            print(f"   Mode: {cfg['ip_mode']} | Lutron: {lutron_status}")
            print(f"   Socket: {socket_path}")

        elif payload['cmd'] == 'list':
            print(f'{"HOSTNAME":<30} {"IP ADDRESSES":<40} {"SERVICE NAME"}')
            print('-' * 90)
            for s in response['data']:
                host = s['server'].rstrip('.')
                ips = ', '.join(s['ips'])
                print(f'{host:<30} {ips:<40} {s["name"]}')
            print(f'\nTotal: {len(response["data"])} services found.')

        elif payload['cmd'] == 'resolve':
            print(f'IPs for {payload["hostname"]}:')
            for ip in response['ips']:
                print(f'  ➜ {ip}')

    except ConnectionRefusedError:
        if json_mode:
            print(json.dumps({'running': False, 'error': 'Connection refused'}))
        else:
            print('❌ Daemon is not running (Connection refused).')
    except Exception as e:
        if json_mode:
            print(json.dumps({'running': False, 'error': str(e)}))
        else:
            print(f'❌ IPC Connection Error: {e}')
    finally:
        client.close()

# Main entry point
def main():
    p = argparse.ArgumentParser(description='mdnsreflect: mDNS Reflector')

    # Common Args
    p.add_argument('--socket', default=os.path.join(os.getcwd(),
                   DEFAULT_SOCKET_NAME),
                   help=f'UNIX socket path (e.g. "{DEFAULT_SOCKET_NAME}")')
    p.add_argument('--json', action='store_true', help='Output results in JSON')

    # Action Group (Mutually exclusive)
    g = p.add_mutually_exclusive_group()
    g.add_argument('--daemon', action='store_true', help='Run the daemon')
    g.add_argument('--status', action='store_true', help='Check status')
    g.add_argument('--list-services', type=str, nargs='?', const='',
                   metavar='FILTER', help='Query services')
    g.add_argument('--resolve-host', type=str, metavar='HOST',
                   help='Resolve hostname')

    # Daemon Configuration (Default to None to detect misuse)
    p.add_argument('--source', '-s',
                   help=f'Source interface (e.g. "{DEFAULT_SOURCE}")')
    p.add_argument('--target', '-t',
                   help=f'Target interface (e.g. "{DEFAULT_TARGET}")')
    p.add_argument('--ip-mode', choices=['v4', 'v6', 'both'], default=None,
                   help='IP Protocol Mode (default: v4)')
    p.add_argument('--add', '-a', action='append', help='Add service type')
    p.add_argument('--exclude', '-e', action='append', help='Exclude service')
    p.add_argument('--no-defaults', action='store_true',
                   help='No built-in list of default services')
    p.add_argument('--lutron', action='store_true',
                   help='Reflect Lutron discovery (IPv4)')

    args = p.parse_args()

    # Determine functionality mode
    is_client_mode = (args.status or
                      args.list_services is not None or
                      args.resolve_host)
    is_server_mode = any([
        args.daemon,
        args.source,
        args.target,
        args.ip_mode,
        args.add,
        args.exclude,
        args.no_defaults,
        args.lutron
    ])

    # Check for nonsense arguments
    if is_client_mode:
        if is_server_mode:
            p.error('Argument conflict: You provided "daemon" configuration '
                    'options (e.g. --source, --target, --add) while running '
                    'a "client" command (e.g. --status, --list, --resolve).\n'
                    'Please run the daemon first, then query it separately.')

        # Dispatch client commands
        if args.status:
            send_ipc_command({'cmd': 'status'}, args.socket, args.json)
        elif args.list_services is not None:
            send_ipc_command({'cmd': 'list', 'filter': args.list_services},
                             args.socket, args.json)
        elif args.resolve_host:
            send_ipc_command({'cmd': 'resolve', 'hostname': args.resolve_host},
                             args.socket, args.json)
        return

    if not is_server_mode:
        p.print_help()
        print('\nℹ️  No mode selected. Use "--daemon" to run with defaults, '
              'or specify interfaces.')
        sys.exit(1)

    # In daemon mode, apply defaults if arguments are missing.
    if not args.source: args.source = DEFAULT_SOURCE
    if not args.target: args.target = DEFAULT_TARGET
    if not args.ip_mode: args.ip_mode = 'v4'

    logger.info('🚀 Starting mDNS Reflector...')

    # Build service list
    if args.no_defaults:
        active = set()
    else:
        active = DEFAULT_SERVICES.copy()

    if args.add:
        for s in args.add:
            active.add(s)
    if args.exclude:
        for s in args.exclude:
            if s in active:
                active.remove(s)

    # Get IPs
    s_ips = get_ip_addresses(args.source, args.ip_mode)
    t_ips = get_ip_addresses(args.target, args.ip_mode)

    if not s_ips or not t_ips:
        logger.critical('💀 Critical error: Could not resolve IPs.')
        if not s_ips:
            logger.critical(f'   Source ({args.source}): Not found/No IP')
        if not t_ips:
            logger.critical(f'   Target ({args.target}): Not found/No IP')
        return

    cfg_summary = {
        'source': args.source,
        'target': args.target,
        'ip_mode': args.ip_mode,
        'socket': args.socket,
        'lutron': args.lutron
    }

    logger.info(f'⚙️ Configuration:')
    logger.info(f'   Listening on:  {args.source} {s_ips}')
    logger.info(f'   Publishing to: {args.target} {t_ips}')
    logger.info(f'   Socket path:   {args.socket}')
    logger.info(f'   Reflecting {len(active)} service types.')

    try:
        with InterfaceContext(args.source):
            source_zc = Zeroconf(interfaces=s_ips)
        with InterfaceContext(args.target):
            target_zc = Zeroconf(interfaces=t_ips)
    except Exception as e:
        logger.critical(f'❌ Failed to bind Zeroconf: {e}')
        return

    listener = ReflectorListener(target_zc, source_zc, args.target, t_ips)
    browser = ServiceBrowser(source_zc, list(active), listener)

    ipc_server = IPCServer(listener, args.socket, time.time(), cfg_summary)
    ipc_thread = threading.Thread(target=ipc_server.run)
    ipc_thread.start()

    # We optionally forward Lutron discovery packages. These predate mDNS and
    # ZeroConf, but address a very related problem.
    lutron_socks = []
    lutron_map = {} # Map socket -> (Name, Send_To_Socket)

    if args.lutron:
        # Lutron discovery is IPv4 only. We grab the first IPv4 address of
        # each interface.
        s_ip4 = next((ip for ip in s_ips if '.' in ip), None)
        t_ip4 = next((ip for ip in t_ips if '.' in ip), None)

        if s_ip4 and t_ip4:
            logger.info(f'💡 Lutron Reflection Enabled ({LUTRON_ADDR})')

            def create_lutron_sock(iface_name, ip_addr):
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

                # Bind to the interface device to prevent cross-talk
                # (Linux specific, so probably OK if it fails)
                try:
                    SO_BINDTODEVICE = 25
                    s.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE,
                                 iface_name.encode('utf-8'))
                except PermissionError:
                    logger.warning(f'⚠️  Lutron: Cannot bind to "{iface_name}" '
                                   f'(root required).')

                # Bind to the multicast port to accept incoming requests.
                s.bind(('0.0.0.0', LUTRON_PORT))
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                             socket.inet_aton(ip_addr))

                # Join multicast group
                mreq = socket.inet_aton(LUTRON_ADDR) + socket.inet_aton(ip_addr)
                s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

                # Disable multicast loopback (Don't hear our own sends on
                # this socket)
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)

                return s

            try:
                l_sock_s = create_lutron_sock(args.source, s_ip4)
                l_sock_t = create_lutron_sock(args.target, t_ip4)

                lutron_socks = [l_sock_s, l_sock_t]

                # Define forwarding logic: Source -> Target, Target -> Source
                lutron_map[l_sock_s] = {
                    'name': 'Source', 'target': l_sock_t, 'iface': args.target }
                lutron_map[l_sock_t] = {
                    'name': 'Target', 'target': l_sock_s, 'iface': args.source}

            except Exception as e:
                logger.error(f'❌ Lutron Setup Failed: {e}')
        else:
            logger.error('❌ Lutron requires IPv4 on both interfaces.')

    try:
        while True:
            # If Lutron is active, we use select. Otherwise we sleep.
            if lutron_socks:
                readable, _, _ = select.select(lutron_socks, [], [])

                for s in readable:
                    try:
                        data, addr = s.recvfrom(4096)

                        # Filter: Ignore our own source/target IPs to prevent
                        # loops. (Even with IP_MULTICAST_LOOP=0, cross-talk can
                        # happen without BINDTODEVICE)
                        if addr[0] == s_ip4 or addr[0] == t_ip4:
                            continue

                        # Forward the packet
                        route = lutron_map[s]
                        dest_sock = route['target']

                        # We send to the multicast group, but via the other
                        # interface
                        dest_sock.sendto(data, (LUTRON_ADDR, LUTRON_PORT))

                        # Log all reflections of Lutron discovery.
                        logger.info(f'💡 Lutron: Reflected {len(data)} bytes '
                                    f'from "{lutron_map[dest_sock]["iface"]}" '
                                    f'-> "{route["iface"]}"')

                    except Exception as e:
                        logger.error(f"❌ Lutron Error: {e}")
            else:
                # Fallback for mDNS-only mode
                stop_event.wait()

    except KeyboardInterrupt:
        logger.info('🛑 Stopping reflector...')
    finally:
        ipc_server.stop()
        source_zc.close()
        target_zc.close()
        for s in lutron_socks: s.close()
        ipc_thread.join()
        logger.info('👋 Reflector stopped.')

if __name__ == '__main__':
    main()
