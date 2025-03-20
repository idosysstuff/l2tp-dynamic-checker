#!/usr/bin/env python3

import routeros_api
import requests
import logging
import time
import os
import re
import sys
import signal
import concurrent.futures
from datetime import datetime
from threading import Lock
import argparse
from dotenv import load_dotenv

try:
    from daemon import DaemonContext
except ImportError:
    print("Warning: python-daemon package not installed. Daemon mode will not be available.")
    print("To install, run: pip install python-daemon")
    class DaemonContext:
        def __init__(self, **kwargs):
            raise ImportError("python-daemon package is required for daemon mode")

log_dir = os.path.expanduser('~/logs')
os.makedirs(log_dir, exist_ok=True)

logging.basicConfig(
    filename=f'{log_dir}/mikrotik_l2tp_monitor.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

load_dotenv()

MIKROTIK_IPS = os.getenv('MIKROTIK', '').split(',')
MIKROTIK_ROUTERS = [{'name': f'router{i+1}', 'ip': ip.strip()} for i, ip in enumerate(MIKROTIK_IPS) if ip.strip()]

MIKROTIK_USERNAME = os.getenv('MIKROTIK_USERNAME', 'admin')
MIKROTIK_PASSWORD = os.getenv('MIKROTIK_PASSWORD', '')

TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN', '')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID', '')

CHECK_INTERVAL = int(os.getenv('CHECK_INTERVAL', '30'))
MAX_WORKERS = int(os.getenv('MAX_WORKERS', '10'))

DYNAMIC_TUNNEL_PATTERN = re.compile(r'<l2tp-[^>]+>')

previous_tunnels = {}
report_lock = Lock()

def check_l2tp_tunnels(router_ip, username, password, router_name):
    try:
        connection = routeros_api.RouterOsApiPool(
            router_ip,
            username=username,
            password=password,
            plaintext_login=True
        )
        api = connection.get_api()

        l2tp_tunnels = []
        try:
            interfaces = api.get_resource('/interface')
            all_interfaces = interfaces.get()

            logging.debug(f"Found {len(all_interfaces)} interfaces on {router_name}")

            for interface in all_interfaces:
                name = interface.get('name', '')
                type_name = interface.get('type', '')

                if 'l2tp' in type_name.lower() or 'l2tp' in name.lower():
                    logging.debug(f"Found L2TP interface on {router_name}: {name} (Type: {type_name})")

                if DYNAMIC_TUNNEL_PATTERN.match(name):
                    logging.info(f"Found dynamic L2TP tunnel on {router_name}: {name}")

                    tunnel_info = {
                        'name': name,
                        'remote_address': 'Unknown',
                        'user': 'Unknown',
                        'uptime': 'Unknown'
                    }

                    try:
                        ppp_active = api.get_resource('/ppp/active')
                        active_connections = ppp_active.get()

                        for conn in active_connections:
                            if conn.get('name', '') == name:
                                if 'address' in conn:
                                    tunnel_info['remote_address'] = conn['address']
                                elif 'remote-address' in conn:
                                    tunnel_info['remote_address'] = conn['remote-address']
                                elif 'caller-id' in conn:
                                    tunnel_info['remote_address'] = conn['caller-id']

                                tunnel_info['user'] = conn.get('user', 'Unknown')
                                tunnel_info['uptime'] = conn.get('uptime', 'Unknown')
                                break
                    except Exception as e:
                        logging.warning(f"Error getting PPP active details for {name}: {str(e)}")

                    l2tp_tunnels.append(tunnel_info)
        except Exception as e:
            logging.warning(f"Error querying interfaces on {router_name}: {str(e)}")

        if not l2tp_tunnels:
            logging.debug(f"No tunnels found via interfaces on {router_name}, checking PPP active")

            ppp_active = api.get_resource('/ppp/active')
            active_connections = ppp_active.get()

            for conn in active_connections:
                if conn.get('service') != 'l2tp':
                    continue

                tunnel_name = conn.get('name', '')

                if DYNAMIC_TUNNEL_PATTERN.match(tunnel_name):
                    logging.info(f"Found L2TP tunnel via PPP: {tunnel_name} on router {router_name}")

                    tunnel_info = {
                        'name': tunnel_name,
                        'user': conn.get('user', 'Unknown'),
                        'uptime': conn.get('uptime', 'Unknown')
                    }

                    if 'address' in conn:
                        tunnel_info['remote_address'] = conn['address']
                    elif 'remote-address' in conn:
                        tunnel_info['remote_address'] = conn['remote-address']
                    elif 'caller-id' in conn:
                        tunnel_info['remote_address'] = conn['caller-id']
                    else:
                        tunnel_info['remote_address'] = 'Unknown'

                    l2tp_tunnels.append(tunnel_info)

        connection.disconnect()
        return l2tp_tunnels

    except routeros_api.exceptions.RouterOsApiConnectionError as e:
        logging.error(f"Connection error to router {router_name} ({router_ip}): {str(e)}")
        return f"CONNECTION_ERROR: {str(e)}"
    except routeros_api.exceptions.RouterOsApiCommunicationError as e:
        logging.error(f"Communication error with router {router_name} ({router_ip}): {str(e)}")
        return f"COMMUNICATION_ERROR: {str(e)}"
    except Exception as e:
        logging.error(f"Unexpected error with router {router_name} ({router_ip}): {str(e)}")
        return f"ERROR: {str(e)}"

def send_to_telegram(message, alert=False):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"

    if alert:
        message = f"🚨 <b>ALERT</b> 🚨\n\n{message}"

    payload = {
        'chat_id': TELEGRAM_CHAT_ID,
        'text': message,
        'parse_mode': 'HTML'
    }

    max_retries = 3
    for attempt in range(max_retries):
        try:
            response = requests.post(url, data=payload, timeout=10)
            if response.status_code == 200:
                return True

            if response.status_code == 400 and "message is too long" in response.text.lower():
                if len(message) > 4000:
                    truncated_message = message[:3950] + "...\n[Message truncated due to length]"
                    payload['text'] = truncated_message
                    continue

            logging.error(f"Failed to send Telegram message (attempt {attempt + 1}): Status {response.status_code} - {response.text}")
            time.sleep(2)

        except requests.exceptions.RequestException as e:
            logging.error(f"Request error sending Telegram message (attempt {attempt + 1}): {str(e)}")
            time.sleep(2)

    logging.error("All attempts to send Telegram message failed")
    return False

def check_router(router):
    router_name = router['name']
    router_ip = router['ip']

    logging.info(f"Checking L2TP tunnels on {router_name} ({router_ip})")

    start_time = time.time()
    tunnels = check_l2tp_tunnels(
        router_ip,
        MIKROTIK_USERNAME,
        MIKROTIK_PASSWORD,
        router_name
    )
    check_duration = time.time() - start_time

    if isinstance(tunnels, str) and tunnels.startswith(("ERROR:", "CONNECTION_ERROR:", "COMMUNICATION_ERROR:")):
        return {
            "router_name": router_name,
            "router_ip": router_ip,
            "error": tunnels,
            "duration": check_duration
        }

    return {
        "router_name": router_name,
        "router_ip": router_ip,
        "tunnels": tunnels,
        "duration": check_duration
    }

def check_and_report():
    global previous_tunnels

    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    all_results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_router = {executor.submit(check_router, router): router for router in MIKROTIK_ROUTERS}

        for future in concurrent.futures.as_completed(future_to_router):
            result = future.result()
            all_results.append(result)

    with report_lock:
        total_tunnels = 0
        new_tunnels = []
        closed_tunnels = []
        current_tunnels = {}

        all_results.sort(key=lambda x: x["router_name"])

        for result in all_results:
            router_name = result["router_name"]
            router_ip = result["router_ip"]

            if "error" in result:
                logging.error(f"Error checking router {router_name} ({router_ip}): {result['error']}")
                continue

            tunnels = result["tunnels"]

            current_router_tunnels = {tunnel['name']: tunnel for tunnel in tunnels}
            current_tunnels[router_name] = current_router_tunnels

            total_tunnels += len(tunnels)

            # Check for new tunnels and send immediate alerts
            is_first_run = router_name not in previous_tunnels

            for tunnel_name, tunnel_info in current_router_tunnels.items():
                is_new_tunnel = is_first_run or tunnel_name not in previous_tunnels.get(router_name, {})

                if is_new_tunnel:
                    new_tunnels.append({
                        "router": router_name,
                        "router_ip": router_ip,
                        "tunnel": tunnel_info
                    })

                    # Simplified alert message with just router name, IP, and tunnel name
                    safe_tunnel_name = tunnel_info['name'].replace('<', '&lt;').replace('>', '&gt;')
                    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    alert_message = f"<b>L2TP tunnel detected:</b>\n"
                    alert_message += f"Router: {router_name}\n"
                    alert_message += f"IP: {router_ip}\n"
                    alert_message += f"Tunnel: {safe_tunnel_name}\n"
                    alert_message += f"Time: {current_time}"

                    logging.info(f"L2TP tunnel detected on {router_name}: {tunnel_name}")
                    send_to_telegram(alert_message, alert=True)

        # Update the previous tunnels state
        previous_tunnels = current_tunnels

        # Log a summary
        logging.info(f"Check completed. Total tunnels found: {total_tunnels}, New tunnels: {len(new_tunnels)}")

def signal_handler(signum, frame):
    logging.info(f"Received signal {signum}, shutting down...")
    sys.exit(0)

def run_monitor(daemon_mode=False):
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    logging.info(f"L2TP Tunnel Monitor started - checking {len(MIKROTIK_ROUTERS)} routers every {CHECK_INTERVAL} seconds")
    if not daemon_mode:
        print(f"L2TP Tunnel Monitor started - checking {len(MIKROTIK_ROUTERS)} routers every {CHECK_INTERVAL} seconds")
        print(f"Logs are being written to: {log_dir}/mikrotik_l2tp_monitor.log")

    # Do the initial check
    check_and_report()

    try:
        while True:
            time.sleep(CHECK_INTERVAL)
            check_and_report()

            if not daemon_mode:
                print(f"Check completed. Next check in {CHECK_INTERVAL} seconds...")

    except Exception as e:
        logging.error(f"Monitor encountered an error: {str(e)}")
        if not daemon_mode:
            print(f"Error: {str(e)}")
        raise

def main():
    parser = argparse.ArgumentParser(description='MikroTik L2TP Tunnel Monitor')
    parser.add_argument('--daemon', action='store_true', help='Run as a daemon process')
    parser.add_argument('--pid-file', type=str, default='/tmp/mikrotik_monitor.pid',
                        help='PID file location when running as daemon')
    parser.add_argument('--stop', action='store_true', help='Stop the running daemon')

    args = parser.parse_args()

    if args.stop:
        try:
            with open(args.pid_file, 'r') as f:
                pid = int(f.read().strip())
            os.kill(pid, signal.SIGTERM)
            print(f"Sent termination signal to process {pid}")
            return
        except FileNotFoundError:
            print(f"PID file not found: {args.pid_file}")
            return
        except ProcessLookupError:
            print(f"Process not found. Removing stale PID file.")
            os.remove(args.pid_file)
            return

    if args.daemon:
        print(f"Starting L2TP Tunnel Monitor as daemon. PID file: {args.pid_file}")
        print(f"Logs will be written to: {log_dir}/mikrotik_l2tp_monitor.log")
        print(f"To stop the daemon, run: {sys.argv[0]} --stop")

        with DaemonContext(
            pidfile=args.pid_file,
            working_directory='/',
            umask=0o022,
            signal_map={
                signal.SIGTERM: signal_handler,
                signal.SIGINT: signal_handler
            }
        ):
            run_monitor(daemon_mode=True)
    else:
        run_monitor(daemon_mode=False)

if __name__ == "__main__":
    main()
