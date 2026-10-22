
import ipaddress
import shutil
import subprocess
import urllib.request
import json
from datetime import datetime

UNUSUAL_PORTS = {23, 2323, 4444, 5555, 6667}
MAX_GEOIP_LOOKUPS = 20


def extract_ip(endpoint):
    """Extract an IP address from an ss remote endpoint."""
    endpoint = endpoint.strip()

    if endpoint.startswith("[") and "]:" in endpoint:
        return endpoint[1:endpoint.rfind("]:")]

    if ":" in endpoint:
        return endpoint.rsplit(":", 1)[0]

    return endpoint




def get_connections():
    """Collect established TCP connections and UDP sockets."""
    if not shutil.which("ss"):
        print("Error: ss is not installed.")
        return []

    connections = []

    commands = [
        ("tcp", ["ss", "-H", "-tn", "state", "established"]),
        ("udp", ["ss", "-H", "-uan"]),
    ]

    for protocol, command in commands:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=10,
                check=True
            )
        except (subprocess.SubprocessError, OSError) as error:
            print(f"Could not read {protocol.upper()} sockets: {error}")
            continue

        for line in result.stdout.splitlines():
            fields = line.split()

            # ss output ends with local endpoint and peer endpoint.
            if len(fields) < 4:
                continue

            local_endpoint = fields[-2]
            remote_endpoint = fields[-1]

            if protocol == "tcp":
                remote_ip = extract_ip(remote_endpoint)

                try:
                    address = ipaddress.ip_address(remote_ip)
                except ValueError:
                    continue

                if not address.is_global:
                    continue

                try:
                    remote_port = int(remote_endpoint.rsplit(":", 1)[1])
                except (ValueError, IndexError):
                    remote_port = 0

                connections.append({
                    "protocol": "tcp",
                    "state": "ESTAB",
                    "remote_ip": remote_ip,
                    "remote_port": remote_port
                })

            else:
                # UDP sockets may have no remote peer (shown as * or
                # 0.0.0.0). Report these as local listeners/sockets.
                remote_ip = extract_ip(remote_endpoint)

                try:
                    address = ipaddress.ip_address(remote_ip)
                    has_public_peer = address.is_global
                except ValueError:
                    has_public_peer = False

                try:
                    local_port = int(local_endpoint.rsplit(":", 1)[1])
                except (ValueError, IndexError):
                    local_port = 0

                try:
                    remote_port = int(remote_endpoint.rsplit(":", 1)[1])
                except (ValueError, IndexError):
                    remote_port = 0

                if has_public_peer:
                    connections.append({
                        "protocol": "udp",
                        "state": "UDP_PEER",
                        "remote_ip": remote_ip,
                        "remote_port": remote_port
                    })
                else:
                    connections.append({
                        "protocol": "udp",
                        "state": "UDP_LISTENER",
                        "remote_ip": "",
                        "remote_port": local_port
                    })

    return connections


def geoip_lookup(ip):
    """Look up approximate public IP location using ipapi.co."""
    url = f"https://ipapi.co/{ip}/json/"
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "ActiveConnectionsAuditor/1.0"}
    )

    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            data = json.loads(response.read().decode("utf-8"))

        if data.get("error"):
            return {"error": data.get("reason", "Lookup failed")}

        return {
            "country": data.get("country_name", "Unknown"),
            "region": data.get("region", "Unknown"),
            "city": data.get("city", "Unknown")
        }

    except Exception as error:
        return {"error": str(error)}


def analyze_connections(connections, locations):
    """Flag connections for review using simple heuristics."""
    findings = []

    for connection in connections:
        ip = connection["remote_ip"]
        port = connection["remote_port"]

        if port in UNUSUAL_PORTS:
            findings.append(
                f"Review {ip}:{port}: port is on the configured review list."
            )

        location = locations.get(ip, {})

        if location.get("error"):
            findings.append(
                f"Location lookup failed for {ip}; investigate manually."
            )

    return findings


def run_audit():
    print("=" * 55)
    print("       ACTIVE CONNECTIONS AUDITOR")
    print("=" * 55)
    print("Audit time:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    connections = get_connections()

    if not connections:
        print("\nNo eligible TCP connections or UDP sockets found.")
        print("This does not necessarily mean there is no network activity.")
        return

    print(f"\nFound {len(connections)} TCP connection(s) or UDP socket(s).")

    # Only look up actual, non-empty remote IP addresses.
    unique_ips = list(dict.fromkeys(
        item["remote_ip"] for item in connections
        if item.get("remote_ip")
    ))

    locations = {}
    for ip in unique_ips[:MAX_GEOIP_LOOKUPS]:
        print(f"Looking up location for {ip}...")
        locations[ip] = geoip_lookup(ip)

    print("\n--- CONNECTION AND SOCKET REPORT ---")

    for connection in connections:
        ip = connection.get("remote_ip", "")
        protocol = connection["protocol"].upper()
        state = connection["state"]
        port = connection["remote_port"]

        print(f"\nProtocol: {protocol}")
        print(f"State: {state}")

        if state == "UDP_LISTENER" and not ip:
            print("Socket type: Local UDP socket (no remote peer)")
            print(f"Local port: {port}")
            print("Remote IP: Not applicable")
            print("Location: Not applicable")
        else:
            print(f"Remote IP: {ip}")
            print(f"Remote port: {port}")

            location = locations.get(ip)
            if not ip:
                print("Location: Not applicable")
            elif location is None:
                print("Location: Lookup limit reached")
            elif location.get("error"):
                print("Location: Unavailable")
            else:
                print(
                    f"Location: {location.get('city', 'Unknown')}, "
                    f"{location.get('region', 'Unknown')}, "
                    f"{location.get('country', 'Unknown')}"
                )

    # Only actual remote IP addresses should be checked for GeoIP errors.
    findings = analyze_connections(connections, locations)

    print("\n--- FINDINGS ---")
    if findings:
        for finding in findings:
            print("-", finding)
    else:
        print("No configured review rules were triggered.")

    print("\nNote: A foreign IP or unusual port is not proof of malicious activity.")
    print("Review unfamiliar connections before taking any action.")


def audit_connections():
    """
    Callable entry point for the main Agentic Shell.
    Returns structured results instead of only printing them.
    """
    import time

    start_time = time.perf_counter()

    connections = get_connections()

    unique_ips = list(dict.fromkeys(
        connection["remote_ip"]
        for connection in connections
        if connection.get("remote_ip")
    ))

    locations = {}

    for ip in unique_ips[:MAX_GEOIP_LOOKUPS]:
        locations[ip] = geoip_lookup(ip)

    findings = analyze_connections(connections, locations)

    return {
        "agent": "Active Connections Auditor",
        "audit_time": datetime.now().isoformat(timespec="seconds"),
        "total_sockets": len(connections),
        "connections": connections,
        "locations": locations,
        "findings": findings,
        "execution_time_seconds": round(
            time.perf_counter() - start_time, 3
        ),
    }


if __name__ == "__main__":
    import time

    start_time = time.perf_counter()

    run_audit()

    end_time = time.perf_counter()

    elapsed = end_time - start_time
    print(f"\nTotal execution time: {elapsed:.3f} seconds")
