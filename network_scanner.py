import socket
import json
import sys
import time
import ssl
import re
import struct
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime


# ==========================================================
# COMMON SERVICES
# ==========================================================

COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP",
    8080: "HTTP",
    8443: "HTTPS",
    902: "VMware Authentication",
    912: "VMware Authentication",
}


# ==========================================================
# SERVICE NAME
# ==========================================================

def get_service_name(port):

    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]

    try:
        return socket.getservbyport(port, "tcp")
    except:
        return "Unknown"


# ==========================================================
# RESULT HELPER
# ==========================================================

def detection_result(
    product="Unknown",
    version="Not detected",
    details=""
):

    return {
        "product": product,
        "version": version,
        "details": details
    }


# ==========================================================
# HTTP DETECTION
# ==========================================================

def detect_http(target, port, use_ssl=False):

    try:

        raw_socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        raw_socket.settimeout(2)

        if use_ssl:

            context = ssl.create_default_context()

            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            sock = context.wrap_socket(
                raw_socket,
                server_hostname=target
            )

        else:

            sock = raw_socket

        sock.connect((target, port))

        request = (
            "HEAD / HTTP/1.0\r\n"
            "Host: " + target + "\r\n"
            "Connection: close\r\n\r\n"
        )

        sock.sendall(request.encode())

        response = sock.recv(8192).decode(
            "utf-8",
            errors="ignore"
        )

        sock.close()

        server_match = re.search(
            r"^Server:\s*(.+)$",
            response,
            re.IGNORECASE | re.MULTILINE
        )

        if server_match:

            server = server_match.group(1).strip()

            # Apache
            apache = re.search(
                r"Apache/([0-9.]+)",
                server,
                re.IGNORECASE
            )

            if apache:

                return detection_result(
                    "Apache",
                    apache.group(1),
                    server
                )

            # nginx
            nginx = re.search(
                r"nginx/([0-9.]+)",
                server,
                re.IGNORECASE
            )

            if nginx:

                return detection_result(
                    "nginx",
                    nginx.group(1),
                    server
                )

            # Microsoft IIS
            iis = re.search(
                r"Microsoft-IIS/([0-9.]+)",
                server,
                re.IGNORECASE
            )

            if iis:

                return detection_result(
                    "Microsoft IIS",
                    iis.group(1),
                    server
                )

            # Generic server banner
            return detection_result(
                server,
                "Detected from HTTP header",
                server
            )

        return detection_result(
            "HTTP",
            "Not disclosed",
            "HTTP service detected"
        )

    except Exception:

        return detection_result(
            "HTTP",
            "Not detected",
            "HTTP probe failed"
        )


# ==========================================================
# SSH DETECTION
# ==========================================================

def detect_ssh(target, port):

    try:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(2)

        sock.connect((target, port))

        banner = sock.recv(2048).decode(
            "utf-8",
            errors="ignore"
        ).strip()

        sock.close()

        if banner:

            match = re.search(
                r"SSH-[0-9.]+-([^\s]+)",
                banner
            )

            if match:

                software = match.group(1)

                version_match = re.search(
                    r"OpenSSH[_/-]?([0-9.]+)",
                    software,
                    re.IGNORECASE
                )

                if version_match:

                    return detection_result(
                        "OpenSSH",
                        version_match.group(1),
                        banner
                    )

                return detection_result(
                    software,
                    "Detected",
                    banner
                )

            return detection_result(
                "SSH",
                "Detected",
                banner
            )

        return detection_result(
            "SSH",
            "Not disclosed",
            "SSH server did not provide a banner"
        )

    except Exception:

        return detection_result(
            "SSH",
            "Not detected",
            "SSH probe failed"
        )


# ==========================================================
# FTP DETECTION
# ==========================================================

def detect_ftp(target, port):

    try:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(2)

        sock.connect((target, port))

        banner = sock.recv(2048).decode(
            "utf-8",
            errors="ignore"
        ).strip()

        sock.close()

        if banner:

            return detection_result(
                "FTP",
                "Banner detected",
                banner
            )

        return detection_result(
            "FTP",
            "Not disclosed",
            "FTP service detected"
        )

    except Exception:

        return detection_result(
            "FTP",
            "Not detected",
            "FTP probe failed"
        )


# ==========================================================
# SMTP DETECTION
# ==========================================================

def detect_smtp(target, port):

    try:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(2)

        sock.connect((target, port))

        banner = sock.recv(2048).decode(
            "utf-8",
            errors="ignore"
        ).strip()

        sock.close()

        if banner:

            return detection_result(
                "SMTP",
                "Banner detected",
                banner
            )

        return detection_result(
            "SMTP",
            "Not disclosed",
            "SMTP service detected"
        )

    except Exception:

        return detection_result(
            "SMTP",
            "Not detected",
            "SMTP probe failed"
        )


# ==========================================================
# MYSQL DETECTION
# ==========================================================

def detect_mysql(target, port):

    try:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(2)

        sock.connect((target, port))

        data = sock.recv(4096)

        sock.close()

        if len(data) < 10:

            return detection_result(
                "MySQL",
                "Not disclosed",
                "MySQL port detected"
            )

        # MySQL handshake
        protocol_version = data[4]

        if protocol_version == 0x0A:

            remaining = data[5:]

            null_pos = remaining.find(
                b"\x00"
            )

            if null_pos != -1:

                version_bytes = remaining[
                    :null_pos
                ]

                server_version = (
                    version_bytes.decode(
                        "ascii",
                        errors="ignore"
                    )
                )

                return detection_result(
                    "MySQL",
                    server_version,
                    "MySQL protocol version 10 handshake"
                )

        return detection_result(
            "MySQL",
            "Not disclosed",
            "MySQL handshake received"
        )

    except Exception:

        return detection_result(
            "MySQL",
            "Not detected",
            "MySQL probe failed"
        )


# ==========================================================
# POSTGRESQL DETECTION
# ==========================================================

def detect_postgresql(target, port):

    try:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(2)

        sock.connect((target, port))

        # PostgreSQL SSLRequest
        packet = struct.pack(
            "!II",
            8,
            80877103
        )

        sock.sendall(packet)

        response = sock.recv(1)

        sock.close()

        if response == b"S":

            return detection_result(
                "PostgreSQL",
                "SSL supported",
                "PostgreSQL SSL negotiation accepted"
            )

        if response == b"N":

            return detection_result(
                "PostgreSQL",
                "Not disclosed",
                "PostgreSQL service responded"
            )

        return detection_result(
            "PostgreSQL",
            "Not disclosed",
            "PostgreSQL protocol response received"
        )

    except Exception:

        return detection_result(
            "PostgreSQL",
            "Not detected",
            "PostgreSQL probe failed"
        )


# ==========================================================
# SMB DETECTION
# ==========================================================

def detect_smb(target, port):

    try:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(3)

        sock.connect((target, port))

        # SMB2 NEGOTIATE request
        negotiate = bytes.fromhex(
            "000000e4"
            "fe534d42400000000000000000000000"
            "00000000000000000000000000000000"
            "00000000000000000000000000000000"
            "00000000000000000000000000000000"
            "00000000000000000000000000000000"
            "24000000000000000000000000000000"
            "00000000000000000000000000000000"
            "0200020003100005"
        )

        sock.sendall(negotiate)

        response = sock.recv(4096)

        sock.close()

        if response.startswith(
            b"\x00"
        ) and b"\xfeSMB" in response:

            # SMB 3.1.1
            if b"\x11\x03" in response:

                return detection_result(
                    "Microsoft SMB",
                    "SMB 3.1.1",
                    "SMB2/SMB3 negotiate response"
                )

            # SMB 3.x
            if b"\x00\x03" in response:

                return detection_result(
                    "Microsoft SMB",
                    "SMB 3.x",
                    "SMB2/SMB3 negotiate response"
                )

            return detection_result(
                "Microsoft SMB",
                "SMB2/SMB3",
                "SMB negotiate response received"
            )

        if b"\xffSMB" in response:

            return detection_result(
                "Microsoft SMB",
                "SMB1",
                "Legacy SMB response detected"
            )

        return detection_result(
            "SMB",
            "Not disclosed",
            "SMB port responded but protocol version was not identified"
        )

    except Exception:

        return detection_result(
            "SMB",
            "Not detected",
            "SMB protocol probe failed"
        )


# ==========================================================
# MSRPC DETECTION
# ==========================================================

def detect_msrpc(target, port):

    try:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(3)

        sock.connect((target, port))

        # DCE/RPC bind request
        rpc_request = bytes.fromhex(
            "05000b031000000000000000"
            "000000000000000000000000"
            "000000000000000000000000"
        )

        sock.sendall(rpc_request)

        response = sock.recv(4096)

        sock.close()

        if response.startswith(
            b"\x05\x00"
        ):

            return detection_result(
                "Microsoft RPC",
                "Not disclosed",
                "DCE/RPC response received from endpoint mapper"
            )

        return detection_result(
            "MSRPC",
            "Not disclosed",
            "RPC port is accessible"
        )

    except Exception:

        return detection_result(
            "MSRPC",
            "Not detected",
            "RPC protocol probe failed"
        )


# ==========================================================
# RDP DETECTION
# ==========================================================

def detect_rdp(target, port):

    try:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(3)

        sock.connect((target, port))

        # Basic RDP negotiation request
        rdp_request = bytes.fromhex(
            "030000130ee000000000000100080003000000"
        )

        sock.sendall(rdp_request)

        response = sock.recv(4096)

        sock.close()

        if response.startswith(
            b"\x03\x00"
        ):

            return detection_result(
                "Microsoft RDP",
                "Not disclosed",
                "RDP negotiation response received"
            )

        return detection_result(
            "RDP",
            "Not disclosed",
            "RDP port responded"
        )

    except Exception:

        return detection_result(
            "RDP",
            "Not detected",
            "RDP probe failed"
        )


# ==========================================================
# VNC DETECTION
# ==========================================================

def detect_vnc(target, port):

    try:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(2)

        sock.connect((target, port))

        banner = sock.recv(1024).decode(
            "ascii",
            errors="ignore"
        ).strip()

        sock.close()

        if banner.startswith("RFB"):

            match = re.search(
                r"RFB\s+([0-9.]+)",
                banner
            )

            if match:

                return detection_result(
                    "VNC",
                    match.group(1),
                    banner
                )

            return detection_result(
                "VNC",
                "Detected",
                banner
            )

        return detection_result(
            "VNC",
            "Not disclosed",
            "VNC service responded"
        )

    except Exception:

        return detection_result(
            "VNC",
            "Not detected",
            "VNC probe failed"
        )


# ==========================================================
# VMWARE DETECTION
# ==========================================================

def detect_vmware(target, port):

    try:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(2)

        sock.connect((target, port))

        banner = sock.recv(4096).decode(
            "utf-8",
            errors="ignore"
        ).strip()

        sock.close()

        if banner:

            version_match = re.search(
                r"Version\s+([0-9.]+)",
                banner,
                re.IGNORECASE
            )

            if version_match:

                return detection_result(
                    "VMware Authentication Daemon",
                    version_match.group(1),
                    banner
                )

            return detection_result(
                "VMware Authentication Daemon",
                "Not disclosed",
                banner
            )

        return detection_result(
            "VMware Authentication Daemon",
            "Not disclosed",
            "VMware service detected"
        )

    except Exception:

        return detection_result(
            "VMware Authentication Daemon",
            "Not detected",
            "VMware probe failed"
        )


# ==========================================================
# GENERIC BANNER
# ==========================================================

def detect_generic(target, port, service):

    try:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(1)

        sock.connect((target, port))

        try:

            banner = sock.recv(
                2048
            ).decode(
                "utf-8",
                errors="ignore"
            ).strip()

        except:

            banner = ""

        sock.close()

        if banner:

            return detection_result(
                service,
                "Banner detected",
                banner[:300]
            )

        return detection_result(
            service,
            "Not disclosed",
            "Service is open but did not provide a readable banner"
        )

    except Exception:

        return detection_result(
            service,
            "Not detected",
            "Generic probe failed"
        )


# ==========================================================
# SERVICE VERSION DETECTION
# ==========================================================

def detect_service(target, port, service):

    if port == 80 or service == "HTTP":

        return detect_http(
            target,
            port,
            False
        )

    if port == 443 or service == "HTTPS":

        return detect_http(
            target,
            port,
            True
        )

    if port == 22 or service == "SSH":

        return detect_ssh(
            target,
            port
        )

    if port == 21 or service == "FTP":

        return detect_ftp(
            target,
            port
        )

    if port in [25, 465, 587] or service in [
        "SMTP",
        "SMTPS"
    ]:

        return detect_smtp(
            target,
            port
        )

    if port == 3306 or service == "MySQL":

        return detect_mysql(
            target,
            port
        )

    if port == 5432 or service == "PostgreSQL":

        return detect_postgresql(
            target,
            port
        )

    if port == 135 or service == "MSRPC":

        return detect_msrpc(
            target,
            port
        )

    if port == 445 or service == "SMB":

        return detect_smb(
            target,
            port
        )

    if port == 3389 or service == "RDP":

        return detect_rdp(
            target,
            port
        )

    if port == 5900 or service == "VNC":

        return detect_vnc(
            target,
            port
        )

    if port in [902, 912]:

        return detect_vmware(
            target,
            port
        )

    return detect_generic(
        target,
        port,
        service
    )


# ==========================================================
# SCAN INDIVIDUAL PORT
# ==========================================================

def scan_port(target, port):

    try:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(0.2)

        result = sock.connect_ex(
            (target, port)
        )

        sock.close()

        if result == 0:

            service = get_service_name(
                port
            )

            detection = detect_service(
                target,
                port,
                service
            )

            return {
                "port": port,
                "service": service,
                "status": "OPEN",
                "product": detection["product"],
                "version": detection["version"],
                "details": detection["details"]
            }

        return None

    except Exception:

        return None


# ==========================================================
# SCAN TARGET
# ==========================================================

def scan_target(target, start_port, end_port):

    start_time = time.time()

    open_ports = []

    ports = range(
        start_port,
        end_port + 1
    )

    with ThreadPoolExecutor(
        max_workers=50
    ) as executor:

        results = executor.map(
            lambda port: scan_port(
                target,
                port
            ),
            ports
        )

        for result in results:

            if result:

                open_ports.append(
                    result
                )

    end_time = time.time()

    total_ports = (
        end_port - start_port + 1
    )

    open_count = len(
        open_ports
    )

    closed_count = (
        total_ports - open_count
    )

    scan_duration = round(
        end_time - start_time,
        2
    )

    # Sort ports numerically
    open_ports.sort(
        key=lambda x: x["port"]
    )

    scan_results = {

        "target": target,

        "start_port": start_port,

        "end_port": end_port,

        "total_ports": total_ports,

        "open_count": open_count,

        "closed_count": closed_count,

        "scan_duration": scan_duration,

        "scan_time": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),

        "open_ports": open_ports
    }

    return scan_results


# ==========================================================
# MAIN
# ==========================================================

def main():

    if len(sys.argv) != 4:

        print(
            "Usage: python network_scanner.py "
            "<target> <start_port> <end_port>"
        )

        sys.exit(1)

    target = sys.argv[1]

    try:

        start_port = int(
            sys.argv[2]
        )

        end_port = int(
            sys.argv[3]
        )

    except ValueError:

        print(
            json.dumps({
                "error": "Ports must be numbers."
            })
        )

        sys.exit(1)

    # Validate ports

    if (
        start_port < 1
        or end_port > 65535
        or start_port > end_port
    ):

        print(
            json.dumps({
                "error": "Invalid port range."
            })
        )

        sys.exit(1)

    # Validate target IP

    try:

        socket.gethostbyname(
            target
        )

    except socket.gaierror:

        print(
            json.dumps({
                "error": "Invalid target."
            })
        )

        sys.exit(1)

    # Run scan

    results = scan_target(
        target,
        start_port,
        end_port
    )

    # Save JSON

    with open(
        "scan_results.json",
        "w"
    ) as file:

        json.dump(
            results,
            file,
            indent=4
        )

    # Print results

    print(
        json.dumps(
            results,
            indent=4
        )
    )


if __name__ == "__main__":

    main()