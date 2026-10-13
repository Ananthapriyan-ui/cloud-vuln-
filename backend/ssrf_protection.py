import ipaddress
import socket
import urllib.parse
import urllib.request
from typing import List, Optional, Dict, Any


# Blocked hostnames that point to localhost, cloud metadata, or internal services
BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata.google.internal",
    "metadata.internal",
    "instance-data",
}

# Special metadata and cloud addresses (IPv4 and IPv6)
BLOCKED_EXACT_IPS = {
    "169.254.169.254",   # AWS / GCP / Azure / OpenStack metadata
    "169.254.169.253",   # AWS DNS resolver
    "100.100.100.200",   # Alibaba Cloud metadata
    "fd00:ec2::254",     # AWS IPv6 metadata
}

# Additional reserved / special CIDR blocks to disallow
RESTRICTED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network (only valid as source)
    ipaddress.ip_network("10.0.0.0/8"),          # Private-Use (RFC 1918)
    ipaddress.ip_network("100.64.0.0/10"),       # Shared Address Space (Carrier-Grade NAT)
    ipaddress.ip_network("127.0.0.0/8"),         # Loopback
    ipaddress.ip_network("169.254.0.0/16"),      # Link Local (RFC 3927)
    ipaddress.ip_network("172.16.0.0/12"),       # Private-Use (RFC 1918)
    ipaddress.ip_network("192.0.0.0/24"),        # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),        # Documentation (TEST-NET-1)
    ipaddress.ip_network("192.168.0.0/16"),      # Private-Use (RFC 1918)
    ipaddress.ip_network("198.18.0.0/15"),       # Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),     # Documentation (TEST-NET-2)
    ipaddress.ip_network("203.0.113.0/24"),      # Documentation (TEST-NET-3)
    ipaddress.ip_network("224.0.0.0/4"),         # Multicast
    ipaddress.ip_network("240.0.0.0/4"),         # Reserved for Future Use
    ipaddress.ip_network("255.255.255.255/32"),  # Limited Broadcast
    # IPv6 blocks
    ipaddress.ip_network("::/128"),              # Unspecified
    ipaddress.ip_network("::1/128"),             # Loopback
    ipaddress.ip_network("::ffff:0:0/96"),       # IPv4-mapped IPv6
    ipaddress.ip_network("64:ff9b::/96"),        # IPv4/IPv6 translation
    ipaddress.ip_network("100::/64"),            # Discard prefix
    ipaddress.ip_network("2001:db8::/32"),       # Documentation
    ipaddress.ip_network("fc00::/7"),            # Unique Local Unicast (ULA)
    ipaddress.ip_network("fe80::/10"),           # Link-Local Unicast
    ipaddress.ip_network("ff00::/8"),            # Multicast
]


def is_safe_public_ip(ip_str: str) -> bool:
    """
    Evaluates whether an IP address string is a globally routable public address.
    Strictly rejects loopback, private RFC1918, link-local, multicast, cloud metadata, and reserved networks.
    """
    clean_ip = ip_str.strip().strip("[]")
    if clean_ip in BLOCKED_EXACT_IPS:
        return False

    try:
        ip = ipaddress.ip_address(clean_ip)
    except ValueError:
        return False

    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return False

    for network in RESTRICTED_NETWORKS:
        if ip in network:
            return False

    return True


def validate_public_hostname_or_ip(hostname_or_ip: str) -> List[str]:
    """
    Validates a target hostname or IP address.
    Resolves all DNS records and ensures EVERY resolved IP address is a safe, public address.
    Raises ValueError if target resolves to any restricted, internal, or loopback address.
    """
    raw_host = hostname_or_ip.strip()
    if not raw_host:
        raise ValueError("Target hostname or IP address cannot be empty.")

    # Strip port if present
    if ":" in raw_host and not (raw_host.startswith("[") and raw_host.endswith("]")):
        # If it's not a raw IPv6 enclosed in brackets
        parts = raw_host.split(":")
        if len(parts) == 2:
            raw_host = parts[0]

    host_lower = raw_host.lower().strip("[]")

    if host_lower in BLOCKED_HOSTNAMES:
        raise ValueError(f"Target '{raw_host}' is a restricted local or internal hostname.")

    if host_lower.endswith(".localhost") or host_lower.endswith(".local") or host_lower.endswith(".internal"):
        raise ValueError(f"Target '{raw_host}' belongs to a reserved or local domain suffix.")

    # Check if target is a direct IP address
    try:
        ip = ipaddress.ip_address(host_lower)
        if not is_safe_public_ip(str(ip)):
            raise ValueError(f"Target IP '{host_lower}' is a private, loopback, or non-routable address.")
        return [str(ip)]
    except ValueError as e:
        if "is a private" in str(e):
            raise

    # Hostname: Resolve via DNS and inspect ALL resolved addresses
    resolved_ips: List[str] = []
    try:
        addr_info = socket.getaddrinfo(host_lower, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for entry in addr_info:
            sockaddr = entry[4]
            ip_candidate = sockaddr[0]
            if ip_candidate not in resolved_ips:
                resolved_ips.append(ip_candidate)
    except socket.gaierror as e:
        raise ValueError(f"DNS resolution failed for hostname '{raw_host}': {e}")
    except Exception as e:
        raise ValueError(f"Could not resolve hostname '{raw_host}': {e}")

    if not resolved_ips:
        raise ValueError(f"Unable to resolve any IP addresses for host '{raw_host}'.")

    for ip_str in resolved_ips:
        if not is_safe_public_ip(ip_str):
            raise ValueError(
                f"SSRF Protection: Hostname '{raw_host}' resolves to restricted/internal IP address '{ip_str}'."
            )

    return resolved_ips


def validate_public_url(url: str) -> str:
    """
    Validates a complete URL for SSRF vulnerabilities.
    Enforces HTTP/HTTPS protocol and validates DNS resolution to public IPs only.
    Returns normalized URL string.
    """
    clean_url = url.strip()
    if not clean_url:
        raise ValueError("Target URL cannot be blank.")

    if len(clean_url) > 2000:
        raise ValueError("Target URL is too long (maximum 2000 characters).")

    # Reject dangerous control characters
    for ch in ["<", ">", '"', "'", ";", "`", "\r", "\n"]:
        if ch in clean_url:
            raise ValueError(f"Target URL contains forbidden character: {ch!r}")

    # Add default scheme if omitted
    if "://" not in clean_url:
        clean_url = f"https://{clean_url}"

    parsed = urllib.parse.urlparse(clean_url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"Invalid URL scheme '{scheme}'. Only HTTP and HTTPS are permitted.")

    hostname = (parsed.netloc or "").split("@")[-1]  # strip userinfo if present
    if not hostname:
        hostname = parsed.path.split("/")[0]

    hostname_clean = hostname.split(":")[0].strip()
    if not hostname_clean:
        raise ValueError("Target URL does not contain a valid hostname.")

    # Validate hostname / IP
    validate_public_hostname_or_ip(hostname_clean)

    return clean_url


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """
    urllib redirect handler that verifies every redirect destination against SSRF rules.
    Prevents open-redirect-to-internal-service attacks.
    """
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Validate that redirect destination is also a public, safe address
        try:
            validated_url = validate_public_url(newurl)
            return super().redirect_request(req, fp, code, msg, headers, validated_url)
        except Exception as e:
            raise urllib.request.HTTPError(
                newurl, 403, f"SSRF Blocked: Redirect to unsafe destination ({e})", headers, fp
            )


def safe_urlopen(
    url: str,
    timeout: float = 5.0,
    headers: Optional[Dict[str, str]] = None,
    max_response_bytes: int = 2 * 1024 * 1024,  # 2MB max
) -> bytes:
    """
    Performs an outbound HTTP GET request with SSRF validation on destination and redirects.
    """
    validated_url = validate_public_url(url)
    default_headers = {"User-Agent": "CloudVuln-Security-Auditor/2.0"}
    if headers:
        default_headers.update(headers)

    req = urllib.request.Request(validated_url, headers=default_headers)
    opener = urllib.request.build_opener(SafeRedirectHandler())

    with opener.open(req, timeout=timeout) as resp:
        content = resp.read(max_response_bytes + 1)
        if len(content) > max_response_bytes:
            content = content[:max_response_bytes]
        return content
