"""
Reconnaissance Runtime - OSINT and Attack Surface Mapping.

Provides comprehensive reconnaissance capabilities for security assessments:
- Port scanning
- DNS enumeration
- Technology detection
- Subdomain discovery
- WHOIS lookups
- Attack surface mapping
"""

from __future__ import annotations

import socket
import logging
import concurrent.futures
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from ..tools.registry import register_tool

logger = logging.getLogger(__name__)

# Common ports for security scanning
COMMON_PORTS = {
    "web": [80, 443, 8080, 8443, 8000, 8888, 3000, 5000],
    "database": [3306, 5432, 27017, 1433, 1521, 6379, 5984, 9200],
    "remote": [22, 23, 3389, 5900, 5901],
    "mail": [25, 110, 143, 587, 993, 995, 465],
    "file": [21, 69, 139, 445, 2049],
    "dns": [53],
    "ldap": [389, 636],
    "misc": [111, 161, 162, 500, 1723, 5060, 5061],
}

# Technology signatures for detection
TECH_SIGNATURES = {
    "server": {
        "nginx": ["nginx", "Nginx"],
        "apache": ["Apache", "apache"],
        "iis": ["IIS", "Microsoft-IIS"],
        "tomcat": ["Tomcat", "Apache-Coyote"],
        "gunicorn": ["gunicorn"],
        "uvicorn": ["uvicorn"],
        "node": ["Express", "Node"],
        "cloudflare": ["cloudflare"],
    },
    "framework": {
        "django": ["csrftoken", "Django", "djdt"],
        "flask": ["Werkzeug"],
        "rails": ["X-Rails", "Rails", "_rails"],
        "laravel": ["laravel_session", "Laravel"],
        "spring": ["X-Application-Context", "Spring"],
        "asp.net": ["ASP.NET", "X-AspNet-Version", "__VIEWSTATE"],
        "react": ["_react", "react"],
        "vue": ["vue", "__vue__"],
        "angular": ["ng-", "angular"],
    },
    "cms": {
        "wordpress": ["wp-content", "wp-includes", "WordPress"],
        "drupal": ["Drupal", "sites/default"],
        "joomla": ["Joomla", "com_content"],
        "magento": ["Magento", "Mage"],
    },
    "cdn": {
        "cloudflare": ["__cfduid", "cf-ray", "cloudflare"],
        "akamai": ["akamai", "X-Akamai"],
        "fastly": ["Fastly", "X-Fastly"],
        "aws_cloudfront": ["X-Amz-Cf-Id", "CloudFront"],
    },
}


@register_tool(sandbox_execution=True, category="recon")
def port_scan(
    agent_state: Any,
    target: str,
    ports: Optional[List[int]] = None,
    port_range: Optional[str] = None,
    preset: Optional[str] = None,
    timeout: float = 1.0,
    max_threads: int = 50,
) -> Dict[str, Any]:
    """
    Perform TCP port scanning on a target.
    
    Scans specified ports to identify open services. Use presets for
    common security-relevant ports or specify custom ranges.
    
    Args:
        agent_state: Current agent state
        target: Target hostname or IP
        ports: Specific ports to scan
        port_range: Port range (e.g., "1-1000")
        preset: Preset port list (web, database, remote, common, all)
        timeout: Connection timeout in seconds
        max_threads: Maximum concurrent threads
    
    Returns:
        Dictionary with scan results
    """
    # Resolve target
    try:
        resolved_ip = socket.gethostbyname(target)
    except socket.gaierror:
        return {
            "success": False,
            "error": f"Could not resolve hostname: {target}",
        }
    
    # Determine ports to scan
    scan_ports = set()
    
    if ports:
        scan_ports.update(ports)
    
    if port_range:
        try:
            start, end = map(int, port_range.split("-"))
            scan_ports.update(range(start, min(end + 1, 65536)))
        except ValueError:
            return {
                "success": False,
                "error": f"Invalid port range: {port_range}",
            }
    
    if preset:
        preset = preset.lower()
        if preset == "common":
            for port_list in COMMON_PORTS.values():
                scan_ports.update(port_list)
        elif preset == "all":
            scan_ports.update(range(1, 1025))  # Well-known ports
        elif preset in COMMON_PORTS:
            scan_ports.update(COMMON_PORTS[preset])
        else:
            return {
                "success": False,
                "error": f"Unknown preset: {preset}",
                "available_presets": list(COMMON_PORTS.keys()) + ["common", "all"],
            }
    
    if not scan_ports:
        # Default: common security ports
        for port_list in COMMON_PORTS.values():
            scan_ports.update(port_list)
    
    scan_ports = sorted(scan_ports)
    
    # Scan function
    def scan_port(port: int) -> Optional[Dict[str, Any]]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((resolved_ip, port))
            sock.close()
            
            if result == 0:
                # Port is open
                service = get_service_name(port)
                return {
                    "port": port,
                    "state": "open",
                    "service": service,
                }
        except Exception:
            pass
        return None
    
    # Execute scan
    open_ports = []
    start_time = datetime.now(timezone.utc)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_port, port): port for port in scan_ports}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
    
    end_time = datetime.now(timezone.utc)
    scan_duration = (end_time - start_time).total_seconds()
    
    # Sort by port number
    open_ports.sort(key=lambda x: x["port"])
    
    # Categorize open ports
    categories = {}
    for port_info in open_ports:
        port = port_info["port"]
        for category, port_list in COMMON_PORTS.items():
            if port in port_list:
                if category not in categories:
                    categories[category] = []
                categories[category].append(port_info)
                break
    
    return {
        "success": True,
        "target": target,
        "resolved_ip": resolved_ip,
        "ports_scanned": len(scan_ports),
        "open_ports_count": len(open_ports),
        "open_ports": open_ports,
        "by_category": categories,
        "scan_duration_seconds": round(scan_duration, 2),
        "scan_time": start_time.isoformat(),
    }


def get_service_name(port: int) -> str:
    """Get common service name for a port."""
    services = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
        993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
        3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
        6379: "redis", 8080: "http-proxy", 8443: "https-alt",
        27017: "mongodb", 9200: "elasticsearch",
    }
    return services.get(port, "unknown")


@register_tool(sandbox_execution=True, category="recon")
def dns_lookup(
    agent_state: Any,
    target: str,
    record_types: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Perform DNS lookups for various record types.
    
    Args:
        agent_state: Current agent state
        target: Domain to lookup
        record_types: Record types to query (A, AAAA, MX, NS, TXT, CNAME, SOA)
    
    Returns:
        Dictionary with DNS records
    """
    import socket
    
    if record_types is None:
        record_types = ["A", "AAAA", "MX", "NS", "TXT"]
    
    results = {
        "success": True,
        "target": target,
        "records": {},
        "errors": [],
    }
    
    # Basic A record lookup using socket
    try:
        ips = socket.gethostbyname_ex(target)
        results["records"]["A"] = {
            "hostname": ips[0],
            "aliases": ips[1],
            "addresses": ips[2],
        }
    except socket.gaierror as e:
        results["errors"].append(f"A record lookup failed: {e}")
    
    # Try AAAA (IPv6)
    try:
        addr_info = socket.getaddrinfo(target, None, socket.AF_INET6)
        ipv6_addresses = list(set(info[4][0] for info in addr_info))
        if ipv6_addresses:
            results["records"]["AAAA"] = ipv6_addresses
    except (socket.gaierror, OSError):
        pass  # IPv6 not available
    
    # Note: For full DNS enumeration, you'd want to use dnspython library
    # This is a basic implementation using standard library
    
    results["note"] = "For comprehensive DNS enumeration, consider using specialized tools like dnspython"
    
    return results


@register_tool(sandbox_execution=True, category="recon")
def whois_lookup(
    agent_state: Any,
    target: str,
) -> Dict[str, Any]:
    """
    Perform WHOIS lookup for domain information.
    
    Note: This requires the 'whois' command to be available on the system.
    In a container environment, results may be limited.
    
    Args:
        agent_state: Current agent state
        target: Domain to lookup
    
    Returns:
        Dictionary with WHOIS information
    """
    import subprocess
    
    # Clean target
    target = target.lower().strip()
    if target.startswith("http"):
        target = urlparse(target).netloc
    
    try:
        result = subprocess.run(
            ["whois", target],
            capture_output=True,
            text=True,
            timeout=30,
        )
        
        if result.returncode == 0:
            raw_output = result.stdout
            
            # Parse common fields
            parsed = {}
            fields = [
                "Registrar:", "Creation Date:", "Expiration Date:",
                "Updated Date:", "Name Server:", "Status:",
                "Registrant Name:", "Registrant Organization:",
                "Admin Email:", "Tech Email:",
            ]
            
            for line in raw_output.split("\n"):
                line = line.strip()
                for field in fields:
                    if line.startswith(field):
                        key = field.rstrip(":").replace(" ", "_").lower()
                        value = line[len(field):].strip()
                        if key in parsed:
                            if isinstance(parsed[key], list):
                                parsed[key].append(value)
                            else:
                                parsed[key] = [parsed[key], value]
                        else:
                            parsed[key] = value
            
            return {
                "success": True,
                "target": target,
                "parsed": parsed,
                "raw": raw_output[:5000],  # Limit raw output
            }
        else:
            return {
                "success": False,
                "error": result.stderr or "WHOIS lookup failed",
                "target": target,
            }
            
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "WHOIS lookup timed out",
            "target": target,
        }
    except FileNotFoundError:
        return {
            "success": False,
            "error": "WHOIS command not available on this system",
            "target": target,
            "suggestion": "Use an online WHOIS service or install whois package",
        }


@register_tool(sandbox_execution=True, category="recon")
def subdomain_enum(
    agent_state: Any,
    domain: str,
    wordlist: Optional[List[str]] = None,
    max_threads: int = 20,
    timeout: float = 2.0,
) -> Dict[str, Any]:
    """
    Enumerate subdomains for a given domain.
    
    Uses DNS resolution to check for valid subdomains.
    
    Args:
        agent_state: Current agent state
        domain: Target domain
        wordlist: Custom subdomain wordlist
        max_threads: Maximum concurrent threads
        timeout: DNS resolution timeout
    
    Returns:
        Dictionary with discovered subdomains
    """
    import socket
    
    # Default wordlist for common subdomains
    default_wordlist = [
        "www", "mail", "ftp", "admin", "blog", "shop", "api", "dev",
        "staging", "test", "app", "portal", "secure", "vpn", "remote",
        "cdn", "assets", "static", "media", "images", "files", "docs",
        "support", "help", "status", "dashboard", "console", "panel",
        "login", "auth", "sso", "accounts", "my", "user", "users",
        "beta", "alpha", "demo", "sandbox", "prod", "production",
        "web", "www2", "www3", "m", "mobile", "ns1", "ns2", "ns3",
        "mx", "mx1", "mx2", "smtp", "pop", "imap", "webmail",
        "git", "gitlab", "github", "svn", "jenkins", "ci", "cd",
        "aws", "azure", "gcp", "cloud", "k8s", "kubernetes", "docker",
        "elasticsearch", "kibana", "grafana", "prometheus", "redis",
        "mysql", "postgres", "mongodb", "db", "database", "sql",
        "office", "outlook", "exchange", "calendar", "sharepoint",
        "intranet", "extranet", "internal", "corp", "corporate",
    ]
    
    wordlist = wordlist or default_wordlist
    
    def check_subdomain(subdomain: str) -> Optional[Dict[str, Any]]:
        full_domain = f"{subdomain}.{domain}"
        try:
            socket.setdefaulttimeout(timeout)
            ip = socket.gethostbyname(full_domain)
            return {
                "subdomain": subdomain,
                "full_domain": full_domain,
                "ip": ip,
            }
        except (socket.gaierror, socket.timeout):
            return None
    
    discovered = []
    start_time = datetime.now(timezone.utc)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(check_subdomain, sub): sub for sub in wordlist}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                discovered.append(result)
    
    end_time = datetime.now(timezone.utc)
    scan_duration = (end_time - start_time).total_seconds()
    
    # Sort by subdomain name
    discovered.sort(key=lambda x: x["subdomain"])
    
    # Group by IP
    by_ip: Dict[str, List[str]] = {}
    for item in discovered:
        ip = item["ip"]
        if ip not in by_ip:
            by_ip[ip] = []
        by_ip[ip].append(item["full_domain"])
    
    return {
        "success": True,
        "domain": domain,
        "subdomains_checked": len(wordlist),
        "subdomains_found": len(discovered),
        "discovered": discovered,
        "by_ip": by_ip,
        "scan_duration_seconds": round(scan_duration, 2),
        "scan_time": start_time.isoformat(),
    }


@register_tool(sandbox_execution=False, category="recon")
def technology_detect(
    agent_state: Any,
    response_headers: Optional[Dict[str, str]] = None,
    response_body: Optional[str] = None,
    cookies: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Detect technologies from HTTP response data.
    
    Analyzes headers, body, and cookies to identify servers,
    frameworks, CMSs, and other technologies.
    
    Args:
        agent_state: Current agent state
        response_headers: HTTP response headers
        response_body: HTTP response body
        cookies: Cookie names/values
    
    Returns:
        Dictionary with detected technologies
    """
    detected = {
        "servers": [],
        "frameworks": [],
        "cms": [],
        "cdn": [],
        "other": [],
    }
    
    confidence_scores: Dict[str, int] = {}
    
    def add_detection(category: str, tech: str, confidence: int = 100):
        if tech not in detected[category]:
            detected[category].append(tech)
        if tech not in confidence_scores:
            confidence_scores[tech] = confidence
        else:
            confidence_scores[tech] = max(confidence_scores[tech], confidence)
    
    # Check headers
    if response_headers:
        headers_lower = {k.lower(): v for k, v in response_headers.items()}
        
        # Server header
        server = headers_lower.get("server", "")
        for tech, signatures in TECH_SIGNATURES["server"].items():
            if any(sig.lower() in server.lower() for sig in signatures):
                add_detection("servers", tech, 100)
        
        # X-Powered-By
        powered_by = headers_lower.get("x-powered-by", "")
        for tech, signatures in TECH_SIGNATURES["framework"].items():
            if any(sig.lower() in powered_by.lower() for sig in signatures):
                add_detection("frameworks", tech, 100)
        
        # CDN detection
        for tech, signatures in TECH_SIGNATURES["cdn"].items():
            for header, value in headers_lower.items():
                if any(sig.lower() in header.lower() or sig.lower() in value.lower() 
                       for sig in signatures):
                    add_detection("cdn", tech, 100)
                    break
    
    # Check cookies
    if cookies:
        cookies_str = " ".join(cookies).lower()
        
        for tech, signatures in TECH_SIGNATURES["framework"].items():
            if any(sig.lower() in cookies_str for sig in signatures):
                add_detection("frameworks", tech, 80)
        
        for tech, signatures in TECH_SIGNATURES["cdn"].items():
            if any(sig.lower() in cookies_str for sig in signatures):
                add_detection("cdn", tech, 80)
    
    # Check body
    if response_body:
        body_lower = response_body.lower()[:50000]  # Limit search
        
        for tech, signatures in TECH_SIGNATURES["framework"].items():
            if any(sig.lower() in body_lower for sig in signatures):
                add_detection("frameworks", tech, 70)
        
        for tech, signatures in TECH_SIGNATURES["cms"].items():
            if any(sig.lower() in body_lower for sig in signatures):
                add_detection("cms", tech, 70)
    
    # Calculate total count
    total_detected = sum(len(v) for v in detected.values())
    
    return {
        "success": True,
        "detected": detected,
        "confidence_scores": confidence_scores,
        "total_technologies": total_detected,
        "note": "Confidence scores: 100 = header match, 80 = cookie match, 70 = body match",
    }


@register_tool(sandbox_execution=False, category="recon")
def map_attack_surface(
    agent_state: Any,
    target: str,
    scan_results: Optional[Dict[str, Any]] = None,
    technologies: Optional[List[str]] = None,
    endpoints: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Create an attack surface map from reconnaissance data.
    
    Aggregates reconnaissance findings into a comprehensive
    attack surface view with vulnerability recommendations.
    
    Args:
        agent_state: Current agent state
        target: Target identifier
        scan_results: Previous port scan results
        technologies: Detected technologies
        endpoints: Discovered endpoints
    
    Returns:
        Dictionary with attack surface map
    """
    attack_surface = {
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "exposure_level": "unknown",
        "entry_points": [],
        "potential_vulnerabilities": [],
        "recommended_tests": [],
        "risk_areas": [],
    }
    
    # Process scan results
    if scan_results:
        open_ports = scan_results.get("open_ports", [])
        for port_info in open_ports:
            port = port_info["port"]
            service = port_info.get("service", "unknown")
            
            entry_point = {
                "type": "network_service",
                "port": port,
                "service": service,
                "protocol": "tcp",
            }
            attack_surface["entry_points"].append(entry_point)
            
            # Add service-specific recommendations
            if service == "http" or port in [80, 8080, 8000]:
                attack_surface["recommended_tests"].extend([
                    "Web application vulnerability scanning",
                    "OWASP Top 10 testing",
                    "Directory enumeration",
                ])
            elif service == "https" or port in [443, 8443]:
                attack_surface["recommended_tests"].extend([
                    "SSL/TLS configuration analysis",
                    "Certificate validation",
                    "Web application security testing",
                ])
            elif service in ["mysql", "postgresql", "mssql", "mongodb"]:
                attack_surface["risk_areas"].append(f"Exposed database ({service})")
                attack_surface["recommended_tests"].extend([
                    f"{service.upper()} authentication testing",
                    "Default credentials check",
                    "SQL injection testing",
                ])
            elif service == "ssh" or port == 22:
                attack_surface["recommended_tests"].extend([
                    "SSH version detection",
                    "SSH key authentication testing",
                    "Brute force resistance check",
                ])
            elif service == "ftp" or port == 21:
                attack_surface["risk_areas"].append("FTP service exposed")
                attack_surface["recommended_tests"].extend([
                    "Anonymous FTP access check",
                    "FTP bounce attack testing",
                ])
    
    # Process technologies
    if technologies:
        for tech in technologies:
            tech_lower = tech.lower()
            
            if "wordpress" in tech_lower:
                attack_surface["potential_vulnerabilities"].extend([
                    "WordPress plugin vulnerabilities",
                    "WordPress theme vulnerabilities",
                    "xmlrpc.php abuse",
                    "User enumeration (wp-json/wp/v2/users)",
                ])
            elif "php" in tech_lower:
                attack_surface["potential_vulnerabilities"].extend([
                    "PHP type juggling",
                    "File inclusion vulnerabilities",
                    "Deserialization attacks",
                ])
            elif "java" in tech_lower or "spring" in tech_lower:
                attack_surface["potential_vulnerabilities"].extend([
                    "Spring4Shell (CVE-2022-22965)",
                    "Java deserialization",
                    "Expression Language injection",
                ])
            elif "node" in tech_lower:
                attack_surface["potential_vulnerabilities"].extend([
                    "Prototype pollution",
                    "npm dependency vulnerabilities",
                    "Server-side JavaScript injection",
                ])
    
    # Process endpoints
    if endpoints:
        for endpoint in endpoints:
            endpoint_lower = endpoint.lower()
            
            entry_point = {
                "type": "endpoint",
                "path": endpoint,
            }
            attack_surface["entry_points"].append(entry_point)
            
            # Check for sensitive endpoints
            if any(word in endpoint_lower for word in ["admin", "login", "auth"]):
                attack_surface["risk_areas"].append(f"Authentication endpoint: {endpoint}")
            if any(word in endpoint_lower for word in ["api", "graphql", "rest"]):
                attack_surface["recommended_tests"].append(f"API security testing: {endpoint}")
            if any(word in endpoint_lower for word in ["upload", "file", "import"]):
                attack_surface["risk_areas"].append(f"File handling endpoint: {endpoint}")
    
    # Calculate exposure level
    risk_count = len(attack_surface["risk_areas"])
    entry_count = len(attack_surface["entry_points"])
    
    if risk_count > 5 or entry_count > 10:
        attack_surface["exposure_level"] = "high"
    elif risk_count > 2 or entry_count > 5:
        attack_surface["exposure_level"] = "medium"
    else:
        attack_surface["exposure_level"] = "low"
    
    # Deduplicate recommendations
    attack_surface["recommended_tests"] = list(set(attack_surface["recommended_tests"]))
    attack_surface["potential_vulnerabilities"] = list(set(attack_surface["potential_vulnerabilities"]))
    
    return {
        "success": True,
        "attack_surface": attack_surface,
        "summary": {
            "entry_points": len(attack_surface["entry_points"]),
            "potential_vulnerabilities": len(attack_surface["potential_vulnerabilities"]),
            "risk_areas": len(attack_surface["risk_areas"]),
            "recommended_tests": len(attack_surface["recommended_tests"]),
            "exposure_level": attack_surface["exposure_level"],
        },
    }
