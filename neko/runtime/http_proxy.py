"""
HTTP Proxy Runtime - Request/Response Manipulation for Security Testing.

Provides HTTP client capabilities with request modification and
response analysis for manual and automated security testing.
"""

from __future__ import annotations

import re
import json
import time
import logging
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Literal
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from ..tools.registry import register_tool

logger = logging.getLogger(__name__)

# Request history for session continuity
_request_history: List[Dict[str, Any]] = []
_max_history = 100


def _add_to_history(request_data: Dict[str, Any], response_data: Dict[str, Any]) -> str:
    """Add request/response pair to history."""
    entry_id = hashlib.md5(
        f"{request_data['url']}{time.time()}".encode()
    ).hexdigest()[:8]
    
    entry = {
        "id": entry_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request": request_data,
        "response": response_data,
    }
    
    _request_history.append(entry)
    
    # Trim history if too long
    if len(_request_history) > _max_history:
        _request_history.pop(0)
    
    return entry_id


@register_tool(sandbox_execution=True, category="http")
def http_request(
    agent_state: Any,
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, str]] = None,
    data: Optional[str] = None,
    json_body: Optional[Dict[str, Any]] = None,
    cookies: Optional[Dict[str, str]] = None,
    timeout: int = 30,
    follow_redirects: bool = True,
    verify_ssl: bool = True,
    auth: Optional[tuple] = None,
) -> Dict[str, Any]:
    """
    Make an HTTP request with full control over request parameters.
    
    Provides comprehensive HTTP client capabilities for security testing
    including header manipulation, authentication, and body formatting.
    
    Args:
        agent_state: Current agent state
        url: Target URL
        method: HTTP method (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD)
        headers: Custom headers
        params: URL query parameters
        data: Raw request body (string)
        json_body: JSON request body (dict)
        cookies: Request cookies
        timeout: Request timeout in seconds
        follow_redirects: Whether to follow redirects
        verify_ssl: Whether to verify SSL certificates
        auth: Basic auth tuple (username, password)
    
    Returns:
        Dictionary with request and response details
    """
    import requests
    from requests.exceptions import RequestException
    
    method = method.upper()
    
    # Build request
    request_data = {
        "url": url,
        "method": method,
        "headers": headers or {},
        "params": params or {},
        "cookies": cookies or {},
    }
    
    if data:
        request_data["body"] = data
    if json_body:
        request_data["json_body"] = json_body
    
    try:
        # Make request
        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            params=params,
            data=data,
            json=json_body,
            cookies=cookies,
            timeout=timeout,
            allow_redirects=follow_redirects,
            verify=verify_ssl,
            auth=auth,
        )
        
        # Build response data
        response_data = {
            "status_code": response.status_code,
            "status_text": response.reason,
            "headers": dict(response.headers),
            "cookies": dict(response.cookies),
            "url": response.url,
            "elapsed_ms": int(response.elapsed.total_seconds() * 1000),
            "redirects": [r.url for r in response.history],
            "content_length": len(response.content),
        }
        
        # Try to get body
        try:
            if response.headers.get("content-type", "").startswith("application/json"):
                response_data["body_json"] = response.json()
                response_data["body"] = json.dumps(response.json(), indent=2)[:10000]
            else:
                response_data["body"] = response.text[:10000]
        except Exception:
            response_data["body"] = response.text[:10000]
        
        # Add to history
        history_id = _add_to_history(request_data, response_data)
        
        return {
            "success": True,
            "history_id": history_id,
            "request": request_data,
            "response": response_data,
        }
        
    except RequestException as e:
        return {
            "success": False,
            "error": str(e),
            "error_type": type(e).__name__,
            "request": request_data,
        }


@register_tool(sandbox_execution=True, category="http")
def http_request_raw(
    agent_state: Any,
    raw_request: str,
    target_host: Optional[str] = None,
    use_ssl: bool = False,
    timeout: int = 30,
) -> Dict[str, Any]:
    """
    Send a raw HTTP request from captured traffic.
    
    Useful for replaying requests from tools like Burp Suite or manual
    request crafting. Parses the raw request and sends it.
    
    Args:
        agent_state: Current agent state
        raw_request: Raw HTTP request string
        target_host: Override target host (extracted from request if not provided)
        use_ssl: Whether to use HTTPS
        timeout: Request timeout
    
    Returns:
        Dictionary with request and response details
    """
    # Parse raw request
    lines = raw_request.strip().split("\n")
    if not lines:
        return {"success": False, "error": "Empty request"}
    
    # Parse request line
    request_line = lines[0].strip()
    parts = request_line.split(" ")
    if len(parts) < 2:
        return {"success": False, "error": f"Invalid request line: {request_line}"}
    
    method = parts[0]
    path = parts[1]
    
    # Parse headers
    headers = {}
    body_start = 0
    for i, line in enumerate(lines[1:], 1):
        line = line.strip()
        if not line:
            body_start = i + 1
            break
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()
    
    # Get body
    body = "\n".join(lines[body_start:]) if body_start < len(lines) else None
    
    # Determine host
    host = target_host or headers.get("Host", "")
    if not host:
        return {"success": False, "error": "No Host header and no target_host provided"}
    
    # Build URL
    scheme = "https" if use_ssl else "http"
    url = f"{scheme}://{host}{path}"
    
    # Make request
    return http_request(
        agent_state,
        url=url,
        method=method,
        headers=headers,
        data=body if body and body.strip() else None,
        timeout=timeout,
        verify_ssl=False,  # Raw requests often target test environments
    )


@register_tool(sandbox_execution=True, category="http")
def http_fuzz(
    agent_state: Any,
    url: str,
    method: str = "GET",
    fuzz_param: str = "FUZZ",
    wordlist: List[str] = None,
    headers: Optional[Dict[str, str]] = None,
    data: Optional[str] = None,
    delay_ms: int = 0,
    match_status: Optional[List[int]] = None,
    filter_status: Optional[List[int]] = None,
    match_size: Optional[int] = None,
    max_requests: int = 100,
) -> Dict[str, Any]:
    """
    Fuzz a parameter with a wordlist.
    
    Replaces FUZZ marker with each word from the wordlist and tracks
    responses. Useful for directory brute-forcing, parameter discovery, etc.
    
    Args:
        agent_state: Current agent state
        url: URL with FUZZ marker for replacement
        method: HTTP method
        fuzz_param: Marker to replace (default: FUZZ)
        wordlist: List of values to try
        headers: Request headers (can contain FUZZ)
        data: Request body (can contain FUZZ)
        delay_ms: Delay between requests in milliseconds
        match_status: Only include results with these status codes
        filter_status: Exclude results with these status codes
        match_size: Only include results with this response size
        max_requests: Maximum number of requests
    
    Returns:
        Dictionary with fuzzing results
    """
    import requests
    from requests.exceptions import RequestException
    
    if not wordlist:
        # Default wordlist for common paths/params
        wordlist = [
            "admin", "login", "api", "test", "backup", "config",
            "debug", "dev", "staging", "prod", "secret", "private",
            "uploads", "files", "images", "assets", "static",
            ".git", ".env", ".htaccess", "robots.txt", "sitemap.xml",
        ]
    
    wordlist = wordlist[:max_requests]
    results = []
    errors = []
    
    start_time = datetime.now(timezone.utc)
    
    for i, word in enumerate(wordlist):
        # Replace fuzz marker
        fuzzed_url = url.replace(fuzz_param, word)
        fuzzed_headers = None
        fuzzed_data = None
        
        if headers:
            fuzzed_headers = {k: v.replace(fuzz_param, word) for k, v in headers.items()}
        if data:
            fuzzed_data = data.replace(fuzz_param, word)
        
        try:
            response = requests.request(
                method=method,
                url=fuzzed_url,
                headers=fuzzed_headers,
                data=fuzzed_data,
                timeout=10,
                verify=False,
                allow_redirects=False,
            )
            
            result = {
                "word": word,
                "url": fuzzed_url,
                "status_code": response.status_code,
                "content_length": len(response.content),
                "content_type": response.headers.get("content-type", ""),
                "elapsed_ms": int(response.elapsed.total_seconds() * 1000),
            }
            
            # Apply filters
            if match_status and response.status_code not in match_status:
                continue
            if filter_status and response.status_code in filter_status:
                continue
            if match_size is not None and len(response.content) != match_size:
                continue
            
            results.append(result)
            
        except RequestException as e:
            errors.append({"word": word, "error": str(e)})
        
        # Delay if specified
        if delay_ms > 0 and i < len(wordlist) - 1:
            time.sleep(delay_ms / 1000)
    
    end_time = datetime.now(timezone.utc)
    duration = (end_time - start_time).total_seconds()
    
    # Sort by status code and then by content length
    results.sort(key=lambda x: (x["status_code"], -x["content_length"]))
    
    # Group by status code
    by_status: Dict[int, int] = {}
    for r in results:
        sc = r["status_code"]
        by_status[sc] = by_status.get(sc, 0) + 1
    
    return {
        "success": True,
        "url_pattern": url,
        "total_requests": len(wordlist),
        "total_results": len(results),
        "total_errors": len(errors),
        "duration_seconds": round(duration, 2),
        "by_status_code": by_status,
        "results": results,
        "errors": errors[:10],  # Limit error output
    }


@register_tool(sandbox_execution=False, category="http")
def analyze_response(
    agent_state: Any,
    history_id: Optional[str] = None,
    response_headers: Optional[Dict[str, str]] = None,
    response_body: Optional[str] = None,
    status_code: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Analyze an HTTP response for security issues.
    
    Checks for security headers, information disclosure, and common
    vulnerabilities indicated by response characteristics.
    
    Args:
        agent_state: Current agent state
        history_id: ID from previous request to analyze
        response_headers: Response headers to analyze
        response_body: Response body to analyze
        status_code: HTTP status code
    
    Returns:
        Dictionary with analysis results
    """
    # Get data from history if provided
    if history_id:
        for entry in _request_history:
            if entry["id"] == history_id:
                response_headers = entry["response"].get("headers", {})
                response_body = entry["response"].get("body", "")
                status_code = entry["response"].get("status_code")
                break
        else:
            return {"success": False, "error": f"History entry '{history_id}' not found"}
    
    findings = []
    security_headers = {}
    
    # Analyze headers
    if response_headers:
        headers_lower = {k.lower(): v for k, v in response_headers.items()}
        
        # Check security headers
        security_header_checks = {
            "x-frame-options": {
                "present": False,
                "expected": ["DENY", "SAMEORIGIN"],
                "issue": "Missing X-Frame-Options header (clickjacking risk)",
            },
            "x-content-type-options": {
                "present": False,
                "expected": ["nosniff"],
                "issue": "Missing X-Content-Type-Options header (MIME sniffing risk)",
            },
            "x-xss-protection": {
                "present": False,
                "expected": ["1; mode=block"],
                "issue": "Missing X-XSS-Protection header",
            },
            "strict-transport-security": {
                "present": False,
                "expected": None,
                "issue": "Missing HSTS header (downgrade attack risk)",
            },
            "content-security-policy": {
                "present": False,
                "expected": None,
                "issue": "Missing Content-Security-Policy header",
            },
            "referrer-policy": {
                "present": False,
                "expected": None,
                "issue": "Missing Referrer-Policy header",
            },
        }
        
        for header, check in security_header_checks.items():
            if header in headers_lower:
                check["present"] = True
                security_headers[header] = headers_lower[header]
            else:
                findings.append({
                    "type": "missing_security_header",
                    "severity": "medium",
                    "header": header,
                    "message": check["issue"],
                })
        
        # Check for information disclosure
        disclosure_headers = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]
        for header in disclosure_headers:
            if header in headers_lower:
                findings.append({
                    "type": "information_disclosure",
                    "severity": "low",
                    "header": header,
                    "value": headers_lower[header],
                    "message": f"Server reveals {header}: {headers_lower[header]}",
                })
    
    # Analyze body
    if response_body:
        # Check for sensitive data patterns
        sensitive_patterns = [
            (r'(?i)password\s*[=:]\s*["\']?[\w!@#$%^&*]+["\']?', "Potential password in response"),
            (r'(?i)api[_-]?key\s*[=:]\s*["\']?[\w-]+["\']?', "Potential API key in response"),
            (r'(?i)(secret|token)\s*[=:]\s*["\']?[\w-]+["\']?', "Potential secret/token in response"),
            (r'(?i)private[_-]?key', "Potential private key reference"),
            (r'(?i)BEGIN (RSA |DSA |EC )?PRIVATE KEY', "Private key in response"),
            (r'\b\d{3}-\d{2}-\d{4}\b', "Potential SSN pattern"),
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', "Email address in response"),
        ]
        
        for pattern, message in sensitive_patterns:
            if re.search(pattern, response_body):
                findings.append({
                    "type": "sensitive_data",
                    "severity": "high",
                    "message": message,
                })
        
        # Check for error messages
        error_patterns = [
            (r'(?i)stack\s*trace', "Stack trace exposed"),
            (r'(?i)sql\s*(syntax|error)', "SQL error exposed"),
            (r'(?i)(exception|error).*at\s+[\w.]+\.\w+\(', "Exception details exposed"),
            (r'(?i)fatal\s+error', "Fatal error message exposed"),
            (r'(?i)debug\s*=\s*true', "Debug mode enabled"),
        ]
        
        for pattern, message in error_patterns:
            if re.search(pattern, response_body):
                findings.append({
                    "type": "error_disclosure",
                    "severity": "medium",
                    "message": message,
                })
        
        # Check for comments with sensitive info
        html_comments = re.findall(r'<!--[\s\S]*?-->', response_body)
        for comment in html_comments[:5]:
            if any(word in comment.lower() for word in ["password", "secret", "api", "key", "todo", "fixme", "bug"]):
                findings.append({
                    "type": "comment_disclosure",
                    "severity": "low",
                    "message": "Potentially sensitive HTML comment",
                    "content": comment[:200],
                })
    
    # Analyze status code
    if status_code:
        if status_code == 500:
            findings.append({
                "type": "server_error",
                "severity": "medium",
                "message": "Internal server error may indicate vulnerability",
            })
        elif status_code == 403 and response_body and "directory" in response_body.lower():
            findings.append({
                "type": "information",
                "severity": "low",
                "message": "Directory listing might be available",
            })
    
    # Deduplicate findings
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f["type"], f.get("message", ""))
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)
    
    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    unique_findings.sort(key=lambda x: severity_order.get(x["severity"], 5))
    
    return {
        "success": True,
        "status_code": status_code,
        "total_findings": len(unique_findings),
        "security_headers": security_headers,
        "missing_security_headers": [f["header"] for f in unique_findings if f["type"] == "missing_security_header"],
        "findings": unique_findings,
    }


@register_tool(sandbox_execution=False, category="http")
def get_request_history(
    agent_state: Any,
    limit: int = 20,
    method_filter: Optional[str] = None,
    status_filter: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Get request/response history from the current session.
    
    Args:
        agent_state: Current agent state
        limit: Maximum entries to return
        method_filter: Filter by HTTP method
        status_filter: Filter by status code
    
    Returns:
        Dictionary with request history
    """
    filtered = []
    
    for entry in reversed(_request_history):
        if method_filter and entry["request"]["method"] != method_filter.upper():
            continue
        if status_filter and entry["response"].get("status_code") != status_filter:
            continue
        
        summary = {
            "id": entry["id"],
            "timestamp": entry["timestamp"],
            "method": entry["request"]["method"],
            "url": entry["request"]["url"],
            "status_code": entry["response"].get("status_code"),
            "content_length": entry["response"].get("content_length", 0),
            "elapsed_ms": entry["response"].get("elapsed_ms", 0),
        }
        filtered.append(summary)
        
        if len(filtered) >= limit:
            break
    
    return {
        "success": True,
        "total_history": len(_request_history),
        "returned": len(filtered),
        "history": filtered,
    }


@register_tool(sandbox_execution=False, category="http")
def modify_request(
    agent_state: Any,
    history_id: str,
    modifications: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Modify and replay a request from history.
    
    Useful for testing parameter manipulation and authentication bypass.
    
    Args:
        agent_state: Current agent state
        history_id: History entry ID to modify
        modifications: Dict with modifications:
            - url: New URL
            - method: New method
            - headers: Headers to add/override
            - params: Query params to add/override
            - data: New body
            - remove_headers: Headers to remove
    
    Returns:
        Dictionary with new request results
    """
    # Find original request
    original = None
    for entry in _request_history:
        if entry["id"] == history_id:
            original = entry["request"]
            break
    
    if not original:
        return {"success": False, "error": f"History entry '{history_id}' not found"}
    
    # Apply modifications
    new_request = {
        "url": modifications.get("url", original["url"]),
        "method": modifications.get("method", original["method"]),
        "headers": {**original.get("headers", {}), **modifications.get("headers", {})},
        "params": {**original.get("params", {}), **modifications.get("params", {})},
        "data": modifications.get("data", original.get("body")),
    }
    
    # Remove specified headers
    for header in modifications.get("remove_headers", []):
        new_request["headers"].pop(header, None)
        new_request["headers"].pop(header.lower(), None)
    
    # Make the modified request
    return http_request(
        agent_state,
        url=new_request["url"],
        method=new_request["method"],
        headers=new_request["headers"],
        params=new_request["params"],
        data=new_request["data"],
    )
