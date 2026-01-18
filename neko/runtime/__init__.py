"""
Neko Runtime - Advanced Python Runtime Features for Security Testing.

This package provides comprehensive runtime capabilities including:
- Custom exploit development and validation
- Reconnaissance and OSINT tools
- Static and dynamic code analysis
- HTTP proxy for request/response manipulation
- Browser automation for security testing

These features enable the Neko agent to perform sophisticated
security testing operations autonomously.
"""

# Python Runtime
from .python_runtime import (
    execute_python,
    create_session,
    list_sessions,
    close_session,
    encode_payload,
    decode_payload,
    hash_data,
)

# Exploit Development
from .exploit_runtime import (
    validate_exploit,
    generate_payload,
    test_payload,
    generate_polyglot,
    create_exploit_template,
)

# Reconnaissance
from .recon_runtime import (
    port_scan,
    dns_lookup,
    whois_lookup,
    subdomain_enum,
    technology_detect,
    map_attack_surface,
)

# Code Analysis
from .code_analysis import (
    static_analysis,
    secret_scan,
    dependency_check,
    analyze_code_quality,
)

# HTTP Proxy
from .http_proxy import (
    http_request,
    http_request_raw,
    http_fuzz,
    analyze_response,
    get_request_history,
    modify_request,
)

# Browser Automation
from .browser_automation import (
    create_browser_session,
    create_tab,
    plan_xss_test,
    plan_csrf_test,
    plan_auth_test,
    extract_forms,
    list_browser_sessions,
    close_browser_session,
)

__all__ = [
    # Python runtime
    "execute_python",
    "create_session",
    "list_sessions", 
    "close_session",
    "encode_payload",
    "decode_payload",
    "hash_data",
    # Exploit development
    "validate_exploit",
    "generate_payload",
    "test_payload",
    "generate_polyglot",
    "create_exploit_template",
    # Reconnaissance
    "port_scan",
    "dns_lookup",
    "whois_lookup",
    "subdomain_enum",
    "technology_detect",
    "map_attack_surface",
    # Code analysis
    "static_analysis",
    "secret_scan",
    "dependency_check",
    "analyze_code_quality",
    # HTTP Proxy
    "http_request",
    "http_request_raw",
    "http_fuzz",
    "analyze_response",
    "get_request_history",
    "modify_request",
    # Browser automation
    "create_browser_session",
    "create_tab",
    "plan_xss_test",
    "plan_csrf_test",
    "plan_auth_test",
    "extract_forms",
    "list_browser_sessions",
    "close_browser_session",
]
