"""
Python Runtime - Secure Python Code Execution Environment.

Provides isolated Python execution with session management
for multi-step exploit development and testing workflows.
"""

from __future__ import annotations

import ast
import io
import sys
import uuid
import traceback
import threading
import logging
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError

from ..tools.registry import register_tool

logger = logging.getLogger(__name__)

# Session storage
_sessions: Dict[str, Dict[str, Any]] = {}
_session_lock = threading.Lock()


def _generate_session_id() -> str:
    """Generate a unique session ID."""
    return f"py_session_{uuid.uuid4().hex[:8]}"


def _validate_code(code: str) -> tuple[bool, str]:
    """
    Validate Python code before execution.
    
    Checks for syntax errors and potentially dangerous operations.
    """
    # Check syntax
    try:
        ast.parse(code)
    except SyntaxError as e:
        return False, f"Syntax error: {e}"
    
    # Check for dangerous imports/operations (basic checks)
    dangerous_patterns = [
        ("subprocess.call", "Direct subprocess calls"),
        ("subprocess.Popen", "Process spawning"),
        ("os.system", "System command execution"),
        ("eval(", "Dynamic eval (use with caution)"),
        ("exec(", "Dynamic exec (use with caution)"),
        ("__import__", "Dynamic imports"),
        ("open('/etc", "System file access"),
        ("open('/root", "Root directory access"),
        ("shutil.rmtree", "Recursive file deletion"),
    ]
    
    warnings = []
    for pattern, desc in dangerous_patterns:
        if pattern in code:
            warnings.append(f"Warning: {desc} detected ({pattern})")
    
    return True, "\n".join(warnings) if warnings else ""


def _execute_with_timeout(
    code: str,
    globals_dict: Dict[str, Any],
    timeout: int
) -> Dict[str, Any]:
    """Execute code with a timeout."""
    result = {
        "stdout": "",
        "stderr": "",
        "return_value": None,
        "error": None,
        "execution_time": 0,
    }
    
    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()
    
    start_time = datetime.now(timezone.utc)
    
    def execute():
        nonlocal result
        try:
            with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
                # Execute the code
                exec(compile(code, "<neko_runtime>", "exec"), globals_dict)
                
                # Try to get return value if '_result' was set
                if "_result" in globals_dict:
                    result["return_value"] = globals_dict["_result"]
        except Exception as e:
            result["error"] = f"{type(e).__name__}: {str(e)}\n{traceback.format_exc()}"
    
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(execute)
        try:
            future.result(timeout=timeout)
        except FuturesTimeoutError:
            result["error"] = f"Execution timed out after {timeout} seconds"
    
    end_time = datetime.now(timezone.utc)
    result["execution_time"] = (end_time - start_time).total_seconds()
    result["stdout"] = stdout_capture.getvalue()
    result["stderr"] = stderr_capture.getvalue()
    
    return result


@register_tool(sandbox_execution=True, category="runtime")
def create_session(
    agent_state: Any,
    session_name: Optional[str] = None,
    imports: Optional[List[str]] = None,
    initial_code: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create a new Python execution session.
    
    Sessions maintain state between executions, allowing for
    multi-step workflows like exploit development and testing.
    
    Args:
        agent_state: Current agent state
        session_name: Optional name for the session
        imports: List of modules to pre-import
        initial_code: Initial code to run in the session
    
    Returns:
        Dictionary with session creation status
    """
    session_id = _generate_session_id()
    
    # Create isolated globals for this session
    session_globals = {
        "__builtins__": __builtins__,
        "__name__": f"neko_session_{session_id}",
        "__doc__": f"Neko Python Session: {session_name or session_id}",
    }
    
    # Pre-import common security testing modules
    default_imports = [
        "import base64",
        "import hashlib",
        "import json",
        "import re",
        "import urllib.parse",
        "import html",
        "import binascii",
        "import struct",
        "import codecs",
        "from typing import Any, Dict, List, Optional",
    ]
    
    if imports:
        default_imports.extend([f"import {m}" for m in imports])
    
    # Execute imports
    import_code = "\n".join(default_imports)
    try:
        exec(compile(import_code, "<imports>", "exec"), session_globals)
    except ImportError as e:
        logger.warning(f"Some imports failed: {e}")
    
    # Execute initial code if provided
    initial_result = None
    if initial_code:
        initial_result = _execute_with_timeout(initial_code, session_globals, 30)
    
    # Store session
    with _session_lock:
        _sessions[session_id] = {
            "id": session_id,
            "name": session_name or session_id,
            "globals": session_globals,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_used_at": datetime.now(timezone.utc).isoformat(),
            "execution_count": 1 if initial_code else 0,
            "history": [],
        }
    
    logger.info(f"[PythonRuntime] Created session: {session_id}")
    
    return {
        "success": True,
        "session_id": session_id,
        "session_name": session_name or session_id,
        "initial_result": initial_result,
        "message": f"Session '{session_name or session_id}' created successfully",
        "tip": "Use execute_python() with this session_id to run code",
    }


@register_tool(sandbox_execution=True, category="runtime")
def execute_python(
    agent_state: Any,
    code: str,
    session_id: Optional[str] = None,
    timeout: int = 30,
    capture_locals: bool = False,
) -> Dict[str, Any]:
    """
    Execute Python code in an isolated environment.
    
    Can be run in an existing session (stateful) or standalone (stateless).
    Use sessions for multi-step workflows like exploit development.
    
    Args:
        agent_state: Current agent state
        code: Python code to execute
        session_id: Optional session ID for stateful execution
        timeout: Maximum execution time in seconds
        capture_locals: Whether to capture local variables after execution
    
    Returns:
        Dictionary with execution results
    """
    # Validate code
    is_valid, validation_msg = _validate_code(code)
    if not is_valid:
        return {
            "success": False,
            "error": validation_msg,
            "stdout": "",
            "stderr": "",
        }
    
    # Get or create globals
    if session_id and session_id in _sessions:
        with _session_lock:
            session = _sessions[session_id]
            globals_dict = session["globals"]
            session["last_used_at"] = datetime.now(timezone.utc).isoformat()
            session["execution_count"] += 1
    else:
        # Create temporary globals for one-shot execution
        globals_dict = {
            "__builtins__": __builtins__,
            "__name__": "__neko_oneshot__",
        }
        
        # Add common imports for one-shot
        try:
            exec(
                "import base64, hashlib, json, re, urllib.parse, html, binascii",
                globals_dict
            )
        except ImportError:
            pass
    
    # Execute code
    result = _execute_with_timeout(code, globals_dict, timeout)
    
    # Add validation warnings
    if validation_msg:
        result["warnings"] = validation_msg
    
    # Capture locals if requested
    if capture_locals and not result["error"]:
        result["captured_locals"] = {
            k: str(v)[:1000] for k, v in globals_dict.items()
            if not k.startswith("__") and k not in ("builtins",)
        }
    
    # Add to history if using session
    if session_id and session_id in _sessions:
        with _session_lock:
            _sessions[session_id]["history"].append({
                "code": code[:500],
                "success": result["error"] is None,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
    
    return {
        "success": result["error"] is None,
        "stdout": result["stdout"],
        "stderr": result["stderr"],
        "return_value": result.get("return_value"),
        "error": result["error"],
        "execution_time": result["execution_time"],
        "session_id": session_id,
        "warnings": result.get("warnings"),
        "captured_locals": result.get("captured_locals"),
    }


@register_tool(sandbox_execution=True, category="runtime")
def list_sessions(agent_state: Any) -> Dict[str, Any]:
    """
    List all active Python execution sessions.
    
    Returns:
        Dictionary with session list
    """
    with _session_lock:
        sessions = []
        for sid, session in _sessions.items():
            sessions.append({
                "session_id": sid,
                "name": session["name"],
                "created_at": session["created_at"],
                "last_used_at": session["last_used_at"],
                "execution_count": session["execution_count"],
                "history_count": len(session["history"]),
            })
    
    return {
        "success": True,
        "session_count": len(sessions),
        "sessions": sessions,
    }


@register_tool(sandbox_execution=True, category="runtime")
def close_session(agent_state: Any, session_id: str) -> Dict[str, Any]:
    """
    Close and cleanup a Python execution session.
    
    Args:
        agent_state: Current agent state
        session_id: Session ID to close
    
    Returns:
        Dictionary with closure status
    """
    with _session_lock:
        if session_id not in _sessions:
            return {
                "success": False,
                "error": f"Session '{session_id}' not found",
            }
        
        session = _sessions.pop(session_id)
    
    logger.info(f"[PythonRuntime] Closed session: {session_id}")
    
    return {
        "success": True,
        "session_id": session_id,
        "name": session["name"],
        "total_executions": session["execution_count"],
        "message": f"Session '{session['name']}' closed successfully",
    }


# Utility functions for security testing

@register_tool(sandbox_execution=True, category="runtime")
def encode_payload(
    agent_state: Any,
    payload: str,
    encoding: str = "base64",
    iterations: int = 1,
) -> Dict[str, Any]:
    """
    Encode a payload using various encoding schemes.
    
    Useful for payload obfuscation and bypassing filters.
    
    Args:
        agent_state: Current agent state
        payload: The payload to encode
        encoding: Encoding type (base64, url, hex, html, unicode)
        iterations: Number of encoding iterations
    
    Returns:
        Dictionary with encoded payload
    """
    import base64
    import urllib.parse
    import html
    import binascii
    
    result = payload
    encoding_steps = []
    
    for i in range(iterations):
        step_before = result
        
        if encoding == "base64":
            result = base64.b64encode(result.encode()).decode()
        elif encoding == "url":
            result = urllib.parse.quote(result, safe="")
        elif encoding == "double_url":
            result = urllib.parse.quote(urllib.parse.quote(result, safe=""), safe="")
        elif encoding == "hex":
            result = binascii.hexlify(result.encode()).decode()
        elif encoding == "html":
            result = html.escape(result)
        elif encoding == "html_entities":
            result = "".join(f"&#{ord(c)};" for c in result)
        elif encoding == "unicode":
            result = "".join(f"\\u{ord(c):04x}" for c in result)
        elif encoding == "ascii_hex":
            result = "".join(f"\\x{ord(c):02x}" for c in result)
        else:
            return {
                "success": False,
                "error": f"Unknown encoding: {encoding}",
                "supported": ["base64", "url", "double_url", "hex", "html", 
                             "html_entities", "unicode", "ascii_hex"],
            }
        
        encoding_steps.append({
            "iteration": i + 1,
            "before_length": len(step_before),
            "after_length": len(result),
        })
    
    return {
        "success": True,
        "original": payload,
        "encoded": result,
        "encoding": encoding,
        "iterations": iterations,
        "steps": encoding_steps,
    }


@register_tool(sandbox_execution=True, category="runtime")
def decode_payload(
    agent_state: Any,
    encoded: str,
    encoding: str = "base64",
    iterations: int = 1,
) -> Dict[str, Any]:
    """
    Decode an encoded payload.
    
    Useful for analyzing obfuscated payloads and malicious content.
    
    Args:
        agent_state: Current agent state
        encoded: The encoded payload
        encoding: Encoding type (base64, url, hex, html, unicode)
        iterations: Number of decoding iterations
    
    Returns:
        Dictionary with decoded payload
    """
    import base64
    import urllib.parse
    import html
    import binascii
    import codecs
    
    result = encoded
    
    try:
        for _ in range(iterations):
            if encoding == "base64":
                result = base64.b64decode(result).decode()
            elif encoding == "url":
                result = urllib.parse.unquote(result)
            elif encoding == "hex":
                result = binascii.unhexlify(result).decode()
            elif encoding == "html":
                result = html.unescape(result)
            elif encoding == "unicode":
                result = codecs.decode(result, "unicode_escape")
            else:
                return {
                    "success": False,
                    "error": f"Unknown encoding: {encoding}",
                }
        
        return {
            "success": True,
            "encoded": encoded,
            "decoded": result,
            "encoding": encoding,
            "iterations": iterations,
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Decoding failed: {e}",
            "encoded": encoded,
        }


@register_tool(sandbox_execution=True, category="runtime")
def hash_data(
    agent_state: Any,
    data: str,
    algorithm: str = "sha256",
) -> Dict[str, Any]:
    """
    Hash data using various algorithms.
    
    Args:
        agent_state: Current agent state
        data: Data to hash
        algorithm: Hash algorithm (md5, sha1, sha256, sha512)
    
    Returns:
        Dictionary with hash results
    """
    import hashlib
    
    algorithms = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512,
    }
    
    if algorithm not in algorithms:
        return {
            "success": False,
            "error": f"Unknown algorithm: {algorithm}",
            "supported": list(algorithms.keys()),
        }
    
    hash_obj = algorithms[algorithm](data.encode())
    
    return {
        "success": True,
        "data": data[:100] + "..." if len(data) > 100 else data,
        "algorithm": algorithm,
        "hash_hex": hash_obj.hexdigest(),
        "hash_base64": __import__("base64").b64encode(hash_obj.digest()).decode(),
    }
