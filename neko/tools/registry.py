"""
Tool Registry - Central registry for all Neko tools.

This module provides a decorator-based registration system for tools,
allowing for dynamic tool discovery and execution.
"""

from functools import wraps
from typing import Any, Callable, Dict, List, Optional
import logging

logger = logging.getLogger(__name__)

# Global tool registry
_registered_tools: Dict[str, Dict[str, Any]] = {}


def register_tool(
    func: Optional[Callable] = None,
    *,
    sandbox_execution: bool = True,
    description: Optional[str] = None,
    category: str = "general",
) -> Callable:
    """
    Decorator to register a function as a Neko tool.
    
    Args:
        func: The function to register (optional, for decorator without arguments)
        sandbox_execution: Whether the tool should be executed in a sandbox
        description: Optional description override
        category: Tool category for organization
    
    Returns:
        The decorated function
    
    Example:
        @register_tool
        def my_tool(arg1: str) -> dict:
            '''Tool description.'''
            return {"result": arg1}
        
        @register_tool(sandbox_execution=False, category="network")
        def network_tool(url: str) -> dict:
            '''Network tool description.'''
            return {"url": url}
    """
    def decorator(fn: Callable) -> Callable:
        tool_name = fn.__name__
        tool_doc = description or fn.__doc__ or "No description available"
        
        # Register the tool
        _registered_tools[tool_name] = {
            "function": fn,
            "name": tool_name,
            "description": tool_doc,
            "sandbox_execution": sandbox_execution,
            "category": category,
        }
        
        @wraps(fn)
        def wrapper(*args, **kwargs):
            logger.debug(f"Executing tool: {tool_name}")
            try:
                result = fn(*args, **kwargs)
                return result
            except Exception as e:
                logger.error(f"Tool {tool_name} failed: {e}")
                return {"error": str(e), "success": False}
        
        return wrapper
    
    # Support both @register_tool and @register_tool()
    if func is not None:
        return decorator(func)
    return decorator


def get_registered_tools() -> Dict[str, Dict[str, Any]]:
    """Get all registered tools."""
    return _registered_tools.copy()


def get_tool(name: str) -> Optional[Dict[str, Any]]:
    """Get a specific tool by name."""
    return _registered_tools.get(name)


def execute_tool(name: str, *args, **kwargs) -> Any:
    """Execute a registered tool by name."""
    tool = _registered_tools.get(name)
    if not tool:
        raise ValueError(f"Tool '{name}' not found")
    return tool["function"](*args, **kwargs)


def list_tools_by_category(category: str) -> List[str]:
    """List all tools in a specific category."""
    return [
        name for name, info in _registered_tools.items()
        if info.get("category") == category
    ]


def get_tool_schema(name: str) -> Optional[Dict[str, Any]]:
    """Get the schema for a tool including parameters."""
    tool = _registered_tools.get(name)
    if not tool:
        return None
    
    fn = tool["function"]
    import inspect
    sig = inspect.signature(fn)
    
    params = {}
    for param_name, param in sig.parameters.items():
        if param_name in ("self", "agent_state"):
            continue
        
        param_info = {
            "type": str(param.annotation) if param.annotation != inspect.Parameter.empty else "any",
            "required": param.default == inspect.Parameter.empty,
        }
        if param.default != inspect.Parameter.empty:
            param_info["default"] = param.default
        
        params[param_name] = param_info
    
    return {
        "name": name,
        "description": tool["description"],
        "category": tool["category"],
        "parameters": params,
        "sandbox_execution": tool["sandbox_execution"],
    }
