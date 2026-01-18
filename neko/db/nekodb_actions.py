"""
NekoDB Actions - GitHub-based persistent storage for Neko security artifacts.

Advanced port of StrixDB with comprehensive features for:
- Storing exploits, scripts, methodologies, and knowledge
- Target tracking with session management
- Technology and vulnerability cataloging
- Search and retrieval capabilities

CONFIGURATION:
- Repository name defaults to 'NekoDB' owned by the token's user
- Authentication via NEKODB_TOKEN (GitHub PAT from secrets)
- Supports NEKODB_REPO override for custom repository paths
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

import requests

from ..tools.registry import register_tool


logger = logging.getLogger(__name__)

# Default categories (can be extended dynamically)
DEFAULT_CATEGORIES = [
    "scripts",
    "exploits", 
    "knowledge",
    "libraries",
    "sources",
    "methods",
    "tools",
    "configs",
    "wordlists",
    "payloads",
    "templates",
    "notes",
    "sessions",
    "vulnerabilities",
]

# Category descriptions
CATEGORY_DESCRIPTIONS = {
    "scripts": "Automation scripts, shell scripts, and utility scripts",
    "exploits": "Working exploits, PoCs, and vulnerability demonstrations",
    "knowledge": "Security knowledge, research notes, and documentation",
    "libraries": "Reusable code libraries and modules",
    "sources": "Data sources, references, and external resource links",
    "methods": "Attack methodologies, techniques, and procedures",
    "tools": "Custom security tools and utilities",
    "configs": "Configuration files, templates, and settings",
    "wordlists": "Custom wordlists for fuzzing and enumeration",
    "payloads": "Useful payloads for various attack types",
    "templates": "Report templates, code templates, and boilerplates",
    "notes": "Quick notes and temporary findings",
    "sessions": "Historical scan sessions",
    "vulnerabilities": "Confirmed security findings",
}

# Runtime storage for dynamically created categories
_dynamic_categories: set[str] = set()


def _get_nekodb_config() -> Dict[str, str]:
    """
    Get NekoDB configuration.
    
    Repository name defaults to 'NekoDB'.
    Owner is determined from the authenticated user.
    Token comes from NEKODB_TOKEN environment variable.
    """
    token = os.getenv("NEKODB_TOKEN", "")
    branch = os.getenv("NEKODB_BRANCH", "main")
    
    repo_name = "NekoDB"
    owner = ""
    
    if token:
        try:
            response = requests.get(
                "https://api.github.com/user",
                headers=_get_headers(token),
                timeout=10,
            )
            if response.status_code == 200:
                owner = response.json().get("login", "")
        except requests.RequestException:
            pass
    
    # Allow override via NEKODB_REPO
    repo_override = os.getenv("NEKODB_REPO", "")
    if repo_override:
        if "/" in repo_override:
            return {
                "repo": repo_override,
                "token": token,
                "branch": branch,
                "api_base": "https://api.github.com",
            }
        repo_name = repo_override
    
    repo = f"{owner}/{repo_name}" if owner else ""
    
    return {
        "repo": repo,
        "token": token,
        "branch": branch,
        "api_base": "https://api.github.com",
    }


def _get_headers(token: str) -> Dict[str, str]:
    """Get headers for GitHub API requests."""
    return {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _sanitize_name(name: str) -> str:
    """Sanitize a name for use as a filename."""
    name = name.replace(" ", "_")
    name = re.sub(r'[^\w\-.]', '_', name)
    name = re.sub(r'_+', '_', name)
    name = name.strip('_')
    return name


def _generate_item_id() -> str:
    """Generate a unique item ID."""
    return str(uuid.uuid4())[:8]


def _get_file_path(category: str, name: str, extension: str = ".json") -> str:
    """Generate the file path for an item."""
    sanitized_name = _sanitize_name(name)
    return f"{category}/{sanitized_name}{extension}"


def _get_valid_categories() -> List[str]:
    """Get all valid categories (default + dynamically created)."""
    return list(set(DEFAULT_CATEGORIES) | _dynamic_categories)


def _create_metadata(
    name: str,
    description: str,
    tags: List[str],
    category: str,
    content_type: str = "text",
) -> Dict[str, Any]:
    """Create metadata for an item."""
    return {
        "id": _generate_item_id(),
        "name": name,
        "description": description,
        "tags": tags,
        "category": category,
        "content_type": content_type,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "version": 1,
    }


def _ensure_category_exists(category: str, config: Dict[str, str]) -> bool:
    """Ensure a category directory exists in NekoDB."""
    if not config["repo"] or not config["token"]:
        return False
    
    try:
        url = f"{config['api_base']}/repos/{config['repo']}/contents/{category}"
        response = requests.get(url, headers=_get_headers(config["token"]), timeout=30)
        
        if response.status_code == 200:
            return True
        
        if response.status_code == 404:
            readme_content = f"""# {category.title()}

This category was automatically created by NekoDB.

{CATEGORY_DESCRIPTIONS.get(category, 'Custom category for storing related items.')}

## Contents

Items in this category will be listed here as they are added.
"""
            readme_encoded = base64.b64encode(readme_content.encode()).decode()
            
            create_url = f"{config['api_base']}/repos/{config['repo']}/contents/{category}/README.md"
            create_response = requests.put(
                create_url,
                headers=_get_headers(config["token"]),
                json={
                    "message": f"[NekoDB] Create category: {category}",
                    "content": readme_encoded,
                    "branch": config["branch"],
                },
                timeout=30,
            )
            
            if create_response.status_code in (200, 201):
                _dynamic_categories.add(category)
                logger.info(f"[NekoDB] Created new category: {category}")
                return True
        
        return False
        
    except requests.RequestException as e:
        logger.exception(f"[NekoDB] Failed to ensure category exists: {e}")
        return False


# =============================================================================
# Core NekoDB Tools
# =============================================================================

@register_tool(sandbox_execution=False, category="nekodb")
def nekodb_save(
    agent_state: Any,
    category: str,
    name: str,
    content: str,
    description: str = "",
    tags: Optional[List[str]] = None,
    content_type: str = "text",
) -> Dict[str, Any]:
    """
    Save an item to NekoDB for permanent storage.
    
    Use this to store useful artifacts like scripts, exploits, knowledge,
    tools, and other items for future reference across sessions.
    
    Args:
        agent_state: Current agent state
        category: Category for the item (existing or new)
        name: Name of the item
        content: Content to save
        description: Description of the item
        tags: List of tags for categorization
        content_type: Type of content (text, script, json, python, etc.)
    
    Returns:
        Dictionary with operation result
    """
    config = _get_nekodb_config()
    
    if not config["repo"] or not config["token"]:
        return {
            "success": False,
            "error": "NekoDB not configured. Ensure NEKODB_TOKEN is set in your GitHub secrets.",
            "hint": "Add NEKODB_TOKEN to your repository secrets with a GitHub PAT that has repo access.",
            "item": None,
        }
    
    category = category.lower().replace(" ", "_")
    
    if not _ensure_category_exists(category, config):
        return {
            "success": False,
            "error": f"Failed to access or create category '{category}'",
            "item": None,
        }
    
    if tags is None:
        tags = []
    
    metadata = _create_metadata(name, description, tags, category, content_type)
    
    # Determine file extension
    extensions = {
        "text": ".md",
        "script": ".sh",
        "json": ".json",
        "python": ".py",
        "javascript": ".js",
        "yaml": ".yml",
        "binary": ".bin",
        "bash": ".sh",
    }
    extension = extensions.get(content_type, ".txt")
    
    content_path = _get_file_path(category, name, extension)
    metadata_path = _get_file_path(category, f"{_sanitize_name(name)}_meta", ".json")
    
    try:
        content_encoded = base64.b64encode(content.encode()).decode()
        
        url = f"{config['api_base']}/repos/{config['repo']}/contents/{content_path}"
        response = requests.get(url, headers=_get_headers(config["token"]), timeout=30)
        
        payload: Dict[str, Any] = {
            "message": f"[NekoDB] Add {category}/{name}",
            "content": content_encoded,
            "branch": config["branch"],
        }
        
        if response.status_code == 200:
            sha = response.json().get("sha")
            payload["sha"] = sha
            payload["message"] = f"[NekoDB] Update {category}/{name}"
            metadata["version"] = response.json().get("version", 1) + 1
        
        response = requests.put(
            url,
            headers=_get_headers(config["token"]),
            json=payload,
            timeout=30,
        )
        
        if response.status_code not in (200, 201):
            return {
                "success": False,
                "error": f"Failed to save content: {response.status_code} - {response.text}",
                "item": None,
            }
        
        # Save metadata
        metadata["file_path"] = content_path
        metadata_encoded = base64.b64encode(json.dumps(metadata, indent=2).encode()).decode()
        
        meta_url = f"{config['api_base']}/repos/{config['repo']}/contents/{metadata_path}"
        meta_response = requests.get(meta_url, headers=_get_headers(config["token"]), timeout=30)
        
        meta_payload: Dict[str, Any] = {
            "message": f"[NekoDB] Add metadata for {category}/{name}",
            "content": metadata_encoded,
            "branch": config["branch"],
        }
        
        if meta_response.status_code == 200:
            meta_sha = meta_response.json().get("sha")
            meta_payload["sha"] = meta_sha
        
        requests.put(
            meta_url,
            headers=_get_headers(config["token"]),
            json=meta_payload,
            timeout=30,
        )
        
        logger.info(f"[NekoDB] Saved item: {category}/{name}")
        
        return {
            "success": True,
            "message": f"Successfully saved '{name}' to NekoDB in category '{category}'",
            "item": {
                "id": metadata["id"],
                "name": name,
                "category": category,
                "path": content_path,
                "tags": tags,
            },
        }
        
    except requests.RequestException as e:
        logger.exception(f"[NekoDB] Failed to save item: {e}")
        return {
            "success": False,
            "error": f"Request failed: {e!s}",
            "item": None,
        }


@register_tool(sandbox_execution=False, category="nekodb")
def nekodb_get(
    agent_state: Any,
    category: str,
    name: str,
) -> Dict[str, Any]:
    """
    Retrieve a specific item from NekoDB.
    
    Args:
        agent_state: Current agent state
        category: Category of the item
        name: Name of the item
    
    Returns:
        Dictionary with the item content and metadata
    """
    config = _get_nekodb_config()
    
    if not config["repo"] or not config["token"]:
        return {
            "success": False,
            "error": "NekoDB not configured",
            "item": None,
        }
    
    try:
        list_url = f"{config['api_base']}/repos/{config['repo']}/contents/{category}"
        list_response = requests.get(
            list_url,
            headers=_get_headers(config["token"]),
            timeout=30,
        )
        
        if list_response.status_code != 200:
            return {
                "success": False,
                "error": f"Category '{category}' not found",
                "item": None,
            }
        
        files = list_response.json()
        sanitized_name = _sanitize_name(name)
        
        content_file = None
        meta_file = None
        
        for file in files:
            file_name = file.get("name", "")
            if file_name.startswith(sanitized_name) and not file_name.endswith("_meta.json"):
                content_file = file
            elif file_name == f"{sanitized_name}_meta.json":
                meta_file = file
        
        if not content_file:
            return {
                "success": False,
                "error": f"Item '{name}' not found in category '{category}'",
                "item": None,
            }
        
        content_response = requests.get(
            content_file["url"],
            headers=_get_headers(config["token"]),
            timeout=30,
        )
        
        if content_response.status_code != 200:
            return {
                "success": False,
                "error": "Failed to fetch content",
                "item": None,
            }
        
        content_data = content_response.json()
        content = base64.b64decode(content_data.get("content", "")).decode()
        
        metadata = {}
        if meta_file:
            meta_response = requests.get(
                meta_file["url"],
                headers=_get_headers(config["token"]),
                timeout=30,
            )
            if meta_response.status_code == 200:
                meta_data = meta_response.json()
                metadata = json.loads(
                    base64.b64decode(meta_data.get("content", "")).decode()
                )
        
        return {
            "success": True,
            "item": {
                "name": name,
                "category": category,
                "content": content,
                "path": content_file["path"],
                "metadata": metadata,
            },
        }
        
    except requests.RequestException as e:
        logger.exception(f"[NekoDB] Get failed: {e}")
        return {
            "success": False,
            "error": f"Request failed: {e!s}",
            "item": None,
        }


@register_tool(sandbox_execution=False, category="nekodb")
def nekodb_search(
    agent_state: Any,
    query: str,
    category: Optional[str] = None,
    tags: Optional[List[str]] = None,
    limit: int = 20,
) -> Dict[str, Any]:
    """
    Search for items in NekoDB.
    
    Args:
        agent_state: Current agent state
        query: Search query (searches name, description, and content)
        category: Optional category filter
        tags: Optional tags filter
        limit: Maximum number of results
    
    Returns:
        Dictionary with search results
    """
    config = _get_nekodb_config()
    
    if not config["repo"] or not config["token"]:
        return {
            "success": False,
            "error": "NekoDB not configured",
            "results": [],
        }
    
    try:
        search_query = f"repo:{config['repo']} {query}"
        if category:
            search_query += f" path:{category}/"
        
        url = f"{config['api_base']}/search/code"
        params = {
            "q": search_query,
            "per_page": min(limit, 100),
        }
        
        response = requests.get(
            url,
            headers=_get_headers(config["token"]),
            params=params,
            timeout=30,
        )
        
        if response.status_code != 200:
            return {
                "success": False,
                "error": f"Search failed: {response.status_code}",
                "results": [],
            }
        
        data = response.json()
        results = []
        
        for item in data.get("items", []):
            path = item.get("path", "")
            
            if "_meta.json" in path:
                continue
            
            parts = path.split("/")
            item_category = parts[0] if parts else "unknown"
            item_name = parts[-1] if parts else path
            
            results.append({
                "name": item_name,
                "category": item_category,
                "path": path,
                "score": item.get("score", 0),
            })
        
        return {
            "success": True,
            "query": query,
            "total_count": data.get("total_count", len(results)),
            "results": results[:limit],
        }
        
    except requests.RequestException as e:
        logger.exception(f"[NekoDB] Search failed: {e}")
        return {
            "success": False,
            "error": f"Search failed: {e!s}",
            "results": [],
        }


@register_tool(sandbox_execution=False, category="nekodb")
def nekodb_list(
    agent_state: Any,
    category: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """
    List items in NekoDB.
    
    Args:
        agent_state: Current agent state
        category: Optional category to list (None for all)
        limit: Maximum number of items
    
    Returns:
        Dictionary with list of items
    """
    config = _get_nekodb_config()
    
    if not config["repo"] or not config["token"]:
        return {
            "success": False,
            "error": "NekoDB not configured",
            "items": [],
        }
    
    try:
        items = []
        categories_to_list = [category] if category else _get_valid_categories()
        
        for cat in categories_to_list:
            url = f"{config['api_base']}/repos/{config['repo']}/contents/{cat}"
            response = requests.get(
                url,
                headers=_get_headers(config["token"]),
                timeout=30,
            )
            
            if response.status_code == 200:
                files = response.json()
                for file in files:
                    name = file.get("name", "")
                    if name.endswith("_meta.json") or name == "README.md":
                        continue
                    
                    items.append({
                        "name": name,
                        "category": cat,
                        "path": file.get("path", ""),
                        "size": file.get("size", 0),
                        "type": file.get("type", "file"),
                    })
            
            if len(items) >= limit:
                break
        
        return {
            "success": True,
            "total": len(items),
            "items": items[:limit],
        }
        
    except requests.RequestException as e:
        logger.exception(f"[NekoDB] List failed: {e}")
        return {
            "success": False,
            "error": f"Request failed: {e!s}",
            "items": [],
        }


@register_tool(sandbox_execution=False, category="nekodb")
def nekodb_delete(
    agent_state: Any,
    category: str,
    name: str,
) -> Dict[str, Any]:
    """
    Delete an item from NekoDB.
    
    Args:
        agent_state: Current agent state
        category: Category of the item
        name: Name of the item
    
    Returns:
        Dictionary with operation result
    """
    config = _get_nekodb_config()
    
    if not config["repo"] or not config["token"]:
        return {
            "success": False,
            "error": "NekoDB not configured",
        }
    
    try:
        existing = nekodb_get(agent_state, category, name)
        
        if not existing["success"]:
            return existing
        
        path = existing["item"]["path"]
        sanitized_name = _sanitize_name(name)
        meta_path = path.replace(
            path.split("/")[-1],
            f"{sanitized_name}_meta.json"
        )
        
        content_url = f"{config['api_base']}/repos/{config['repo']}/contents/{path}"
        content_response = requests.get(
            content_url,
            headers=_get_headers(config["token"]),
            timeout=30,
        )
        
        if content_response.status_code != 200:
            return {
                "success": False,
                "error": "Failed to get file info for deletion",
            }
        
        content_sha = content_response.json().get("sha")
        
        delete_response = requests.delete(
            content_url,
            headers=_get_headers(config["token"]),
            json={
                "message": f"[NekoDB] Delete {category}/{name}",
                "sha": content_sha,
                "branch": config["branch"],
            },
            timeout=30,
        )
        
        if delete_response.status_code not in (200, 204):
            return {
                "success": False,
                "error": f"Failed to delete content: {delete_response.status_code}",
            }
        
        # Try to delete metadata
        meta_url = f"{config['api_base']}/repos/{config['repo']}/contents/{meta_path}"
        meta_response = requests.get(
            meta_url,
            headers=_get_headers(config["token"]),
            timeout=30,
        )
        
        if meta_response.status_code == 200:
            meta_sha = meta_response.json().get("sha")
            requests.delete(
                meta_url,
                headers=_get_headers(config["token"]),
                json={
                    "message": f"[NekoDB] Delete metadata for {category}/{name}",
                    "sha": meta_sha,
                    "branch": config["branch"],
                },
                timeout=30,
            )
        
        return {
            "success": True,
            "message": f"Successfully deleted '{name}' from category '{category}'",
        }
        
    except requests.RequestException as e:
        logger.exception(f"[NekoDB] Delete failed: {e}")
        return {
            "success": False,
            "error": f"Request failed: {e!s}",
        }


@register_tool(sandbox_execution=False, category="nekodb")
def nekodb_get_categories(agent_state: Any) -> Dict[str, Any]:
    """
    Get all available categories in NekoDB with descriptions.
    
    Args:
        agent_state: Current agent state
    
    Returns:
        Dictionary with categories information
    """
    config = _get_nekodb_config()
    
    categories = []
    all_categories = _get_valid_categories()
    
    for cat in all_categories:
        desc = CATEGORY_DESCRIPTIONS.get(cat, "Custom category")
        cat_info = {
            "name": cat,
            "description": desc,
            "item_count": 0,
            "is_custom": cat in _dynamic_categories,
        }
        
        if config["repo"] and config["token"]:
            try:
                url = f"{config['api_base']}/repos/{config['repo']}/contents/{cat}"
                response = requests.get(
                    url,
                    headers=_get_headers(config["token"]),
                    timeout=10,
                )
                if response.status_code == 200:
                    files = response.json()
                    cat_info["item_count"] = sum(
                        1 for f in files 
                        if not f.get("name", "").endswith("_meta.json") 
                        and f.get("name") != "README.md"
                    )
            except requests.RequestException:
                pass
        
        categories.append(cat_info)
    
    return {
        "success": True,
        "categories": categories,
        "total_categories": len(categories),
        "hint": "You can create new categories dynamically by saving items to them",
    }


@register_tool(sandbox_execution=False, category="nekodb")
def nekodb_get_config_status(agent_state: Any) -> Dict[str, Any]:
    """
    Get the current NekoDB configuration status.
    
    Args:
        agent_state: Current agent state
    
    Returns:
        Dictionary with configuration status
    """
    config = _get_nekodb_config()
    
    is_configured = bool(config["repo"] and config["token"])
    
    connection_status = "not_tested"
    if is_configured:
        try:
            url = f"{config['api_base']}/repos/{config['repo']}"
            response = requests.get(
                url,
                headers=_get_headers(config["token"]),
                timeout=10,
            )
            if response.status_code == 200:
                connection_status = "connected"
            elif response.status_code == 404:
                connection_status = "repository_not_found"
            elif response.status_code == 401:
                connection_status = "authentication_failed"
            else:
                connection_status = f"error_{response.status_code}"
        except requests.RequestException as e:
            connection_status = f"connection_error: {e!s}"
    
    return {
        "success": True,
        "configured": is_configured,
        "connection_status": connection_status,
        "repository": config["repo"] if is_configured else None,
        "branch": config["branch"],
        "token_set": bool(config["token"]),
        "setup_instructions": (
            "To configure NekoDB:\n"
            "1. Create a GitHub repository named 'NekoDB'\n"
            "2. Create a GitHub Personal Access Token (PAT) with 'repo' scope\n"
            "3. Add the token as NEKODB_TOKEN in your repository secrets\n"
            "4. The workflow will automatically pass the token to Neko"
        ) if not is_configured else None,
    }


# =============================================================================
# Target Tracking System (Port from StrixDB)
# =============================================================================

def _sanitize_target_slug(target: str) -> str:
    """Create a safe directory-friendly slug from a target identifier."""
    target = re.sub(r'^https?://', '', target)
    target = target.split('/')[0]
    target = re.sub(r':\d+$', '', target)
    slug = re.sub(r'[^\w\-.]', '_', target)
    slug = re.sub(r'_+', '_', slug)
    slug = slug.strip('_').lower()
    
    if len(slug) < 3:
        slug = f"{slug}_{hashlib.md5(target.encode()).hexdigest()[:8]}"
    
    return slug


def _generate_session_id() -> str:
    """Generate a unique session ID."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    unique = str(uuid.uuid4())[:8]
    return f"session_{timestamp}_{unique}"


def _get_or_create_target_file(
    config: Dict[str, str],
    target_slug: str,
    file_name: str,
    default_content: Union[Dict[str, Any], List[Any]],
) -> tuple[Union[Dict[str, Any], List[Any]], Optional[str]]:
    """Get existing file content or return default."""
    path = f"targets/{target_slug}/{file_name}"
    url = f"{config['api_base']}/repos/{config['repo']}/contents/{path}"
    
    try:
        response = requests.get(url, headers=_get_headers(config["token"]), timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            content = json.loads(base64.b64decode(data.get("content", "")).decode())
            return content, data.get("sha")
        
        return default_content, None
        
    except (requests.RequestException, json.JSONDecodeError):
        return default_content, None


def _save_target_file(
    config: Dict[str, str],
    target_slug: str,
    file_name: str,
    content: Union[Dict[str, Any], List[Any]],
    sha: Optional[str] = None,
    commit_message: str = "",
) -> bool:
    """Save a file to the target's directory in NekoDB."""
    path = f"targets/{target_slug}/{file_name}"
    url = f"{config['api_base']}/repos/{config['repo']}/contents/{path}"
    
    content_encoded = base64.b64encode(json.dumps(content, indent=2).encode()).decode()
    
    payload: Dict[str, Any] = {
        "message": commit_message or f"[NekoDB] Update {path}",
        "content": content_encoded,
        "branch": config["branch"],
    }
    
    if sha:
        payload["sha"] = sha
    
    try:
        response = requests.put(
            url,
            headers=_get_headers(config["token"]),
            json=payload,
            timeout=30,
        )
        return response.status_code in (200, 201)
    except requests.RequestException:
        return False


def _ensure_target_directory(config: Dict[str, str], target_slug: str) -> bool:
    """Ensure the target directory exists in NekoDB."""
    readme_path = f"targets/{target_slug}/README.md"
    url = f"{config['api_base']}/repos/{config['repo']}/contents/{readme_path}"
    
    try:
        response = requests.get(url, headers=_get_headers(config["token"]), timeout=30)
        
        if response.status_code == 200:
            return True
        
        if response.status_code == 404:
            readme_content = f"""# Target: {target_slug}

This directory contains comprehensive scan data for target: `{target_slug}`

## Contents

- `profile.json` - Main target profile and metadata
- `sessions/` - Individual session data
- `findings/` - Vulnerability findings
- `endpoints.json` - Discovered endpoints
- `technologies.json` - Technology stack
- `notes.json` - Session notes

## Auto-generated by NekoDB Target Tracking System
"""
            content_encoded = base64.b64encode(readme_content.encode()).decode()
            
            create_response = requests.put(
                url,
                headers=_get_headers(config["token"]),
                json={
                    "message": f"[NekoDB] Initialize target: {target_slug}",
                    "content": content_encoded,
                    "branch": config["branch"],
                },
                timeout=30,
            )
            
            return create_response.status_code in (200, 201)
        
        return False
        
    except requests.RequestException:
        return False


@register_tool(sandbox_execution=False, category="nekodb")
def nekodb_target_init(
    agent_state: Any,
    target: str,
    target_type: str = "web_app",
    description: str = "",
    scope: Optional[List[str]] = None,
    out_of_scope: Optional[List[str]] = None,
    tags: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Initialize a new target in NekoDB for comprehensive tracking.
    
    Creates a persistent target profile that stores ALL data discovered
    across all scanning sessions. Call when starting to scan a new target.
    
    Args:
        agent_state: Current agent state
        target: Target identifier (URL, domain, IP, repo URL, etc.)
        target_type: Type - web_app, api, domain, ip, repository, network
        description: Description of the target and engagement
        scope: List of in-scope items
        out_of_scope: List of out-of-scope items
        tags: Tags for categorization
    
    Returns:
        Dictionary with target profile and previous session info if exists
    """
    config = _get_nekodb_config()
    
    if not config["repo"] or not config["token"]:
        return {
            "success": False,
            "error": "NekoDB not configured. Ensure NEKODB_TOKEN is set.",
            "target": None,
        }
    
    target_slug = _sanitize_target_slug(target)
    
    # Check if target already exists
    existing_profile, existing_sha = _get_or_create_target_file(
        config, target_slug, "profile.json", {}
    )
    
    if existing_profile and existing_sha:
        return {
            "success": True,
            "message": f"Target '{target_slug}' already exists. Use existing data to continue.",
            "is_new": False,
            "target": {
                "slug": target_slug,
                "profile": existing_profile,
                "previous_sessions_count": existing_profile.get("total_sessions", 0),
                "last_scan_at": existing_profile.get("last_scan_at"),
                "stats": existing_profile.get("stats", {}),
                "quick_info": existing_profile.get("quick_info", {}),
                "tested_areas": existing_profile.get("tested_areas", {}),
                "pending_work": existing_profile.get("pending_work", {}),
            },
            "continuation_guidance": (
                "This target has been scanned before. Review 'tested_areas' to avoid "
                "repeating work. Check 'pending_work' for follow-up items. "
                "Start a new session with nekodb_target_session_start() to continue."
            ),
        }
    
    # Create new target
    if not _ensure_target_directory(config, target_slug):
        return {
            "success": False,
            "error": f"Failed to create target directory for '{target_slug}'",
            "target": None,
        }
    
    now = datetime.now(timezone.utc).isoformat()
    
    profile = {
        "id": str(uuid.uuid4())[:12],
        "slug": target_slug,
        "target": target,
        "target_type": target_type,
        "description": description,
        "created_at": now,
        "updated_at": now,
        "last_scan_at": None,
        "total_sessions": 0,
        "status": "initialized",
        "scope": {
            "in_scope": scope or [target],
            "out_of_scope": out_of_scope or [],
        },
        "tags": tags or [],
        "stats": {
            "total_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "endpoints_discovered": 0,
            "technologies_identified": 0,
            "sessions_count": 0,
        },
        "quick_info": {
            "main_technologies": [],
            "confirmed_vulnerabilities": [],
            "key_endpoints": [],
            "authentication_status": "unknown",
            "last_session_summary": "",
        },
        "tested_areas": {
            "reconnaissance": [],
            "vulnerability_types": [],
            "endpoints_tested": [],
            "payloads_tried": [],
        },
        "pending_work": {
            "high_priority": [],
            "medium_priority": [],
            "low_priority": [],
            "follow_ups": [],
        },
        "session_history": [],
    }
    
    if not _save_target_file(
        config,
        target_slug,
        "profile.json",
        profile,
        commit_message=f"[NekoDB] Initialize target profile: {target_slug}",
    ):
        return {
            "success": False,
            "error": f"Failed to save target profile for '{target_slug}'",
            "target": None,
        }
    
    # Create empty data files
    empty_structures = {
        "endpoints.json": {"discovered": [], "tested": [], "vulnerable": []},
        "technologies.json": {"identified": [], "versions": {}},
        "notes.json": {"entries": []},
        "findings.json": {"vulnerabilities": [], "informational": []},
    }
    
    for file_name, content in empty_structures.items():
        _save_target_file(
            config,
            target_slug,
            file_name,
            content,
            commit_message=f"[NekoDB] Initialize {file_name} for {target_slug}",
        )
    
    logger.info(f"[NekoDB] Initialized new target: {target_slug}")
    
    return {
        "success": True,
        "message": f"Successfully initialized target '{target_slug}'",
        "is_new": True,
        "target": {
            "slug": target_slug,
            "profile": profile,
            "previous_sessions_count": 0,
        },
        "next_step": (
            "Target initialized! Call nekodb_target_session_start() to begin "
            "your first scan session and start tracking your work."
        ),
    }


@register_tool(sandbox_execution=False, category="nekodb")
def nekodb_target_session_start(
    agent_state: Any,
    target: str,
    objective: str = "",
    focus_areas: Optional[List[str]] = None,
    timeframe_minutes: int = 60,
) -> Dict[str, Any]:
    """
    Start a new scan session for a target.
    
    Call at the beginning of each scanning session to:
    1. Load all previous data about the target
    2. Get a summary of what has been tested/found
    3. Create a new session to track this session's work
    4. Get guidance on what to focus on
    
    Args:
        agent_state: Current agent state
        target: Target identifier
        objective: What you aim to accomplish
        focus_areas: Specific areas to focus on
        timeframe_minutes: Expected session duration
    
    Returns:
        Dictionary with session info and target summary
    """
    config = _get_nekodb_config()
    
    if not config["repo"] or not config["token"]:
        return {
            "success": False,
            "error": "NekoDB not configured",
            "session": None,
        }
    
    target_slug = _sanitize_target_slug(target)
    
    profile, profile_sha = _get_or_create_target_file(
        config, target_slug, "profile.json", {}
    )
    
    if not profile or not profile_sha:
        return {
            "success": False,
            "error": f"Target '{target_slug}' not found. Initialize it first with nekodb_target_init()",
            "session": None,
        }
    
    # Load supplementary data
    endpoints, _ = _get_or_create_target_file(
        config, target_slug, "endpoints.json",
        {"discovered": [], "tested": [], "vulnerable": []}
    )
    technologies, _ = _get_or_create_target_file(
        config, target_slug, "technologies.json",
        {"identified": [], "versions": {}}
    )
    
    # Create new session
    session_id = _generate_session_id()
    now = datetime.now(timezone.utc).isoformat()
    
    session_data = {
        "session_id": session_id,
        "target_slug": target_slug,
        "started_at": now,
        "ended_at": None,
        "duration_minutes": 0,
        "status": "active",
        "objective": objective,
        "focus_areas": focus_areas or [],
        "accomplishments": [],
        "findings": [],
        "endpoints": {"discovered": [], "tested": [], "vulnerable": []},
        "technologies": [],
        "notes": [],
        "continuation_notes": {
            "immediate_follow_ups": [],
            "promising_leads": [],
            "blocked_by": [],
            "recommendations": [],
        },
        "metrics": {
            "findings_count": 0,
            "endpoints_discovered": 0,
            "endpoints_tested": 0,
            "tools_used": [],
        },
    }
    
    if not _save_target_file(
        config,
        target_slug,
        f"sessions/{session_id}.json",
        session_data,
        commit_message=f"[NekoDB] Start session {session_id} for {target_slug}",
    ):
        return {
            "success": False,
            "error": "Failed to create session",
            "session": None,
        }
    
    # Update profile
    profile["status"] = "active"
    profile["last_scan_at"] = now
    profile["total_sessions"] = profile.get("total_sessions", 0) + 1
    profile["stats"]["sessions_count"] = profile["total_sessions"]
    
    _save_target_file(
        config,
        target_slug,
        "profile.json",
        profile,
        sha=profile_sha,
        commit_message=f"[NekoDB] Update profile - session {session_id} started",
    )
    
    # Build recommendations
    tested_areas = profile.get("tested_areas", {})
    pending_work = profile.get("pending_work", {})
    quick_info = profile.get("quick_info", {})
    
    recommendations = []
    if pending_work.get("high_priority"):
        recommendations.append(f"HIGH PRIORITY: {', '.join(pending_work['high_priority'][:3])}")
    if pending_work.get("follow_ups"):
        recommendations.append(f"Follow-ups: {', '.join(pending_work['follow_ups'][:3])}")
    if not tested_areas.get("vulnerability_types"):
        recommendations.append("No vuln testing recorded - start with recon and common vulns")
    
    logger.info(f"[NekoDB] Started session {session_id} for target {target_slug}")
    
    return {
        "success": True,
        "message": f"Session '{session_id}' started for target '{target_slug}'",
        "session": {
            "session_id": session_id,
            "target_slug": target_slug,
            "objective": objective,
            "focus_areas": focus_areas,
            "timeframe_minutes": timeframe_minutes,
        },
        "target_summary": {
            "previous_sessions": profile.get("total_sessions", 1) - 1,
            "total_findings": profile.get("stats", {}).get("total_findings", 0),
            "severity_breakdown": {
                "critical": profile.get("stats", {}).get("critical", 0),
                "high": profile.get("stats", {}).get("high", 0),
                "medium": profile.get("stats", {}).get("medium", 0),
                "low": profile.get("stats", {}).get("low", 0),
            },
            "endpoints_discovered": len(endpoints.get("discovered", [])),
            "technologies": technologies.get("identified", [])[:10],
            "confirmed_vulns": quick_info.get("confirmed_vulnerabilities", []),
            "key_endpoints": quick_info.get("key_endpoints", [])[:10],
        },
        "previous_work": {
            "tested_vulnerability_types": tested_areas.get("vulnerability_types", []),
            "tested_endpoints_count": len(tested_areas.get("endpoints_tested", [])),
            "recon_completed": tested_areas.get("reconnaissance", []),
        },
        "pending_work": pending_work,
        "recommendations": recommendations,
        "guidance": (
            "Session started! As you work, use:\n"
            "- nekodb_target_add_finding() to record vulnerabilities\n"
            "- nekodb_target_add_endpoint() to track discovered endpoints\n"
            "- nekodb_target_add_note() for observations\n"
            "- nekodb_target_session_end() when finished\n\n"
            "IMPORTANT: Store EVERYTHING useful - be comprehensive!"
        ),
    }


@register_tool(sandbox_execution=False, category="nekodb")
def nekodb_target_add_finding(
    agent_state: Any,
    target: str,
    session_id: str,
    title: str,
    severity: str,
    vulnerability_type: str,
    description: str,
    affected_endpoint: str = "",
    proof_of_concept: str = "",
    steps_to_reproduce: Optional[List[str]] = None,
    impact: str = "",
    remediation: str = "",
    references: Optional[List[str]] = None,
    tags: Optional[List[str]] = None,
    additional_data: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Add a vulnerability finding to the target.
    
    Store COMPREHENSIVE finding data with all evidence and details.
    
    Args:
        agent_state: Current agent state
        target: Target identifier
        session_id: Current session ID
        title: Clear, descriptive title
        severity: critical, high, medium, low, info
        vulnerability_type: sqli, xss, idor, ssrf, rce, auth_bypass, etc.
        description: Detailed description
        affected_endpoint: The vulnerable endpoint/parameter
        proof_of_concept: Working PoC payload
        steps_to_reproduce: Step-by-step reproduction
        impact: Business/security impact
        remediation: How to fix
        references: Related CVEs, articles, etc.
        tags: Categorization tags
        additional_data: Extra data (request/response, etc.)
    
    Returns:
        Dictionary with saved finding info
    """
    config = _get_nekodb_config()
    
    if not config["repo"] or not config["token"]:
        return {"success": False, "error": "NekoDB not configured"}
    
    target_slug = _sanitize_target_slug(target)
    now = datetime.now(timezone.utc).isoformat()
    
    finding_id = f"finding_{str(uuid.uuid4())[:8]}"
    
    finding = {
        "id": finding_id,
        "session_id": session_id,
        "title": title,
        "severity": severity.lower(),
        "vulnerability_type": vulnerability_type,
        "description": description,
        "affected_endpoint": affected_endpoint,
        "proof_of_concept": proof_of_concept,
        "steps_to_reproduce": steps_to_reproduce or [],
        "impact": impact,
        "remediation": remediation,
        "references": references or [],
        "tags": tags or [],
        "additional_data": additional_data or {},
        "created_at": now,
        "status": "confirmed",
        "verified": True,
    }
    
    findings, findings_sha = _get_or_create_target_file(
        config, target_slug, "findings.json",
        {"vulnerabilities": [], "informational": []}
    )
    
    if severity.lower() == "info":
        findings["informational"].append(finding)
    else:
        findings["vulnerabilities"].append(finding)
    
    if not _save_target_file(
        config,
        target_slug,
        "findings.json",
        findings,
        sha=findings_sha,
        commit_message=f"[NekoDB] Add finding: {title[:50]}",
    ):
        return {"success": False, "error": "Failed to save finding"}
    
    # Update profile stats
    profile, profile_sha = _get_or_create_target_file(
        config, target_slug, "profile.json", {}
    )
    
    if profile and profile_sha:
        stats = profile.get("stats", {})
        stats["total_findings"] = stats.get("total_findings", 0) + 1
        stats[severity.lower()] = stats.get(severity.lower(), 0) + 1
        profile["stats"] = stats
        
        if severity.lower() in ["critical", "high"]:
            confirmed = profile.get("quick_info", {}).get("confirmed_vulnerabilities", [])
            confirmed.append(f"{severity.upper()}: {title}")
            profile["quick_info"]["confirmed_vulnerabilities"] = confirmed[-10:]
        
        tested = profile.get("tested_areas", {}).get("vulnerability_types", [])
        if vulnerability_type not in tested:
            tested.append(vulnerability_type)
            profile["tested_areas"]["vulnerability_types"] = tested
        
        _save_target_file(
            config,
            target_slug,
            "profile.json",
            profile,
            sha=profile_sha,
            commit_message=f"[NekoDB] Update stats for finding: {finding_id}",
        )
    
    # Update session
    session_data, session_sha = _get_or_create_target_file(
        config, target_slug, f"sessions/{session_id}.json", {}
    )
    
    if session_data and session_sha:
        session_data["findings"].append({
            "id": finding_id,
            "title": title,
            "severity": severity,
        })
        session_data["metrics"]["findings_count"] = len(session_data["findings"])
        
        _save_target_file(
            config,
            target_slug,
            f"sessions/{session_id}.json",
            session_data,
            sha=session_sha,
            commit_message=f"[NekoDB] Update session with finding: {finding_id}",
        )
    
    logger.info(f"[NekoDB] Added finding '{title}' ({severity}) for {target_slug}")
    
    return {
        "success": True,
        "message": f"Finding '{title}' saved successfully",
        "finding": {
            "id": finding_id,
            "title": title,
            "severity": severity,
            "vulnerability_type": vulnerability_type,
        },
    }


@register_tool(sandbox_execution=False, category="nekodb")
def nekodb_target_session_end(
    agent_state: Any,
    target: str,
    session_id: str,
    summary: str,
    accomplishments: Optional[List[str]] = None,
    immediate_follow_ups: Optional[List[str]] = None,
    promising_leads: Optional[List[str]] = None,
    blocked_by: Optional[List[str]] = None,
    recommendations: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    End a scan session and save comprehensive session data.
    
    Provide detailed continuation notes for efficient pickup in next session.
    
    Args:
        agent_state: Current agent state
        target: Target identifier
        session_id: The session ID to end
        summary: Comprehensive summary of work done
        accomplishments: List of things accomplished
        immediate_follow_ups: Things to do immediately next session
        promising_leads: Areas that need more investigation
        blocked_by: Things that blocked progress
        recommendations: Recommendations for next session
    
    Returns:
        Dictionary with session summary
    """
    config = _get_nekodb_config()
    
    if not config["repo"] or not config["token"]:
        return {"success": False, "error": "NekoDB not configured"}
    
    target_slug = _sanitize_target_slug(target)
    
    session_data, session_sha = _get_or_create_target_file(
        config, target_slug, f"sessions/{session_id}.json", {}
    )
    
    if not session_data or not session_sha:
        return {
            "success": False,
            "error": f"Session '{session_id}' not found for target '{target_slug}'",
        }
    
    profile, profile_sha = _get_or_create_target_file(
        config, target_slug, "profile.json", {}
    )
    
    now = datetime.now(timezone.utc)
    started_at = datetime.fromisoformat(
        session_data.get("started_at", now.isoformat()).replace('Z', '+00:00')
    )
    duration = int((now - started_at).total_seconds() / 60)
    
    session_data["ended_at"] = now.isoformat()
    session_data["duration_minutes"] = duration
    session_data["status"] = "completed"
    session_data["accomplishments"] = accomplishments or []
    session_data["continuation_notes"] = {
        "immediate_follow_ups": immediate_follow_ups or [],
        "promising_leads": promising_leads or [],
        "blocked_by": blocked_by or [],
        "recommendations": recommendations or [],
    }
    
    _save_target_file(
        config,
        target_slug,
        f"sessions/{session_id}.json",
        session_data,
        sha=session_sha,
        commit_message=f"[NekoDB] End session {session_id}",
    )
    
    if profile and profile_sha:
        profile["status"] = "paused"
        profile["updated_at"] = now.isoformat()
        profile["quick_info"]["last_session_summary"] = summary
        
        if immediate_follow_ups:
            existing_high = profile.get("pending_work", {}).get("high_priority", [])
            profile["pending_work"]["high_priority"] = list(
                set(existing_high + immediate_follow_ups)
            )[:20]
        if promising_leads:
            existing_medium = profile.get("pending_work", {}).get("medium_priority", [])
            profile["pending_work"]["medium_priority"] = list(
                set(existing_medium + promising_leads)
            )[:20]
        if recommendations:
            profile["pending_work"]["follow_ups"] = recommendations[:10]
        
        session_summary = {
            "session_id": session_id,
            "date": now.isoformat(),
            "duration_minutes": duration,
            "summary": summary[:500],
            "findings_count": session_data.get("metrics", {}).get("findings_count", 0),
        }
        history = profile.get("session_history", [])
        history.append(session_summary)
        profile["session_history"] = history[-20:]
        
        _save_target_file(
            config,
            target_slug,
            "profile.json",
            profile,
            sha=profile_sha,
            commit_message=f"[NekoDB] Update profile after session {session_id}",
        )
    
    logger.info(f"[NekoDB] Ended session {session_id} for target {target_slug}")
    
    return {
        "success": True,
        "message": f"Session '{session_id}' ended successfully",
        "session_summary": {
            "session_id": session_id,
            "duration_minutes": duration,
            "accomplishments": accomplishments,
            "findings_recorded": session_data.get("metrics", {}).get("findings_count", 0),
            "endpoints_discovered": session_data.get("metrics", {}).get("endpoints_discovered", 0),
        },
        "continuation_saved": {
            "immediate_follow_ups": immediate_follow_ups,
            "promising_leads": promising_leads,
            "blocked_by": blocked_by,
            "recommendations": recommendations,
        },
        "hint": (
            "Session data saved! Next time, use nekodb_target_session_start() "
            "to load all context and continue efficiently."
        ),
    }
