import os
import json
import base64
import logging
import requests
from typing import Any, List, Optional, Dict
from datetime import datetime

logger = logging.getLogger(__name__)

class NekoDB:
    """Neko's persistence system, powered by GitHub (Port of StrixDB)."""
    
    def __init__(self, token: Optional[str] = None, repo: Optional[str] = None, branch: str = "main"):
        self.token = token or os.getenv("NEKODB_TOKEN")
        self.repo = repo or os.getenv("NEKODB_REPO", "NekoDB")
        self.branch = branch
        self.api_base = "https://api.github.com"
        
        self.categories = {
            "sessions": "Historical scan sessions",
            "exploits": "Verified exploit payloads and PoCs",
            "methods": "Custom methodologies developed by Neko",
            "tools": "Tool configurations and custom scripts",
            "libraries": "Identified libraries and dependencies",
            "sources": "Interesting code snippets and entry points",
            "knowledge": "Contextual knowledge about the target",
            "vulnerabilities": "Confirmed security findings",
        }

    def _get_headers(self):
        return {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json",
        }

    def save(self, category: str, name: str, content: Any, metadata: Optional[Dict] = None) -> bool:
        if not self.token or not self.repo:
            logger.warning("NekoDB not configured, skipping save.")
            return False
            
        if category not in self.categories:
            logger.error(f"Invalid category: {category}")
            return False

        path = f"{category}/{name}.json"
        url = f"{self.api_base}/repos/{self.repo}/contents/{path}"
        
        data = {
            "content": content,
            "metadata": metadata or {},
            "timestamp": datetime.utcnow().isoformat()
        }
        
        content_json = json.dumps(data, indent=2)
        content_b64 = base64.b64encode(content_json.encode()).decode()
        
        # Check if file exists to get SHA
        res = requests.get(url, headers=self._get_headers())
        sha = res.json().get("sha") if res.status_code == 200 else None
        
        payload = {
            "message": f"[NekoDB] Save {category}/{name}",
            "content": content_b64,
            "branch": self.branch
        }
        if sha:
            payload["sha"] = sha
            
        res = requests.put(url, headers=self._get_headers(), json=payload)
        return res.status_code in (200, 201)

    def get(self, category: str, name: str) -> Optional[Dict]:
        if not self.token or not self.repo: return None
        
        path = f"{category}/{name}.json"
        url = f"{self.api_base}/repos/{self.repo}/contents/{path}"
        
        res = requests.get(url, headers=self._get_headers())
        if res.status_code == 200:
            content_b64 = res.json().get("content", "")
            content_json = base64.b64decode(content_b64).decode()
            return json.loads(content_json)
        return None

    def list_items(self, category: str) -> List[str]:
        if not self.token or not self.repo: return []
        
        url = f"{self.api_base}/repos/{self.repo}/contents/{category}"
        res = requests.get(url, headers=self._get_headers())
        if res.status_code == 200:
            return [item["name"].replace(".json", "") for item in res.json() if item["type"] == "file"]
        return []
