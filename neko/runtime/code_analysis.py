"""
Code Analysis Runtime - Static and Dynamic Code Analysis.

Provides security-focused code analysis capabilities:
- Static analysis with pattern matching
- Dependency vulnerability checking
- Secret/credential scanning
- Code quality assessment
"""

from __future__ import annotations

import re
import os
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pathlib import Path

from ..tools.registry import register_tool

logger = logging.getLogger(__name__)

# Security vulnerability patterns
VULN_PATTERNS = {
    "python": {
        "sql_injection": [
            (r'execute\s*\(\s*["\'].*%s.*["\']\s*%', "SQL injection via string formatting"),
            (r'execute\s*\(\s*f["\']', "SQL injection via f-string"),
            (r'cursor\.execute\s*\([^,]+\+', "SQL injection via concatenation"),
        ],
        "command_injection": [
            (r'os\.system\s*\(', "Potential command injection via os.system"),
            (r'subprocess\.call\s*\(.*shell\s*=\s*True', "Command injection risk with shell=True"),
            (r'subprocess\.Popen\s*\(.*shell\s*=\s*True', "Command injection risk with shell=True"),
            (r'eval\s*\(', "Dangerous eval() usage"),
            (r'exec\s*\(', "Dangerous exec() usage"),
        ],
        "path_traversal": [
            (r'open\s*\([^)]*\+[^)]*\)', "Potential path traversal via concatenation"),
            (r'os\.path\.join\s*\([^)]*request', "Path traversal risk with user input"),
        ],
        "deserialization": [
            (r'pickle\.loads?\s*\(', "Unsafe pickle deserialization"),
            (r'yaml\.load\s*\([^)]*\)', "Unsafe YAML loading (use safe_load)"),
            (r'marshal\.loads?\s*\(', "Unsafe marshal deserialization"),
        ],
        "hardcoded_secrets": [
            (r'password\s*=\s*["\'][^"\']+["\']', "Hardcoded password"),
            (r'api_key\s*=\s*["\'][^"\']+["\']', "Hardcoded API key"),
            (r'secret\s*=\s*["\'][^"\']+["\']', "Hardcoded secret"),
            (r'token\s*=\s*["\'][A-Za-z0-9_-]{20,}["\']', "Hardcoded token"),
        ],
        "xss": [
            (r'render_template_string\s*\(', "XSS risk with render_template_string"),
            (r'\|safe\b', "Jinja2 |safe filter disables escaping"),
        ],
        "ssrf": [
            (r'requests\.(get|post|put|delete)\s*\([^)]*request\.', "Potential SSRF with user input"),
            (r'urllib\.request\.urlopen\s*\([^)]*request\.', "Potential SSRF with user input"),
        ],
    },
    "javascript": {
        "xss": [
            (r'\.innerHTML\s*=', "XSS risk with innerHTML"),
            (r'document\.write\s*\(', "XSS risk with document.write"),
            (r'eval\s*\(', "Dangerous eval() usage"),
            (r'\$\([^)]*\)\.html\s*\(', "XSS risk with jQuery .html()"),
        ],
        "sql_injection": [
            (r'query\s*\(\s*[`"\'].*\$\{', "SQL injection via template literal"),
            (r'execute\s*\(\s*[`"\'].*\+', "SQL injection via concatenation"),
        ],
        "prototype_pollution": [
            (r'Object\.assign\s*\([^)]*req\.', "Prototype pollution risk"),
            (r'\[\s*req\.(body|query|params)', "Prototype pollution via dynamic property"),
        ],
        "path_traversal": [
            (r'path\.join\s*\([^)]*req\.', "Path traversal risk with user input"),
            (r'fs\.(readFile|writeFile|unlink)\s*\([^)]*\+', "Path traversal via concatenation"),
        ],
        "command_injection": [
            (r'child_process\.exec\s*\(', "Command injection risk with exec"),
            (r'require\s*\(\s*[`"\']child_process', "Child process usage detected"),
        ],
    },
    "java": {
        "sql_injection": [
            (r'Statement\.execute(Query|Update)\s*\([^)]*\+', "SQL injection via concatenation"),
            (r'createQuery\s*\([^)]*\+', "HQL injection via concatenation"),
        ],
        "deserialization": [
            (r'ObjectInputStream\s*\(', "Unsafe Java deserialization"),
            (r'XMLDecoder\s*\(', "XXE and deserialization risk"),
        ],
        "xxe": [
            (r'DocumentBuilderFactory\.newInstance\s*\(\s*\)', "XXE risk without secure configuration"),
            (r'SAXParserFactory\.newInstance\s*\(\s*\)', "XXE risk without secure configuration"),
        ],
        "path_traversal": [
            (r'new\s+File\s*\([^)]*\+', "Path traversal via concatenation"),
            (r'Paths\.get\s*\([^)]*\+', "Path traversal via concatenation"),
        ],
    },
}

# Secret patterns for scanning
SECRET_PATTERNS = [
    # API Keys
    (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,})["\']?', "API Key"),
    (r'(?i)(secret[_-]?key|secretkey)\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,})["\']?', "Secret Key"),
    
    # AWS
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
    (r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', "AWS Secret Access Key"),
    
    # Google
    (r'AIza[0-9A-Za-z_-]{35}', "Google API Key"),
    (r'(?i)google[_-]?api[_-]?key\s*[=:]\s*["\']?([A-Za-z0-9_-]{39})["\']?', "Google API Key"),
    
    # GitHub
    (r'ghp_[0-9A-Za-z]{36}', "GitHub Personal Access Token"),
    (r'gho_[0-9A-Za-z]{36}', "GitHub OAuth Token"),
    (r'ghu_[0-9A-Za-z]{36}', "GitHub User-to-Server Token"),
    (r'ghs_[0-9A-Za-z]{36}', "GitHub Server-to-Server Token"),
    
    # Slack
    (r'xox[baprs]-[0-9A-Za-z-]{10,}', "Slack Token"),
    
    # Generic passwords
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']', "Password"),
    
    # JWT
    (r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', "JWT Token"),
    
    # Private keys
    (r'-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----', "Private Key"),
    
    # Database URLs
    (r'(?i)(mysql|postgres|mongodb|redis)://[^\s<>"]+:[^\s<>"]+@', "Database Connection String"),
]


@register_tool(sandbox_execution=True, category="analysis")
def static_analysis(
    agent_state: Any,
    code: str,
    language: str = "python",
    check_secrets: bool = True,
    severity_filter: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Perform static security analysis on source code.
    
    Scans code for common vulnerability patterns specific to the language.
    
    Args:
        agent_state: Current agent state
        code: Source code to analyze
        language: Programming language (python, javascript, java)
        check_secrets: Also check for hardcoded secrets
        severity_filter: Filter by severity (high, medium, low)
    
    Returns:
        Dictionary with analysis results
    """
    language = language.lower()
    
    if language not in VULN_PATTERNS:
        return {
            "success": False,
            "error": f"Unsupported language: {language}",
            "supported_languages": list(VULN_PATTERNS.keys()),
        }
    
    findings = []
    patterns = VULN_PATTERNS[language]
    
    # Assign severity based on vulnerability type
    severity_map = {
        "sql_injection": "high",
        "command_injection": "critical",
        "deserialization": "high",
        "xss": "medium",
        "ssrf": "high",
        "xxe": "high",
        "path_traversal": "high",
        "hardcoded_secrets": "high",
        "prototype_pollution": "medium",
    }
    
    # Check each pattern category
    for category, category_patterns in patterns.items():
        for pattern, description in category_patterns:
            try:
                matches = list(re.finditer(pattern, code, re.MULTILINE | re.IGNORECASE))
                for match in matches:
                    # Find line number
                    line_start = code.rfind('\n', 0, match.start()) + 1
                    line_num = code[:match.start()].count('\n') + 1
                    line_end = code.find('\n', match.end())
                    if line_end == -1:
                        line_end = len(code)
                    
                    line_content = code[line_start:line_end].strip()
                    severity = severity_map.get(category, "medium")
                    
                    # Apply severity filter
                    if severity_filter:
                        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
                        if severity_order.get(severity, 2) > severity_order.get(severity_filter, 2):
                            continue
                    
                    findings.append({
                        "category": category,
                        "description": description,
                        "severity": severity,
                        "line": line_num,
                        "code_snippet": line_content[:200],
                        "match": match.group()[:100],
                        "start": match.start(),
                        "end": match.end(),
                    })
            except re.error as e:
                logger.warning(f"Regex error for pattern {pattern}: {e}")
    
    # Check for secrets if requested
    if check_secrets:
        secret_findings = secret_scan(agent_state, code)
        if secret_findings.get("success"):
            for secret in secret_findings.get("secrets", []):
                findings.append({
                    "category": "hardcoded_secret",
                    "description": f"Potential {secret['type']} found",
                    "severity": "high",
                    "line": secret["line"],
                    "code_snippet": secret["context"],
                    "match": secret["redacted_value"],
                    "start": secret.get("start", 0),
                    "end": secret.get("end", 0),
                })
    
    # Sort by severity and line number
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda x: (severity_order.get(x["severity"], 2), x["line"]))
    
    # Summarize by category
    by_category: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}
    for finding in findings:
        cat = finding["category"]
        sev = finding["severity"]
        by_category[cat] = by_category.get(cat, 0) + 1
        by_severity[sev] = by_severity.get(sev, 0) + 1
    
    return {
        "success": True,
        "language": language,
        "total_findings": len(findings),
        "by_severity": by_severity,
        "by_category": by_category,
        "findings": findings,
        "scan_time": datetime.now(timezone.utc).isoformat(),
    }


@register_tool(sandbox_execution=True, category="analysis")
def secret_scan(
    agent_state: Any,
    content: str,
    redact: bool = True,
) -> Dict[str, Any]:
    """
    Scan content for hardcoded secrets and credentials.
    
    Detects various types of secrets including API keys, passwords,
    tokens, and private keys.
    
    Args:
        agent_state: Current agent state
        content: Content to scan
        redact: Whether to redact found secrets in output
    
    Returns:
        Dictionary with found secrets
    """
    secrets = []
    
    for pattern, secret_type in SECRET_PATTERNS:
        try:
            matches = list(re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE))
            for match in matches:
                # Find line number
                line_num = content[:match.start()].count('\n') + 1
                
                # Get context (the line containing the secret)
                line_start = content.rfind('\n', 0, match.start()) + 1
                line_end = content.find('\n', match.end())
                if line_end == -1:
                    line_end = len(content)
                
                line_content = content[line_start:line_end].strip()
                
                # Get the actual secret value
                full_match = match.group()
                
                # Redact if requested
                if redact:
                    if len(full_match) > 10:
                        redacted = full_match[:4] + "..." + full_match[-4:]
                    else:
                        redacted = full_match[:2] + "***"
                else:
                    redacted = full_match
                
                # Also redact in context
                if redact:
                    context = line_content.replace(full_match, redacted)
                else:
                    context = line_content
                
                secrets.append({
                    "type": secret_type,
                    "line": line_num,
                    "redacted_value": redacted,
                    "context": context[:200],
                    "start": match.start(),
                    "end": match.end(),
                })
        except re.error as e:
            logger.warning(f"Regex error for secret pattern: {e}")
    
    # Deduplicate by line and type
    seen = set()
    unique_secrets = []
    for secret in secrets:
        key = (secret["line"], secret["type"])
        if key not in seen:
            seen.add(key)
            unique_secrets.append(secret)
    
    # Group by type
    by_type: Dict[str, int] = {}
    for secret in unique_secrets:
        t = secret["type"]
        by_type[t] = by_type.get(t, 0) + 1
    
    return {
        "success": True,
        "total_secrets": len(unique_secrets),
        "by_type": by_type,
        "secrets": unique_secrets,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "note": "Secrets are redacted by default. Set redact=False for full values (use with caution).",
    }


@register_tool(sandbox_execution=True, category="analysis")
def dependency_check(
    agent_state: Any,
    package_json: Optional[str] = None,
    requirements_txt: Optional[str] = None,
    pom_xml: Optional[str] = None,
    package_lock: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Check dependencies for known vulnerabilities.
    
    Analyzes package manifests to identify outdated or vulnerable dependencies.
    Note: For comprehensive CVE checking, integrate with a vulnerability database.
    
    Args:
        agent_state: Current agent state
        package_json: Contents of package.json (Node.js)
        requirements_txt: Contents of requirements.txt (Python)
        pom_xml: Contents of pom.xml (Java)
        package_lock: Contents of package-lock.json (Node.js)
    
    Returns:
        Dictionary with dependency analysis
    """
    dependencies = []
    warnings = []
    vulnerabilities = []
    
    # Known vulnerable package versions (simplified - in production, use a CVE database)
    KNOWN_VULNS = {
        # Python packages
        "django": {"<3.2": "CVE-2021-33203: Directory traversal"},
        "flask": {"<2.0": "Various security fixes in 2.0"},
        "requests": {"<2.20": "CVE-2018-18074: CRLF injection"},
        "pyyaml": {"<5.4": "CVE-2020-14343: Arbitrary code execution"},
        "pillow": {"<8.3.2": "Multiple CVEs including buffer overflow"},
        "urllib3": {"<1.26.5": "CVE-2021-33503: ReDoS"},
        
        # Node.js packages
        "lodash": {"<4.17.21": "CVE-2021-23337: Command injection"},
        "axios": {"<0.21.1": "CVE-2020-28168: SSRF"},
        "minimist": {"<1.2.6": "CVE-2021-44906: Prototype pollution"},
        "express": {"<4.17.3": "CVE-2022-24999: Open redirect"},
        "mongoose": {"<5.7.5": "CVE-2019-17426: Prototype pollution"},
    }
    
    def parse_version(version_str: str) -> tuple:
        """Parse version string into comparable tuple."""
        # Remove leading ^ or ~
        version_str = version_str.lstrip("^~>=<!")
        parts = version_str.split(".")
        try:
            return tuple(int(p) for p in parts[:3])
        except ValueError:
            return (0, 0, 0)
    
    def check_version_vulnerable(package: str, version: str) -> Optional[str]:
        """Check if a specific version is known to be vulnerable."""
        if package.lower() in KNOWN_VULNS:
            for vuln_version, cve in KNOWN_VULNS[package.lower()].items():
                # Simple version comparison
                if vuln_version.startswith("<"):
                    target = vuln_version[1:]
                    if parse_version(version) < parse_version(target):
                        return cve
        return None
    
    # Parse package.json (Node.js)
    if package_json:
        try:
            pkg = json.loads(package_json)
            all_deps = {}
            all_deps.update(pkg.get("dependencies", {}))
            all_deps.update(pkg.get("devDependencies", {}))
            
            for name, version in all_deps.items():
                dep_info = {
                    "name": name,
                    "version": version,
                    "ecosystem": "npm",
                    "type": "dependency" if name in pkg.get("dependencies", {}) else "devDependency",
                }
                dependencies.append(dep_info)
                
                # Check for vulnerabilities
                vuln = check_version_vulnerable(name, version)
                if vuln:
                    vulnerabilities.append({
                        "package": name,
                        "version": version,
                        "vulnerability": vuln,
                        "ecosystem": "npm",
                    })
        except json.JSONDecodeError as e:
            warnings.append(f"Failed to parse package.json: {e}")
    
    # Parse requirements.txt (Python)
    if requirements_txt:
        for line in requirements_txt.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            # Parse package==version or package>=version
            match = re.match(r'^([a-zA-Z0-9_-]+)\s*([<>=!]+)?\s*([0-9.]+)?', line)
            if match:
                name = match.group(1)
                version = match.group(3) or "unknown"
                
                dep_info = {
                    "name": name,
                    "version": version,
                    "ecosystem": "pypi",
                    "type": "dependency",
                }
                dependencies.append(dep_info)
                
                # Check for vulnerabilities
                if version != "unknown":
                    vuln = check_version_vulnerable(name, version)
                    if vuln:
                        vulnerabilities.append({
                            "package": name,
                            "version": version,
                            "vulnerability": vuln,
                            "ecosystem": "pypi",
                        })
    
    # Parse pom.xml (Java) - basic parsing
    if pom_xml:
        # Simple regex extraction (full parsing would need XML library)
        dep_pattern = r'<dependency>.*?<groupId>([^<]+)</groupId>.*?<artifactId>([^<]+)</artifactId>.*?<version>([^<]+)</version>.*?</dependency>'
        matches = re.findall(dep_pattern, pom_xml, re.DOTALL)
        
        for group_id, artifact_id, version in matches:
            dep_info = {
                "name": f"{group_id}:{artifact_id}",
                "version": version,
                "ecosystem": "maven",
                "type": "dependency",
            }
            dependencies.append(dep_info)
    
    # Categorize findings
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for vuln in vulnerabilities:
        if "CVE" in vuln.get("vulnerability", ""):
            severity_counts["high"] += 1
        else:
            severity_counts["medium"] += 1
    
    return {
        "success": True,
        "total_dependencies": len(dependencies),
        "total_vulnerabilities": len(vulnerabilities),
        "severity_counts": severity_counts,
        "dependencies": dependencies,
        "vulnerabilities": vulnerabilities,
        "warnings": warnings,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "note": "This is a basic check. For comprehensive vulnerability scanning, use tools like npm audit, pip-audit, or OWASP Dependency-Check.",
    }


@register_tool(sandbox_execution=True, category="analysis")
def analyze_code_quality(
    agent_state: Any,
    code: str,
    language: str = "python",
) -> Dict[str, Any]:
    """
    Analyze code quality and security hygiene.
    
    Checks for coding best practices and potential security issues.
    
    Args:
        agent_state: Current agent state
        code: Source code to analyze
        language: Programming language
    
    Returns:
        Dictionary with quality analysis
    """
    issues = []
    metrics = {
        "lines_of_code": len(code.split("\n")),
        "blank_lines": sum(1 for line in code.split("\n") if not line.strip()),
        "comment_lines": 0,
        "function_count": 0,
        "class_count": 0,
        "complexity_estimate": "low",
    }
    
    language = language.lower()
    
    if language == "python":
        # Count comments
        metrics["comment_lines"] = sum(1 for line in code.split("\n") if line.strip().startswith("#"))
        
        # Count functions and classes
        metrics["function_count"] = len(re.findall(r'^\s*def\s+\w+', code, re.MULTILINE))
        metrics["class_count"] = len(re.findall(r'^\s*class\s+\w+', code, re.MULTILINE))
        
        # Check for issues
        if not re.search(r'^"""[\s\S]*?"""', code) and not re.search(r"^'''[\s\S]*?'''", code):
            issues.append({
                "type": "documentation",
                "severity": "low",
                "message": "Missing module docstring",
            })
        
        if "__debug__" in code:
            issues.append({
                "type": "security",
                "severity": "medium",
                "message": "Debug code detected (__debug__)",
            })
        
        if "print(" in code and "logging" not in code:
            issues.append({
                "type": "best_practice",
                "severity": "low",
                "message": "Using print() instead of logging",
            })
        
        # Check exception handling
        bare_except = len(re.findall(r'except\s*:', code))
        if bare_except > 0:
            issues.append({
                "type": "error_handling",
                "severity": "medium",
                "message": f"Bare except clause found ({bare_except} occurrences)",
            })
        
        # Check for TODO/FIXME
        todos = len(re.findall(r'#.*(?:TODO|FIXME|XXX|HACK)', code, re.IGNORECASE))
        if todos > 0:
            issues.append({
                "type": "maintenance",
                "severity": "low",
                "message": f"Found {todos} TODO/FIXME comments",
            })
    
    elif language == "javascript":
        # Count comments
        single_line_comments = len(re.findall(r'//', code))
        multi_line_comments = len(re.findall(r'/\*[\s\S]*?\*/', code))
        metrics["comment_lines"] = single_line_comments + multi_line_comments
        
        # Count functions
        metrics["function_count"] = len(re.findall(r'function\s+\w+|=>\s*{|\w+\s*=\s*function', code))
        metrics["class_count"] = len(re.findall(r'\bclass\s+\w+', code))
        
        # Check for issues
        if "console.log" in code:
            issues.append({
                "type": "security",
                "severity": "low",
                "message": "console.log statements found (should be removed in production)",
            })
        
        if "var " in code:
            issues.append({
                "type": "best_practice",
                "severity": "low",
                "message": "Using 'var' instead of 'let' or 'const'",
            })
        
        if "==" in code and "===" not in code.replace("==", ""):
            issues.append({
                "type": "best_practice",
                "severity": "low",
                "message": "Using loose equality (==) instead of strict equality (===)",
            })
    
    # Estimate complexity
    total_lines = metrics["lines_of_code"]
    func_count = metrics["function_count"]
    
    if total_lines > 500 or func_count > 20:
        metrics["complexity_estimate"] = "high"
    elif total_lines > 200 or func_count > 10:
        metrics["complexity_estimate"] = "medium"
    
    # Calculate score
    base_score = 100
    for issue in issues:
        if issue["severity"] == "high":
            base_score -= 20
        elif issue["severity"] == "medium":
            base_score -= 10
        else:
            base_score -= 5
    
    score = max(0, min(100, base_score))
    
    return {
        "success": True,
        "language": language,
        "quality_score": score,
        "metrics": metrics,
        "issue_count": len(issues),
        "issues": issues,
        "summary": {
            "documentation": "adequate" if metrics["comment_lines"] > metrics["lines_of_code"] * 0.1 else "lacking",
            "complexity": metrics["complexity_estimate"],
            "maintainability": "good" if score >= 80 else "fair" if score >= 60 else "needs improvement",
        },
    }
