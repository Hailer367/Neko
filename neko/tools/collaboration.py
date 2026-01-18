"""
Multi-Agent Collaboration Protocol for Neko.

This module enables efficient collaboration between multiple AI agents during
security testing, preventing duplicate effort and enabling vulnerability chaining.

Key Systems:
1. CLAIM SYSTEM - Prevent duplicate testing by claiming targets
2. FINDING SHARING - Share vulnerabilities for chaining opportunities
3. WORK QUEUE - Central queue for coordinated testing coverage
4. HELP REQUESTS - Request specialized assistance from other agents

Ported from Strix with Neko-specific enhancements.
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Literal, Optional
import logging

from .registry import register_tool

logger = logging.getLogger(__name__)

# =============================================================================
# Data Structures
# =============================================================================

# Claims: agent_id -> list of claimed targets
_claims: Dict[str, List[Dict[str, Any]]] = {}

# Findings: shared vulnerability findings for chaining
_findings: Dict[str, Dict[str, Any]] = {}

# Work Queue: central queue of targets to test
_work_queue: List[Dict[str, Any]] = []

# Help Requests: requests for specialized assistance
_help_requests: List[Dict[str, Any]] = []

# Messages: broadcast messages between agents
_messages: List[Dict[str, Any]] = []

# Statistics
_collaboration_stats: Dict[str, Any] = {
    "total_claims": 0,
    "total_findings": 0,
    "total_work_items": 0,
    "total_help_requests": 0,
    "total_broadcasts": 0,
    "duplicate_tests_prevented": 0,
    "chaining_opportunities": 0,
    "start_time": datetime.now(timezone.utc).isoformat(),
}


def _generate_id(prefix: str = "id") -> str:
    """Generate a unique identifier."""
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


def _get_agent_info(agent_state: Any) -> Dict[str, str]:
    """Extract agent information from state."""
    if agent_state is None:
        return {"agent_id": "system", "agent_name": "System"}
    return {
        "agent_id": getattr(agent_state, "agent_id", "unknown"),
        "agent_name": getattr(agent_state, "agent_name", "Unknown Agent"),
    }


# =============================================================================
# Target Claiming System
# =============================================================================

@register_tool(sandbox_execution=False, category="collaboration")
def claim_target(
    agent_state: Any,
    target: str,
    test_type: str,
    scope: Optional[str] = None,
    estimated_duration: int = 30,
    priority: Literal["critical", "high", "medium", "low"] = "medium",
) -> Dict[str, Any]:
    """
    Claim an endpoint or parameter for testing to prevent duplicate work.
    
    Before testing any target, claim it first to ensure no other agent
    is already testing the same thing. This prevents wasted effort and
    ensures complete coverage.
    
    Args:
        agent_state: Current agent's state
        target: The target to claim (URL, endpoint, parameter)
        test_type: Type of test (sqli, xss, ssrf, auth_bypass, idor, etc.)
        scope: Optional scope description (e.g., "login form", "api endpoint")
        estimated_duration: Estimated test duration in minutes (default: 30)
        priority: Test priority level
    
    Returns:
        Dictionary with claim status. If already claimed, returns the claiming agent's info.
    """
    agent_info = _get_agent_info(agent_state)
    claim_key = f"{target}:{test_type}"
    
    # Check if already claimed by any agent
    for agent_id, claims in _claims.items():
        for claim in claims:
            if claim.get("claim_key") == claim_key:
                if claim.get("status") == "active":
                    # Check if claim has expired (2x estimated duration)
                    claimed_at = datetime.fromisoformat(claim["claimed_at"].replace('Z', '+00:00'))
                    expiry_minutes = claim.get("estimated_duration", 30) * 2
                    if datetime.now(timezone.utc) - claimed_at < timedelta(minutes=expiry_minutes):
                        _collaboration_stats["duplicate_tests_prevented"] += 1
                        return {
                            "success": False,
                            "status": "already_claimed",
                            "claimed_by": {
                                "agent_id": agent_id,
                                "agent_name": claim.get("agent_name"),
                            },
                            "claimed_at": claim["claimed_at"],
                            "test_type": claim["test_type"],
                            "message": f"Target already being tested by {claim.get('agent_name', agent_id)}. "
                                       f"Consider testing a different vulnerability type or target.",
                            "suggestion": f"Try a different test_type (currently claimed for: {test_type})",
                        }
                    else:
                        # Claim expired, release it
                        claim["status"] = "expired"
    
    # Create new claim
    claim_id = _generate_id("claim")
    new_claim = {
        "claim_id": claim_id,
        "claim_key": claim_key,
        "target": target,
        "test_type": test_type,
        "scope": scope,
        "agent_id": agent_info["agent_id"],
        "agent_name": agent_info["agent_name"],
        "priority": priority,
        "estimated_duration": estimated_duration,
        "status": "active",
        "claimed_at": datetime.now(timezone.utc).isoformat(),
        "results": None,
    }
    
    if agent_info["agent_id"] not in _claims:
        _claims[agent_info["agent_id"]] = []
    
    _claims[agent_info["agent_id"]].append(new_claim)
    _collaboration_stats["total_claims"] += 1
    
    return {
        "success": True,
        "status": "claimed",
        "claim_id": claim_id,
        "target": target,
        "test_type": test_type,
        "scope": scope,
        "priority": priority,
        "estimated_duration": estimated_duration,
        "message": f"Successfully claimed {target} for {test_type} testing",
        "reminder": "Remember to call release_claim() when done, and share_finding() if you find something!",
    }


@register_tool(sandbox_execution=False, category="collaboration")
def release_claim(
    agent_state: Any,
    claim_id: Optional[str] = None,
    target: Optional[str] = None,
    test_type: Optional[str] = None,
    result: Optional[str] = None,
    finding_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Release a claim on a target after completing testing.
    
    Always release claims when done testing to allow other agents
    to test the same target with different techniques.
    
    Args:
        agent_state: Current agent's state
        claim_id: The claim ID to release (preferred)
        target: Target that was claimed (alternative to claim_id)
        test_type: Test type that was claimed (used with target)
        result: Brief description of test results
        finding_id: If a vulnerability was found, link the finding ID
    
    Returns:
        Dictionary with release status.
    """
    agent_info = _get_agent_info(agent_state)
    agent_claims = _claims.get(agent_info["agent_id"], [])
    
    released = False
    released_claim = None
    
    for claim in agent_claims:
        should_release = False
        
        if claim_id and claim.get("claim_id") == claim_id:
            should_release = True
        elif target and test_type:
            if claim.get("target") == target and claim.get("test_type") == test_type:
                should_release = True
        
        if should_release and claim.get("status") == "active":
            claim["status"] = "completed"
            claim["released_at"] = datetime.now(timezone.utc).isoformat()
            claim["results"] = result
            claim["finding_id"] = finding_id
            released = True
            released_claim = claim
            break
    
    if released and released_claim:
        return {
            "success": True,
            "status": "released",
            "claim_id": released_claim["claim_id"],
            "target": released_claim["target"],
            "test_type": released_claim["test_type"],
            "had_finding": finding_id is not None,
            "message": "Claim released successfully",
        }
    
    return {
        "success": False,
        "error": "Claim not found or already released",
        "searched_for": {
            "claim_id": claim_id,
            "target": target,
            "test_type": test_type,
        },
    }


@register_tool(sandbox_execution=False, category="collaboration")
def list_claims(
    agent_state: Any,
    status: Optional[str] = None,
    test_type: Optional[str] = None,
    agent_filter: Optional[str] = None,
) -> Dict[str, Any]:
    """
    List all current claims to see what's being tested.
    
    Use this to find unclaimed targets or see what other agents
    are working on to avoid duplicate effort.
    """
    all_claims = []
    
    for agent_id, claims in _claims.items():
        for claim in claims:
            # Apply filters
            if status and claim.get("status") != status:
                continue
            if test_type and claim.get("test_type") != test_type:
                continue
            if agent_filter and agent_id != agent_filter:
                continue
            
            all_claims.append({
                "claim_id": claim["claim_id"],
                "target": claim["target"],
                "test_type": claim["test_type"],
                "scope": claim.get("scope"),
                "agent_id": agent_id,
                "agent_name": claim.get("agent_name"),
                "status": claim["status"],
                "priority": claim.get("priority", "medium"),
                "claimed_at": claim["claimed_at"],
                "finding_id": claim.get("finding_id"),
            })
    
    # Sort by priority and claim time
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    all_claims.sort(key=lambda x: (priority_order.get(x["priority"], 2), x["claimed_at"]))
    
    # Calculate statistics
    active_claims = [c for c in all_claims if c["status"] == "active"]
    by_test_type: Dict[str, int] = {}
    by_agent: Dict[str, int] = {}
    
    for claim in active_claims:
        tt = claim["test_type"]
        by_test_type[tt] = by_test_type.get(tt, 0) + 1
        
        aid = claim["agent_id"]
        by_agent[aid] = by_agent.get(aid, 0) + 1
    
    return {
        "success": True,
        "total_claims": len(all_claims),
        "active_claims": len(active_claims),
        "claims": all_claims,
        "statistics": {
            "by_test_type": by_test_type,
            "by_agent": by_agent,
            "duplicate_tests_prevented": _collaboration_stats["duplicate_tests_prevented"],
        },
    }


# =============================================================================
# Finding Sharing System
# =============================================================================

@register_tool(sandbox_execution=False, category="collaboration")
def share_finding(
    agent_state: Any,
    title: str,
    vulnerability_type: str,
    target: str,
    description: str,
    severity: Literal["critical", "high", "medium", "low", "info"] = "medium",
    poc: Optional[str] = None,
    evidence: Optional[str] = None,
    chainable: bool = True,
    chain_suggestions: Optional[List[str]] = None,
    affected_parameters: Optional[List[str]] = None,
    remediation: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Share a vulnerability finding with all agents for potential chaining.
    
    When you find a vulnerability, share it so other agents can:
    1. Avoid testing the same thing
    2. Try to chain it with their findings
    3. Build on your discovery
    
    Args:
        agent_state: Current agent's state
        title: Brief title of the finding
        vulnerability_type: Type (sqli, xss, ssrf, idor, rce, etc.)
        target: Affected endpoint/parameter
        description: Detailed description of the vulnerability
        severity: Severity level
        poc: Proof of concept (payload, request, etc.)
        evidence: Evidence of exploitation (response, screenshot description)
        chainable: Whether this could be chained with other vulns
        chain_suggestions: Suggested vulns to chain with
        affected_parameters: List of affected parameters
        remediation: Suggested fix
    
    Returns:
        Dictionary with finding ID and sharing status.
    """
    agent_info = _get_agent_info(agent_state)
    finding_id = _generate_id("finding")
    
    finding = {
        "finding_id": finding_id,
        "title": title,
        "vulnerability_type": vulnerability_type,
        "target": target,
        "description": description,
        "severity": severity,
        "poc": poc,
        "evidence": evidence,
        "chainable": chainable,
        "chain_suggestions": chain_suggestions or [],
        "affected_parameters": affected_parameters or [],
        "remediation": remediation,
        "found_by": {
            "agent_id": agent_info["agent_id"],
            "agent_name": agent_info["agent_name"],
        },
        "found_at": datetime.now(timezone.utc).isoformat(),
        "chain_attempts": [],
        "successfully_chained": False,
    }
    
    _findings[finding_id] = finding
    _collaboration_stats["total_findings"] += 1
    
    if chainable:
        _collaboration_stats["chaining_opportunities"] += 1
    
    # Broadcast notification
    broadcast_message(
        agent_state,
        f"🔍 New {severity.upper()} finding: {title} ({vulnerability_type}) at {target}",
        message_type="finding",
        priority="high" if severity in ["critical", "high"] else "normal",
    )
    
    return {
        "success": True,
        "finding_id": finding_id,
        "title": title,
        "severity": severity,
        "chainable": chainable,
        "message": f"Finding shared successfully! Other agents have been notified.",
    }


@register_tool(sandbox_execution=False, category="collaboration")
def list_findings(
    agent_state: Any,
    severity: Optional[str] = None,
    vulnerability_type: Optional[str] = None,
    chainable_only: bool = False,
    limit: int = 50,
) -> Dict[str, Any]:
    """
    List all shared findings for review and potential chaining.
    """
    filtered_findings = []
    
    for finding_id, finding in _findings.items():
        if severity and finding.get("severity") != severity:
            continue
        if vulnerability_type and finding.get("vulnerability_type") != vulnerability_type:
            continue
        if chainable_only and not finding.get("chainable"):
            continue
        
        filtered_findings.append({
            "finding_id": finding_id,
            "title": finding["title"],
            "vulnerability_type": finding["vulnerability_type"],
            "target": finding["target"],
            "severity": finding["severity"],
            "chainable": finding.get("chainable", False),
            "chain_suggestions": finding.get("chain_suggestions", []),
            "found_by": finding["found_by"],
            "found_at": finding["found_at"],
            "successfully_chained": finding.get("successfully_chained", False),
        })
    
    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    filtered_findings.sort(key=lambda x: severity_order.get(x["severity"], 5))
    filtered_findings = filtered_findings[:limit]
    
    return {
        "success": True,
        "total_findings": len(_findings),
        "filtered_count": len(filtered_findings),
        "findings": filtered_findings,
    }


@register_tool(sandbox_execution=False, category="collaboration")
def get_finding_details(agent_state: Any, finding_id: str) -> Dict[str, Any]:
    """Get full details of a specific finding including PoC."""
    if finding_id not in _findings:
        return {"success": False, "error": f"Finding '{finding_id}' not found"}
    
    finding = _findings[finding_id].copy()
    return {"success": True, "finding": finding}


# =============================================================================
# Work Queue System
# =============================================================================

@register_tool(sandbox_execution=False, category="collaboration")
def add_to_work_queue(
    agent_state: Any,
    target: str,
    description: str,
    test_types: Optional[List[str]] = None,
    priority: Literal["critical", "high", "medium", "low"] = "medium",
    notes: Optional[str] = None,
    source: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Add a target to the central work queue for testing.
    
    Use this when you discover new endpoints or parameters that
    need testing but you can't handle them right now.
    """
    agent_info = _get_agent_info(agent_state)
    work_id = _generate_id("work")
    
    work_item = {
        "work_id": work_id,
        "target": target,
        "description": description,
        "test_types": test_types or ["general"],
        "priority": priority,
        "notes": notes,
        "source": source,
        "added_by": agent_info,
        "added_at": datetime.now(timezone.utc).isoformat(),
        "status": "pending",
        "assigned_to": None,
        "assigned_at": None,
    }
    
    _work_queue.append(work_item)
    _collaboration_stats["total_work_items"] += 1
    
    # Sort queue by priority
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    _work_queue.sort(key=lambda x: (priority_order.get(x["priority"], 2), x["added_at"]))
    
    return {
        "success": True,
        "work_id": work_id,
        "target": target,
        "priority": priority,
        "queue_position": _work_queue.index(work_item) + 1,
        "message": f"Added to work queue at position {_work_queue.index(work_item) + 1}",
    }


@register_tool(sandbox_execution=False, category="collaboration")
def get_next_work_item(
    agent_state: Any,
    preferred_test_types: Optional[List[str]] = None,
    min_priority: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Get the next work item from the queue to test.
    """
    agent_info = _get_agent_info(agent_state)
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    
    for item in _work_queue:
        if item["status"] != "pending":
            continue
        
        # Check priority filter
        if min_priority:
            item_priority = priority_order.get(item["priority"], 2)
            min_pri = priority_order.get(min_priority, 2)
            if item_priority > min_pri:
                continue
        
        # Check test type preference
        if preferred_test_types:
            item_types = set(item.get("test_types", []))
            preferred = set(preferred_test_types)
            if not item_types.intersection(preferred):
                continue
        
        # Assign to this agent
        item["status"] = "assigned"
        item["assigned_to"] = agent_info
        item["assigned_at"] = datetime.now(timezone.utc).isoformat()
        
        return {
            "success": True,
            "work_item": {
                "work_id": item["work_id"],
                "target": item["target"],
                "description": item["description"],
                "test_types": item["test_types"],
                "priority": item["priority"],
                "notes": item.get("notes"),
                "source": item.get("source"),
                "added_by": item["added_by"],
            },
            "message": "Work item assigned to you. Remember to claim specific tests!",
        }
    
    return {
        "success": True,
        "work_item": None,
        "message": "No suitable work items in queue",
        "queue_status": {
            "total_items": len(_work_queue),
            "pending": sum(1 for i in _work_queue if i["status"] == "pending"),
            "assigned": sum(1 for i in _work_queue if i["status"] == "assigned"),
        },
    }


# =============================================================================
# Help Request System
# =============================================================================

@register_tool(sandbox_execution=False, category="collaboration")
def request_help(
    agent_state: Any,
    help_type: Literal["decode", "analyze", "exploit", "bypass", "escalate", "other"],
    description: str,
    context: Optional[str] = None,
    data: Optional[str] = None,
    urgency: Literal["critical", "high", "normal", "low"] = "normal",
) -> Dict[str, Any]:
    """
    Request specialized help from other agents.
    
    Use this when you encounter something you can't handle alone,
    like encoded data, complex exploits, or unfamiliar technologies.
    """
    agent_info = _get_agent_info(agent_state)
    request_id = _generate_id("help")
    
    help_request = {
        "request_id": request_id,
        "help_type": help_type,
        "description": description,
        "context": context,
        "data": data,
        "urgency": urgency,
        "requested_by": agent_info,
        "requested_at": datetime.now(timezone.utc).isoformat(),
        "status": "open",
        "responses": [],
    }
    
    _help_requests.append(help_request)
    _collaboration_stats["total_help_requests"] += 1
    
    # Broadcast help request
    broadcast_message(
        agent_state,
        f"🆘 Help needed ({help_type}): {description[:100]}",
        message_type="warning",
        priority="high" if urgency in ["critical", "high"] else "normal",
    )
    
    return {
        "success": True,
        "request_id": request_id,
        "help_type": help_type,
        "urgency": urgency,
        "message": "Help request broadcasted to all agents",
    }


# =============================================================================
# Collaboration Status & Communication
# =============================================================================

@register_tool(sandbox_execution=False, category="collaboration")
def get_collaboration_status(agent_state: Any) -> Dict[str, Any]:
    """
    Get comprehensive collaboration status dashboard.
    """
    agent_info = _get_agent_info(agent_state)
    
    # Active claims
    active_claims = []
    for agent_id, claims in _claims.items():
        for claim in claims:
            if claim["status"] == "active":
                active_claims.append({
                    "target": claim["target"],
                    "test_type": claim["test_type"],
                    "agent_name": claim.get("agent_name"),
                    "priority": claim.get("priority"),
                    "claimed_at": claim["claimed_at"],
                })
    
    # My claims
    my_claims = _claims.get(agent_info["agent_id"], [])
    my_active_claims = [c for c in my_claims if c["status"] == "active"]
    
    # Recent findings (last 10)
    recent_findings = sorted(
        _findings.values(),
        key=lambda x: x["found_at"],
        reverse=True
    )[:10]
    
    # Pending work items
    pending_work = [w for w in _work_queue if w["status"] == "pending"][:10]
    
    # Open help requests
    open_help = [h for h in _help_requests if h["status"] == "open"]
    
    return {
        "success": True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "my_status": {
            "agent_id": agent_info["agent_id"],
            "agent_name": agent_info["agent_name"],
            "active_claims": len(my_active_claims),
        },
        "collaboration_overview": {
            "total_active_claims": len(active_claims),
            "total_findings": len(_findings),
            "pending_work_items": len(pending_work),
            "open_help_requests": len(open_help),
        },
        "recent_findings": [{
            "finding_id": f["finding_id"],
            "title": f["title"],
            "severity": f["severity"],
            "vulnerability_type": f["vulnerability_type"],
            "found_by": f["found_by"]["agent_name"],
        } for f in recent_findings],
        "statistics": _collaboration_stats,
    }


@register_tool(sandbox_execution=False, category="collaboration")
def broadcast_message(
    agent_state: Any,
    message: str,
    message_type: Literal["info", "warning", "finding", "question", "coordination"] = "info",
    priority: Literal["low", "normal", "high", "urgent"] = "normal",
) -> Dict[str, Any]:
    """
    Broadcast a message to all agents.
    """
    agent_info = _get_agent_info(agent_state)
    message_id = _generate_id("msg")
    
    broadcast = {
        "message_id": message_id,
        "type": message_type,
        "from": agent_info,
        "content": message,
        "priority": priority,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    
    _messages.append(broadcast)
    _collaboration_stats["total_broadcasts"] += 1
    
    return {
        "success": True,
        "message_id": message_id,
        "delivered_to": "all_agents",
        "message_type": message_type,
        "priority": priority,
    }


@register_tool(sandbox_execution=False, category="collaboration")
def get_messages(
    agent_state: Any,
    limit: int = 50,
    message_type: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Get recent broadcast messages.
    """
    filtered = _messages
    if message_type:
        filtered = [m for m in _messages if m["type"] == message_type]
    
    # Sort by timestamp (newest first)
    filtered = sorted(filtered, key=lambda x: x["timestamp"], reverse=True)[:limit]
    
    return {
        "success": True,
        "total_messages": len(_messages),
        "filtered_count": len(filtered),
        "messages": filtered,
    }
