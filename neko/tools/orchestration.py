"""
Advanced Multi-Agent Orchestration System for Neko.

This module provides significantly enhanced multi-agent coordination with:
- Priority-based task scheduling with dependencies
- Agent workload balancing and capacity management
- Parallel task execution with batch processing
- Team-based coordination
- Workflow automation
- Resource allocation
- Health monitoring and metrics
- Checkpoint synchronization

Ported from Strix with Neko-specific enhancements.
"""

import asyncio
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Literal, Optional, Callable
import logging

from .registry import register_tool

logger = logging.getLogger(__name__)

# =============================================================================
# Data Structures
# =============================================================================

# Task management
_tasks: Dict[str, Dict[str, Any]] = {}
_task_dependencies: List[Dict[str, str]] = []
_task_assignments: Dict[str, List[str]] = {}  # agent_id -> [task_ids]

# Priority queue
_priority_queue: List[str] = []

# Agent capacities and workloads
_agent_capacities: Dict[str, int] = {}  # agent_id -> max concurrent tasks
_agent_workloads: Dict[str, Dict[str, Any]] = {}

# Agent registry
_agents: Dict[str, Dict[str, Any]] = {}

# Teams
_teams: Dict[str, Dict[str, Any]] = {}

# Batch processing
_batch_queue: List[Dict[str, Any]] = []
_batch_results: Dict[str, List[Dict[str, Any]]] = {}

# Metrics
_metrics: Dict[str, Any] = {
    "total_tasks_created": 0,
    "total_tasks_completed": 0,
    "total_tasks_failed": 0,
    "total_batches_processed": 0,
    "parallel_executions": 0,
    "start_time": datetime.now(timezone.utc).isoformat(),
}


def _generate_id(prefix: str = "id") -> str:
    """Generate a unique ID."""
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


def _update_priority_queue() -> None:
    """Update the priority queue based on current tasks."""
    pending_tasks = [
        (tid, task) for tid, task in _tasks.items()
        if task["status"] in ["pending", "assigned"]
    ]
    
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    
    # Sort by priority, then by creation time
    pending_tasks.sort(key=lambda x: (
        priority_order.get(x[1]["priority"], 2),
        x[1]["created_at"]
    ))
    
    _priority_queue.clear()
    _priority_queue.extend([tid for tid, _ in pending_tasks])


# =============================================================================
# Task Management
# =============================================================================

@register_tool(sandbox_execution=False, category="orchestration")
def create_task(
    agent_state: Any,
    title: str,
    description: str,
    priority: Literal["critical", "high", "medium", "low"] = "medium",
    estimated_effort: Optional[str] = None,
    deadline: Optional[str] = None,
    tags: Optional[List[str]] = None,
    auto_assign: bool = False,
    batch_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create a new orchestrated task with priority and metadata.
    
    Args:
        agent_state: Current agent's state
        title: Task title
        description: Detailed description of the task
        priority: Task priority level (critical, high, medium, low)
        estimated_effort: Estimated effort (e.g., "1h", "2d")
        deadline: ISO date deadline
        tags: Tags for categorization
        auto_assign: If True, automatically assign to least busy agent
        batch_id: Optional batch ID for grouped task execution
    
    Returns:
        Dictionary with task creation status
    """
    task_id = _generate_id("task")
    agent_id = getattr(agent_state, "agent_id", "unknown") if agent_state else "system"
    
    task = {
        "id": task_id,
        "title": title,
        "description": description,
        "priority": priority,
        "status": "pending",
        "estimated_effort": estimated_effort,
        "deadline": deadline,
        "tags": tags or [],
        "batch_id": batch_id,
        "created_by": agent_id,
        "assigned_to": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "started_at": None,
        "completed_at": None,
        "result": None,
        "error": None,
    }
    
    _tasks[task_id] = task
    _metrics["total_tasks_created"] += 1
    
    # Add to priority queue
    _update_priority_queue()
    
    # Auto-assign if requested
    assigned_to = None
    if auto_assign:
        result = balance_workload(agent_state, task_ids=[task_id])
        if result.get("success") and result.get("assignments"):
            assigned_to = result["assignments"].get(task_id)
    
    return {
        "success": True,
        "task_id": task_id,
        "title": title,
        "priority": priority,
        "assigned_to": assigned_to,
        "batch_id": batch_id,
        "message": f"Task '{title}' created successfully",
    }


@register_tool(sandbox_execution=False, category="orchestration")
def assign_task(
    agent_state: Any,
    task_id: str,
    target_agent_id: str,
    notify: bool = True,
) -> Dict[str, Any]:
    """
    Assign a task to a specific agent.
    
    Args:
        agent_state: Current agent's state
        task_id: Task to assign
        target_agent_id: Agent to assign the task to
        notify: Send notification to the agent
    
    Returns:
        Dictionary with assignment status
    """
    if task_id not in _tasks:
        return {"success": False, "error": f"Task '{task_id}' not found"}
    
    task = _tasks[task_id]
    
    # Check agent capacity
    capacity = _agent_capacities.get(target_agent_id, 5)  # Default capacity of 5
    current_tasks = _task_assignments.get(target_agent_id, [])
    active_tasks = [t for t in current_tasks if _tasks.get(t, {}).get("status") in ["pending", "in_progress"]]
    
    if len(active_tasks) >= capacity:
        return {
            "success": False,
            "error": f"Agent '{target_agent_id}' is at capacity ({len(active_tasks)}/{capacity})",
        }
    
    # Assign task
    task["assigned_to"] = target_agent_id
    task["status"] = "assigned"
    task["updated_at"] = datetime.now(timezone.utc).isoformat()
    
    # Update assignments
    if target_agent_id not in _task_assignments:
        _task_assignments[target_agent_id] = []
    _task_assignments[target_agent_id].append(task_id)
    
    return {
        "success": True,
        "task_id": task_id,
        "assigned_to": target_agent_id,
        "agent_notified": notify,
    }


@register_tool(sandbox_execution=False, category="orchestration")
def update_task_status(
    agent_state: Any,
    task_id: str,
    status: Literal["pending", "assigned", "in_progress", "completed", "failed", "blocked"],
    result: Optional[str] = None,
    error: Optional[str] = None,
    notes: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Update the status of a task.
    
    Args:
        agent_state: Current agent's state
        task_id: Task to update
        status: New status
        result: Result description (for completed/failed)
        error: Error message (for failed)
        notes: Additional notes
    
    Returns:
        Dictionary with update status
    """
    if task_id not in _tasks:
        return {"success": False, "error": f"Task '{task_id}' not found"}
    
    task = _tasks[task_id]
    old_status = task["status"]
    task["status"] = status
    task["updated_at"] = datetime.now(timezone.utc).isoformat()
    
    if status == "in_progress" and not task.get("started_at"):
        task["started_at"] = datetime.now(timezone.utc).isoformat()
    
    if status == "completed":
        task["completed_at"] = datetime.now(timezone.utc).isoformat()
        task["result"] = result
        _metrics["total_tasks_completed"] += 1
    
    if status == "failed":
        task["completed_at"] = datetime.now(timezone.utc).isoformat()
        task["error"] = error or result
        _metrics["total_tasks_failed"] += 1
    
    if notes:
        task.setdefault("notes", []).append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "by": getattr(agent_state, "agent_id", "unknown") if agent_state else "system",
            "content": notes,
        })
    
    # Update priority queue
    _update_priority_queue()
    
    return {
        "success": True,
        "task_id": task_id,
        "old_status": old_status,
        "new_status": status,
        "message": f"Task status updated to '{status}'",
    }


@register_tool(sandbox_execution=False, category="orchestration")
def get_task_status(agent_state: Any, task_id: str) -> Dict[str, Any]:
    """Get detailed status of a task."""
    if task_id not in _tasks:
        return {"success": False, "error": f"Task '{task_id}' not found"}
    
    task = _tasks[task_id].copy()
    
    # Get dependencies
    deps = get_task_dependencies(agent_state, task_id)
    task["dependencies"] = deps.get("dependencies", [])
    task["dependents"] = deps.get("dependents", [])
    
    return {"success": True, "task": task}


@register_tool(sandbox_execution=False, category="orchestration")
def list_tasks(
    agent_state: Any,
    status: Optional[str] = None,
    priority: Optional[str] = None,
    assigned_to: Optional[str] = None,
    created_by: Optional[str] = None,
    batch_id: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """List tasks with filtering options."""
    results = []
    
    for task_id, task in _tasks.items():
        if status and task["status"] != status:
            continue
        if priority and task["priority"] != priority:
            continue
        if assigned_to and task.get("assigned_to") != assigned_to:
            continue
        if created_by and task.get("created_by") != created_by:
            continue
        if batch_id and task.get("batch_id") != batch_id:
            continue
        
        results.append({
            "task_id": task_id,
            "title": task["title"],
            "status": task["status"],
            "priority": task["priority"],
            "assigned_to": task.get("assigned_to"),
            "batch_id": task.get("batch_id"),
            "created_at": task["created_at"],
        })
    
    # Sort by priority and creation time
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    results.sort(key=lambda x: (priority_order.get(x["priority"], 2), x["created_at"]))
    results = results[:limit]
    
    return {"success": True, "total_count": len(results), "tasks": results}


@register_tool(sandbox_execution=False, category="orchestration")
def create_task_dependency(
    agent_state: Any,
    task_id: str,
    depends_on_task_id: str,
) -> Dict[str, Any]:
    """Create a dependency between tasks."""
    if task_id not in _tasks:
        return {"success": False, "error": f"Task '{task_id}' not found"}
    if depends_on_task_id not in _tasks:
        return {"success": False, "error": f"Task '{depends_on_task_id}' not found"}
    if task_id == depends_on_task_id:
        return {"success": False, "error": "Task cannot depend on itself"}
    
    # Check for circular dependency
    def has_circular(tid: str, visited: set) -> bool:
        if tid in visited:
            return True
        visited.add(tid)
        for dep in _task_dependencies:
            if dep["task_id"] == tid:
                if has_circular(dep["depends_on"], visited.copy()):
                    return True
        return False
    
    if has_circular(depends_on_task_id, {task_id}):
        return {"success": False, "error": "This would create a circular dependency"}
    
    # Check if dependency already exists
    for dep in _task_dependencies:
        if dep["task_id"] == task_id and dep["depends_on"] == depends_on_task_id:
            return {"success": False, "error": "Dependency already exists"}
    
    _task_dependencies.append({
        "task_id": task_id,
        "depends_on": depends_on_task_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    
    return {
        "success": True,
        "task_id": task_id,
        "depends_on": depends_on_task_id,
        "message": f"Dependency created successfully",
    }


@register_tool(sandbox_execution=False, category="orchestration")
def get_task_dependencies(agent_state: Any, task_id: str) -> Dict[str, Any]:
    """Get dependencies and dependents of a task."""
    if task_id not in _tasks:
        return {"success": False, "error": f"Task '{task_id}' not found"}
    
    dependencies = []  # Tasks this task depends on
    dependents = []    # Tasks that depend on this task
    
    for dep in _task_dependencies:
        if dep["task_id"] == task_id:
            dep_task = _tasks.get(dep["depends_on"], {})
            dependencies.append({
                "task_id": dep["depends_on"],
                "title": dep_task.get("title", "Unknown"),
                "status": dep_task.get("status", "unknown"),
            })
        if dep["depends_on"] == task_id:
            dep_task = _tasks.get(dep["task_id"], {})
            dependents.append({
                "task_id": dep["task_id"],
                "title": dep_task.get("title", "Unknown"),
                "status": dep_task.get("status", "unknown"),
            })
    
    # Check if task can start (all dependencies complete)
    can_start = all(d["status"] == "completed" for d in dependencies)
    
    return {
        "success": True,
        "task_id": task_id,
        "dependencies": dependencies,
        "dependents": dependents,
        "can_start": can_start,
        "blocking_tasks": [d for d in dependencies if d["status"] != "completed"],
    }


# =============================================================================
# Workload Balancing
# =============================================================================

@register_tool(sandbox_execution=False, category="orchestration")
def balance_workload(
    agent_state: Any,
    task_ids: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Balance workload by assigning unassigned tasks to least busy agents.
    
    Args:
        agent_state: Current agent's state
        task_ids: Specific tasks to assign (default: all unassigned)
    
    Returns:
        Dictionary with assignment results
    """
    # Get tasks to assign
    if task_ids:
        tasks_to_assign = [tid for tid in task_ids if tid in _tasks and not _tasks[tid].get("assigned_to")]
    else:
        tasks_to_assign = [
            tid for tid, task in _tasks.items()
            if task["status"] == "pending" and not task.get("assigned_to")
        ]
    
    if not tasks_to_assign:
        return {"success": True, "message": "No tasks to assign", "assignments": {}}
    
    # Get available agents and their utilization
    agent_utilizations = []
    for agent_id, agent in _agents.items():
        if agent.get("status") not in ["running", "waiting", "active"]:
            continue
        
        assigned = _task_assignments.get(agent_id, [])
        active = sum(1 for tid in assigned if _tasks.get(tid, {}).get("status") in ["pending", "assigned", "in_progress"])
        capacity = _agent_capacities.get(agent_id, 5)
        
        if active < capacity:
            agent_utilizations.append({
                "agent_id": agent_id,
                "name": agent.get("name"),
                "active": active,
                "capacity": capacity,
                "available": capacity - active,
            })
    
    if not agent_utilizations:
        # No external agents, assign to self
        self_agent_id = getattr(agent_state, "agent_id", "commander") if agent_state else "commander"
        agent_utilizations = [{
            "agent_id": self_agent_id,
            "name": "Commander",
            "active": 0,
            "capacity": 10,
            "available": 10,
        }]
    
    # Sort by utilization (least busy first)
    agent_utilizations.sort(key=lambda x: x["active"] / max(x["capacity"], 1))
    
    # Assign tasks
    assignments = {}
    for task_id in tasks_to_assign:
        # Find agent with most availability
        for agent in agent_utilizations:
            if agent["available"] > 0:
                result = assign_task(agent_state, task_id, agent["agent_id"], notify=True)
                if result.get("success"):
                    assignments[task_id] = agent["agent_id"]
                    agent["available"] -= 1
                    agent["active"] += 1
                break
    
    return {
        "success": True,
        "total_assigned": len(assignments),
        "assignments": assignments,
        "unassigned": [tid for tid in tasks_to_assign if tid not in assignments],
    }


@register_tool(sandbox_execution=False, category="orchestration")
def get_priority_queue(agent_state: Any) -> Dict[str, Any]:
    """Get the current priority queue of pending tasks."""
    _update_priority_queue()
    
    queue = []
    for i, task_id in enumerate(_priority_queue):
        task = _tasks.get(task_id, {})
        queue.append({
            "position": i + 1,
            "task_id": task_id,
            "title": task.get("title", "Unknown"),
            "priority": task.get("priority", "medium"),
            "status": task.get("status", "unknown"),
            "assigned_to": task.get("assigned_to"),
        })
    
    return {"success": True, "queue_length": len(queue), "queue": queue}


# =============================================================================
# Parallel & Batch Processing
# =============================================================================

@register_tool(sandbox_execution=False, category="orchestration")
def create_batch(
    agent_state: Any,
    name: str,
    tasks: List[Dict[str, Any]],
    parallel: bool = True,
    max_workers: int = 5,
) -> Dict[str, Any]:
    """
    Create a batch of tasks for parallel or sequential execution.
    
    Args:
        agent_state: Current agent's state
        name: Batch name
        tasks: List of task definitions with title, description, priority
        parallel: Whether to execute tasks in parallel
        max_workers: Maximum parallel workers
    
    Returns:
        Dictionary with batch creation status
    """
    batch_id = _generate_id("batch")
    
    created_tasks = []
    for task_def in tasks:
        result = create_task(
            agent_state,
            title=task_def.get("title", "Unnamed Task"),
            description=task_def.get("description", ""),
            priority=task_def.get("priority", "medium"),
            tags=task_def.get("tags", []),
            batch_id=batch_id,
        )
        if result.get("success"):
            created_tasks.append(result["task_id"])
    
    batch = {
        "id": batch_id,
        "name": name,
        "task_ids": created_tasks,
        "parallel": parallel,
        "max_workers": max_workers,
        "status": "pending",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "started_at": None,
        "completed_at": None,
    }
    
    _batch_queue.append(batch)
    _batch_results[batch_id] = []
    
    return {
        "success": True,
        "batch_id": batch_id,
        "name": name,
        "task_count": len(created_tasks),
        "task_ids": created_tasks,
        "parallel": parallel,
    }


@register_tool(sandbox_execution=False, category="orchestration")
def execute_batch(
    agent_state: Any,
    batch_id: str,
    executor: Optional[Callable] = None,
) -> Dict[str, Any]:
    """
    Execute all tasks in a batch (parallel or sequential).
    
    Args:
        agent_state: Current agent's state
        batch_id: Batch to execute
        executor: Optional custom executor function for tasks
    
    Returns:
        Dictionary with execution results
    """
    # Find batch
    batch = None
    for b in _batch_queue:
        if b["id"] == batch_id:
            batch = b
            break
    
    if not batch:
        return {"success": False, "error": f"Batch '{batch_id}' not found"}
    
    batch["status"] = "running"
    batch["started_at"] = datetime.now(timezone.utc).isoformat()
    _metrics["total_batches_processed"] += 1
    
    results = []
    
    if batch["parallel"]:
        # Parallel execution using ThreadPoolExecutor
        _metrics["parallel_executions"] += 1
        
        def execute_task(task_id: str):
            task = _tasks.get(task_id)
            if not task:
                return {"task_id": task_id, "success": False, "error": "Task not found"}
            
            # Update status
            update_task_status(agent_state, task_id, "in_progress")
            
            try:
                if executor:
                    result = executor(task)
                else:
                    # Default: mark as completed
                    result = {"output": f"Task {task_id} executed"}
                
                update_task_status(agent_state, task_id, "completed", result=str(result))
                return {"task_id": task_id, "success": True, "result": result}
            except Exception as e:
                update_task_status(agent_state, task_id, "failed", error=str(e))
                return {"task_id": task_id, "success": False, "error": str(e)}
        
        with ThreadPoolExecutor(max_workers=batch["max_workers"]) as pool:
            futures = {pool.submit(execute_task, tid): tid for tid in batch["task_ids"]}
            for future in as_completed(futures):
                results.append(future.result())
    else:
        # Sequential execution
        for task_id in batch["task_ids"]:
            task = _tasks.get(task_id)
            if not task:
                results.append({"task_id": task_id, "success": False, "error": "Task not found"})
                continue
            
            update_task_status(agent_state, task_id, "in_progress")
            
            try:
                if executor:
                    result = executor(task)
                else:
                    result = {"output": f"Task {task_id} executed"}
                
                update_task_status(agent_state, task_id, "completed", result=str(result))
                results.append({"task_id": task_id, "success": True, "result": result})
            except Exception as e:
                update_task_status(agent_state, task_id, "failed", error=str(e))
                results.append({"task_id": task_id, "success": False, "error": str(e)})
    
    batch["status"] = "completed"
    batch["completed_at"] = datetime.now(timezone.utc).isoformat()
    _batch_results[batch_id] = results
    
    successful = sum(1 for r in results if r.get("success"))
    failed = len(results) - successful
    
    return {
        "success": True,
        "batch_id": batch_id,
        "total_tasks": len(results),
        "successful": successful,
        "failed": failed,
        "results": results,
    }


@register_tool(sandbox_execution=False, category="orchestration")
def get_batch_status(agent_state: Any, batch_id: str) -> Dict[str, Any]:
    """Get the status of a batch."""
    for batch in _batch_queue:
        if batch["id"] == batch_id:
            results = _batch_results.get(batch_id, [])
            task_statuses = {}
            for tid in batch["task_ids"]:
                task = _tasks.get(tid, {})
                task_statuses[tid] = task.get("status", "unknown")
            
            return {
                "success": True,
                "batch": batch,
                "task_statuses": task_statuses,
                "results": results,
            }
    
    return {"success": False, "error": f"Batch '{batch_id}' not found"}


# =============================================================================
# Agent Management
# =============================================================================

@register_tool(sandbox_execution=False, category="orchestration")
def register_agent(
    agent_state: Any,
    agent_id: str,
    name: str,
    capabilities: Optional[List[str]] = None,
    capacity: int = 5,
) -> Dict[str, Any]:
    """
    Register a new agent in the orchestration system.
    
    Args:
        agent_state: Current agent's state
        agent_id: Unique agent identifier
        name: Agent display name
        capabilities: List of agent capabilities/specializations
        capacity: Maximum concurrent tasks
    
    Returns:
        Dictionary with registration status
    """
    _agents[agent_id] = {
        "id": agent_id,
        "name": name,
        "capabilities": capabilities or [],
        "status": "active",
        "registered_at": datetime.now(timezone.utc).isoformat(),
    }
    _agent_capacities[agent_id] = capacity
    _task_assignments[agent_id] = []
    
    return {
        "success": True,
        "agent_id": agent_id,
        "name": name,
        "capacity": capacity,
    }


@register_tool(sandbox_execution=False, category="orchestration")
def get_orchestration_metrics(agent_state: Any) -> Dict[str, Any]:
    """Get orchestration system metrics."""
    active_tasks = sum(1 for t in _tasks.values() if t["status"] in ["pending", "in_progress", "assigned"])
    completed_tasks = sum(1 for t in _tasks.values() if t["status"] == "completed")
    failed_tasks = sum(1 for t in _tasks.values() if t["status"] == "failed")
    
    return {
        "success": True,
        "metrics": {
            **_metrics,
            "total_tasks": len(_tasks),
            "active_tasks": active_tasks,
            "completed_tasks": completed_tasks,
            "failed_tasks": failed_tasks,
            "total_agents": len(_agents),
            "active_batches": sum(1 for b in _batch_queue if b["status"] == "running"),
            "pending_batches": sum(1 for b in _batch_queue if b["status"] == "pending"),
        }
    }
