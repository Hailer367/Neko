"""
Neko Tools Package - Advanced Security Testing Toolkit

This package provides a comprehensive set of tools for autonomous security testing,
including parallel processing, multi-agent collaboration, and knowledge management.
"""

from .registry import (
    register_tool,
    get_registered_tools,
    get_tool,
    execute_tool,
    list_tools_by_category,
    get_tool_schema,
)

from .orchestration import (
    create_task,
    assign_task,
    update_task_status,
    get_task_status,
    list_tasks,
    balance_workload,
    get_priority_queue,
    create_task_dependency,
    get_task_dependencies,
    register_agent,
    create_batch,
    execute_batch,
    get_batch_status,
    get_orchestration_metrics,
)

from .collaboration import (
    claim_target,
    release_claim,
    list_claims,
    share_finding,
    list_findings,
    get_finding_details,
    add_to_work_queue,
    get_next_work_item,
    request_help,
    get_collaboration_status,
    broadcast_message,
    get_messages,
)

__all__ = [
    # Registry
    "register_tool",
    "get_registered_tools",
    "get_tool",
    "execute_tool",
    "list_tools_by_category",
    "get_tool_schema",
    # Orchestration
    "create_task",
    "assign_task",
    "update_task_status",
    "get_task_status",
    "list_tasks",
    "balance_workload",
    "get_priority_queue",
    "create_task_dependency",
    "get_task_dependencies",
    "register_agent",
    "create_batch",
    "execute_batch",
    "get_batch_status",
    "get_orchestration_metrics",
    # Collaboration
    "claim_target",
    "release_claim",
    "list_claims",
    "share_finding",
    "list_findings",
    "get_finding_details",
    "add_to_work_queue",
    "get_next_work_item",
    "request_help",
    "get_collaboration_status",
    "broadcast_message",
    "get_messages",
]
