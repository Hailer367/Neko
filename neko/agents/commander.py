import os
import json
import asyncio
import logging
import subprocess
from typing import Any, List, Dict, Optional
from neko.llm.cliproxy_client import NekoClient
from neko.db.nekodb import NekoDB
from jinja2 import Template

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("NekoCommander")

class ToolRegistry:
    """Registry for Neko's 70+ tools."""

    @staticmethod
    def execute_command(command: str) -> Dict[str, Any]:
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=300)
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_code": result.returncode,
                "success": result.returncode == 0
            }
        except subprocess.TimeoutExpired:
            return {"error": "Command timed out", "success": False}
        except Exception as e:
            return {"error": str(e), "success": False}

class NekoCommander:
    """The Active Commander: Orchestrates and Executes."""

    def __init__(self):
        self.client = NekoClient(
            api_key=os.getenv("QWEN_TOKEN"),
            endpoint=os.getenv("CLIPROXY_ENDPOINT", "http://localhost:8085")
        )
        self.db = NekoDB()
        self.target = os.getenv("TARGET_PATH", "/workspace")
        self.model = os.getenv("MODEL", "qwen3-coder-plus")
        self.agent_id = "commander"
        self.running = True

    async def run(self):
        logger.info(f"🐱 Neko Commander online. Target: {self.target}")

        # Initial Shannon-style Recon
        recon_context = await self.perform_recon()

        # Main Execution Loop
        messages = [
            {"role": "system", "content": self.load_prompt("commander")},
            {"role": "user", "content": f"Begin white-box assessment of {self.target}. Recon context: {recon_context}"}
        ]

        iteration = 0
        while self.running and iteration < 50:
            iteration += 1
            logger.info(f"🐱 Iteration {iteration}...")

            try:
                response = await self.client.chat_completion(
                    model=self.model,
                    messages=messages,
                    temperature=0.1
                )

                assistant_message = response.choices[0].message
                content = assistant_message.content
                messages.append({"role": "assistant", "content": content})

                # Simple tool call parser (XML style like Strix)
                if "<function=" in content:
                    tool_output = await self.handle_tool_calls(content)
                    messages.append({"role": "user", "content": f"Tool Output: {tool_output}"})
                else:
                    logger.info(f"🐱 Neko says: {content[:200]}...")
                    # If no tool call and no finish, ask to continue or wait
                    if "FINISH" in content.upper():
                        self.running = False

            except Exception as e:
                logger.error(f"🐱 Error in loop: {e}")
                break

        logger.info("🐱 Neko scan finalized.")

    def load_prompt(self, name: str) -> str:
        path = f"neko/prompts/{name}.jinja"
        with open(path) as f:
            return f.read()

    async def perform_recon(self) -> str:
        """Actually runs some SAST tools to gather context."""
        logger.info("🐱 Gathering initial context with Semgrep & ls...")
        structure = ToolRegistry.execute_command(f"ls -R {self.target}")
        # Run a fast semgrep scan for hotspots
        semgrep = ToolRegistry.execute_command(f"semgrep --config=p/security-audit {self.target} --json")

        recon_data = {
            "structure": structure.get("stdout", ""),
            "hotspots": semgrep.get("stdout", "")[:5000] # Limit context size
        }
        return json.dumps(recon_data)

    async def handle_tool_calls(self, content: str) -> str:
        """Parses and executes tool calls in <function=name><parameter=key>value</parameter></function> format."""
        # This is a simplified parser for the implementation
        results = []
        import re
        tool_pattern = re.compile(r"<function=(\w+)>(.*?)</function>", re.DOTALL)
        param_pattern = re.compile(r"<parameter=(\w+)>(.*?)</parameter>", re.DOTALL)

        for match in tool_pattern.finditer(content):
            tool_name = match.group(1)
            params_raw = match.group(2)
            params = {m.group(1): m.group(2) for m in param_pattern.finditer(params_raw)}

            logger.info(f"🐱 Executing tool: {tool_name} with {params}")

            if tool_name == "terminal_execute":
                res = ToolRegistry.execute_command(params.get("command", ""))
                results.append(json.dumps(res))
            elif tool_name == "strixdb_save":
                res = self.db.save(params.get("category"), params.get("name"), params.get("content"))
                results.append(json.dumps({"success": res}))
            elif tool_name == "create_custom_agent":
                # In a real multi-container setup, this would spawn a new process/container
                # For this implementation, we log the delegation
                results.append(json.dumps({"success": True, "message": f"Agent {params.get('name')} scheduled."}))
            else:
                results.append(f"Error: Unknown tool {tool_name}")

        return "\n".join(results)

if __name__ == "__main__":
    asyncio.run(NekoCommander().run())
