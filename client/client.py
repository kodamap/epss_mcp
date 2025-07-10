# ref: # https://modelcontextprotocol.io/quickstart/client
# See also:
# - https://nikkie-ftnext.hatenablog.com/entry/model-context-protocol-quickstart-python-sse-transport

import asyncio
import json
import os
import sys
from contextlib import AsyncExitStack
from mcp.client.stdio import stdio_client
from mcp import StdioServerParameters

from anthropic import Anthropic
from dotenv import load_dotenv
from mcp import ClientSession
from openai import OpenAI

load_dotenv()

MODEL_NAME = "gemini-2.0-flash"
MAX_TOKENS = 1000

def convert_schema_types_to_uppercase(schema):
    """Recursively convert JSON schema type values to uppercase."""
    if isinstance(schema, dict):
        new_schema = {}
        for key, value in schema.items():
            if key == 'type' and isinstance(value, str):
                new_schema[key] = value.upper()
            else:
                new_schema[key] = convert_schema_types_to_uppercase(value)
        return new_schema
    elif isinstance(schema, list):
        return [convert_schema_types_to_uppercase(item) for item in schema]
    else:
        return schema


class MCPClient:
    def __init__(self):
        self.session: ClientSession | None = None
        self.exit_stack = AsyncExitStack()
        self.anthropic = Anthropic()
        self.openai = OpenAI(
            api_key=os.getenv("GOOGLE_API_KEY"),
            base_url="https://generativelanguage.googleapis.com/v1beta/",
        )

    async def connect_to_server(self, server_script_path: str):
        """Connect to an MCP server

        Args:
            server_script_path: Path to the server script (.py or .js)
        """
        is_python = server_script_path.endswith('.py')
        if not is_python:
            raise ValueError("Server script must be a .py file")

        server_params = StdioServerParameters(
            command="python",
            args=[server_script_path],
            env=None
        )

        stdio_transport = await self.exit_stack.enter_async_context(stdio_client(server_params))
        self.stdio, self.write = stdio_transport
        self.session = await self.exit_stack.enter_async_context(ClientSession(self.stdio, self.write))

        await self.session.initialize()

        # List available tools and store them
        response = await self.session.list_tools()
        tools = response.tools
        print("\nConnected to server with tools:", [tool.name for tool in tools])

    async def process_query(self, query: str) -> str:
        """Process a query using Claude and available tools"""
        if not self.session:
            return "Error: Not connected to a server."

        messages = [{"role": "user", "content": query}]
        response = await self.session.list_tools()
        available_tools = [
            {
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": convert_schema_types_to_uppercase(tool.inputSchema),
                },
            }
            for tool in response.tools
        ]

        # Initial Claude API call
        print("\n> Thinking...")
        response = self.openai.chat.completions.create(
            model=MODEL_NAME,
            max_tokens=MAX_TOKENS,
            messages=messages,
            tools=available_tools,
        )

        message = response.choices[0].message
        if not message.tool_calls:
            return message.content

        # Process response and handle tool calls
        final_text = []

        messages.append(message)
        for tool_call in message.tool_calls:
            tool_name = tool_call.function.name
            tool_call_id = tool_call.id

            tool_args = json.loads(tool_call.function.arguments)
            tool_result = await self.session.call_tool(tool_name, tool_args)

            tool_result_contents = [
                content.model_dump() for content in tool_result.content
            ]
            final_text.append(f"[Calling tool {tool_name} with args {tool_args}]")
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tool_call_id,
                    "name": tool_name,
                    "content": json.dumps(tool_result_contents),
                }
            )

            print("> Thinking...")
            response = self.openai.chat.completions.create(
                model=MODEL_NAME,
                max_tokens=MAX_TOKENS,
                messages=messages,
                tools=available_tools,
            )
            final_text.append(response.choices[0].message.content)

        return "\n".join(final_text)

    async def chat_loop(self) -> None:
        print("\nMCP Client Started!")
        print("Type your queries or `quit` to exit.")

        while True:
            try:
                query = input("\nQuery: ").strip()

                if query.lower() == "quit":
                    break

                response = await self.process_query(query)
                print("\n", response)

            except KeyboardInterrupt:
                print("\nExiting...")
                break
            except Exception as e:
                print(f"\nError: {str(e)}")

    async def cleanup(self):
        """Clean up resources"""
        await self.exit_stack.aclose()


async def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python client.py <path_to_server_script>")
        sys.exit(1)

    client = MCPClient()
    try:
        await client.connect_to_server(sys.argv[1])
        await client.chat_loop()
    finally:
        await client.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
