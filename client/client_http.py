# https://github.com/modelcontextprotocol/python-sdk?tab=readme-ov-file#streamable-http-transport
# See also:
# - https://nikkie-ftnext.hatenablog.com/entry/model-context-protocol-quickstart-python-sse-transport

import asyncio
import json
import os
from contextlib import AsyncExitStack
from mcp.client.streamable_http import streamablehttp_client

from anthropic import Anthropic
from dotenv import load_dotenv
from mcp import ClientSession
from openai import OpenAI

load_dotenv()

MODEL_NAME = "gemini-2.0-flash"
MAX_TOKENS = 1000

class MCPClient:
    def __init__(self):
        self.session: ClientSession | None = None
        self.exit_stack = AsyncExitStack()
        self.anthropic = Anthropic()
        self.openai = OpenAI(
            api_key=os.getenv("GOOGLE_API_KEY"),
            base_url="https://generativelanguage.googleapis.com/v1beta/",
        )

    async def connect_to_server(self, url: str):
        """Connect to an MCP server using streamable HTTP transport.

        Args:
            server_script_path: Path to the server script (.py or .js)
        """
        # Use streamablehttp_client instead of sse_client
        streamable_transport = await self.exit_stack.enter_async_context(
            streamablehttp_client(url)
        )
        self.stdio, self.write, _ = streamable_transport
        self.session = await self.exit_stack.enter_async_context(
            ClientSession(self.stdio, self.write)
        )

        await self.session.initialize()

        # List available tools and store them
        response = await self.session.list_tools()
        tools = response.tools
        print("\nConnected to server with tools:", [tool.name for tool in tools])

    async def process_query(self, query: str) -> str:
        """Process a query using Claude and available tools via SSE-compatible client."""
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
                    "parameters": tool.inputSchema,
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
        print("\nMCP SSE Client Started!")
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
        """Clean up resources and close SSE connections."""
        await self.exit_stack.aclose()


async def main() -> None:
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000/mcp"
    client = MCPClient()
    try:
        await client.connect_to_server(url)
        await client.chat_loop()
    finally:
        await client.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
