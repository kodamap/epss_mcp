# Use an official Python runtime as a parent image
FROM python:3.13

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container
COPY . /app

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set environment variables for the MCP server
ENV FASTMCP_HOST=0.0.0.0
ENV FASTMCP_PORT=8000

# Expose port 8000 for the MCP server
EXPOSE 8000

# Run the MCP server with stdio transport
# (Available options: stdio, sse, http)
CMD ["python3", "epss_mcp.py", "--transport", "stdio"]
