# 1. EPSS MCP Server


- [1. EPSS MCP Server](#1-epss-mcp-server)
- [2. Features](#2-features)
- [3. Run MCP Server on Docker](#3-run-mcp-server-on-docker)
- [4. Installation](#4-installation)
  - [4.1. Stdio](#41-stdio)
  - [4.2. Streamable HTTP, SSE](#42-streamable-http-sse)
- [5. Tool Examples](#5-tool-examples)
  - [5.1. Get EPSS Score of single CVE](#51-get-epss-score-of-single-cve)
  - [5.2. Get EPSS Score of multiple CVEs](#52-get-epss-score-of-multiple-cves)
  - [5.3. Get EPSS Score of multiple CVEs with time series](#53-get-epss-score-of-multiple-cves-with-time-series)
  - [5.4. Get top 5 CVEs with the highest EPSS scores](#54-get-top-5-cves-with-the-highest-epss-scores)
- [6. Reference](#6-reference)


**Note:** The major design of code in this repository is based on [EPSS-MCP](https://github.com/jgamblin/EPSS-MCP).


# 2. Features

EPSS MCP Server provides the following features:

- Retrieve vulnerability details (including description, CWE, and CVSS scores) from the NVD API, and EPSS scores and percentiles from the EPSS API.
- Retrieve EPSS scores for multiple CVEs.
- Retrieve the EPSS time series data for a single CVE.
- Retrieve the top N CVEs with the highest EPSS scores.

# 3. Run MCP Server on Docker

__Note:__ If you want to change transport type, edit `Dockerfile` like this.

```sh
# Stdio transport(Default)
CMD ["python3", "epss_mcp.py", "--transport", "stdio"]
# SSE transport
CMD ["python3", "epss_mcp.py", "--transport", "sse"]
# Streamable HTTP transport
CMD ["python3", "epss_mcp.py", "--transport", "http"]
```

Build docker image

```sh
cd epss-mcp
docker build -t epss-mcp .
```

Run MCP server

```sh
# Stdio transport
docker run --rm -i epss-mcp

# SSE transport (Access from localhost only is recommended)
docker run -d -p 127.0.0.1:8000:8000 epss-mcp

# Streamable HTTP transport (Access from localhost only is recommended)
docker run -d -p 127.0.0.1:8000:8000 epss-mcp
```

# 4. Installation

## 4.1. Stdio

Prepare a Python virtual environment using uv. See [uv](https://docs.astral.sh/uv/getting-started/installation/#installation-methods) for more details. 
```sh
curl -LsSf https://astral.sh/uv/install.sh | sh
``` 

```sh
uv sync
. .venv/bin/activate
```

__Cursor, Windsurf__

```json
{
  "mcpServers": {
    "epss-mcp": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "epss-mcp"
      ]
    }
  }
}
```


## 4.2. Streamable HTTP, SSE

__Cursor__

```json
{
  "mcpServers": {
    "epss-mcp": {
      "url": "http://localhost:8000/mcp"
    }
  }
}
```

__Windsurf__

`serverUrl` is your server URL or IP address. 

```json
{
  "mcpServers": {
    "epss-mcp": {
      "serverUrl": "http://localhost:8000/sse"
    }
  }
}
```
>Windsurf supports two transport types for MCP servers: stdio and /sse
https://docs.windsurf.com/windsurf/cascade/mcp



# 5. Tool Examples

This example is simply demonstrating how each function works, so it's executed using a Python script as the MCP client.
(You can use them via an LLM through editors like Cursor or Windsurf.)

**Note:** MCP client for testing purposes. ([Gemini API Key](https://ai.google.dev/gemini-api/docs/api-key?hl=ja) required)

```sh
export GOOGLE_API_KEY=<your api key>
```

Start the MCP server with stdio transport

```sh
$ uv run client/client.py epss-mcp/epss_mcp.py

Connected to server with tools: ['get_cve_info', 'top_epss_cves']

MCP Client Started!
Type your queries or `quit` to exit.

Query: 
```

## 5.1. Get EPSS Score of single CVE
```sh
Query: Get EPSS of CVE-2025-33053
> Thinking...

 [Calling tool get_cve_info with args {'cve_id': 'CVE-2025-33053'}]
The EPSS score for CVE-2025-33053 is 0.41763, and the percentile is 97.264.
```

## 5.2. Get EPSS Score of multiple CVEs

```sh
Query: Get EPSS of CVE-2025-33053, CVE-2025-21298
> Thinking...

 [Calling tool get_cve_info with args {'cve_id': 'CVE-2025-33053,CVE-2025-21298'}]
CVE-2025-33053 has an EPSS score of 0.41763 and is in the 97.264 percentile. CVE-2025-21298 has an EPSS score of 0.70558 and is in the 98.593 percentile.
```

## 5.3. Get EPSS Score of multiple CVEs with time series

```sh
Query: Get time series of CVE-2025-33053 with table format

> Thinking...

 [Calling tool get_cve_info with args {'cve_id': 'CVE-2025-33053', 'time_series': True}]
Here is the time series data for CVE-2025-33053 in a table format:

| Date       | EPSS       | Percentile |
|------------|------------|------------|
| 2025-07-07 | 0.417630000 | 0.972650000 |
| 2025-07-06 | 0.37155000 | 0.96976000 |
| 2025-07-01 | 0.32398000 | 0.96662000 |
| 2025-06-30 | 0.30219000 | 0.96437000 |
| 2025-06-23 | 0.15008000 | 0.94213000 |
| 2025-06-18 | 0.16497000 | 0.94551000 |
| 2025-06-16 | 0.18266000 | 0.94860000 |
| 2025-06-15 | 0.32831000 | 0.96637000 |
| 2025-06-13 | 0.27895000 | 0.96193000 |
| 2025-06-12 | 0.53232000 | 0.97806000 |
| 2025-06-11 | 0.54359000 | 0.97862000 |
```

## 5.4. Get top 5 CVEs with the highest EPSS scores

```sh
uv run client_stdio.py ../epss-mcp/epss_mcp.py --top_n 5

> Thinking...

 [Calling tool top_epss_cves with args {'top_n': 5}]
Here are the top 5 CVEs with the highest EPSS scores:
CVE-2023-42793, EPSS score: 0.94584, EPSS percentile: 100.0
CVE-2024-27198, EPSS score: 0.94577, EPSS percentile: 100.0
CVE-2023-23752, EPSS score: 0.94532, EPSS percentile: 100.0
CVE-2024-27199, EPSS score: 0.94489, EPSS percentile: 99.99900000000001
CVE-2018-7600, EPSS score: 0.94489, EPSS percentile: 99.99900000000001
```


# 6. Reference

- https://github.com/jgamblin/EPSS-MCP
- https://nvd.nist.gov/developers/vulnerabilities
- https://www.first.org/epss/api