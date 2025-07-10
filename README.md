# EPSS MCP Server


**Note:** The major design of code in this repository is based on [EPSS-MCP](https://github.com/jgamblin/EPSS-MCP).


## Features

EPSS MCP Server has the following functions.

- Retrieve vulnerability details (including description, CWE, and CVSS scores) from the NVD API, and EPSS scores and percentiles from the EPSS API.
- Retrieve EPSS scores for multiple CVEs.
- Retrieve the EPSS time series data for a single CVE.
- Retrieve the top N CVEs with the highest EPSS scores.


## Run MCP Server

### Requirements

Prepare a Python virtual environment using uv. See [uv](https://docs.astral.sh/uv/getting-started/installation/#installation-methods) for more details. 
```sh
curl -LsSf https://astral.sh/uv/install.sh | sh
``` 



```sh
uv sync
. .venv/bin/activate
```


### Stdio
```sh
uv run client/client.py epss-mcp/epss_mcp.py
```

### Streamable HTTP
```sh
uv run epss_mcp.py --transport http
```

### SSE (Deprecated)
```sh
uv run epss_mcp.py --transport sse
```

>Windsurf supports two transport types for MCP servers: stdio and /sse
https://docs.windsurf.com/windsurf/cascade/mcp

## Run MCP Server with Docker

Run the MCP server with http transport

```sh
cd epss-mcp
docke build -t epss-mcp .
docker run -d -p 8000:8000 epss-mcp
```

## Installtion

### Streamable HTTP, SSE

__Corsor__

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

```json
{
  "mcpServers": {
    "epss-mcp": {
      "serverUrl": "http://localhost:8000/sse"
    }
  }
}
```

### Stdio

__Corsor, Windsurf__
```json
{
  "mcpServers": {
    "epss-mcp": {
      "command" : "<your python path>/python",
      "args": [
        "<script path>/epss_mcp.py"
      ]
    }
  }
}
```



## Examples

This example is simply demonstrating how each function works, so it's executed using a Python script as the MCP client.
(You can use them via an LLM through editors like Cursor or Windsurf.)

**※MCP client for testing purposes. (Gemini API Key required)**

Start mcp server with stdio transport

```sh
$ uv run client/client.py epss-mcp/epss_mcp.py

Connected to server with tools: ['get_cve_info', 'top_epss_cves']

MCP Client Started!
Type your queries or `quit` to exit.

Query: 
```

### Get EPSS Score of single CVE
```sh
Query: Get EPSS of CVE-2025-33053
> Thinking...

 [Calling tool get_cve_info with args {'cve_id': 'CVE-2025-33053'}]
The EPSS score for CVE-2025-33053 is 0.41763, and the percentile is 97.264.
```

### Get EPSS Score of multiple CVEs

```sh
Query: Get EPSS of CVE-2025-33053, CVE-2025-21298
> Thinking...

 [Calling tool get_cve_info with args {'cve_id': 'CVE-2025-33053,CVE-2025-21298'}]
CVE-2025-33053 has an EPSS score of 0.41763 and is in the 97.264 percentile. CVE-2025-21298 has an EPSS score of 0.70558 and is in the 98.593 percentile.
```

### Get EPSS Score of multiple CVEs with time series

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

### Get top 5 CVEs with the highest EPSS scores

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


## Reference

- https://github.com/jgamblin/EPSS-MCP
- https://nvd.nist.gov/developers/vulnerabilities
- https://www.first.org/epss/api



