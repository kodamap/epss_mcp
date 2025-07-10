from mcp.server.fastmcp import FastMCP
from epss_api import fetch_epss_data, fetch_top_epss_cves
from nvd_api import fetch_cve_details
import logging
import sys
import argparse
import asyncio
import json
from typing import List, Optional, Union, Dict, Any


# Initialize FastMCP server
mcp = FastMCP("EPSS-MCP")

@mcp.tool()
async def get_cve_info(cve_id: str, time_series: bool = False) -> List[Dict[str, Any]]:
    """Get CVE information including description, CWE, CVSS score, and EPSS data.

    Args:
        cve_id: A single CVE ID (e.g., "CVE-2022-0087") or comma-separated list
               of CVE IDs (e.g., "CVE-2022-27225,CVE-2022-27223,CVE-2022-27218")
        time_series: If True, include EPSS time-series data
    
    Returns:
        List of dicts with CVE details
    """
    cve_list = [cve.strip() for cve in cve_id.split(",") if cve.strip()]
    if not cve_list:
        return [{"error": "No valid CVE IDs provided"}]
    logging.debug(f"Fetching CVE information for: {cve_list}")
    epss_results = await fetch_epss_data(cve_list, time_series=time_series)
    results = []
    for i, cve in enumerate(cve_list):
        epss_data = epss_results[i] if i < len(epss_results) else {"epss_score": "N/A", "epss_percentile": "N/A", "time_series": [] if time_series else None}
        nvd_data = await fetch_cve_details(cve)
        if not nvd_data:
            results.append({
                "cve_id": cve,
                "error": "Unable to fetch CVE details. Please check the CVE ID or try again later."
            })
            continue
        if time_series and epss_data.get("time_series"):
            summarized = summarize_epss_timeseries(epss_data)
        else:
            summarized = "N/A"
        result = {
            "cve_id": cve,
            "cvss_score": nvd_data.get("cvss_score", "N/A"),
            "epss_data": {
                "score": float(epss_data.get("epss_score", 0)) if epss_data.get("epss_score") != "N/A" else "N/A",
                "percentile": float(epss_data.get("epss_percentile", 0)) * 100 if epss_data.get("epss_percentile") != "N/A" else "N/A",
                **({"time_series": summarized} if time_series else {})
            },
            "cwe": nvd_data.get("cwe", "N/A"),
            "description": nvd_data.get("description", "No description available"),
            "last_modified": nvd_data.get("last_modified", "N/A")[:10] if nvd_data.get("last_modified") and nvd_data.get("last_modified") != "N/A" else "N/A",
            #"raw_data": {
            #    "nvd": nvd_data,
            #    "epss": epss_data
            #}
        }
        results.append(result)

    return [{
        "status": "success",
        "count": len(results),
        "results": results
    }]

@mcp.tool()
async def top_epss_cves(top_n: int = 100) -> List[Dict[str, Any]]:
    """Get the top N CVEs with the highest EPSS scores.
    Args:
        top_n: Number of top CVEs to fetch (default: 100)
    Returns:
        List of dicts with cve, epss_score, and epss_percentile
    """
    top_epss = await fetch_top_epss_cves(top_n)
    results = []

    for epss in top_epss:
        result = {
            "cve": epss.get("cve", ""),
            "epss_score": float(epss["epss_score"]) if epss.get("epss_score") != "N/A" else "N/A",
            "epss_percentile": float(epss["epss_percentile"]) * 100 
                             if epss.get("epss_percentile") != "N/A" 
                             else "N/A",
            "epss_date": epss.get("epss_date", "")
        }
        results.append(result)
    
    return [{
        "status": "success",
        "count": len(results),
        "results": results
    }]

def summarize_epss_timeseries(epss_data):
    # Get laatest record
    epss_score = epss_data['epss_score']
    epss_percentile = epss_data['epss_percentile']
    epss_date = epss_data['epss_date']
    latest_entry = {'epss': epss_score, 'percentile': epss_percentile, 'date': epss_date}

    # Insert latest record
    timeseries = epss_data['time_series']
    timeseries.insert(0, latest_entry)

    result = []
    prev = latest_entry

    # Summarize time series
    for entry in timeseries:
        # Compare the EPSS scores and percentiles with 3 decimal places
        # If the EPSS score or percentile is different from the previous entry,
        # add the previous entry to the result list.
        if prev['epss'] != entry['epss'] or prev['percentile'] != entry['percentile']:
            result.append(prev)
        prev = entry

        # If the current entry is the last one, add it to the result list
        if entry == timeseries[-1]:
            result.append(entry)
    
    return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="EPSS MCP Server or CLI tool.")
    parser.add_argument("--cve", type=str, help="Run in CLI mode to fetch CVE information.")
    parser.add_argument("--top_n", type=int, help="Fetch and print the top N EPSS CVEs.")
    parser.add_argument("--time_series", action="store_true", help="Include EPSS time-series data.")
    transport_group = parser.add_argument_group('server mode')
    transport_group.add_argument("--transport", 
                              choices=['stdio', 'sse', 'http'], 
                              default='stdio',
                              help="Transport mode for MCP server (default: stdio)")

    args = parser.parse_args()

    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )

    if args.cve or args.top_n:
        # CLI mode
        async def main():
            if args.cve:
                result = await get_cve_info(args.cve, time_series=args.time_series)
                print(json.dumps(result, indent=2, ensure_ascii=False))
                #if args.time_series:
                #    print(json.dumps(result[0], indent=2, ensure_ascii=False))
            elif args.top_n:
                result = await top_epss_cves(args.top_n)
                print(json.dumps(result, indent=2, ensure_ascii=False))
        asyncio.run(main())
    else:
        # MCP server mode
        transport = args.transport
        if transport == 'http':
            transport = 'streamable-http'
        elif transport == 'sse':
            transport = 'sse'
        elif transport == 'stdio':
            transport = 'stdio'
        mcp.run(transport=transport)