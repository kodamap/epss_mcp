from typing import Any, Dict, List, Union, Optional
import httpx

# Constants
EPSS_API_BASE = "https://api.first.org/data/v1/epss"

async def fetch_epss_data(cve_id: Union[str, List[str]], time_series: bool = False) -> List[Dict[str, Any]]:
    """
    Fetch the EPSS percentile and score for one or more CVE IDs.
    Optionally fetch time-series data if time_series is True.
    
    Args:
        cve_id: A single CVE ID as string or a list of CVE IDs
        time_series: If True, include time-series data in the result
        
    Returns:
        List of dicts with cve, epss_percentile, epss_score, and optionally time_series
    """
    is_batch = isinstance(cve_id, list)
    cve_list = cve_id if is_batch else [cve_id]
    
    # Join CVE IDs with commas for the API request
    cve_param = ",".join(cve_list)
    url = f"{EPSS_API_BASE}?cve={cve_param}"
    if time_series:
        url += "&scope=time-series"
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, timeout=30.0)
            response.raise_for_status()
            data = response.json()

            # Validate the JSON structure
            if not isinstance(data, dict) or "data" not in data or not data["data"]:
                return [
                    {"cve": cve, "epss_percentile": "N/A", "epss_score": "N/A", "epss_date": "N/A", "time_series": [] if time_series else None}
                    for cve in cve_list
                ]

            # Create a mapping of CVE to its EPSS data for efficient lookup
            epss_mapping = {
                item["cve"]: {
                    "epss_score": item.get("epss", "N/A"),
                    "epss_percentile": item.get("percentile", "N/A"),
                    "epss_date": item.get("date", "N/A"),
                    "time_series": item.get("time-series", []) if time_series else None
                } for item in data["data"]
            }
            
            return [
                {
                    "cve": cve,
                    "epss_percentile": epss_mapping.get(cve, {}).get("epss_percentile", "N/A"),
                    "epss_score": epss_mapping.get(cve, {}).get("epss_score", "N/A"),
                    "epss_date": epss_mapping.get(cve, {}).get("epss_date", "N/A"),
                    **({"time_series": epss_mapping.get(cve, {}).get("time_series", [])} if time_series else {})
                }
                for cve in cve_list
            ]
                
        except (httpx.RequestError, httpx.HTTPStatusError, ValueError, KeyError, IndexError):
            return [
                {"cve": cve, "epss_percentile": "N/A", "epss_score": "N/A", "epss_date": "N/A", "time_series": [] if time_series else None}
                for cve in cve_list
            ]

async def fetch_top_epss_cves(top_n: int = 10) -> List[Dict[str, Any]]:
    """
    Fetch the top N CVEs with the highest EPSS scores.
    Args:
        top_n: Number of top CVEs to fetch (default: 10)
    Returns:
        List of dicts with cve, epss_score, and epss_percentile
    """
    url = f"{EPSS_API_BASE}?order=!epss&limit={top_n}"
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, timeout=30.0)
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict) or "data" not in data or not data["data"]:
                return []
            results = []
            for item in data["data"]:
                results.append({
                    "cve": item.get("cve", "N/A"),
                    "epss_score": item.get("epss", "N/A"),
                    "epss_percentile": item.get("percentile", "N/A"),
                    "epss_date": item.get("date", "N/A")
                })
            return results
        except (httpx.RequestError, httpx.HTTPStatusError, ValueError, KeyError, IndexError):
            return []