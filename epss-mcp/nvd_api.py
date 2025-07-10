from typing import Any, Dict
import httpx

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="

async def fetch_cve_details(cve_id: str) -> Dict[str, Any] | None:
    """Fetch CVE details from the NVD API."""
    url = f"{NVD_API_BASE}{cve_id}"
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, timeout=30.0)
            response.raise_for_status()
            data = response.json()

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                return {
                    "description": "No description available",
                    "cwe": "N/A",
                    "cvss_score": "N/A",
                    "last_modified": "N/A"
                }

            cve_data = vulnerabilities[0].get("cve", {})
            cve_description = cve_data.get("descriptions", [{}])[0].get("value", "No description available")
            cwe = cve_data.get("weaknesses", [{}])[0].get("description", [{}])[0].get("value", "N/A")
            cvss_score = cve_data.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "N/A")
            last_modified = cve_data.get("lastModified", cve_data.get("lastModifiedDate", "N/A"))

            return {
                "description": cve_description,
                "cwe": cwe,
                "cvss_score": cvss_score,
                "last_modified": last_modified
            }
        except httpx.RequestError:
            pass
        except httpx.HTTPStatusError:
            pass
        except ValueError:
            pass
        except Exception:
            pass
        return {
            "description": "No description available",
            "cwe": "N/A",
            "cvss_score": "N/A",
            "last_modified": "N/A"
        }