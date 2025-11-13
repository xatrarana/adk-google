"""
Cybersecurity Agent with Network and Threat Intelligence Tools
"""

# Standard library imports
import os
import socket
import ssl
import subprocess
import platform
from datetime import datetime

# Third-party imports
import requests
from google.adk.agents.llm_agent import Agent



# ============================================================================
# Constants
# ============================================================================

VT_API_KEY = os.getenv("VT_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3"



# ============================================================================
# Network Tools
# ============================================================================

def ping_test(ip_address: str) -> dict:
    """Ping an IP address and return reachability and stats."""
    ping_param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", ping_param, "4", ip_address]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10
        )

        output = result.stdout
        error = result.stderr
        reachable = "TTL=" in output or "ttl=" in output

        packet_loss, avg_latency = _parse_ping_output(output)

        return {
            "reachable": reachable,
            "packet_loss": packet_loss,
            "avg_latency": avg_latency,
            "stdout": output.strip(),
            "stderr": error.strip(),
        }

    except subprocess.TimeoutExpired:
        return {"reachable": False, "error": "Ping timed out"}
    except Exception as e:
        return {"reachable": False, "error": str(e)}


def _parse_ping_output(output: str) -> tuple:
    """Parse ping output to extract packet loss and latency information."""
    packet_loss = None
    avg_latency = None

    if platform.system().lower() == "windows":
        for line in output.splitlines():
            if "Packets:" in line:
                packet_loss = line.strip()
            if "Average =" in line:
                avg_latency = line.strip()
    else:
        for line in output.splitlines():
            if "packet loss" in line:
                packet_loss = line.strip()
            if "rtt min/avg/max" in line:
                avg_latency = line.strip()

    return packet_loss, avg_latency


# ============================================================================
# Threat Intelligence Tools
# ============================================================================

def web_search(query: str, type_: str = "domain") -> dict:
    """
    Search VirusTotal for threat intelligence.
    
    Args:
        query: Domain, IP, URL, or file hash to search
        type_: Type of search ('domain', 'ip_addresses', 'urls', 'file')
    
    Returns:
        Dictionary with threat intelligence data
    """
    headers = {"x-apikey": VT_API_KEY}
    url = f"{VT_BASE_URL}/{type_}/{query}"
    
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code != 200:
            return {"error": f"HTTP {resp.status_code} from VirusTotal API"}

        data = resp.json()
        return {
            "id": data.get("data", {}).get("id"),
            "type": data.get("data", {}).get("type"),
            "attributes": data.get("data", {}).get("attributes"),
        }
    except Exception as e:
        return {"error": str(e)}
## [TODO]
"""
The Toll is working fine and the response is working there is issue with model over loaded 
"""
def check_file_hash(file_hash: str) -> dict:
    """
    Check a file hash against VirusTotal.
    
    Args:
        file_hash: MD5, SHA1, or SHA256 hash of the file
    
    Returns:
        Dictionary with threat detection statistics and file information
    """
    headers = {"x-apikey": VT_API_KEY}
    url = f"{VT_BASE_URL}/files/{file_hash}"
    
    try:
        print(f"headers {headers}the shit with the url is: {url}")
        resp = requests.get(url, headers=headers, timeout=10)
        print(f"response {resp}")
        if resp.status_code == 404:
            return {"error": "File hash not found in VirusTotal database"}
        if resp.status_code != 200:
            return {"error": f"HTTP {resp.status_code} from VirusTotal API"}
        
        data = resp.json()
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        print(f"shit man {data} and the fuck this shit on the {attributes} and now th efuckin gshit {stats}")

        
        return {
            "hash": file_hash,
            "type": data.get("data", {}).get("type"),
            "malicious_detections": stats.get("malicious", 0),
            "suspicious_detections": stats.get("suspicious", 0),
            "harmless_detections": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "total_scans": sum(stats.values()),
            "reputation": attributes.get("reputation", "N/A"),
            "first_seen": attributes.get("first_submission_date"),
            "last_seen": attributes.get("last_analysis_date"),
            "file_type": attributes.get("type_description", "Unknown"),
            "file_size": attributes.get("size", "Unknown")
        }
    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# Agent Configuration
# ============================================================================

CYBERSECURITY_INSTRUCTIONS = '''Duties and Responsibilities
·        Project Setup & Initiation, develop a project schedule, Design Endpoint Security Architecture, validate pre-requisites, conduct risk assessment

·        Co-ordinate with Technical, Non-technical team members to lead or accomplish the project

·        Validate of solution requirements (Capabilities and functional use cases) and assumptions

·        Identification and definition of solution scope and requirements

·        Integration and configuration of Security Equipment ( Endpoint protection, firewall, Router, switches, servers, etc) as per the design, architecture, solution requirement as per the best practices

·        Prepare solution integration and unit testing document

·        Execute functional (Use cases) and system (Integration) tests, review and documents results

·        Prepare operation & procedures document, updated solution design and integration documents etc

·        Maximize performance by monitoring thoroughly, troubleshooting a variety of problems and outages, schedule software and patch upgrades

·        Monitor and Troubleshoot product related issues and resolve it

·        Willing to learn new technologies with competitive brands and technology

·        Take the ownership of the cases and drive and consult with different department's team member until issues are completely resolved and customer are satisfied with resolution

·        Provide technical support to customer onsite, online, on call




Skills and Qualifications

·        Excellent interpersonal, communication, presentation skills

·        Strong team co-ordination and problem solving skills

·        Strong knowledge on enterprise class networking protocol and technology (TCP/IP, AD, Routing, Switching, VPN, Firewall, Email Protection, Endpoint/antivirus)

·        Proven experience in installing, configuring, monitoring and troubleshooting security appliances/software and troubleshooting skills

·        Demonstrated passion, desire and dedication for ongoing training, development etc

·        Ability to work independently and able to work in team environment'''


# All available tools
AGENT_TOOLS = [
    ping_test,
    web_search,
    check_file_hash
]


root_agent = Agent(
    model='gemini-2.5-flash',
    name='root_agent',
    description='You are Cybersecurity Engineer who solve or help other in the organization',
    instruction=CYBERSECURITY_INSTRUCTIONS,
    tools=AGENT_TOOLS
)
