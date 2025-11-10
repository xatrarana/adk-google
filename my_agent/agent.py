import os
from google.adk.agents.llm_agent import Agent
import subprocess
import platform
import requests

def ping_test(ip_address: str) -> dict:
    """Ping an IP address and return reachability and stats."""
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "4", ip_address]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10
        )

        output = result.stdout
        error = result.stderr

        # Basic success detection
        reachable = "TTL=" in output or "ttl=" in output

        packet_loss = None
        avg_latency = None

        if platform.system().lower() == "windows":
            # Example lines to look for: "Packets: Sent = 4, Received = 4, Lost = 0 (0% loss)"
            for line in output.splitlines():
                if "Packets:" in line:
                    packet_loss = line.strip()
                if "Average =" in line:
                    avg_latency = line.strip()
        else:
            # Example for Linux: "4 packets transmitted, 4 received, 0% packet loss, time 4004ms"
            for line in output.splitlines():
                if "packet loss" in line:
                    packet_loss = line.strip()
                if "rtt min/avg/max" in line:
                    avg_latency = line.strip()

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



key = os.getenv("VT_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3"

def web_search(query: str, type_: str = "domain") -> dict:
    """
    Search VirusTotal for threat intel.
    
    type_ can be: 'domain', 'ip_addresses', 'urls', 'file'
    """
    headers = {
        "x-apikey": key
    }

    url = f"{VT_BASE_URL}/{type_}/{query}"
    print(f"the url is: {url}")
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code != 200:
            return {"error": f"HTTP {resp.status_code} from VirusTotal API"}

        data = resp.json()

        # Simplified structured response
        result = {
            "id": data.get("data", {}).get("id"),
            "type": data.get("data", {}).get("type"),
            "attributes": data.get("data", {}).get("attributes"),
        }
        return result

    except Exception as e:
        return {"error": str(e)}

root_agent = Agent(
    model='gemini-2.5-flash',
    name='root_agent',
    description='You are Cybersecurity Engineer who solve or help other in the organization',
    instruction='''Duties and Responsibilities
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

·        Ability to work independently and able to work in team environment''',
    tools = [ping_test,web_search]
)
