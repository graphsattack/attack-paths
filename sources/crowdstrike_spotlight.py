from sources.base_parser import BaseParser
from falconpy import SpotlightVulnerabilities
from collections import defaultdict

class CrowdstrikeSpotlight(BaseParser):

    def __init__(self):
        super().__init__()

        self.export_file = "crowdstrike_spotlight.json"
        self.app_config = self.config["app_settings"]["crowdstrike_idp"]

    def retrieve_data(self):
        falcon = SpotlightVulnerabilities(client_id=self.app_config["authentication"]["client_id"], client_secret=self.app_config["authentication"]["client_secret"])

        all_vulnerabilities = []
        after_cursor = None

        while True:
            params = {
                "filter": "status:!'closed'+suppression_info.is_suppressed:'false'+confidence:!'potential'+cve.exploit_status:!'0'",
                "facet": ["host_info", "cve", "remediation"],
                "limit": 5000,
                "sort": "created_timestamp.desc"
            }
            if after_cursor:
                params["after"] = after_cursor
            
            response = falcon.query_vulnerabilities_combined(parameters=params)

            all_vulnerabilities.extend(response["body"]["resources"])
            
            after_cursor = response.get("meta", {}).get("pagination", {}).get("after")
            if not after_cursor:
                break

        filtered_vulnerabilities = [vuln for vuln in all_vulnerabilities if vuln.get("host_info", {}).get("managed_by") == "Falcon sensor"]

        vuln_count = defaultdict(int)
        for entry in filtered_vulnerabilities:
            vuln_count[entry["host_info"]["hostname"]] += 1

        host_vulns = [{"host": host, "vuln_count": count} for host, count in vuln_count.items()]

        self.export_data(host_vulns, "crowdstrike_spotlight.json")
