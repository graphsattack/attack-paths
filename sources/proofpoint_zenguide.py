from sources.base_parser import BaseParser
import requests
from time import sleep
from collections import defaultdict

class ProofpointZenGuide(BaseParser):

    def __init__(self):
        super().__init__()

        self.export_file = "proofpoint_zenguide.json"
        self.app_config = self.config["app_settings"]["proofpoint_zenguide"]

    def retrieve_data(self):
        all_results = []
        url="{}/api/reporting/v0.3.0/phishing?page[size]=10000".format(self.app_config["base_url"])

        while True:
            phishing_drills = requests.get(url=url, headers={"x-apikey-token": self.app_config["authentication"]["client_secret"]}).json()
            all_results.extend(phishing_drills["data"])

            #Sleep required due to Proofpoint rate limiting
            sleep(5)

            if phishing_drills["links"].get("next"):
                url = "{}{}".format(self.app_config["base_url"], phishing_drills["links"]["next"])
            else:
                break

        self.export_data(all_results, self.export_file)

    def generate_risks(self):
        #Enrich with EntraID data for samAccountNames
        entra_id = self.load_data("entra_id.json")

        #Create entra_id lookup dict
        entra_id_user_lookup = {
            account["userPrincipalName"].lower(): {
                "id": account["id"],
                "accountEnabled": account["accountEnabled"],
                "samAccountName": (
                    f'{account.get("onPremisesDomainName", "UNKNOWN")}\\{account["onPremisesSamAccountName"]}'
                    if "onPremisesSamAccountName" in account else "UNKNOWN"
                ),
                "displayName": account["displayName"]
            }
            for account in entra_id
        }

        proofpoint_zenguide = self.load_data("proofpoint_zenguide.json")

        risks = []

        user_stats = defaultdict(lambda: {"total": 0, "failed": 0, "passed": 0})

        for entry in proofpoint_zenguide:
            user = entry["attributes"]["useremailaddress"]
            status = entry["attributes"]["eventtype"]

            if user and (status == "Email Click" or status == "Data Submission"):
                user_stats[user]["total"] += 1
                user_stats[user]["failed"] += 1
            else:
                user_stats[user]["total"] += 1
                user_stats[user]["passed"] += 1

        for user, stats in user_stats.items():
            total = stats["total"]
            failed_pct = (stats["failed"] / total) * 100 if total else 0

            if failed_pct > 0 and entra_id_user_lookup.get(user.lower()):
                risk = {
                    "RiskSource": "ProofpointZenGuide",
                    "UserID": entra_id_user_lookup.get(user.lower())["samAccountName"],
                    "RiskName": "FAILED_PHISHING_DRILLS",
                    "RiskScore": (round(failed_pct))
                }

                risks.append(risk)
        
        return risks
