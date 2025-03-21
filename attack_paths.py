from time import sleep
from pathlib import Path
from sources.entra_id import EntraID
from sources.proofpoint_zenguide import ProofpointZenGuide
from sources.crowdstrike_idp import CrowdstrikeIDP
from sources.crowdstrike_spotlight import CrowdstrikeSpotlight
import json

class AttackPathsHandler:
    def __init__(self):
        print("Welcome to the SA Power Networks Attack Paths tool.")

        #Define sources here
        self.sources = [
            EntraID,
            ProofpointZenGuide,
            CrowdstrikeIDP,
            CrowdstrikeSpotlight
        ]

        self.output_dir = Path(__file__).parent / "data"

        #Attack Paths
        self.attack_paths = []

        #Risks
        self.risks = []

    def export_data(self, data, file_name):
        file_path = self.output_dir / file_name
        with file_path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)

    def collect_data(self):
        print("[+] Starting data collection...")

        #Collect attack path data sources
        for source in self.sources:
            print(f"[+] Collecting data from {source.__name__}...")
            module = source()
            #module.retrieve_data()

    def generate_attack_paths(self):
        #Generate attack path data 
        for source in self.sources:
            print(f"[+] Generating attack paths from {source.__name__}...")
            module = source()
            self.attack_paths.extend(module.generate_attack_paths())

    def generate_risks(self):
        #Generate node risk data 
        for source in self.sources:
            print(f"[+] Generating risks from {source.__name__}...")
            module = source()
            self.risks.extend(module.generate_risks())

    def attribute_risks_to_users(self):
        for path in self.attack_paths:
            start_node_risks = [risk for risk in self.risks if risk["UserID"] == path["StartNodeID"]]
            end_node_risks = [risk for risk in self.risks if risk["UserID"] == path["EndNodeID"]]

            path.update({"StartNodeRisks": start_node_risks})
            path.update({"EndNodeRisks": end_node_risks})

        self.export_data(self.attack_paths, "attack_paths.json")
        print("[+] Exported %s paths to attack_paths.json" % (len(self.attack_paths)))

    def main(self):
        #self.collect_data()
        self.generate_attack_paths()
        self.generate_risks()
        self.attribute_risks_to_users()

if __name__ == "__main__":
    ap = AttackPathsHandler()
    ap.main()
