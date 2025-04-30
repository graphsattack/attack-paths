# Attack Paths

**The Attack Paths tool** is a Python module that integrates with third-party cybersecurity tools such as **CrowdStrike**, **Proofpoint**, and others. It pulls data from their APIs, parses relevant data, and generates structured **attack paths** represented as JSON objects. The tool while usable, is still being worked on and fine tuned.

## 📦 Requirements

- API credentials for the integrated third-party services

## 🛠️ Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/graphsattack/attack-paths.git
cd attack-paths
pip install -r requirements.txt
```
## 🔧 Configuration
To configure, insert the API credentials in the config.json file. As they are in plaintext, this is recommended to only be used for testing. A better approach to storing creds will be added in the future, or else you can add your own method.

## 🧪 Usage
Run the module as a script:
```bash
python3 attack_paths.py
```

## 📄 Output
The module produces a JSON file (attack_paths.json) in the generated data folder, containing structured representations of detected attack paths.

Example output:
```json
{
    "PathSource": "SomePlatform",
    "StartNodeType": "User",
    "StartNodeDisplayName": "Bob Jones",
    "StartNodeID": "DOMAIN\bob",
    "Relation": "ADMIN",
    "EndNodeType": "Access",
    "EndNodeDisplayName": "ADMIN",
    "EndNodeID": "ADMIN",
    "PathType": "EndPath",
    "Complexity": "Medium",
    "StartNodeRisks": [],
    "EndNodeRisks": []
}
```

## ✅ Roadmap / TODO
 - Finish off the Path Prioritisation
 - Ingest new data sources
 - Add better way to store creds
 - Add better error handling
