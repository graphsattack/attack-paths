from pathlib import Path
import json

class BaseParser:
    def __init__(self):
        self.__config_path = Path(__file__).parent.parent / "config.json"
        self.export_path = Path(__file__).parent.parent / "data"
        
        with open(self.__config_path, "r") as file:
            self.config = json.load(file)

    def export_data(self, data, file_name):
        file_path = self.export_path / file_name
        with file_path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
            print("[+] Exported %s objects to %s." % (len(data), file_name))

    def load_data(self, file_name):
        try:
            file = self.export_path / file_name
            with file.open("r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"[-] Failed to load {file.name}: {e}")
            return []
        
    def generate_attack_paths(self):
        return []
    
    def generate_risks(self):
        return []