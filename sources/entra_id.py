from sources.base_parser import BaseParser
import requests
import msal

class EntraID(BaseParser):

    def __init__(self):
        super().__init__()

        self.app_config = self.config["app_settings"]["entra_id"]

    def retrieve_data(self):
        app = msal.ConfidentialClientApplication(self.app_config["authentication"]["client_id"], self.app_config["authentication"]["client_secret"], "https://login.microsoftonline.com/{}".format(self.app_config["tenant_id"]))
        token_response = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])

        if "access_token" not in token_response:
            print("[-] Failed to acquire token:", token_response.get("error_description"))
            exit()

        access_token = token_response["access_token"]
        headers = {"Authorization": f"Bearer {access_token}"}

        url = "https://graph.microsoft.com/v1.0/users?$top=120&$select=id, userPrincipalName, accountEnabled, onPremisesSamAccountName, displayName, onPremisesDomainName"
        users = []

        while url:
            response = requests.get(url, headers=headers)
            data = response.json()

            if "value" in data:
                users.extend(data["value"])

            url = data.get("@odata.nextLink")

        self.export_data(users, "entra_id.json")