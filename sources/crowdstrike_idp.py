from sources.base_parser import BaseParser
from falconpy import IdentityProtection
from time import sleep

class CrowdstrikeIDP(BaseParser):

    def __init__(self):
        super().__init__()

        self.export_file_entities = "crowdstrike_idp_entities.json"
        self.export_file_aps = "crowdstrike_idp.json"
        self.app_config = self.config["app_settings"]["crowdstrike_idp"]

    def retrieve_data(self):
        falcon = IdentityProtection(client_id=self.app_config["authentication"]["client_id"], client_secret=self.app_config["authentication"]["client_secret"])

        idp_query = """
        query ($after: Cursor) {
            entities(archived: false, types: [USER, ENDPOINT], sortKey: RISK_SCORE, sortOrder: DESCENDING, first: 1000, after: $after) {
            pageInfo {
                hasNextPage
                endCursor
            }
            nodes {
                primaryDisplayName
                secondaryDisplayName
                type
                entityId
                archived
                accounts {
                ... on ActiveDirectoryAccountDescriptor {
                    enabled
                    ou
                    domain
                    title
                    department
                    description
                    creationTime
                    dataSource
                    samAccountName
                    passwordAttributes {
                    lastChange
                    }
                }
                }
                ... on UserEntity {
                riskScoreSeverity
                mostRecentActivity
                riskScore
                riskFactors {
                    type
                }
                }
                ... on EndpointEntity {
                riskScoreSeverity
                mostRecentActivity
                riskScore
                riskFactors {
                    type
                }
                }
            }
            }
        }
        """

        after_cursor = None
        all_results = []

        while True:
            variables = {"after": after_cursor}
            response = falcon.graphql(query=idp_query, variables=variables)
            
            if response["status_code"] != 200:
                print(f"Error: {response}")
                break

            data = response["body"]["data"]["entities"]
            all_results.extend(data["nodes"])

            if data["pageInfo"]["hasNextPage"]:
                after_cursor = data["pageInfo"]["endCursor"]
            else:
                break

        self.export_data(all_results, self.export_file_entities)

        idp_query = """
        query ($after: Cursor) {
            entities(archived: false, riskFactorTypes: [HAS_ATTACK_PATH, STEALTHY_PRIVILEGES, DUPLICATE_PASSWORD], 
                    sortKey: RISK_SCORE, sortOrder: DESCENDING, first: 1000, after: $after) {
                pageInfo {
                    hasNextPage
                    endCursor
                }
                nodes {
                    primaryDisplayName
                    secondaryDisplayName
                    entityId
                    riskScoreSeverity
                    riskFactors {
                        type
                        ... on AttackPathBasedRiskFactor {
                            attackPath {
                                entity {
                                    primaryDisplayName
                                    entityId
                                    type
                                    riskScoreSeverity
                                }
                                relation
                                nextEntity {
                                    primaryDisplayName
                                    entityId
                                    type
                                    riskScoreSeverity
                                }
                            }
                        }
                        ... on DuplicatePasswordRiskEntityFactor {
                            groupId
                        }
                    }
                }
            }
        }
        """

        after_cursor = None
        attack_paths = []

        while True:
            variables = {"after": after_cursor}
            response = falcon.graphql(query=idp_query, variables=variables)
            
            if response["status_code"] != 200:
                print(f"Error: {response}")
                break

            data = response["body"]["data"]["entities"]
            attack_paths.extend(data["nodes"])

            if data["pageInfo"]["hasNextPage"]:
                after_cursor = data["pageInfo"]["endCursor"]
            else:
                break

        self.export_data(attack_paths, self.export_file_aps)

    def generate_attack_paths(self):
        #Create CSIDP mapping
        crowdstrike_idp_entities = self.load_data("crowdstrike_idp_entities.json")

        crowdstrike_idp_entities_user_lookup = {
            account["entityId"].lower(): {
                "samAccountName": account.get("secondaryDisplayName", "UNKNOWN").lower(),
                "displayName": account["primaryDisplayName"]
            }
            for account in crowdstrike_idp_entities
        }

        crowdstrike_idp = self.load_data("crowdstrike_idp.json")

        paths = []

        for entry in crowdstrike_idp:
            for risk in entry["riskFactors"]:
                if risk["type"] == "STEALTHY_PRIVILEGES" or risk["type"] == "HAS_ATTACK_PATH":
                    if len(risk["attackPath"]) > 0:
                        for path in risk["attackPath"]:
                            
                            #Get user mappings
                            if path["entity"]["type"] == "USER" and crowdstrike_idp_entities_user_lookup.get(path["entity"]["entityId"]):
                                start_node_id = crowdstrike_idp_entities_user_lookup.get(path["entity"]["entityId"])["samAccountName"]
                            else:
                                start_node_id = path["entity"]["primaryDisplayName"]

                            #Eval path type
                            if path["nextEntity"] == None:
                                end_node_display_name = path["relation"]
                                end_node_type = "Access"
                                end_node_id = path["relation"]
                                path_type = "EndPath"
                            else:
                                if path["nextEntity"]["type"] == "USER" and crowdstrike_idp_entities_user_lookup.get(path["nextEntity"]["entityId"]):
                                    end_node_id = crowdstrike_idp_entities_user_lookup.get(path["nextEntity"]["entityId"])["samAccountName"]
                                else:
                                    end_node_id = path["nextEntity"]["primaryDisplayName"]

                                if path["nextEntity"]["type"] == "USER":
                                    end_node_type = "User"
                                elif path["nextEntity"]["type"] == "ENDPOINT":
                                    end_node_type = "Endpoint"
                                elif path["nextEntity"]["type"] == "ENTITY_CONTAINER":
                                    end_node_type = "Group"
                                elif path["nextEntity"]["type"] == "CLOUD_SERVICE":
                                    end_node_type = "Cloud Application"
                                else:
                                    end_node_type = path["nextEntity"]["type"]

                                end_node_display_name = path["nextEntity"]["primaryDisplayName"]
                                path_type = "MidPath"

                            if path["entity"]["type"] == "USER":
                                start_node_type = "User"
                            elif path["entity"]["type"] == "ENDPOINT":
                                start_node_type = "Endpoint"
                            elif path["entity"]["type"] == "ENTITY_CONTAINER":
                                start_node_type = "Group"
                            elif path["entity"]["type"] == "CLOUD_SERVICE":
                                start_node_type = "Cloud Application"
                            else:
                                start_node_type = path["entity"]["type"]

                            #Eval complexity
                            if path["relation"] in ["IN_GROUP", "LOCAL_ADMIN", "PASSWORD_RESETTER"]:
                                complexity = "Low"
                            else:
                                complexity = "Medium"

                            #Eval

                            ap = {
                                "PathSource": "CrowdstrikeIDP",
                                "StartNodeType": start_node_type,
                                "StartNodeDisplayName": path["entity"]["primaryDisplayName"],
                                "StartNodeID": start_node_id,
                                "Relation": path["relation"],
                                "EndNodeType": end_node_type,
                                "EndNodeDisplayName": end_node_display_name,
                                "EndNodeID": end_node_id,
                                "PathType": path_type,
                                "Complexity": complexity
                            }

                            paths.append(ap)
                            
        return paths