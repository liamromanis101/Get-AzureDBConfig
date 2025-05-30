from azure.identity import AzureCliCredential
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.sql import SqlManagementClient
from azure.core.exceptions import HttpResponseError

# Authenticate using Azure CLI credentials
credential = AzureCliCredential()

def get_resource_group_from_id(resource_id: str) -> str:
    """
    Extract the resource group name from an Azure resource ID.
    Example ID: /subscriptions/{sub}/resourceGroups/{rg}/providers/...
    """
    try:
        return resource_id.split("/")[4]
    except IndexError:
        return None

# List all subscriptions
subscription_client = SubscriptionClient(credential)

for sub in subscription_client.subscriptions.list():
    subscription_id = sub.subscription_id
    print(f"\n📦 Subscription: {sub.display_name} ({subscription_id})")

    sql_client = SqlManagementClient(credential, subscription_id)

    try:
        for server in sql_client.servers.list():
            resource_group = get_resource_group_from_id(server.id)
            print(f"  🖥️ SQL Server: {server.name} ({server.location}, RG: {resource_group})")

            # --- Check firewall rules ---
            try:
                firewall_rules = list(sql_client.firewall_rules.list_by_server(resource_group, server.name))
                for rule in firewall_rules:
                    if rule.start_ip_address == "0.0.0.0" and rule.end_ip_address == "255.255.255.255":
                        print(f"    ⚠️ Insecure firewall rule: {rule.name} allows all IPs")
            except HttpResponseError as e:
                print(f"    ❌ Failed to list firewall rules: {e}")

            # --- List and inspect databases ---
            try:
                for db in sql_client.databases.list_by_server(resource_group, server.name):
                    print(f"    📂 Database: {db.name} (Status: {db.status})")

                    # --- Transparent Data Encryption (TDE) check ---
                    try:
                        tde = sql_client.transparent_data_encryptions.get(
                            resource_group, server.name, db.name, "current"
                        )
                        if tde.status != "Enabled":
                            print(f"      ❌ TDE (encryption at rest) is not enabled!")
                    except HttpResponseError as e:
                        print(f"      ⚠️ Failed to check TDE: {e}")

                    # --- Threat Detection check ---
                    try:
                        policy = sql_client.server_security_alert_policies.get(resource_group, server.name)
                        if policy.state != "Enabled":
                            print(f"      ❌ Threat detection is disabled!")
                    except HttpResponseError as e:
                        print(f"      ⚠️ Failed to get threat detection policy: {e}")
            except HttpResponseError as e:
                print(f"    ❌ Failed to list databases: {e}")
    except HttpResponseError as e:
        print(f"  ❌ Failed to list SQL servers: {e}")
