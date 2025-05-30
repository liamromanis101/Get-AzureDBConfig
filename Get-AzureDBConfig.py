from azure.identity import AzureCliCredential
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.sql import SqlManagementClient
from azure.core.exceptions import HttpResponseError

# Authenticate using Azure CLI credentials
credential = AzureCliCredential()

def get_resource_group_from_id(resource_id: str) -> str:
    try:
        return resource_id.split("/")[4]
    except IndexError:
        return None

subscription_client = SubscriptionClient(credential)

for sub in subscription_client.subscriptions.list():
    subscription_id = sub.subscription_id
    print(f"\n📦 Subscription: {sub.display_name} ({subscription_id})")

    sql_client = SqlManagementClient(credential, subscription_id)

    for server in sql_client.servers.list():
        resource_group = get_resource_group_from_id(server.id)
        print(f"  🖥️ SQL Server: {server.name} ({server.location}, RG: {resource_group})")

        # Firewall rules
        try:
            firewall_rules = list(sql_client.firewall_rules.list_by_server(resource_group, server.name))
            for rule in firewall_rules:
                if rule.start_ip_address == "0.0.0.0" and rule.end_ip_address == "255.255.255.255":
                    print(f"    ⚠️ Insecure firewall rule: {rule.name} allows all IPs")
        except HttpResponseError as e:
            print(f"    ❌ Failed to list firewall rules: {e}")

        # Threat detection policy (server-level)
        try:
            policy = sql_client.server_security_alert_policies.get(resource_group, server.name, "Default")
            if policy.state != "Enabled":
                print(f"    ❌ Server-level threat detection is disabled!")
            else:
                if not policy.email_addresses:
                    print(f"    ⚠️ No email addresses configured for threat alerts.")
                if not policy.email_account_admins:
                    print(f"    ⚠️ Email to admins is not enabled.")
                if policy.retention_days == 0:
                    print(f"    ⚠️ Threat detection retention period is 0 days.")
        except HttpResponseError as e:
            print(f"    ⚠️ Failed to get threat detection policy: {e}")

        # Databases
        try:
            for db in sql_client.databases.list_by_server(resource_group, server.name):
                print(f"    📂 Database: {db.name} (Status: {db.status})")

                # TDE
                try:
                    tde = sql_client.transparent_data_encryptions.get(resource_group, server.name, db.name, "current")
                    if tde.state != "Enabled":
                        print(f"      ❌ TDE (encryption at rest) is not enabled!")
                except HttpResponseError as e:
                    print(f"      ⚠️ Failed to check TDE: {e}")

                # Auditing
                try:
                    audit_policy = sql_client.database_blob_auditing_policies.get(resource_group, server.name, db.name)
                    if audit_policy.state != "Enabled":
                        print(f"      ❌ Auditing is not enabled!")
                    else:
                        if audit_policy.retention_days == 0:
                            print(f"      ⚠️ Auditing retention period is 0 days.")
                        if not audit_policy.storage_endpoint:
                            print(f"      ⚠️ Auditing is enabled but no storage endpoint configured.")
                except HttpResponseError as e:
                    print(f"      ⚠️ Failed to check auditing: {e}")

                # Threat detection (database-level)
                try:
                    db_alert_policy = sql_client.database_security_alert_policies.get(resource_group, server.name, db.name)
                    if db_alert_policy.state != "Enabled":
                        print(f"      ❌ Threat detection is disabled at DB level!")
                    else:
                        if not db_alert_policy.email_addresses:
                            print(f"      ⚠️ No email addresses configured for DB threat alerts.")
                        if not db_alert_policy.email_account_admins:
                            print(f"      ⚠️ Email to admins not enabled at DB level.")
                        if db_alert_policy.retention_days == 0:
                            print(f"      ⚠️ Threat detection retention period is 0 days.")
                except HttpResponseError as e:
                    print(f"      ⚠️ Failed to get DB threat detection policy: {e}")

                # Geo-replication
                try:
                    replicas = list(sql_client.replication_links.list_by_database(resource_group, server.name, db.name))
                    if not replicas:
                        print(f"      ⚠️ No geo-replication configured.")
                    else:
                        for replica in replicas:
                            print(f"      🔁 Geo-replication: Linked to {replica.partner_server} in {replica.partner_location}")
                except HttpResponseError as e:
                    print(f"      ⚠️ Failed to check geo-replication: {e}")

        except HttpResponseError as e:
            print(f"    ❌ Failed to list databases: {e}")
