from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.sql import SqlManagementClient

# Authentication
credential = DefaultAzureCredential()
subscription_client = SubscriptionClient(credential)

# Get all subscriptions
for sub in subscription_client.subscriptions.list():
    subscription_id = sub.subscription_id
    print(f"\n📦 Subscription: {sub.display_name} ({subscription_id})")

    sql_client = SqlManagementClient(credential, subscription_id)

    # List all SQL servers in this subscription
    for server in sql_client.servers.list():
        print(f"  🖥️ SQL Server: {server.name} ({server.location})")

        # Check firewall rules
        firewall_rules = list(sql_client.firewall_rules.list_by_server(server.resource_group_name, server.name))
        for rule in firewall_rules:
            if rule.start_ip_address == "0.0.0.0" and rule.end_ip_address == "255.255.255.255":
                print(f"    ⚠️ Insecure firewall rule: {rule.name} allows all IPs")

        # List all databases on this server
        for db in sql_client.databases.list_by_server(server.resource_group_name, server.name):
            print(f"    📂 Database: {db.name} (Status: {db.status})")

            # Check if TDE is enabled
            tde = sql_client.transparent_data_encryptions.get(server.resource_group_name, server.name, db.name)
            if tde.status != "Enabled":
                print(f"      ❌ TDE (encryption at rest) is not enabled!")

            # Check threat detection policies
            threat_policy = sql_client.server_security_alert_policies.get(server.resource_group_name, server.name)
            if threat_policy.state != "Enabled":
                print(f"      ❌ Threat detection is disabled!")

