resource "azurerm_monitor_data_collection_rule" "security_events" {
  name                = "dcr-phix-security-events"
  resource_group_name = azurerm_resource_group.phix.name
  location            = azurerm_resource_group.phix.location

  destinations {
    log_analytics {
      name                  = "law-phix" # internal label, referenced below
      workspace_resource_id = azurerm_log_analytics_workspace.phix.id
    }
  }

  data_sources {
    windows_event_log {
      name           = "security-events"
      streams        = ["Microsoft-SecurityEvent"]
      x_path_queries = ["Security!*"]
    }
  }

  data_flow {
    streams      = ["Microsoft-SecurityEvent"]
    destinations = ["law-phix"]
  }
}

# DC01 was onboarded imperatively via the Arc script, so we read it, not manage it.
data "azurerm_arc_machine" "dc01" {
  name                = "DC01"
  resource_group_name = azurerm_resource_group.phix.name
}

# Installs the Azure Monitor Agent onto DC01 — the process that reads the
# Windows event log and ships it. automatic_upgrade_enabled defaults to true,
# so Azure keeps the agent version current; no type_handler_version pinned.
resource "azurerm_arc_machine_extension" "ama" {
  name           = "AzureMonitorWindowsAgent"
  location       = azurerm_resource_group.phix.location
  arc_machine_id = data.azurerm_arc_machine.dc01.id
  publisher      = "Microsoft.Azure.Monitor"
  type           = "AzureMonitorWindowsAgent"
}

# Binds the DCR to DC01 — tells the agent which collection rule to follow.
# Without this, AMA installs but collects nothing.
resource "azurerm_monitor_data_collection_rule_association" "dc01_security" {
  name                    = "dcr-dc01-security"
  target_resource_id      = data.azurerm_arc_machine.dc01.id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.security_events.id
}