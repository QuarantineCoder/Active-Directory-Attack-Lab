# Log Analytics Workspace 
# Windows Security Events from the AD lab land here; detections query it.
resource "azurerm_log_analytics_workspace" "phix" {
  name = "law-phix-sentinel"

  resource_group_name = azurerm_resource_group.phix.name
  location            = azurerm_resource_group.phix.location

  sku               = "PerGB2018" # pay-per-GB tier
  retention_in_days = 30          # free-tier default
}

resource "azurerm_sentinel_log_analytics_workspace_onboarding" "phix" {
  workspace_id                 = azurerm_log_analytics_workspace.phix.id
  customer_managed_key_enabled = false
}