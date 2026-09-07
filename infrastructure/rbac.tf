resource "azurerm_user_assigned_identity" "triage_tool" {
  name                = "id-phix-triage"
  resource_group_name = azurerm_resource_group.phix.name
  location            = azurerm_resource_group.phix.location
}

resource "azurerm_role_assignment" "triage_sentinel_reader" {
  scope                = azurerm_resource_group.phix.id
  role_definition_name = "Microsoft Sentinel Reader"
  principal_id         = azurerm_user_assigned_identity.triage_tool.principal_id
}

resource "azurerm_role_assignment" "triage_log_reader" {
  scope                = azurerm_resource_group.phix.id
  role_definition_name = "Log Analytics Reader"
  principal_id         = azurerm_user_assigned_identity.triage_tool.principal_id
}
