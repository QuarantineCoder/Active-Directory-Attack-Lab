output "workspace_id" {
  value       = azurerm_log_analytics_workspace.phix.workspace_id
  description = "Log Analytics workspace GUID — used by the Phase 3 triage tool for KQL queries."
}

output "triage_identity_client_id" {
  value       = azurerm_user_assigned_identity.triage_tool.client_id
  description = "Client ID of the triage-tool managed identity for Phase 3 authentication."
}
