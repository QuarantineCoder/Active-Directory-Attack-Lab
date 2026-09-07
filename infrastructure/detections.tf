resource "azurerm_sentinel_alert_rule_scheduled" "kerberoasting" {
  name                       = "kerberoasting-rc4-tgs"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.phix.id
  display_name               = "Kerberoasting — RC4 TGS Requests"
  severity                   = "High"
  enabled                    = true

  description = "Detects Kerberos TGS requests (4769) encrypted with RC4 (0x17), a signature of Kerberoasting tools like Rubeus and Impacket. Machine accounts and krbtgt are excluded."

  query = <<-KQL
    SecurityEvent
    | where EventID == 4769
    | where Status == "0x0"
    | extend EncryptionType = extract(@"TicketEncryptionType[^>]+>([^<]+)", 1, EventData)
    | where EncryptionType == "0x17"
    | where ServiceName !endswith "$"
    | where ServiceName != "krbtgt"
    | project TimeGenerated, Account, ServiceName, EncryptionType, IpAddress, Computer
  KQL

  query_frequency = "PT1H"
  query_period    = "PT1H"

  trigger_operator  = "GreaterThan"
  trigger_threshold = 0

  tactics    = ["CredentialAccess"]
  techniques = ["T1558"]

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "FullName"
      column_name = "Account"
    }
  }

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "Computer"
    }
  }

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "IpAddress"
    }
  }

  incident {
    create_incident_enabled = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "AllEntities"
      by_entities             = ["Account"]
    }
  }

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.phix]
}

resource "azurerm_sentinel_alert_rule_scheduled" "asrep_roasting" {
  name                       = "asrep-roasting-no-preauth"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.phix.id
  display_name               = "AS-REP Roasting — TGT Without Pre-Authentication"
  severity                   = "High"
  enabled                    = true

  description = "Detects TGT requests (4768) that succeeded without Kerberos pre-authentication, indicating accounts with 'Do not require preauthentication' targeted for offline cracking."

  query = <<-KQL
    SecurityEvent
    | where EventID == 4768
    | where Status == "0x0"
    | extend PreAuth = extract(@"PreAuthType[^>]+>([^<]+)", 1, EventData)
    | where PreAuth == "0"
    | project TimeGenerated, TargetUserName, IpAddress, Computer
  KQL

  query_frequency = "PT1H"
  query_period    = "PT1H"

  trigger_operator  = "GreaterThan"
  trigger_threshold = 0

  tactics    = ["CredentialAccess"]
  techniques = ["T1558"]

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "TargetUserName"
    }
  }

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "Computer"
    }
  }

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "IpAddress"
    }
  }

  incident {
    create_incident_enabled = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "AllEntities"
      by_entities             = ["Account"]
    }
  }

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.phix]
}

resource "azurerm_sentinel_alert_rule_scheduled" "dcsync" {
  name                       = "dcsync-replication-non-dc"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.phix.id
  display_name               = "DCSync — Directory Replication from Non-Machine Account"
  severity                   = "High"
  enabled                    = true

  description = "Detects directory replication rights (DS-Replication-Get-Changes / Get-Changes-All) exercised by a non-machine account — the signature of Mimikatz lsadump::dcsync."

  query = <<-KQL
    SecurityEvent
    | where EventID == 4662
    | where Properties contains "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
        or Properties contains "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
    | where SubjectUserName !endswith "$"
    | project TimeGenerated, SubjectUserName, SubjectDomainName, ObjectName, Properties, Computer
  KQL

  query_frequency = "PT1H"
  query_period    = "PT1H"

  trigger_operator  = "GreaterThan"
  trigger_threshold = 0

  tactics    = ["CredentialAccess"]
  techniques = ["T1003"]

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "SubjectUserName"
    }
    field_mapping {
      identifier  = "NTDomain"
      column_name = "SubjectDomainName"
    }
  }

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "Computer"
    }
  }

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.phix]
}
