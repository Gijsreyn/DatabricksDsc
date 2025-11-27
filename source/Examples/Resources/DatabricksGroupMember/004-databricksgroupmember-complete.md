---
description: Example configuration for managing multiple group members.
---

# Manage Multiple Group Members

This example shows how to manage multiple members in different groups using
DSC configuration.

## Requirements

* Target machine must have network connectivity to the Databricks workspace.
* A valid Databricks Personal Access Token (PAT) with admin privileges.

## Example

```yaml
$schema: https://aka.ms/dsc/schemas/v3/bundled/config/document.json
resources:
- name: Add user1 to data-engineers
  type: DatabricksDsc/DatabricksGroupMember
  properties:
    WorkspaceUrl: 'https://adb-1234567890123456.12.azuredatabricks.net'
    AccessToken: 'dapi1234567890abcdef'
    GroupDisplayName: 'data-engineers'
    MemberIdentifier: 'user1@example.com'
    MemberType: 'User'
    _exist: true

- name: Add user2 to data-engineers
  type: DatabricksDsc/DatabricksGroupMember
  properties:
    WorkspaceUrl: 'https://adb-1234567890123456.12.azuredatabricks.net'
    AccessToken: 'dapi1234567890abcdef'
    GroupDisplayName: 'data-engineers'
    MemberIdentifier: 'user2@example.com'
    MemberType: 'User'
    _exist: true

- name: Add service principal to admins
  type: DatabricksDsc/DatabricksGroupMember
  properties:
    WorkspaceUrl: 'https://adb-1234567890123456.12.azuredatabricks.net'
    AccessToken: 'dapi1234567890abcdef'
    GroupDisplayName: 'admins'
    MemberIdentifier: '12345678-1234-1234-1234-123456789012'
    MemberType: 'ServicePrincipal'
    _exist: true

- name: Remove user from analysts
  type: DatabricksDsc/DatabricksGroupMember
  properties:
    WorkspaceUrl: 'https://adb-1234567890123456.12.azuredatabricks.net'
    AccessToken: 'dapi1234567890abcdef'
    GroupDisplayName: 'analysts'
    MemberIdentifier: 'olduser@example.com'
    MemberType: 'User'
    _exist: false
```
