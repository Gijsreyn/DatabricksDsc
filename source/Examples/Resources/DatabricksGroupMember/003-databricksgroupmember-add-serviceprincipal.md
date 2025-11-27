---
description: Example configuration for adding a service principal to a Databricks group.
---

# Add Service Principal to Group

This example shows how to add a service principal member to a Databricks workspace group.

## Requirements

* Target machine must have network connectivity to the Databricks workspace.
* A valid Databricks Personal Access Token (PAT) with admin privileges.
* Service principal must already exist in the workspace.

## Example

```yaml
$schema: https://aka.ms/dsc/schemas/v3/bundled/config/document.json
resources:
- name: Add service principal to admins group
  type: DatabricksDsc/DatabricksGroupMember
  properties:
    WorkspaceUrl: 'https://adb-1234567890123456.12.azuredatabricks.net'
    AccessToken: 'dapi1234567890abcdef'
    GroupDisplayName: 'admins'
    MemberIdentifier: '12345678-1234-1234-1234-123456789012'
    MemberType: 'ServicePrincipal'
    _exist: true
```
