---
description: Example configuration for adding a user to a Databricks group.
---

# Add User to Group

This example shows how to add a user member to a Databricks workspace group.

## Requirements

* Target machine must have network connectivity to the Databricks workspace.
* A valid Databricks Personal Access Token (PAT) with admin privileges.

## Example

```yaml
$schema: https://aka.ms/dsc/schemas/v3/bundled/config/document.json
resources:
- name: Add user to data-engineers group
  type: DatabricksDsc/DatabricksGroupMember
  properties:
    WorkspaceUrl: 'https://adb-1234567890123456.12.azuredatabricks.net'
    AccessToken: 'dapi1234567890abcdef'
    GroupDisplayName: 'data-engineers'
    MemberIdentifier: 'user@example.com'
    MemberType: 'User'
    _exist: true
```
