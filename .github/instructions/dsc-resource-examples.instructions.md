---
description: Guidelines for creating DSC resource configuration examples in YAML format.
applyTo: "Examples/Resources/**/*.yaml"
---

# DSC Resource Examples Guidelines

## Overview
This document provides guidelines for creating configuration examples for DatabricksDsc resources using the DSC v3 YAML format.

## File Organization
- Examples location: `Examples/Resources/<ResourceName>/`
- File naming: Use format `001-<resourcename>-<scenario>.dsc.config.yaml` (all lowercase)
- Numbering: Prefix files with sequential numbers (001-, 002-, 003-) to indicate complexity or order
- Extension: Always use `.dsc.config.yaml` to indicate DSC configuration

## YAML Structure

### Basic Template
```yaml
$schema: https://aka.ms/dsc/schemas/v3/bundled/config/document.json
resources:
- name: <Descriptive scenario name>
  type: Microsoft.DSC/PowerShell
  properties:
    resources:
    - name: <Resource instance description>
      type: DatabricksDsc/<ResourceName>
      properties:
        <PropertyName>: <value>
        <PropertyName>: <value>
```

### Required Elements
1. **$schema**: Always use `https://aka.ms/dsc/schemas/v3/bundled/config/document.json`
2. **name**: Descriptive name explaining the scenario
3. **type**: Use `Microsoft.DSC/PowerShell` for the outer resource, `DatabricksDsc/<ResourceName>` for the inner resource
4. **properties**: All DSC resource properties with example values

## Property Guidelines

### Authentication Properties
- **WorkspaceUrl**: Use format `https://adb-<workspace-id>.<region>.azuredatabricks.net`
- **AccessToken**: Use placeholder JWT token or `'<YourAccessTokenHere>'`
- **AccountId**: Use GUID format `12345678-1234-1234-1234-123456789012` or `'<YourAccountIdHere>'`

### Sensitive Data
- Do not use real access tokens or credentials
- Use placeholder values that clearly indicate they need replacement
- Add comments when necessary to explain security considerations

### Property Values
- **Strings**: Use single quotes for string values
- **Booleans**: Use lowercase `true` or `false` without quotes
- **Arrays**: Use YAML list format with `-` prefix
- **GUIDs**: Use standard GUID format with hyphens

### Non-Configurable Properties
Properties marked with `[DscProperty(NotConfigurable)]` attribute should **NOT** be included in examples:
- **Id**: System-generated identifier (read-only)
- **ExternalId**: System-managed external identifier (read-only)
- **Reasons**: Compliance/drift reasons (read-only, populated by DSC framework)
- Any property used for internal state management (e.g., `_exist`)

These properties are either:
1. Automatically populated by the system
2. Used for internal DSC state tracking
3. Read-only output from Get() operations

**Important**: Only include properties that users can actually configure when creating or modifying resources.

### Example Property Patterns
```yaml
# String property
DisplayName: 'My Resource Name'

# Boolean property
Active: true

# Array of strings
Roles:
- 'account_admin'
- 'workspace_creator'

# Array of objects
AccessControlList:
- UserName: 'user@example.com'
  PermissionLevel: 'CAN_MANAGE'
- GroupName: 'data-engineers'
  PermissionLevel: 'CAN_USE'

# GUID property
ClusterPolicyId: '001CC22723A9379C'

# Enum-like property
PermissionLevel: 'CAN_USE'
```

## Example Scenarios

### 1. Basic/Minimal Configuration
- File: `001-<resourcename>-basic.dsc.config.yaml`
- Include only required properties
- Use simple, straightforward values

### 2. Complete Configuration
- File: `002-<resourcename>-complete.dsc.config.yaml`
- Include all properties (required + optional)
- Demonstrate advanced features

### 3. Specific Use Cases
- File: `003-<resourcename>-<scenario>.dsc.config.yaml`
- Examples: Account-level vs Workspace-level, Different permission levels, etc.

## Resource-Specific Patterns

### Workspace-Level Resources
```yaml
properties:
  WorkspaceUrl: 'https://adb-953475542402434.14.azuredatabricks.net'
  AccessToken: '<YourAccessTokenHere>'
  # Resource-specific properties
```

### Account-Level Resources
```yaml
properties:
  WorkspaceUrl: 'https://accounts.azuredatabricks.net'
  AccessToken: '<YourAccountAccessTokenHere>'
  AccountId: '12345678-1234-1234-1234-123456789012'
  # Resource-specific properties
```

### Permission Resources
```yaml
AccessControlList:
- UserName: 'user1@example.com'
  PermissionLevel: 'CAN_MANAGE'
- ServicePrincipalName: 'my-service-principal'
  PermissionLevel: 'CAN_USE'
- GroupName: 'data-team'
  PermissionLevel: 'CAN_USE'
```

## Best Practices

1. **Clarity**: Use descriptive names and values that clearly explain the purpose
2. **Completeness**: Include comments for complex or non-obvious configurations
3. **Validity**: Ensure all YAML is properly formatted and valid
4. **Relevance**: Choose realistic scenarios that users commonly need
5. **Security**: Never include real tokens, passwords, or sensitive data
6. **Consistency**: Follow the same structure across all examples
7. **Testing**: Examples should be testable (with real values substituted)

## Validation Checklist

Before submitting an example:
- [ ] YAML is valid and properly indented (2 spaces)
- [ ] Schema reference is correct
- [ ] All required properties are present
- [ ] No real credentials or sensitive data
- [ ] Descriptive names explain the scenario
- [ ] Property values are appropriate for the type
- [ ] File is placed in correct directory
- [ ] File naming follows convention
- [ ] Comments explain non-obvious aspects

## Common Resources

### DatabricksUser (Workspace-Level)
```yaml
type: DatabricksDsc/DatabricksUser
properties:
  WorkspaceUrl: 'https://adb-953475542402434.14.azuredatabricks.net'
  AccessToken: '<YourAccessTokenHere>'
  UserName: 'user@example.com'
  DisplayName: 'Example User'
  Active: true
```

### DatabricksAccountUser (Account-Level)
```yaml
type: DatabricksDsc/DatabricksAccountUser
properties:
  WorkspaceUrl: 'https://accounts.azuredatabricks.net'
  AccessToken: '<YourAccountAccessTokenHere>'
  AccountId: '12345678-1234-1234-1234-123456789012'
  UserName: 'user@example.com'
  DisplayName: 'Example User'
  Active: true
  Roles:
  - 'account_admin'
```

### DatabricksClusterPolicy
```yaml
type: DatabricksDsc/DatabricksClusterPolicy
properties:
  WorkspaceUrl: 'https://adb-953475542402434.14.azuredatabricks.net'
  AccessToken: '<YourAccessTokenHere>'
  Name: 'My Cluster Policy'
  Definition: '{"spark_version":{"type":"fixed","value":"13.3.x-scala2.12"}}'
```

### DatabricksClusterPolicyPermission
```yaml
type: DatabricksDsc/DatabricksClusterPolicyPermission
properties:
  WorkspaceUrl: 'https://adb-953475542402434.14.azuredatabricks.net'
  AccessToken: '<YourAccessTokenHere>'
  ClusterPolicyId: '001CC22723A9379C'
  AccessControlList:
  - UserName: 'user@example.com'
    PermissionLevel: 'CAN_USE'
```

## AI Assistant Notes

When creating examples:
1. Always start with the correct schema reference
2. Use the resource-specific patterns above
3. Ensure property names match the DSC resource class properties exactly (case-sensitive)
4. **Exclude non-configurable properties** (Id, ExternalId, Reasons, _exist, etc.)
5. Use realistic but clearly placeholder values for sensitive data
6. Include inline comments for complex scenarios
7. Validate YAML syntax before completion
8. Follow the numbering convention for multiple examples
9. Consider both minimal and complete examples for each resource
10. Only include properties that users can actually set or modify
