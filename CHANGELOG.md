# Changelog for DatabricksDsc

The format is based on and uses the types of changes according to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial implementation of Databricks User management
  - Added `DatabricksResourceBase` class as the base class for all
    Databricks DSC resources
  - Added `DatabricksUser` DSC resource for managing users in Databricks
    workspace
  - Added complex types: `DatabricksReason`, `UserEmail`, `UserName`,
    `UserEntitlement`, and `UserRole` with `IComparable` and `IEquatable`
    implementations for proper comparison and sorting
  - Added `IpAccessList` DSC resource as a simple demonstration resource
  - Added public commands:
    - `Get-DatabricksUser` - Retrieve users from workspace
    - `New-DatabricksUser` - Create new users in workspace
    - `Set-DatabricksUser` - Update existing users in workspace
    - `Remove-DatabricksUser` - Remove users from workspace
  - Added private functions:
    - `ConvertTo-DatabricksAuthHeader` - Convert SecureString to Bearer token
  - Added localization support for all resources and commands
  - Complex types now implement `Equals()`, `CompareTo()`, and `ToString()`
    methods for proper comparison and display
  - Added unit tests for all complex type classes:
    - `DatabricksReason.Tests.ps1`
    - `UserEmail.Tests.ps1`
    - `UserName.Tests.ps1`
    - `UserEntitlement.Tests.ps1`
    - `UserRole.Tests.ps1`
  - Added unit tests for all public commands:
    - `Get-DatabricksUser.Tests.ps1`
    - `New-DatabricksUser.Tests.ps1`
    - `Set-DatabricksUser.Tests.ps1`
    - `Remove-DatabricksUser.Tests.ps1`
  - Added unit tests for all private functions:
    - `ConvertTo-DatabricksAuthHeader.Tests.ps1`
    - `UserName.Tests.ps1`
    - `UserEntitlement.Tests.ps1`
    - `UserRole.Tests.ps1`
- Added `DatabricksClusterPolicyPermission` DSC resource for managing
  cluster policy permissions in Databricks workspace
  - Added `ClusterPolicyAccessControlEntry` complex type with `IComparable`
    and `IEquatable` implementations for proper comparison and sorting
  - Supports user, group, and service principal permissions
  - Automatically detects principal type based on format (@ for users,
    GUID for service principals)
  - Added comprehensive unit tests for `DatabricksClusterPolicyPermission`
    covering all methods and validation logic
- Added `DatabricksServicePrincipal` DSC resource for managing service
  principals via SCIM API
  - Uses `ApplicationId` (GUID) as the key property
  - Supports SCIM 2.0 PatchOp format for updates
  - Reuses `UserEntitlement` and `UserRole` complex types
  - Includes GUID validation for ApplicationId
  - Added localization strings for all operations
  - Added comprehensive unit tests covering all methods and SCIM operations
- Updated `DatabricksUser` resource to use SCIM 2.0 PatchOp format for
  PATCH operations
  - Added `BuildUserPatchPayload()` method with proper SCIM schemas and
    Operations array structure
  - Added unit tests for SCIM PatchOp payload generation
  - Supports CAN_USE permission level
  - Uses PUT for creating permissions and PATCH for updating
  - Supports removing all permissions by setting `_exist` to `$false`
  - Added unit tests for complex types:
    - `ClusterPolicyAccessControlEntry.Tests.ps1`
    - `ClusterPolicyPermissionTypes.Tests.ps1`
- Added account-level resources for managing users and service principals
  across all workspaces in a Databricks account:
  - Added `DatabricksAccountUser` DSC resource for account-level user management
    - Uses account-level SCIM API: `/api/2.0/accounts/{account_id}/scim/v2/Users`
    - Requires `AccountId` (UUID) as additional key property
    - Does not support entitlements (account-level limitation)
    - Supports roles for admin assignments
    - Uses SCIM 2.0 PatchOp format for updates
    - Added localization strings for all operations
    - Added comprehensive unit tests (~1100 lines) covering all methods
  - Added `DatabricksAccountServicePrincipal` DSC resource for account-level
    service principal management
    - Uses account-level SCIM API: `/api/2.0/accounts/{account_id}/scim/v2/ServicePrincipals`
    - Requires `AccountId` (UUID) as additional key property
    - Uses `ApplicationId` (GUID) as the key identifier
    - Does not support entitlements (account-level limitation)
    - Supports roles for admin assignments
    - Uses SCIM 2.0 PatchOp format for updates
    - Added localization strings for all operations
    - Added comprehensive unit tests (~950 lines) covering all methods
  - Both account-level resources have `ExternalId` as read-only property
  - Updated help documentation for workspace-level resources to clarify scope
    and reference account-level alternatives

### Changed

- For changes in existing functionality.

### Deprecated

- For soon-to-be removed features.

### Removed

- For now removed features.

### Fixed

- For any bug fix.

### Security

- In case of vulnerabilities.
