# Changelog for DatabricksDsc

The format is based on and uses the types of changes according to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added `DatabricksAccountMetastoreAssignment` resource for managing Unity
  Catalog metastore assignments to workspaces
  - Manages workspace-to-metastore assignments at the account level
  - Key properties: `AccountId`, `WorkspaceId`, and `MetastoreId`
  - Supports assignment (create/update via PUT) and unassignment (DELETE)
  - Uses account-level API endpoints:
    - GET: `/api/2.0/accounts/{account_id}/workspaces/{workspace_id}/metastore`
    - POST: `/api/2.0/accounts/{account_id}/workspaces/{workspace_id}/metastores`
    - DELETE: `/api/2.0/accounts/{account_id}/workspaces/{workspace_id}/metastores/{metastore_id}`
  - Validates AccountId and MetastoreId as GUIDs, WorkspaceId as numeric
  - Includes comprehensive unit tests with 32 test cases covering all methods
    and scenarios
  - Implements Export functionality:
    - `GetAllResourcesFromApi()` retrieves all workspace assignments for a
      metastore using GET `/api/2.0/accounts/{account_id}/metastores/{metastore_id}/workspaces`
    - `CreateExportInstance()` converts API workspace assignment data to
      resource instances
    - `Export([FilteringInstance])` supports filtering by WorkspaceId
    - Requires AccountId and MetastoreId to be set in the filtering instance
    - Added localization strings for export operations (DAMA0016-DAMA0019)
    - Added 7 unit tests for Export functionality covering all scenarios
- Added `DatabricksAccountResourceBase` intermediate base class for account-level
  DSC resources
  - Inherits from `DatabricksResourceBase` and provides specialized functionality
    for account-level operations
  - Introduces `AccountsUrl` property with default value `https://accounts.azuredatabricks.net`
  - Constructor automatically sets `WorkspaceUrl` from `AccountsUrl` for base
    class compatibility
  - Simplifies configuration for account-level resources by providing sensible
    defaults
  - Account-level resources (`DatabricksAccountUser`, `DatabricksAccountServicePrincipal`,
    `DatabricksAccountMetastoreAssignment`) now inherit from this base class
- Added `_exist` property to all account-level resources
  - `DatabricksAccountUser`, `DatabricksAccountServicePrincipal`, and
    `DatabricksAccountMetastoreAssignment` now include the `_exist` property
  - Defaults to `$true` for proper existence management
  - Enables proper handling of resource presence/absence in desired state
- Added configuration examples for `DatabricksAccountMetastoreAssignment` resource
  - Example 001: Basic metastore assignment to workspace
  - Example 002: Remove metastore assignment from workspace

### Fixed

- Fixed `DatabricksClusterPolicy` resource examples to use hashtable format
  for the `Definition` property instead of JSON string
  - Updated all three examples (basic, complete, and user limit) to demonstrate
    proper hashtable usage with YAML syntax
  - Makes examples more readable and easier to maintain
- Fixed `DatabricksAccountMetastoreAssignment` to correctly parse API response
  - Updated to handle nested `metastore_assignment` object structure from API
  - Checks `$response.metastore_assignment.metastore_id` instead of flat structure
  - Updated unit test mocks to match actual API response format

## [0.3.0] - 2025-11-21

### Added

- Added DSC Export capability to `DatabricksResourceBase` class
  - Added static `Export()` method to base class that provides guidance for
    using the parameterized overload
  - Added static `Export([FilteringInstance])` method that exports resources
    with optional filtering based on instance properties
  - Added virtual static methods `GetAllResourcesFromApi([Instance])` and
    `CreateExportInstance([ApiData], [Instance])` that child classes override
    to implement resource-specific export logic
  - Implemented Export capability in `DatabricksUser` resource
    - `GetAllResourcesFromApi()` retrieves all users from SCIM API endpoint
      `/api/2.0/preview/scim/v2/Users`
    - `CreateExportInstance()` converts API user data to `DatabricksUser`
      instances with proper type conversion and sorting
    - `Export([FilteringInstance])` supports filtering by UserName, DisplayName,
      Active status, and other user properties
  - Added comprehensive unit tests for Export functionality covering:
    - API interaction and error handling
    - Instance creation and property mapping
    - Filtering logic with single and multiple filters
    - Empty result handling
- Improved unit test coverage for existing resources
  - Added `BuildAccountUserPayload()` tests for `DatabricksAccountUser`
  - Added error handling tests for `DatabricksAccountUser.Modify()` method
    (create, update, and delete failure scenarios)
  - Added `Test()` and `Set()` method tests for `DatabricksClusterPolicyPermission`
  - Increased overall code coverage to ensure reliability

## [0.2.1] - 2025-11-19

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
