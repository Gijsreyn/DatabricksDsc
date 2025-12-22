# Changelog for DatabricksDsc

The format is based on and uses the types of changes according to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.0] - 2025-12-22

### Added

- Added `DatabricksSqlWarehouse` resource for managing SQL warehouses
  - Manages SQL warehouses in a Databricks workspace
  - Key property: `Name`
  - Configurable properties:
    - `ClusterSize`: Size of clusters (2X-Small to 4X-Large)
    - `AutoStopMins`: Auto-stop timeout (0 for no autostop, or >= 10 minutes)
    - `Channel`: Channel configuration with Name and DbsqlVersion
    - `EnablePhoton`: Enable Photon optimized clusters
    - `EnableServerlessCompute`: Enable serverless compute (requires PRO warehouse type)
    - `MinNumClusters`/`MaxNumClusters`: Cluster scaling configuration
    - `SpotInstancePolicy`: POLICY_UNSPECIFIED, COST_OPTIMIZED, or RELIABILITY_OPTIMIZED
    - `Tags`: Custom tags for warehouse resources
    - `WarehouseType`: CLASSIC, PRO, or TYPE_UNSPECIFIED
  - Uses workspace-level SQL Warehouses API:
    - Create: `POST /api/2.0/sql/warehouses`
    - Update: `POST /api/2.0/sql/warehouses/{id}/edit`
    - Delete: `DELETE /api/2.0/sql/warehouses/{id}`
    - List: `GET /api/2.0/sql/warehouses`
  - Includes `Export()` static method for exporting SQL warehouses
    - Supports exporting all SQL warehouses from workspace
    - Supports filtering by `WarehouseType`, `ClusterSize`, `EnablePhoton`, and other properties
  - Includes complex types: `SqlWarehouseChannel`, `SqlWarehouseTag`, `SqlWarehouseTags`
  - Includes comprehensive unit tests for class, type definitions, and Export functionality

- Added `DatabricksSqlWarehousePermission` resource for managing SQL warehouse permissions
  - Manages permissions for SQL warehouses in a Databricks workspace
  - Key property: `WarehouseId`
  - Configurable properties:
    - `AccessControlList`: Array of access control entries with:
      - `GroupName`, `UserName`, or `ServicePrincipalName` (mutually exclusive)
      - `PermissionLevel`: CAN_MANAGE, CAN_MONITOR, CAN_USE, CAN_VIEW, or IS_OWNER
    - `_exist`: Set to `$false` to remove all permissions
  - Uses workspace-level Permissions API:
    - Get: `GET /api/2.0/permissions/sql/warehouses/{warehouse_id}`
    - Update: `PATCH /api/2.0/permissions/sql/warehouses/{warehouse_id}`
    - Set/Delete: `PUT /api/2.0/permissions/sql/warehouses/{warehouse_id}`
  - Includes complex type: `SqlWarehouseAccessControlEntry`
  - Includes comprehensive unit tests for class and type definitions

- Added `DatabricksSecret` resource for managing individual secrets in secret scopes
  - Manages secrets stored in Databricks-backed secret scopes
  - Key properties: `ScopeName`, `SecretKey`, `StringValue`/`BytesValue`
  - Supports both string values (UTF-8) and byte values (base64-encoded)
  - SecretKey validation: alphanumeric, dashes, underscores, periods (max 128 chars)
  - Maximum secret size: 128 KB
  - Note: API does not return secret values, so value changes cannot be detected
    - Existing secrets are recreated when Set() is called to ensure desired state
  - Uses workspace-level Secrets API:
    - Create/Update: `POST /api/2.0/secrets/put`
    - Delete: `POST /api/2.0/secrets/delete`
    - List: `GET /api/2.0/secrets/list`
  - Includes `Export()` static methods for exporting secrets
    - Note: Secret values are not exported (not returned by API)
    - Supports exporting all secrets from all scopes
    - Supports filtering by `ScopeName` to export secrets from specific scope
  - Cannot be used with Azure Key Vault-backed scopes
  - Includes comprehensive unit tests for class and public functions
  - Includes public functions: `Get-DatabricksSecret`, `New-DatabricksSecret`, `Remove-DatabricksSecret`

- Added `DatabricksSecretScope` resource for managing secret scopes
  - Manages both Databricks-backed and Azure Key Vault-backed secret scopes
  - Key property: `ScopeName`
  - Supports two backend types: `DATABRICKS` (default) and `AZURE_KEYVAULT`
  - For Azure Key Vault scopes, requires `BackendAzureKeyVault` with DNS name
    and resource ID
  - Includes `AzureKeyVaultBackend` complex type implementing IComparable and IEquatable
  - Note: API does not support updating scopes - scopes are deleted and
    recreated on changes
  - Uses workspace-level Secrets API:
    - Create: `POST /api/2.0/secrets/scopes/create`
    - Delete: `POST /api/2.0/secrets/scopes/delete`
    - List: `GET /api/2.0/secrets/scopes/list`
  - Includes `Export()` static methods for exporting secret scopes
    - Supports exporting all secret scopes from workspace
    - Supports filtering by `ScopeName` and `ScopeBackendType` properties
  - Includes comprehensive unit tests for class and public functions
  - Includes public functions: `Get-DatabricksSecretScope`,
    `New-DatabricksSecretScope`, `Remove-DatabricksSecretScope`

## [0.6.0] - 2025-11-28

### Changed

- `DatabricksAccountWorkspacePermissionAssignment`
  - Added `Export()` static methods for exporting permission assignments
  - Supports exporting all permission assignments for a workspace
  - Supports filtering by `PrincipalId` and `Permissions` properties
  - Uses account-level API endpoint:
    `/api/2.0/accounts/{account_id}/workspaces/{workspace_id}/permissionassignments`

## [0.5.0] - 2025-11-27

### Added

- Added `DatabricksGroupMember` resource for managing individual group memberships
  - Provides granular control over adding/removing members from groups
  - Key properties: `GroupDisplayName`, `MemberIdentifier`, `MemberType`
  - Supports both User and ServicePrincipal member types
  - Uses `_exist` property: `true` to add member, `false` to remove member
  - Uses workspace-level SCIM API PATCH operations:
    - Add: `{"op":"add","value":{"members":[{"value":"<memberId>"}]}}`
    - Remove: `{"op":"remove","path":"members[value eq \"<memberId>\"]"}`
  - Automatically retrieves group ID and member ID dynamically
  - MemberIdentifier: email for users, application ID for service principals
  - Validates WorkspaceUrl, GroupDisplayName, and MemberIdentifier
  - Includes comprehensive unit tests covering all scenarios
  - Includes example configurations for various use cases

### Changed

- **BREAKING CHANGE**: `DatabricksGroup`
  - **Removed `Members` property** - member management is now handled exclusively
    by the `DatabricksGroupMember` resource for granular control
  - Changed `Modify()` method to use PUT instead of PATCH for group updates
  - Now performs full group replacement (displayName, entitlements, roles only)
  - Removed `BuildGroupPatchPayload()` helper method
  - Removed member-related code from `BuildGroupPayload()` and `CreateFromApiData()`
  - Migration:
    - Remove `Members` property from `DatabricksGroup` configurations
    - Use `DatabricksGroupMember` resource for all member add/remove operations
    - `DatabricksGroup` now only manages group metadata
      (displayName, entitlements, roles)

## [0.4.2] - 2025-11-26

### Changed

- `DatabricksGroup`
  - Updated `GetCurrentState()` to retrieve all groups and filter locally instead
    of using SCIM filter parameters, aligning with `DatabricksUser` pattern
  - Enhanced `Modify()` method to automatically retrieve group ID when not set
    before PATCH or DELETE operations
- `DatabricksAccountServicePrincipal`
  - Added workspace URL fallback support via `GetServicePrincipalEndpoint()` helper
  - Automatically routes to workspace proxy endpoint (`/api/2.0/account/scim/v2/ServicePrincipals`)
    when using workspace URL instead of account console URL
  - Enables users without account-level console access to manage account-level
    service principals through their workspace
- `DatabricksAccountUser`
  - Added workspace URL fallback support via `GetUserEndpoint()` helper
  - Automatically routes to workspace proxy endpoint (`/api/2.0/account/scim/v2/Users`)
    when using workspace URL instead of account console URL
  - Enables users without account-level console access to manage account-level
    users through their workspace

### Fixed

- `DatabricksGroup`
  - Fixed issue where empty `$this.Id` caused malformed PATCH and DELETE URLs

## [0.4.0] - 2025-11-23

### Added

- Added `DatabricksGroup` resource for managing groups in a Databricks workspace
  - Manages groups using the workspace-level SCIM API v2
  - Key property: `DisplayName` (unique identifier)
  - Properties: `ExternalId`, `Members`, `Entitlements`, `Roles`, and read-only
    `Groups` (parent groups)
  - Supports create, update, and delete operations
  - Uses workspace-level SCIM API endpoints:
    - POST: `/api/2.0/preview/scim/v2/Groups` for create
    - GET: `/api/2.0/preview/scim/v2/Groups` for list/read
    - PATCH: `/api/2.0/preview/scim/v2/Groups/{id}` for update (SCIM PatchOp format)
    - DELETE: `/api/2.0/preview/scim/v2/Groups/{id}` for remove
  - Implements complex types: `GroupMember`, `GroupEntitlement`, `GroupRole`,
    and `ParentGroup` following SCIM schema
  - Members can be users or other groups (nested groups)
  - Entitlements support values: `allow-cluster-create`, `allow-instance-pool-create`,
    `workspace-access`, `databricks-sql-access`
  - Roles support AWS instance profile ARNs
  - Groups property shows parent groups (read-only, cannot be set directly)
  - All array properties are sorted for consistent comparison
  - Validates WorkspaceUrl format (must start with https://)
  - Validates DisplayName is not empty
  - Includes comprehensive unit tests (40+ tests) covering all methods and scenarios
  - Implements Export functionality:
    - `GetAllResourcesFromApi()` retrieves all groups from workspace
    - `CreateExportInstance()` converts API group data to resource instances
    - `Export([FilteringInstance])` supports filtering by any property
    - Export() without parameters throws error requiring authentication
  - Added localization strings for all operations (DG0001-DG0018)
- Added `DatabricksAccountWorkspacePermissionAssignment` resource for managing
  workspace permission assignments at the account level
  - Manages permission assignments for principals (users, service principals,
    or groups) at the workspace level
  - Key properties: `AccountId`, `WorkspaceId`, `PrincipalId`, and `Permissions`
  - Supports assignment (create/update via PUT) and unassignment (DELETE)
  - Uses account-level API endpoints:
    - GET: `/api/2.0/accounts/{account_id}/workspaces/{workspace_id}/permissionassignments`
    - PUT: `/api/2.0/accounts/{account_id}/workspaces/{workspace_id}/permissionassignments/principals/{principal_id}`
    - DELETE: `/api/2.0/accounts/{account_id}/workspaces/{workspace_id}/permissionassignments/principals/{principal_id}`
  - Validates AccountId as GUID, WorkspaceId and PrincipalId as numeric
  - Supports WorkspacePermissionLevel enum with User and Admin values
  - Handles API response structure with `principal.principal_id` for identification
    and `permissions` as string array
  - Includes comprehensive unit tests covering all methods and scenarios
  - Added localization strings for all operations (DAWPA0001-DAWPA0015)
- Added `WorkspacePermissionLevel` enum for workspace permission levels
  - Supported values: User and Admin
  - Used by `DatabricksAccountWorkspacePermissionAssignment` resource
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
