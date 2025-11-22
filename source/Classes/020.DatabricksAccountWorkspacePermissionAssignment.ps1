<#
    .SYNOPSIS
        The `DatabricksAccountWorkspacePermissionAssignment` DSC resource manages
        permission assignments for principals (users, service principals, or groups)
        at the workspace level in a Databricks account.

    .DESCRIPTION
        The `DatabricksAccountWorkspacePermissionAssignment` DSC resource is used to
        assign or unassign workspace permissions to/from principals at the account level.

        This resource manages workspace-level permissions, which control whether a
        principal has USER or ADMIN level access to a specific workspace.

        ## Requirements

        * Target machine must have network connectivity to the Databricks account console.
        * A valid Databricks Account API token with account admin privileges.
        * The workspace must already exist before assignment.
        * The principal (user, service principal, or group) must already exist.

        ## Known issues

        All issues are not listed here, see [all open issues](https://github.com/Gijsreyn/DatabricksDsc/issues?q=is%3Aissue+is%3Aopen+in%3Atitle+DatabricksAccountWorkspacePermissionAssignment).

        ### Using `AccessToken` property

        The `AccessToken` must be provided as a SecureString containing the
        Account API token with appropriate permissions.

    .PARAMETER AccountId
        The Databricks account ID (UUID format). This identifies the target account.

    .PARAMETER WorkspaceId
        The Databricks workspace ID (integer). This identifies the workspace where
        permissions are being managed.

    .PARAMETER PrincipalId
        The ID of the user, service principal, or group (integer). This identifies
        the principal receiving the permissions.

    .PARAMETER Permissions
        Array of permission levels to assign. Valid values are "USER" and "ADMIN".
        If both are provided, "ADMIN" takes precedence. If empty when _exist is true,
        this will result in deletion of all permissions for the principal.

    .PARAMETER AccountsUrl
        The URL of the Databricks Account Console. Defaults to
        'https://accounts.azuredatabricks.net' and typically does not need to be specified.

    .PARAMETER AccessToken
        The Account API token used to authenticate to the Databricks account.
        Must be provided as a SecureString.

    .PARAMETER _exist
        Specifies if the assignment should exist or not. Used internally by DSC.
        Set to $false to remove the assignment.

    .EXAMPLE
        DatabricksAccountWorkspacePermissionAssignment AdminPermissionExample
        {
            AccountId    = '12345678-1234-1234-1234-123456789012'
            WorkspaceId  = '1234567890123456'
            PrincipalId  = '9876543210'
            Permissions  = @('ADMIN')
            AccessToken  = $accessToken
        }

        Assigns ADMIN permissions to the specified principal.

    .EXAMPLE
        DatabricksAccountWorkspacePermissionAssignment UserPermissionExample
        {
            AccountId    = '12345678-1234-1234-1234-123456789012'
            WorkspaceId  = '1234567890123456'
            PrincipalId  = '9876543210'
            Permissions  = @('USER')
            AccessToken  = $accessToken
        }

        Assigns USER permissions to the specified principal.

    .EXAMPLE
        DatabricksAccountWorkspacePermissionAssignment RemovePermissionExample
        {
            AccountId    = '12345678-1234-1234-1234-123456789012'
            WorkspaceId  = '1234567890123456'
            PrincipalId  = '9876543210'
            Permissions  = @()
            AccessToken  = $accessToken
            _exist       = $false
        }

        Removes all permissions from the specified principal.
#>

[DscResource()]
class DatabricksAccountWorkspacePermissionAssignment : DatabricksAccountResourceBase
{
    [DscProperty(Key)]
    [System.String]
    $AccountId

    [DscProperty(Key)]
    [System.String]
    $WorkspaceId

    [DscProperty(Key)]
    [System.String]
    $PrincipalId

    [DscProperty()]
    [WorkspacePermissionLevel[]]
    $Permissions

    [DscProperty()]
    [System.Boolean]
    $_exist = $true

    DatabricksAccountWorkspacePermissionAssignment() : base ()
    {
        $this.ExcludeDscProperties = @(
            'AccountsUrl'
            'WorkspaceUrl'
            'AccountId'
            'WorkspaceId'
            'PrincipalId'
            'AccessToken'
        )
    }

    [DatabricksAccountWorkspacePermissionAssignment] Get()
    {
        return ([ResourceBase] $this).Get()
    }

    [System.Boolean] Test()
    {
        return ([ResourceBase] $this).Test()
    }

    [void] Set()
    {
        ([ResourceBase] $this).Set()
    }

    <#
        Base method Get() call this method to get the current state as a hashtable.
        The parameter properties will contain the key properties.
    #>
    hidden [System.Collections.Hashtable] GetCurrentState([System.Collections.Hashtable] $properties)
    {
        Write-Verbose -Message (
            $this.localizedData.EvaluatingPermissionAssignment -f @(
                $properties.PrincipalId,
                $properties.WorkspaceId,
                $properties.AccountId
            )
        )

        $currentState = @{
            WorkspaceUrl = $this.WorkspaceUrl
            AccountId    = $properties.AccountId
            WorkspaceId  = $properties.WorkspaceId
            PrincipalId  = $properties.PrincipalId
            Permissions  = @()
            _exist       = $false
        }

        try
        {
            # Get all permission assignments for the workspace
            $response = $this.InvokeDatabricksApi(
                'GET',
                "/api/2.0/accounts/$($properties.AccountId)/workspaces/$($properties.WorkspaceId)/permissionassignments",
                $null
            )

            if ($response -and $response.permission_assignments)
            {
                # Find the assignment for the specified principal using principal_id
                $principalAssignment = $response.permission_assignments | Where-Object {
                    $_.principal.principal_id -eq [int64]$properties.PrincipalId
                }

                if ($principalAssignment -and $principalAssignment.permissions)
                {
                    # Permissions is a simple string array (e.g., ['USER', 'ADMIN'])
                    $currentState.Permissions = $principalAssignment.permissions
                    $currentState._exist = $true

                    Write-Verbose -Message (
                        $this.localizedData.PermissionAssignmentFound -f @(
                            $properties.PrincipalId,
                            ($currentState.Permissions -join ', '),
                            $properties.WorkspaceId
                        )
                    )
                }
                else
                {
                    Write-Verbose -Message (
                        $this.localizedData.NoPermissionAssigned -f @(
                            $properties.PrincipalId,
                            $properties.WorkspaceId
                        )
                    )
                }
            }
            else
            {
                Write-Verbose -Message (
                    $this.localizedData.NoPermissionAssigned -f @(
                        $properties.PrincipalId,
                        $properties.WorkspaceId
                    )
                )
            }
        }
        catch
        {
            Write-Verbose -Message (
                $this.localizedData.ErrorGettingPermissionAssignment -f @(
                    $properties.PrincipalId,
                    $properties.WorkspaceId,
                    $_.Exception.Message
                )
            )
        }

        return $currentState
    }

    <#
        Base method Set() call this method with the properties that should be
        enforced are not in desired state. It is not called if all properties
        are in desired state. The variable $properties contain the properties
        that are not in desired state.
    #>
    hidden [void] Modify([System.Collections.Hashtable] $properties)
    {
        # Check if _exist property needs to be changed (assignment should be created/updated or removed)
        if ($properties.ContainsKey('_exist') -or $properties.ContainsKey('Permissions'))
        {
            # Determine the desired state
            $shouldExist = if ($properties.ContainsKey('_exist'))
            {
                $properties._exist
            }
            else
            {
                $this._exist
            }

            if ($shouldExist)
            {
                # Create/Update the permission assignment
                $permissionsToAssign = if ($properties.ContainsKey('Permissions'))
                {
                    $properties.Permissions
                }
                else
                {
                    $this.Permissions
                }

                # Validate that permissions are provided
                if ($null -eq $permissionsToAssign -or $permissionsToAssign.Count -eq 0)
                {
                    $errorMessage = 'The Permissions property must be set and cannot be empty when creating or updating a workspace permission assignment.'

                    New-InvalidOperationException -Message $errorMessage
                }

                Write-Verbose -Message (
                    $this.localizedData.AssigningPermissions -f @(
                        ($permissionsToAssign -join ', '),
                        $this.PrincipalId,
                        $this.WorkspaceId
                    )
                )

                # Convert permissions to uppercase strings array
                $permissionStrings = $permissionsToAssign.ForEach{
                    $_.ToString().ToUpper()
                }

                $body = @{
                    permissions = $permissionStrings
                }

                try
                {
                    # Use PUT to create or update permission assignment
                    $this.InvokeDatabricksApi(
                        'PUT',
                        "/api/2.0/accounts/$($this.AccountId)/workspaces/$($this.WorkspaceId)/permissionassignments/principals/$($this.PrincipalId)",
                        $body
                    )

                    Write-Verbose -Message (
                        $this.localizedData.PermissionsAssigned -f @(
                            ($permissionsToAssign -join ', '),
                            $this.PrincipalId,
                            $this.WorkspaceId
                        )
                    )
                }
                catch
                {
                    $errorMessage = $this.localizedData.FailedToAssignPermissions -f @(
                        ($permissionsToAssign -join ', '),
                        $this.PrincipalId,
                        $this.WorkspaceId,
                        $_.Exception.Message
                    )

                    New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
                }
            }
            else
            {
                # Remove the permission assignment
                Write-Verbose -Message (
                    $this.localizedData.UnassigningPermissions -f @(
                        $this.PrincipalId,
                        $this.WorkspaceId
                    )
                )

                try
                {
                    $this.InvokeDatabricksApi(
                        'DELETE',
                        "/api/2.0/accounts/$($this.AccountId)/workspaces/$($this.WorkspaceId)/permissionassignments/principals/$($this.PrincipalId)",
                        $null
                    )

                    Write-Verbose -Message (
                        $this.localizedData.PermissionsUnassigned -f @(
                            $this.PrincipalId,
                            $this.WorkspaceId
                        )
                    )
                }
                catch
                {
                    $errorMessage = $this.localizedData.FailedToUnassignPermissions -f @(
                        $this.PrincipalId,
                        $this.WorkspaceId,
                        $_.Exception.Message
                    )

                    New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
                }
            }
        }
    }

    <#
        Base method Assert() call this method with the properties that was assigned
        a value.
    #>
    hidden [void] AssertProperties([System.Collections.Hashtable] $properties)
    {
        # Validate WorkspaceUrl format
        if ($properties.WorkspaceUrl -notmatch '^https://')
        {
            $errorMessage = $this.localizedData.InvalidWorkspaceUrl -f $properties.WorkspaceUrl

            New-ArgumentException -ArgumentName 'WorkspaceUrl' -Message $errorMessage
        }

        # Validate AccountId format (must be a GUID)
        if ($properties.AccountId -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')
        {
            $errorMessage = $this.localizedData.InvalidAccountId -f $properties.AccountId

            New-ArgumentException -ArgumentName 'AccountId' -Message $errorMessage
        }

        # Validate WorkspaceId format (must be numeric)
        if ($properties.WorkspaceId -notmatch '^\d+$')
        {
            $errorMessage = $this.localizedData.InvalidWorkspaceId -f $properties.WorkspaceId

            New-ArgumentException -ArgumentName 'WorkspaceId' -Message $errorMessage
        }

        # Validate PrincipalId format (must be numeric)
        if ($properties.PrincipalId -notmatch '^\d+$')
        {
            $errorMessage = $this.localizedData.InvalidPrincipalId -f $properties.PrincipalId

            New-ArgumentException -ArgumentName 'PrincipalId' -Message $errorMessage
        }
    }
}
