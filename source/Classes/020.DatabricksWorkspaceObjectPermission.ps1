<#
    .SYNOPSIS
        The `DatabricksWorkspaceObjectPermission` DSC resource manages permissions for
        workspace objects in a Databricks workspace.

    .DESCRIPTION
        The `DatabricksWorkspaceObjectPermission` DSC resource is used to manage permissions
        for workspace objects such as notebooks, directories, and repos. It allows you to
        grant or revoke access for users, groups, and service principals.

        ## Requirements

        * Target machine must have network connectivity to the Databricks workspace.
        * Valid Databricks workspace access token with appropriate permissions.

        ## Known issues

        All issues are not listed here, see [all open issues](https://github.com/Gijsreyn/DatabricksDsc/issues?q=is%3Aissue+is%3Aopen+in%3Atitle+DatabricksWorkspaceObjectPermission).

    .PARAMETER WorkspaceUrl
        The URL of the Databricks workspace.

    .PARAMETER AccessToken
        The access token used to authenticate to the Databricks workspace.

    .PARAMETER WorkspacePath
        The workspace path of the object (e.g., '/Users/user@example.com/notebook', '/Shared', '/Repos/my-repo').

    .PARAMETER AccessControlList
        The list of access control entries defining permissions for principals.

    .PARAMETER _exist
        Indicates whether permissions should exist. Set to `$false` to remove all permissions.

    .EXAMPLE
        $accessToken = ConvertTo-SecureString -String $env:DATABRICKS_TOKEN -AsPlainText -Force

        DatabricksWorkspaceObjectPermission NotebookPermissions
        {
            WorkspaceUrl       = 'https://adb-1234567890123456.12.azuredatabricks.net'
            AccessToken        = $accessToken
            WorkspacePath      = '/Shared/my-notebook'
            AccessControlList  = @(
                [WorkspaceObjectAccessControlEntry] @{
                    GroupName       = 'data-team'
                    PermissionLevel = 'CAN_EDIT'
                }
                [WorkspaceObjectAccessControlEntry] @{
                    UserName        = 'user@company.com'
                    PermissionLevel = 'CAN_READ'
                }
            )
        }

        Grants edit permissions to the 'data-team' group and read permissions to a specific user.

    .EXAMPLE
        $accessToken = ConvertTo-SecureString -String $env:DATABRICKS_TOKEN -AsPlainText -Force

        DatabricksWorkspaceObjectPermission DirectoryPermissions
        {
            WorkspaceUrl       = 'https://adb-1234567890123456.12.azuredatabricks.net'
            AccessToken        = $accessToken
            WorkspacePath      = '/Users/admin@company.com'
            AccessControlList  = @(
                [WorkspaceObjectAccessControlEntry] @{
                    ServicePrincipalName = '6c81d91b-397d-4f70-871a-d07e84689edc'
                    PermissionLevel      = 'CAN_MANAGE'
                }
            )
        }

        Grants manage permissions to a service principal on a user directory.
#>

[DscResource()]
class DatabricksWorkspaceObjectPermission : DatabricksResourceBase
{
    [DscProperty(Key)]
    [System.String]
    $WorkspacePath

    [DscProperty()]
    [WorkspaceObjectAccessControlEntry[]]
    $AccessControlList

    [DscProperty()]
    [System.Boolean]
    $_exist = $true

    hidden [System.String] $_objectId
    hidden [System.String] $_objectType
    hidden [System.String] $_permissionObjectType

    DatabricksWorkspaceObjectPermission() : base ()
    {
        $this.ExcludeDscProperties = @(
            'WorkspaceUrl'
            'AccessToken'
            'WorkspacePath'
            '_exist'
        )
    }

    [DatabricksWorkspaceObjectPermission] Get()
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
            $this.localizedData.Get_WorkspaceObjectPermission_EvaluatingPermissions -f $properties.WorkspacePath
        )

        $currentState = @{
            WorkspaceUrl      = $this.WorkspaceUrl
            WorkspacePath     = $properties.WorkspacePath
            _exist            = $false
        }

        # If desired state is _exist = $false, don't populate AccessControlList for comparison
        # This ensures the comparison focuses on _exist only
        if ($this._exist -ne $false)
        {
            $currentState.AccessControlList = @()
        }

        try
        {
            # First, get the object ID and type
            $this.ResolveWorkspaceObject($properties.WorkspacePath)

            # Get permissions for the object
            $apiPath = "/api/2.0/permissions/$($this._permissionObjectType)/$($this._objectId)"

            $response = $this.InvokeDatabricksApi(
                'GET',
                $apiPath,
                $null
            )

            if ($response -and $response.access_control_list)
            {
                Write-Verbose -Message (
                    $this.localizedData.Get_WorkspaceObjectPermission_PermissionsFound -f @(
                        $response.access_control_list.Count,
                        $properties.WorkspacePath
                    )
                )

                $nonInheritedPermissions = @()

                # Convert API response to WorkspaceObjectAccessControlEntry objects
                foreach ($ace in $response.access_control_list)
                {
                    foreach ($permission in $ace.all_permissions)
                    {
                        # Skip inherited permissions - we only manage direct permissions
                        if ($permission.inherited -eq $true)
                        {
                            continue
                        }

                        $entry = [WorkspaceObjectAccessControlEntry]::new()
                        $entry.PermissionLevel = [WorkspaceObjectPermissionLevel] $permission.permission_level

                        if ($ace.group_name)
                        {
                            $entry.GroupName = $ace.group_name
                        }
                        elseif ($ace.user_name)
                        {
                            $entry.UserName = $ace.user_name
                        }
                        elseif ($ace.service_principal_name)
                        {
                            $entry.ServicePrincipalName = $ace.service_principal_name
                        }

                        $nonInheritedPermissions += $entry
                    }
                }

                # Only populate AccessControlList if we need to compare it (not deleting)
                if ($this._exist -ne $false)
                {
                    $currentState.AccessControlList = $nonInheritedPermissions | Sort-Object
                }

                # Only consider permissions to exist if there are non-inherited permissions
                if ($nonInheritedPermissions.Count -gt 0)
                {
                    $currentState._exist = $true
                }
            }
            else
            {
                Write-Verbose -Message (
                    $this.localizedData.Get_WorkspaceObjectPermission_NoPermissions -f $properties.WorkspacePath
                )
            }
        }
        catch
        {
            Write-Verbose -Message (
                $this.localizedData.Get_WorkspaceObjectPermission_ErrorGettingPermissions -f @(
                    $properties.WorkspacePath,
                    $_.Exception.Message
                )
            )
        }

        return $currentState
    }

    <#
        Base method Set() call this method with the properties that should be enforced
        and that are not in desired state.
    #>
    hidden [void] Modify([System.Collections.Hashtable] $properties)
    {
        # Check if we're removing permissions (_exist = false)
        # Use $properties._exist if provided, otherwise fall back to $this._exist
        $removePermissions = if ($properties.ContainsKey('_exist')) { $properties._exist -eq $false } else { $this._exist -eq $false }

        if ($removePermissions)
        {
            # Ensure object is resolved
            if (-not $this._objectId)
            {
                $this.ResolveWorkspaceObject($this.WorkspacePath)
            }

            $apiPath = "/api/2.0/permissions/$($this._permissionObjectType)/$($this._objectId)"

            # Check if we're removing specific principals or all permissions
            # Use AccessControlList from $properties if provided, otherwise use $this.AccessControlList
            $aclToRemove = if ($properties.ContainsKey('AccessControlList')) { $properties.AccessControlList } else { $this.AccessControlList }

            if ($aclToRemove -and $aclToRemove.Count -gt 0)
            {
                # Remove specific principals - get current permissions and filter them out
                Write-Verbose -Message (
                    $this.localizedData.Set_WorkspaceObjectPermission_RemovingSpecificPermissions -f @(
                        $aclToRemove.Count,
                        $this.WorkspacePath
                    )
                )

                try
                {
                    # Get current permissions
                    $response = $this.InvokeDatabricksApi(
                        'GET',
                        $apiPath,
                        $null
                    )

                    $remainingAclEntries = @()

                    if ($response -and $response.access_control_list)
                    {
                        # Build list of principals to remove
                        $principalsToRemove = @()
                        foreach ($ace in $aclToRemove)
                        {
                            if ($ace.GroupName)
                            {
                                $principalsToRemove += @{ Type = 'group'; Name = $ace.GroupName }
                            }
                            elseif ($ace.UserName)
                            {
                                $principalsToRemove += @{ Type = 'user'; Name = $ace.UserName }
                            }
                            elseif ($ace.ServicePrincipalName)
                            {
                                $principalsToRemove += @{ Type = 'service_principal'; Name = $ace.ServicePrincipalName }
                            }
                        }

                        # Filter out the principals to remove from current permissions
                        foreach ($currentAce in $response.access_control_list)
                        {
                            $shouldKeep = $true

                            foreach ($toRemove in $principalsToRemove)
                            {
                                if ($toRemove.Type -eq 'group' -and $currentAce.group_name -eq $toRemove.Name)
                                {
                                    $shouldKeep = $false
                                    break
                                }
                                elseif ($toRemove.Type -eq 'user' -and $currentAce.user_name -eq $toRemove.Name)
                                {
                                    $shouldKeep = $false
                                    break
                                }
                                elseif ($toRemove.Type -eq 'service_principal' -and $currentAce.service_principal_name -eq $toRemove.Name)
                                {
                                    $shouldKeep = $false
                                    break
                                }
                            }

                            if ($shouldKeep)
                            {
                                # Keep this permission - convert to API format
                                foreach ($permission in $currentAce.all_permissions)
                                {
                                    # Skip inherited permissions
                                    if ($permission.inherited -eq $true)
                                    {
                                        continue
                                    }

                                    $entry = @{
                                        permission_level = $permission.permission_level
                                    }

                                    if ($currentAce.group_name)
                                    {
                                        $entry.group_name = $currentAce.group_name
                                    }
                                    elseif ($currentAce.user_name)
                                    {
                                        $entry.user_name = $currentAce.user_name
                                    }
                                    elseif ($currentAce.service_principal_name)
                                    {
                                        $entry.service_principal_name = $currentAce.service_principal_name
                                    }

                                    $remainingAclEntries += $entry
                                }
                            }
                        }
                    }

                    $requestBody = @{
                        access_control_list = $remainingAclEntries
                    }

                    $null = $this.InvokeDatabricksApi(
                        'PUT',
                        $apiPath,
                        $requestBody
                    )

                    Write-Verbose -Message (
                        $this.localizedData.Set_WorkspaceObjectPermission_SpecificPermissionsRemoved -f @(
                            $aclToRemove.Count,
                            $this.WorkspacePath
                        )
                    )
                }
                catch
                {
                    $errorMessage = $this.localizedData.Set_WorkspaceObjectPermission_ErrorRemovingPermissions -f @(
                        $this.WorkspacePath,
                        $_.Exception.Message
                    )

                    throw $errorMessage
                }
            }
            else
            {
                # Remove all permissions
                Write-Verbose -Message (
                    $this.localizedData.Set_WorkspaceObjectPermission_RemovingPermissions -f $this.WorkspacePath
                )

                try
                {
                    $requestBody = @{
                        access_control_list = @()
                    }

                    $null = $this.InvokeDatabricksApi(
                        'PUT',
                        $apiPath,
                        $requestBody
                    )

                    Write-Verbose -Message (
                        $this.localizedData.Set_WorkspaceObjectPermission_PermissionsRemoved -f $this.WorkspacePath
                    )
                }
                catch
                {
                    $errorMessage = $this.localizedData.Set_WorkspaceObjectPermission_ErrorRemovingPermissions -f @(
                        $this.WorkspacePath,
                        $_.Exception.Message
                    )

                    throw $errorMessage
                }
            }
        }
        else
        {
            Write-Verbose -Message (
                $this.localizedData.Set_WorkspaceObjectPermission_UpdatingPermissions -f @(
                    $properties.AccessControlList.Count,
                    $this.WorkspacePath
                )
            )

            try
            {
                # Ensure object is resolved
                if (-not $this._objectId)
                {
                    $this.ResolveWorkspaceObject($this.WorkspacePath)
                }

                $apiPath = "/api/2.0/permissions/$($this._permissionObjectType)/$($this._objectId)"

                # Build access control list
                $aclEntries = @()
                foreach ($ace in $properties.AccessControlList)
                {
                    $entry = @{
                        permission_level = $ace.PermissionLevel.ToString()
                    }

                    if ($ace.GroupName)
                    {
                        $entry.group_name = $ace.GroupName
                    }
                    elseif ($ace.UserName)
                    {
                        $entry.user_name = $ace.UserName
                    }
                    elseif ($ace.ServicePrincipalName)
                    {
                        $entry.service_principal_name = $ace.ServicePrincipalName
                    }

                    $aclEntries += $entry
                }

                $requestBody = @{
                    access_control_list = $aclEntries
                }

                $null = $this.InvokeDatabricksApi(
                    'PATCH',
                    $apiPath,
                    $requestBody
                )

                Write-Verbose -Message (
                    $this.localizedData.Set_WorkspaceObjectPermission_PermissionsUpdated -f @(
                        $properties.AccessControlList.Count,
                        $this.WorkspacePath
                    )
                )
            }
            catch
            {
                $errorMessage = $this.localizedData.Set_WorkspaceObjectPermission_ErrorUpdatingPermissions -f @(
                    $this.WorkspacePath,
                    $_.Exception.Message
                )

                throw $errorMessage
            }
        }
    }

    <#
        Resolves the workspace object to get its ID and type for permissions API.
    #>
    hidden [void] ResolveWorkspaceObject([System.String] $path)
    {
        Write-Verbose -Message (
            $this.localizedData.Resolve_WorkspaceObject_ResolvingPath -f $path
        )

        $encodedPath = [System.Uri]::EscapeDataString($path)
        $apiPath = "/api/2.0/workspace/get-status?path=$encodedPath"

        $response = $this.InvokeDatabricksApi(
            'GET',
            $apiPath,
            $null
        )

        if (-not $response.object_id)
        {
            $errorMessage = $this.localizedData.Resolve_WorkspaceObject_ObjectNotFound -f $path
            throw $errorMessage
        }

        $this._objectId = $response.object_id.ToString()
        $this._objectType = $response.object_type

        # Determine permission object type
        $this._permissionObjectType = switch ($this._objectType)
        {
            'DIRECTORY' { 'directories' }
            'NOTEBOOK' { 'notebooks' }
            'REPO' { 'repos' }
            default
            {
                $errorMessage = $this.localizedData.Resolve_WorkspaceObject_UnsupportedType -f $this._objectType
                throw $errorMessage
            }
        }

        Write-Verbose -Message (
            $this.localizedData.Resolve_WorkspaceObject_Resolved -f @(
                $this._objectId,
                $this._objectType,
                $this._permissionObjectType
            )
        )
    }
}
