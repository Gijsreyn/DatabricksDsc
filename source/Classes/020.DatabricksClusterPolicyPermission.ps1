<#
    .SYNOPSIS
        The `DatabricksClusterPolicyPermission` DSC resource is used to manage
        permissions for cluster policies in a Databricks workspace.

    .DESCRIPTION
        The `DatabricksClusterPolicyPermission` DSC resource is used to manage
        permissions for cluster policies in a Databricks workspace using the
        Permissions API.

        ## Requirements

        * Target machine must have network connectivity to the Databricks workspace.
        * A valid Databricks Personal Access Token (PAT) with admin privileges.
        * The cluster policy must exist before permissions can be managed.

        ## Known issues

        All issues are not listed here, see [all open issues](https://github.com/Gijsreyn/DatabricksDsc/issues?q=is%3Aissue+is%3Aopen+in%3Atitle+DatabricksClusterPolicyPermission).

        ### Using `AccessToken` property

        The `AccessToken` must be provided as a SecureString containing the
        Personal Access Token.

    .PARAMETER ClusterPolicyId
        The unique identifier of the cluster policy. This is the key property.

    .PARAMETER AccessControlList
        An array of access control entries defining who has permission to use the
        cluster policy. Each entry specifies a principal (user, group, or service
        principal) and their permission level.

    .PARAMETER _exist
        Specifies whether the permissions should exist. Defaults to `$true`.
        Set to `$false` to remove all permissions (empty access control list).

    .EXAMPLE
        $token = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
        $accessControl = @(
            [ClusterPolicyAccessControlEntry]@{
                UserName = 'user@example.com'
                PermissionLevel = 'CAN_USE'
            }
            [ClusterPolicyAccessControlEntry]@{
                GroupName = 'data-engineers'
                PermissionLevel = 'CAN_USE'
            }
        )
        Invoke-DscResource -ModuleName DatabricksDsc -Name DatabricksClusterPolicyPermission -Method Set -Property @{
            WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
            AccessToken = $token
            ClusterPolicyId = 'ABC123DEF456'
            AccessControlList = $accessControl
        }

        This example shows how to set cluster policy permissions using Invoke-DscResource.

    .EXAMPLE
        $token = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
        Invoke-DscResource -ModuleName DatabricksDsc -Name DatabricksClusterPolicyPermission -Method Set -Property @{
            WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
            AccessToken = $token
            ClusterPolicyId = 'ABC123DEF456'
            _exist = $false
        }

        This example shows how to remove all permissions from a cluster policy.
#>
[DscResource(RunAsCredential = 'NotSupported')]
class DatabricksClusterPolicyPermission : DatabricksResourceBase
{
    [DscProperty(Key)]
    [System.String]
    $ClusterPolicyId

    [DscProperty()]
    [ClusterPolicyAccessControlEntry[]]
    $AccessControlList

    [DscProperty()]
    [System.Boolean]
    $_exist = $true

    DatabricksClusterPolicyPermission () : base ()
    {
        # These properties will not be enforced.
        $this.ExcludeDscProperties = @(
            'WorkspaceUrl'
            'ClusterPolicyId'
            'AccessToken'
        )
    }

    [DatabricksClusterPolicyPermission] Get()
    {
        # Call the base method to return the properties.
        return ([ResourceBase] $this).Get()
    }

    [System.Boolean] Test()
    {
        # Call the base method to test all of the properties that should be enforced.
        return ([ResourceBase] $this).Test()
    }

    [void] Set()
    {
        # Call the base method to enforce the properties.
        ([ResourceBase] $this).Set()
    }

    <#
        Base method Get() call this method to get the current state as a hashtable.
        The parameter properties will contain the key properties.
    #>
    hidden [System.Collections.Hashtable] GetCurrentState([System.Collections.Hashtable] $properties)
    {
        Write-Verbose -Message (
            $this.localizedData.EvaluatingPermissionState -f @(
                $properties.ClusterPolicyId,
                $this.WorkspaceUrl
            )
        )

        $currentState = @{
            WorkspaceUrl    = $this.WorkspaceUrl
            AccessToken     = $this.AccessToken
            ClusterPolicyId = $properties.ClusterPolicyId
            _exist          = $false
        }

        try
        {
            # Get permissions for the cluster policy
            $response = $this.InvokeDatabricksApi(
                'GET',
                "/api/2.0/permissions/cluster-policies/$($properties.ClusterPolicyId)",
                $null
            )

            if ($response)
            {
                # Convert access control list
                if ($response.access_control_list -and $response.access_control_list.Count -gt 0)
                {
                    $currentState.AccessControlList = @()

                    foreach ($acl in $response.access_control_list)
                    {
                        $entry = [ClusterPolicyAccessControlEntry]::new()
                        $entry.PermissionLevel = $acl.all_permissions[0].permission_level

                        # Determine principal type based on the properties present
                        if ($acl.group_name)
                        {
                            $entry.GroupName = $acl.group_name
                        }
                        elseif ($acl.user_name)
                        {
                            $entry.UserName = $acl.user_name
                        }
                        elseif ($acl.service_principal_name)
                        {
                            $entry.ServicePrincipalName = $acl.service_principal_name
                        }

                        $currentState.AccessControlList += $entry
                    }

                    # Sort access control list for consistent comparison
                    $currentState.AccessControlList = $currentState.AccessControlList | Sort-Object

                    # Check if the desired principals exist in the current state
                    if ($null -ne $this.AccessControlList -and $this.AccessControlList.Count -gt 0)
                    {
                        $allPrincipalsFound = $true

                        foreach ($desiredEntry in $this.AccessControlList)
                        {
                            $principalFound = $false

                            foreach ($currentEntry in $currentState.AccessControlList)
                            {
                                # Check if the principal matches
                                if ((-not [System.String]::IsNullOrEmpty($desiredEntry.UserName) -and
                                        $desiredEntry.UserName -eq $currentEntry.UserName) -or
                                    (-not [System.String]::IsNullOrEmpty($desiredEntry.GroupName) -and
                                    $desiredEntry.GroupName -eq $currentEntry.GroupName) -or
                                    (-not [System.String]::IsNullOrEmpty($desiredEntry.ServicePrincipalName) -and
                                    $desiredEntry.ServicePrincipalName -eq $currentEntry.ServicePrincipalName))
                                {
                                    $principalFound = $true
                                    break
                                }
                            }

                            if (-not $principalFound)
                            {
                                $allPrincipalsFound = $false
                                break
                            }
                        }

                        $currentState._exist = $allPrincipalsFound
                    }
                    else
                    {
                        # No desired principals specified, so permissions exist
                        $currentState._exist = $true
                    }
                }
                else
                {
                    # Empty access control list - no principals exist
                    $currentState._exist = $false
                    $currentState.AccessControlList = @()
                }
            }
            else
            {
                # Permissions don't exist (shouldn't happen, but handle gracefully)
                $currentState._exist = $false
                $currentState.AccessControlList = $null

                Write-Verbose -Message (
                    $this.localizedData.PermissionNotFound -f $properties.ClusterPolicyId
                )
            }
        }
        catch
        {
            # Error retrieving permissions - assume they don't exist
            $currentState._exist = $false
            $currentState.AccessControlList = $null

            Write-Verbose -Message (
                $this.localizedData.ErrorGettingPermission -f @(
                    $properties.ClusterPolicyId,
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
        # Check if _exist property needs to be changed
        if ($properties.ContainsKey('_exist'))
        {
            # Evaluate the desired state for property _exist
            if ($properties._exist -eq $false)
            {
                # Remove all permissions by setting empty access control list
                Write-Verbose -Message (
                    $this.localizedData.RemovingPermission -f $this.ClusterPolicyId
                )

                $body = @{
                    access_control_list = @()
                }

                $this.InvokeDatabricksApi(
                    'PUT',
                    "/api/2.0/permissions/cluster-policies/$($this.ClusterPolicyId)",
                    $body
                )

                Write-Verbose -Message (
                    $this.localizedData.PermissionRemoved -f $this.ClusterPolicyId
                )

                return
            }
        }

        # Determine if this is a create or update operation
        $currentState = $this.GetCurrentState(@{
            ClusterPolicyId = $this.ClusterPolicyId
        })

        if ($currentState._exist -eq $false -or
            $null -eq $currentState.AccessControlList -or
            $currentState.AccessControlList.Count -eq 0)
        {
            # Create new permissions
            Write-Verbose -Message (
                $this.localizedData.CreatingPermission -f $this.ClusterPolicyId
            )

            $body = $this.BuildPermissionPayload($properties)

            $this.InvokeDatabricksApi(
                'PUT',
                "/api/2.0/permissions/cluster-policies/$($this.ClusterPolicyId)",
                $body
            )

            Write-Verbose -Message (
                $this.localizedData.PermissionCreated -f $this.ClusterPolicyId
            )
        }
        else
        {
            # Update existing permissions
            Write-Verbose -Message (
                $this.localizedData.UpdatingPermission -f $this.ClusterPolicyId
            )

            $body = $this.BuildPermissionPayload($properties)

            $this.InvokeDatabricksApi(
                'PATCH',
                "/api/2.0/permissions/cluster-policies/$($this.ClusterPolicyId)",
                $body
            )

            Write-Verbose -Message (
                $this.localizedData.PermissionUpdated -f $this.ClusterPolicyId
            )
        }
    }

    <#
        Helper method to build the permission payload for create/update operations.
    #>
    hidden [System.Collections.Hashtable] BuildPermissionPayload([System.Collections.Hashtable] $properties)
    {
        $payload = @{
            access_control_list = @()
        }

        # Determine which AccessControlList to use
        $aclToUse = if ($properties.ContainsKey('AccessControlList'))
        {
            $properties.AccessControlList
        }
        else
        {
            $this.AccessControlList
        }

        if ($null -ne $aclToUse -and $aclToUse.Count -gt 0)
        {
            # Sort access control list before sending to API
            $sortedAcl = $aclToUse | Sort-Object

            foreach ($entry in $sortedAcl)
            {
                $aclEntry = @{
                    permission_level = $entry.PermissionLevel
                }

                # Add the appropriate principal identifier
                if (-not [System.String]::IsNullOrEmpty($entry.GroupName))
                {
                    $aclEntry.group_name = $entry.GroupName
                }
                elseif (-not [System.String]::IsNullOrEmpty($entry.UserName))
                {
                    # UserName is identified by the presence of '@' character
                    if ($entry.UserName -match '@')
                    {
                        $aclEntry.user_name = $entry.UserName
                    }
                    else
                    {
                        $errorMessage = $this.localizedData.InvalidUserName -f $entry.UserName

                        New-ArgumentException -ArgumentName 'UserName' -Message $errorMessage
                    }
                }
                elseif (-not [System.String]::IsNullOrEmpty($entry.ServicePrincipalName))
                {
                    # ServicePrincipalName should be a GUID
                    if ($entry.ServicePrincipalName -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')
                    {
                        $aclEntry.service_principal_name = $entry.ServicePrincipalName
                    }
                    else
                    {
                        $errorMessage = $this.localizedData.InvalidServicePrincipalName -f $entry.ServicePrincipalName

                        New-ArgumentException -ArgumentName 'ServicePrincipalName' -Message $errorMessage
                    }
                }
                else
                {
                    $errorMessage = $this.localizedData.NoPrincipalSpecified

                    New-ArgumentException -ArgumentName 'AccessControlList' -Message $errorMessage
                }

                $payload.access_control_list += $aclEntry
            }
        }

        return $payload
    }

    <#
        This method is called to validate the properties before they are set.
    #>
    hidden [void] AssertProperties([System.Collections.Hashtable] $properties)
    {
        # Validate WorkspaceUrl format
        if ($this.WorkspaceUrl -notmatch '^https://')
        {
            $errorMessage = $this.localizedData.InvalidWorkspaceUrl -f $this.WorkspaceUrl

            New-ArgumentException -ArgumentName 'WorkspaceUrl' -Message $errorMessage
        }

        # Validate ClusterPolicyId is not empty
        if ([System.String]::IsNullOrWhiteSpace($this.ClusterPolicyId))
        {
            $errorMessage = $this.localizedData.ClusterPolicyIdRequired

            New-ArgumentException -ArgumentName 'ClusterPolicyId' -Message $errorMessage
        }

        # Validate that each access control entry has only one principal type specified
        if ($null -ne $this.AccessControlList)
        {
            foreach ($entry in $this.AccessControlList)
            {
                $principalCount = 0

                if (-not [System.String]::IsNullOrEmpty($entry.GroupName))
                {
                    $principalCount++
                }

                if (-not [System.String]::IsNullOrEmpty($entry.UserName))
                {
                    $principalCount++
                }

                if (-not [System.String]::IsNullOrEmpty($entry.ServicePrincipalName))
                {
                    $principalCount++
                }

                if ($principalCount -eq 0)
                {
                    $errorMessage = $this.localizedData.NoPrincipalSpecified

                    New-ArgumentException -ArgumentName 'AccessControlList' -Message $errorMessage
                }

                if ($principalCount -gt 1)
                {
                    $errorMessage = $this.localizedData.MultiplePrincipalsSpecified

                    New-ArgumentException -ArgumentName 'AccessControlList' -Message $errorMessage
                }
            }
        }
    }
}
