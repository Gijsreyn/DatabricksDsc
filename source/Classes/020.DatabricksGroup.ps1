<#
    .SYNOPSIS
        The `DatabricksGroup` DSC resource is used to create, modify, or remove
        groups in a Databricks workspace at the workspace level.

    .DESCRIPTION
        The `DatabricksGroup` DSC resource is used to create, modify, or remove
        groups in a Databricks workspace using the workspace-level SCIM API.

        This resource manages groups within a specific workspace. Groups can contain
        users and other groups, and can be assigned entitlements and roles.

        ## Requirements

        * Target machine must have network connectivity to the Databricks workspace.
        * A valid Databricks Personal Access Token (PAT) with admin privileges.

        ## Known issues

        All issues are not listed here, see [all open issues](https://github.com/Gijsreyn/DatabricksDsc/issues?q=is%3Aissue+is%3Aopen+in%3Atitle+DatabricksGroup).

        ### Using `AccessToken` property

        The `AccessToken` must be provided as a SecureString containing the
        Personal Access Token.

    .PARAMETER DisplayName
        The display name of the group. This is the unique identifier.

    .PARAMETER ExternalId
        An external identifier for the group (optional).

    .PARAMETER Members
        An array of members (users or groups) in this group.

    .PARAMETER Entitlements
        An array of entitlements assigned to the group.

    .PARAMETER Roles
        An array of roles assigned to the group.

    .PARAMETER Groups
        An array of parent groups that this group belongs to (read-only).

    .PARAMETER _exist
        Specifies whether the group should exist in the workspace. Defaults to `$true`.
        Set to `$false` to remove the group.

    .EXAMPLE
        $token = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
        Invoke-DscResource -ModuleName DatabricksDsc -Name DatabricksGroup -Method Get -Property @{
            WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
            AccessToken  = $token
            DisplayName  = 'data-engineers'
        }

        This example shows how to call the resource using Invoke-DscResource.
#>
[DscResource(RunAsCredential = 'NotSupported')]
class DatabricksGroup : DatabricksResourceBase
{
    [DscProperty(Key)]
    [System.String]
    $DisplayName

    [DscProperty()]
    [System.String]
    $ExternalId

    [DscProperty()]
    [GroupMember[]]
    $Members

    [DscProperty()]
    [GroupEntitlement[]]
    $Entitlements

    [DscProperty()]
    [GroupRole[]]
    $Roles

    [DscProperty(NotConfigurable)]
    [ParentGroup[]]
    $Groups

    [DscProperty(NotConfigurable)]
    [System.String]
    $Id

    [DscProperty()]
    [System.Boolean]
    $_exist = $true

    DatabricksGroup () : base ()
    {
        # These properties will not be enforced.
        $this.ExcludeDscProperties = @(
            'WorkspaceUrl'
            'DisplayName'
            'AccessToken'
            'Id'
            'Groups'
        )
    }

    [DatabricksGroup] Get()
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
            $this.localizedData.EvaluatingGroupState -f @(
                $properties.DisplayName,
                $this.WorkspaceUrl
            )
        )

        $currentState = @{
            WorkspaceUrl = $this.WorkspaceUrl
            AccessToken  = $this.AccessToken
            DisplayName  = $properties.DisplayName
            _exist       = $false
        }

        try
        {
            # Get all groups and filter by displayName
            $response = $this.InvokeDatabricksApi(
                'GET',
                '/api/2.0/preview/scim/v2/Groups',
                $null
            )

            $group = $response.Resources | Where-Object -FilterScript {
                $_.displayName -eq $properties.DisplayName
            } | Select-Object -First 1

            if ($group)
            {
                $currentState._exist = $true
                $currentState.Id = $group.id
                $currentState.ExternalId = $group.externalId

                # Convert members
                if ($group.members)
                {
                    $currentState.Members = @()
                    foreach ($member in $group.members)
                    {
                        $currentState.Members += [GroupMember]@{
                            Value   = $member.value
                            Display = $member.display
                            Ref     = $member.'$ref'
                        }
                    }

                    # Sort members for consistent comparison
                    $currentState.Members = $currentState.Members | Sort-Object
                }

                # Convert entitlements
                if ($group.entitlements)
                {
                    $currentState.Entitlements = @()
                    foreach ($entitlement in $group.entitlements)
                    {
                        $currentState.Entitlements += [GroupEntitlement]@{
                            Value = $entitlement.value
                        }
                    }

                    # Sort entitlements for consistent comparison
                    $currentState.Entitlements = $currentState.Entitlements | Sort-Object
                }

                # Convert roles
                if ($group.roles)
                {
                    $currentState.Roles = @()
                    foreach ($role in $group.roles)
                    {
                        $currentState.Roles += [GroupRole]@{
                            Value = $role.value
                        }
                    }

                    # Sort roles for consistent comparison
                    $currentState.Roles = $currentState.Roles | Sort-Object
                }

                # Convert parent groups (read-only)
                if ($group.groups)
                {
                    $currentState.Groups = @()
                    foreach ($parentGroup in $group.groups)
                    {
                        $currentState.Groups += [ParentGroup]@{
                            Value   = $parentGroup.value
                            Display = $parentGroup.display
                            Ref     = $parentGroup.'$ref'
                        }
                    }

                    # Sort groups for consistent comparison
                    $currentState.Groups = $currentState.Groups | Sort-Object
                }
            }
            else
            {
                # When group doesn't exist, set all other properties to $null
                $currentState.ExternalId = $null
                $currentState.Members = $null
                $currentState.Entitlements = $null
                $currentState.Roles = $null
                $currentState.Groups = $null
                $currentState.Id = $null

                Write-Verbose -Message (
                    $this.localizedData.GroupNotFound -f $properties.DisplayName
                )
            }
        }
        catch
        {
            Write-Verbose -Message (
                $this.localizedData.ErrorGettingGroup -f @(
                    $properties.DisplayName,
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
        # Check if _exist property needs to be changed (group should be created or removed)
        if ($properties.ContainsKey('_exist'))
        {
            # Evaluate the desired state for property _exist
            if ($properties._exist -eq $true)
            {
                # Create the group since it doesn't exist
                Write-Verbose -Message (
                    $this.localizedData.CreatingGroup -f $this.DisplayName
                )

                $body = $this.BuildGroupPayload($properties)
                $body.displayName = $this.DisplayName
                $body.schemas = @('urn:ietf:params:scim:schemas:core:2.0:Group')

                try
                {
                    $this.InvokeDatabricksApi(
                        'POST',
                        '/api/2.0/preview/scim/v2/Groups',
                        $body
                    )

                    Write-Verbose -Message (
                        $this.localizedData.GroupCreated -f $this.DisplayName
                    )
                }
                catch
                {
                    $errorMessage = $this.localizedData.FailedToCreateGroup -f @(
                        $this.DisplayName,
                        $_.Exception.Message
                    )

                    New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
                }
            }
            else
            {
                # Remove the group since it exists (delete the entire group)
                Write-Verbose -Message (
                    $this.localizedData.RemovingGroup -f $this.DisplayName
                )

                # Retrieve the group ID if not already set
                $groupId = $this.Id
                if ([string]::IsNullOrEmpty($groupId))
                {
                    $response = $this.InvokeDatabricksApi(
                        'GET',
                        '/api/2.0/preview/scim/v2/Groups',
                        $null
                    )

                    $group = $response.Resources | Where-Object -FilterScript {
                        $_.displayName -eq $this.DisplayName
                    } | Select-Object -First 1

                    if ($group)
                    {
                        $groupId = $group.id
                    }
                }

                try
                {
                    $this.InvokeDatabricksApi(
                        'DELETE',
                        "/api/2.0/preview/scim/v2/Groups/$groupId",
                        $null
                    )

                    Write-Verbose -Message (
                        $this.localizedData.GroupRemoved -f $this.DisplayName
                    )
                }
                catch
                {
                    $errorMessage = $this.localizedData.FailedToRemoveGroup -f @(
                        $this.DisplayName,
                        $_.Exception.Message
                    )

                    New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
                }
            }
        }
        else
        {
            # Update existing group properties (group exists and should exist)
            if ($this._exist -eq $true)
            {
                Write-Verbose -Message (
                    $this.localizedData.UpdatingGroup -f $this.DisplayName
                )

                # Retrieve the group ID if not already set
                $groupId = $this.Id
                if ([string]::IsNullOrEmpty($groupId))
                {
                    $response = $this.InvokeDatabricksApi(
                        'GET',
                        '/api/2.0/preview/scim/v2/Groups',
                        $null
                    )

                    $group = $response.Resources | Where-Object -FilterScript {
                        $_.displayName -eq $this.DisplayName
                    } | Select-Object -First 1

                    if ($group)
                    {
                        $groupId = $group.id
                    }
                }

                $body = $this.BuildGroupPatchPayload($properties)

                try
                {
                    $this.InvokeDatabricksApi(
                        'PATCH',
                        "/api/2.0/preview/scim/v2/Groups/$groupId",
                        $body
                    )

                    Write-Verbose -Message (
                        $this.localizedData.GroupUpdated -f $this.DisplayName
                    )
                }
                catch
                {
                    $errorMessage = $this.localizedData.FailedToUpdateGroup -f @(
                        $this.DisplayName,
                        $_.Exception.Message
                    )

                    New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
                }
            }
        }
    }

    <#
        Helper method to build the group payload for API calls.
    #>
    hidden [System.Collections.Hashtable] BuildGroupPayload([System.Collections.Hashtable] $properties)
    {
        $body = @{}

        if ($properties.ContainsKey('ExternalId'))
        {
            $body.externalId = $this.ExternalId
        }

        if ($properties.ContainsKey('Members') -and $this.Members)
        {
            $body.members = @()
            # Sort members before sending to API
            $sortedMembers = $this.Members | Sort-Object

            foreach ($member in $sortedMembers)
            {
                $memberObj = @{
                    value = $member.Value
                }

                $body.members += $memberObj
            }
        }

        if ($properties.ContainsKey('Entitlements') -and $this.Entitlements)
        {
            $body.entitlements = @()
            # Sort entitlements before sending to API
            $sortedEntitlements = $this.Entitlements | Sort-Object

            foreach ($entitlement in $sortedEntitlements)
            {
                $body.entitlements += @{
                    value = $entitlement.Value
                }
            }
        }

        if ($properties.ContainsKey('Roles') -and $this.Roles)
        {
            $body.roles = @()
            # Sort roles before sending to API
            $sortedRoles = $this.Roles | Sort-Object

            foreach ($role in $sortedRoles)
            {
                $body.roles += @{
                    value = $role.Value
                }
            }
        }

        return $body
    }

    <#
        Helper method to build the SCIM PATCH payload for group updates.
        Uses SCIM PatchOp format as per documentation.
    #>
    hidden [System.Collections.Hashtable] BuildGroupPatchPayload([System.Collections.Hashtable] $properties)
    {
        $body = @{
            schemas    = @('urn:ietf:params:scim:api:messages:2.0:PatchOp')
            Operations = @()
        }

        # Handle Members updates
        if ($properties.ContainsKey('Members') -and $null -ne $this.Members)
        {
            # Sort members before sending to API
            $sortedMembers = $this.Members | Sort-Object

            $memberValues = @()
            foreach ($member in $sortedMembers)
            {
                $memberValues += @{
                    value = $member.Value
                }
            }

            $body.Operations += @{
                op    = 'add'
                path  = 'members'
                value = $memberValues
            }
        }

        # Handle Entitlements updates
        if ($properties.ContainsKey('Entitlements') -and $null -ne $this.Entitlements)
        {
            # Sort entitlements before sending to API
            $sortedEntitlements = $this.Entitlements | Sort-Object

            $entitlementValues = @()
            foreach ($entitlement in $sortedEntitlements)
            {
                $entitlementValues += @{
                    value = $entitlement.Value
                }
            }

            $body.Operations += @{
                op    = 'add'
                path  = 'entitlements'
                value = $entitlementValues
            }
        }

        # Handle Roles updates
        if ($properties.ContainsKey('Roles') -and $null -ne $this.Roles)
        {
            # Sort roles before sending to API
            $sortedRoles = $this.Roles | Sort-Object

            $roleValues = @()
            foreach ($role in $sortedRoles)
            {
                $roleValues += @{
                    value = $role.Value
                }
            }

            $body.Operations += @{
                op    = 'add'
                path  = 'roles'
                value = $roleValues
            }
        }

        return $body
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

        # Validate DisplayName is not empty
        if ([string]::IsNullOrWhiteSpace($properties.DisplayName))
        {
            $errorMessage = $this.localizedData.InvalidDisplayName

            New-ArgumentException -ArgumentName 'DisplayName' -Message $errorMessage
        }
    }

    <#
        Retrieves all groups from the Databricks workspace API.

        .PARAMETER Instance
            An instance of DatabricksGroup with WorkspaceUrl and AccessToken populated.

        .RETURNS
            Array of PSCustomObjects representing group data from the SCIM API.
    #>
    static [PSObject[]] GetAllResourcesFromApi([DatabricksResourceBase] $Instance)
    {
        try
        {
            # Call the SCIM API to get all groups
            $response = $Instance.InvokeDatabricksApi(
                'GET',
                '/api/2.0/preview/scim/v2/Groups',
                $null
            )

            # Return the Resources array from the response
            if ($response.Resources)
            {
                return $response.Resources
            }
            else
            {
                return @()
            }
        }
        catch
        {
            Write-Verbose -Message (
                'Failed to retrieve groups from Databricks workspace: {0}' -f $_.Exception.Message
            )
            throw
        }
    }

    <#
        Converts API group data to a DatabricksGroup instance.

        .PARAMETER ApiData
            A PSCustomObject containing group data from the SCIM API.

        .PARAMETER Instance
            An instance of DatabricksGroup with WorkspaceUrl and AccessToken populated.

        .RETURNS
            A DatabricksGroup instance populated with data from the API.
    #>
    static [DatabricksResourceBase] CreateExportInstance([PSObject] $ApiData, [DatabricksResourceBase] $Instance)
    {
        $exportInstance = [DatabricksGroup]::new()

        # Copy authentication properties
        $exportInstance.WorkspaceUrl = $Instance.WorkspaceUrl
        $exportInstance.AccessToken = $Instance.AccessToken

        # Populate key property
        $exportInstance.DisplayName = $ApiData.displayName

        # Populate other properties
        if ($ApiData.externalId)
        {
            $exportInstance.ExternalId = $ApiData.externalId
        }

        if ($ApiData.id)
        {
            $exportInstance.Id = $ApiData.id
        }

        # Convert members
        if ($ApiData.members)
        {
            $exportInstance.Members = @()
            foreach ($member in $ApiData.members)
            {
                $exportInstance.Members += [GroupMember]@{
                    Value   = $member.value
                    Display = $member.display
                    Ref     = $member.'$ref'
                }
            }

            # Sort members for consistency
            $exportInstance.Members = $exportInstance.Members | Sort-Object
        }

        # Convert entitlements
        if ($ApiData.entitlements)
        {
            $exportInstance.Entitlements = @()
            foreach ($entitlement in $ApiData.entitlements)
            {
                $exportInstance.Entitlements += [GroupEntitlement]@{
                    Value = $entitlement.value
                }
            }

            # Sort entitlements for consistency
            $exportInstance.Entitlements = $exportInstance.Entitlements | Sort-Object
        }

        # Convert roles
        if ($ApiData.roles)
        {
            $exportInstance.Roles = @()
            foreach ($role in $ApiData.roles)
            {
                $exportInstance.Roles += [GroupRole]@{
                    Value = $role.value
                }
            }

            # Sort roles for consistency
            $exportInstance.Roles = $exportInstance.Roles | Sort-Object
        }

        # Convert parent groups (read-only)
        if ($ApiData.groups)
        {
            $exportInstance.Groups = @()
            foreach ($parentGroup in $ApiData.groups)
            {
                $exportInstance.Groups += [ParentGroup]@{
                    Value   = $parentGroup.value
                    Display = $parentGroup.display
                    Ref     = $parentGroup.'$ref'
                }
            }

            # Sort groups for consistency
            $exportInstance.Groups = $exportInstance.Groups | Sort-Object
        }

        # Set _exist to true since we're exporting existing resources
        $exportInstance._exist = $true

        return $exportInstance
    }

    <#
        .SYNOPSIS
            Exports all groups from the Databricks workspace.

        .DESCRIPTION
            This parameterless overload requires using Export([FilteringInstance]) instead.
            Create a DatabricksGroup instance with WorkspaceUrl and AccessToken set, then
            call Export with that instance to retrieve all groups.

        .EXAMPLE
            $instance = [DatabricksGroup]::new()
            $instance.WorkspaceUrl = 'https://adb-123.azuredatabricks.net'
            $instance.AccessToken = $token
            [DatabricksGroup]::Export($instance)

        .OUTPUTS
            [DatabricksGroup[]] Array of DatabricksGroup instances representing all groups in the workspace.
    #>
    static [DatabricksResourceBase[]] Export()
    {
        $errorMessage = 'Export() requires authentication. Create a DatabricksGroup instance with WorkspaceUrl and AccessToken set, then call Export($instance) instead.'

        throw [System.InvalidOperationException]::new($errorMessage)
    }

    <#
        .SYNOPSIS
            Exports groups from the Databricks workspace filtered by the provided instance.

        .PARAMETER FilteringInstance
            A DatabricksGroup instance with WorkspaceUrl and AccessToken set (required).
            Optionally set filter properties (DisplayName, etc.) to filter results.
            If no filter properties are set, all groups are returned.

        .DESCRIPTION
            Retrieves all groups from the workspace and filters them based on properties
            set in the FilteringInstance parameter. This method overrides the base class
            Export([FilteringInstance]) method.

        .EXAMPLE
            # Export all groups
            $instance = [DatabricksGroup]::new()
            $instance.WorkspaceUrl = 'https://adb-123.azuredatabricks.net'
            $instance.AccessToken = $token
            [DatabricksGroup]::Export($instance)

        .EXAMPLE
            # Export filtered groups
            $instance = [DatabricksGroup]::new()
            $instance.WorkspaceUrl = 'https://adb-123.azuredatabricks.net'
            $instance.AccessToken = $token
            $instance.DisplayName = 'data-engineers'
            [DatabricksGroup]::Export($instance)

        .OUTPUTS
            [DatabricksGroup[]] Array of DatabricksGroup instances matching the filter criteria.
    #>
    static [DatabricksResourceBase[]] Export([DatabricksResourceBase] $FilteringInstance)
    {
        $resourceType = $FilteringInstance.GetType().Name

        try
        {
            Write-Verbose -Message (
                $FilteringInstance.localizedData.ExportingResources -f $resourceType
            )

            # Call the virtual method to get all resources
            $apiResources = [DatabricksGroup]::GetAllResourcesFromApi($FilteringInstance)

            if ($null -eq $apiResources -or $apiResources.Count -eq 0)
            {
                Write-Verbose -Message (
                    $FilteringInstance.localizedData.NoResourcesFound -f $resourceType
                )
                return @()
            }

            # Convert each API resource to a resource instance
            [DatabricksResourceBase[]] $allResources = $apiResources.ForEach{
                [DatabricksGroup]::CreateExportInstance($_, $FilteringInstance)
            }

            # Get all properties from the filtering instance that have values
            # Exclude common base properties and DSC framework properties
            $filterProperties = $FilteringInstance.PSObject.Properties.Where{
                $_.Name -notin @('WorkspaceUrl', 'AccessToken', 'Reasons', 'Id', 'Groups', 'localizedData', '_exist', 'ExcludeDscProperties') -and
                -not [string]::IsNullOrEmpty($_.Value)
            }

            # If no filter properties, return all resources
            if ($filterProperties.Count -eq 0)
            {
                Write-Verbose -Message (
                    $FilteringInstance.localizedData.ExportedResourceCount -f $allResources.Count, $resourceType
                )
                return $allResources
            }

            # Apply filtering based on properties set in FilteringInstance
            $result = $allResources.Where{
                $currentResource = $_
                $matches = $true

                # Check if all specified filter properties match
                foreach ($property in $filterProperties)
                {
                    if ($currentResource.PSObject.Properties.Name -contains $property.Name)
                    {
                        if ($currentResource.($property.Name) -ne $property.Value)
                        {
                            $matches = $false
                            break
                        }
                    }
                }

                $matches
            }

            Write-Verbose -Message (
                $FilteringInstance.localizedData.ExportedResourceCount -f $result.Count, $resourceType
            )

            return $result
        }
        catch
        {
            $errorMessage = $FilteringInstance.localizedData.ExportFailed -f @(
                $resourceType,
                $_.Exception.Message
            )

            Write-Verbose -Message $errorMessage
            return @()
        }
    }
}
