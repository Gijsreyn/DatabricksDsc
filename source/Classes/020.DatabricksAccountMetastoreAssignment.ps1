<#
    .SYNOPSIS
        The `DatabricksAccountMetastoreAssignment` DSC resource manages the assignment
        of a Unity Catalog metastore to a Databricks workspace.

    .DESCRIPTION
        The `DatabricksAccountMetastoreAssignment` DSC resource is used to assign or
        unassign a Unity Catalog metastore to/from a specific Databricks workspace at
        the account level.

        This resource manages workspace-to-metastore assignments, which is a prerequisite
        for using Unity Catalog features within a workspace.

        ## Requirements

        * Target machine must have network connectivity to the Databricks account console.
        * A valid Databricks Account API token with account admin privileges.
        * The metastore must already exist before assignment.
        * The workspace must already exist before assignment.

        ## Known issues

        All issues are not listed here, see [all open issues](https://github.com/Gijsreyn/DatabricksDsc/issues?q=is%3Aissue+is%3Aopen+in%3Atitle+DatabricksAccountMetastoreAssignment).

        ### Using `AccessToken` property

        The `AccessToken` must be provided as a SecureString containing the
        Account API token with appropriate permissions.

    .PARAMETER AccountId
        The Databricks account ID (UUID format). This identifies the target account.

    .PARAMETER WorkspaceId
        The Databricks workspace ID (integer). This identifies the workspace to assign
        the metastore to.

    .PARAMETER MetastoreId
        The Unity Catalog metastore ID (UUID format). This identifies the metastore
        to assign to the workspace.

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
        DatabricksAccountMetastoreAssignment MetastoreAssignmentExample
        {
            AccountId    = '12345678-1234-1234-1234-123456789012'
            WorkspaceId  = '1234567890123456'
            MetastoreId  = '87654321-4321-4321-4321-210987654321'
            AccessToken  = $accessToken
        }

        Assigns the specified metastore to the workspace.

    .EXAMPLE
        DatabricksAccountMetastoreAssignment RemoveMetastoreAssignment
        {
            AccountId    = '12345678-1234-1234-1234-123456789012'
            WorkspaceId  = '1234567890123456'
            MetastoreId  = '87654321-4321-4321-4321-210987654321'
            AccessToken  = $accessToken
            _exist       = $false
        }

        Removes the metastore assignment from the workspace.
#>

[DscResource()]
class DatabricksAccountMetastoreAssignment : DatabricksAccountResourceBase
{
    [DscProperty(Key)]
    [System.String]
    $AccountId

    [DscProperty(Key)]
    [System.String]
    $WorkspaceId

    [DscProperty(Key)]
    [System.String]
    $MetastoreId

    [DscProperty()]
    [System.Boolean]
    $_exist = $true

    DatabricksAccountMetastoreAssignment() : base ()
    {
        $this.ExcludeDscProperties = @(
            'AccountsUrl'
            'WorkspaceUrl'
            'AccountId'
            'WorkspaceId'
            'MetastoreId'
            'AccessToken'
        )
    }

    [DatabricksAccountMetastoreAssignment] Get()
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
            $this.localizedData.EvaluatingMetastoreAssignment -f @(
                $properties.WorkspaceId,
                $properties.MetastoreId,
                $properties.AccountId
            )
        )

        $currentState = @{
            WorkspaceUrl = $this.WorkspaceUrl
            AccountId    = $properties.AccountId
            WorkspaceId  = $properties.WorkspaceId
            MetastoreId  = $properties.MetastoreId
            _exist       = $false
        }

        try
        {
            # Try to get the current metastore assignment for the workspace
            $response = $this.InvokeDatabricksApi(
                'GET',
                "/api/2.0/accounts/$($properties.AccountId)/workspaces/$($properties.WorkspaceId)/metastore",
                $null
            )

            if ($response -and $response.metastore_assignment -and $response.metastore_assignment.metastore_id)
            {
                # Check if the assigned metastore matches the desired one
                if ($response.metastore_assignment.metastore_id -eq $properties.MetastoreId)
                {
                    $currentState._exist = $true

                    Write-Verbose -Message (
                        $this.localizedData.MetastoreAssignmentFound -f @(
                            $properties.MetastoreId,
                            $properties.WorkspaceId
                        )
                    )
                }
                else
                {
                    Write-Verbose -Message (
                        $this.localizedData.DifferentMetastoreAssigned -f @(
                            $response.metastore_assignment.metastore_id,
                            $properties.WorkspaceId,
                            $properties.MetastoreId
                        )
                    )
                }
            }
            else
            {
                Write-Verbose -Message (
                    $this.localizedData.NoMetastoreAssigned -f $properties.WorkspaceId
                )
            }
        }
        catch
        {
            # If we get a 404 or similar, no metastore is assigned
            Write-Verbose -Message (
                $this.localizedData.ErrorGettingMetastoreAssignment -f @(
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
        # Check if _exist property needs to be changed (assignment should be created or removed)
        if ($properties.ContainsKey('_exist'))
        {
            # Evaluate the desired state for property _exist
            if ($properties._exist -eq $true)
            {
                # Create/Update the metastore assignment
                Write-Verbose -Message (
                    $this.localizedData.AssigningMetastore -f @(
                        $this.MetastoreId,
                        $this.WorkspaceId
                    )
                )

                $body = @{
                    metastore_id = $this.MetastoreId
                }

                try
                {
                    # Use POST for both create and update (upsert operation)
                    $this.InvokeDatabricksApi(
                        'POST',
                        "/api/2.0/accounts/$($this.AccountId)/workspaces/$($this.WorkspaceId)/metastores/$($this.MetastoreId)",
                        $body
                    )

                    Write-Verbose -Message (
                        $this.localizedData.MetastoreAssigned -f @(
                            $this.MetastoreId,
                            $this.WorkspaceId
                        )
                    )
                }
                catch
                {
                    $errorMessage = $this.localizedData.FailedToAssignMetastore -f @(
                        $this.MetastoreId,
                        $this.WorkspaceId,
                        $_.Exception.Message
                    )

                    New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
                }
            }
            else
            {
                # Remove the metastore assignment
                Write-Verbose -Message (
                    $this.localizedData.UnassigningMetastore -f @(
                        $this.MetastoreId,
                        $this.WorkspaceId
                    )
                )

                try
                {
                    $this.InvokeDatabricksApi(
                        'DELETE',
                        "/api/2.0/accounts/$($this.AccountId)/workspaces/$($this.WorkspaceId)/metastores/$($this.MetastoreId)",
                        $null
                    )

                    Write-Verbose -Message (
                        $this.localizedData.MetastoreUnassigned -f @(
                            $this.MetastoreId,
                            $this.WorkspaceId
                        )
                    )
                }
                catch
                {
                    $errorMessage = $this.localizedData.FailedToUnassignMetastore -f @(
                        $this.MetastoreId,
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

        # Validate MetastoreId format (must be a GUID)
        if ($properties.MetastoreId -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')
        {
            $errorMessage = $this.localizedData.InvalidMetastoreId -f $properties.MetastoreId

            New-ArgumentException -ArgumentName 'MetastoreId' -Message $errorMessage
        }
    }

    <#
        Retrieves all workspace assignments for a metastore from the Databricks account API.

        .PARAMETER Instance
            An instance of DatabricksAccountMetastoreAssignment with AccountsUrl, AccessToken,
            AccountId, and MetastoreId populated.

        .RETURNS
            Array of PSCustomObjects representing workspace assignment data from the API.
    #>
    static [PSObject[]] GetAllResourcesFromApi([DatabricksResourceBase] $Instance)
    {
        $typedInstance = [DatabricksAccountMetastoreAssignment] $Instance

        try
        {
            # Call the account API to get all workspace assignments for the metastore
            $response = $Instance.InvokeDatabricksApi(
                'GET',
                "/api/2.0/accounts/$($typedInstance.AccountId)/metastores/$($typedInstance.MetastoreId)/workspaces",
                $null
            )

            # Return the workspace_ids array from the response
            if ($response -and $response.workspace_ids)
            {
                # Convert workspace IDs to objects for processing
                return $response.workspace_ids.ForEach{ @{ workspace_id = $_ } }
            }
            else
            {
                return @()
            }
        }
        catch
        {
            Write-Verbose -Message (
                'Failed to retrieve metastore workspace assignments from Databricks account: {0}' -f $_.Exception.Message
            )
            throw
        }
    }

    <#
        Converts API workspace assignment data to a DatabricksAccountMetastoreAssignment instance.

        .PARAMETER ApiData
            A PSCustomObject containing workspace assignment data from the API.

        .PARAMETER Instance
            An instance of DatabricksAccountMetastoreAssignment with AccountsUrl, AccessToken,
            AccountId, and MetastoreId populated.

        .RETURNS
            A DatabricksAccountMetastoreAssignment instance populated with data from the API.
    #>
    static [DatabricksResourceBase] CreateExportInstance([PSObject] $ApiData, [DatabricksResourceBase] $Instance)
    {
        $typedInstance = [DatabricksAccountMetastoreAssignment] $Instance
        $exportInstance = [DatabricksAccountMetastoreAssignment]::new()

        # Copy authentication properties
        $exportInstance.WorkspaceUrl = $Instance.WorkspaceUrl
        $exportInstance.AccessToken = $Instance.AccessToken

        # Populate key properties
        $exportInstance.AccountId = $typedInstance.AccountId
        $exportInstance.MetastoreId = $typedInstance.MetastoreId

        # ApiData.workspace_id is already an integer from the API
        if ($ApiData.workspace_id -is [System.Int64] -or $ApiData.workspace_id -is [System.Int32])
        {
            $exportInstance.WorkspaceId = $ApiData.workspace_id.ToString()
        }
        else
        {
            $exportInstance.WorkspaceId = $ApiData.workspace_id
        }

        # Set _exist to true since we're exporting existing assignments
        $exportInstance._exist = $true

        return $exportInstance
    }

    <#
        .SYNOPSIS
            Exports all workspace assignments for a metastore from the Databricks account.

        .DESCRIPTION
            This parameterless overload requires using Export([FilteringInstance]) instead.
            Create a DatabricksAccountMetastoreAssignment instance with AccountsUrl, AccessToken,
            AccountId, and MetastoreId set, then call Export with that instance to retrieve
            all workspace assignments.

        .EXAMPLE
            $instance = [DatabricksAccountMetastoreAssignment]::new()
            $instance.AccessToken = $token
            $instance.AccountId = '12345678-1234-1234-1234-123456789012'
            $instance.MetastoreId = '87654321-4321-4321-4321-210987654321'
            [DatabricksAccountMetastoreAssignment]::Export($instance)

        .OUTPUTS
            [DatabricksAccountMetastoreAssignment[]] Array of DatabricksAccountMetastoreAssignment
            instances representing all workspace assignments for the metastore.
    #>
    static [DatabricksResourceBase[]] Export()
    {
        $errorMessage = 'Export() requires authentication and key properties. Create a DatabricksAccountMetastoreAssignment instance with AccessToken, AccountId, and MetastoreId set, then call Export($instance) instead.'

        throw [System.InvalidOperationException]::new($errorMessage)
    }

    <#
        .SYNOPSIS
            Exports workspace assignments for a metastore filtered by the provided instance.

        .PARAMETER FilteringInstance
            A DatabricksAccountMetastoreAssignment instance with AccessToken, AccountId,
            and MetastoreId set (required). Optionally set WorkspaceId to filter results.
            If WorkspaceId is not set, all workspace assignments for the metastore are returned.

        .DESCRIPTION
            Retrieves all workspace assignments for the specified metastore and filters them
            based on properties set in the FilteringInstance parameter. This method overrides
            the base class Export([FilteringInstance]) method.

        .EXAMPLE
            # Export all workspace assignments for a metastore
            $instance = [DatabricksAccountMetastoreAssignment]::new()
            $instance.AccessToken = $token
            $instance.AccountId = '12345678-1234-1234-1234-123456789012'
            $instance.MetastoreId = '87654321-4321-4321-4321-210987654321'
            [DatabricksAccountMetastoreAssignment]::Export($instance)

        .EXAMPLE
            # Export specific workspace assignment
            $instance = [DatabricksAccountMetastoreAssignment]::new()
            $instance.AccessToken = $token
            $instance.AccountId = '12345678-1234-1234-1234-123456789012'
            $instance.MetastoreId = '87654321-4321-4321-4321-210987654321'
            $instance.WorkspaceId = '1234567890123456'
            [DatabricksAccountMetastoreAssignment]::Export($instance)

        .OUTPUTS
            [DatabricksAccountMetastoreAssignment[]] Array of DatabricksAccountMetastoreAssignment
            instances matching the filter criteria.
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
            $apiResources = [DatabricksAccountMetastoreAssignment]::GetAllResourcesFromApi($FilteringInstance)

            if ($null -eq $apiResources -or $apiResources.Count -eq 0)
            {
                Write-Verbose -Message (
                    $FilteringInstance.localizedData.NoResourcesFound -f $resourceType
                )
                return @()
            }

            # Convert each API resource to a resource instance
            [DatabricksResourceBase[]] $allResources = $apiResources.ForEach{
                [DatabricksAccountMetastoreAssignment]::CreateExportInstance($_, $FilteringInstance)
            }

            # Get all properties from the filtering instance that have values
            # Exclude common base properties and DSC framework properties
            $typedInstance = [DatabricksAccountMetastoreAssignment] $FilteringInstance
            $filterProperties = $FilteringInstance.PSObject.Properties.Where{
                $_.Name -notin @('WorkspaceUrl', 'AccountsUrl', 'AccessToken', 'Reasons', 'localizedData', '_exist', 'ExcludeDscProperties', 'AccountId', 'MetastoreId') -and
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
