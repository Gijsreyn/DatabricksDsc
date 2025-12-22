<#
    .SYNOPSIS
        The `DatabricksSqlWarehouse` DSC resource is used to create, modify, or remove
        SQL warehouses in a Databricks workspace.

    .DESCRIPTION
        The `DatabricksSqlWarehouse` DSC resource is used to create, modify, or remove
        SQL warehouses in a Databricks workspace using the SQL Warehouses API.

        ## Requirements

        * Target machine must have network connectivity to the Databricks workspace.
        * A valid Databricks Personal Access Token (PAT) with permissions to manage SQL warehouses.

        ## Known issues

        All issues are not listed here, see [all open issues](https://github.com/Gijsreyn/DatabricksDsc/issues?q=is%3Aissue+is%3Aopen+in%3Atitle+DatabricksSqlWarehouse).

        ### Using `AccessToken` property

        The `AccessToken` must be provided as a SecureString containing the
        Personal Access Token.

    .PARAMETER Name
        The logical name of the SQL warehouse. This is the unique identifier.
        Must be unique within the workspace and less than 100 characters.

    .PARAMETER ClusterSize
        Size of the clusters allocated for this warehouse. Supported values:
        2X-Small, X-Small, Small, Medium, Large, X-Large, 2X-Large, 3X-Large, 4X-Large.

    .PARAMETER AutoStopMins
        The amount of time in minutes that a SQL warehouse must be idle before it is
        automatically stopped. Must be 0 (no autostop) or >= 10 mins. Defaults to 120.

    .PARAMETER Channel
        Channel Details for the SQL warehouse. Contains Name and DbsqlVersion properties.

    .PARAMETER EnablePhoton
        Configures whether the warehouse should use Photon optimized clusters. Defaults to $false.

    .PARAMETER EnableServerlessCompute
        Configures whether the warehouse should use serverless compute.

    .PARAMETER MaxNumClusters
        Maximum number of clusters that the autoscaler will create to handle concurrent queries.
        Must be >= MinNumClusters and <= 40.

    .PARAMETER MinNumClusters
        Minimum number of available clusters that will be maintained for this SQL warehouse.
        Must be > 0 and <= min(MaxNumClusters, 30). Defaults to 1.

    .PARAMETER SpotInstancePolicy
        Configures whether the endpoint should use spot instances.
        Supported values: POLICY_UNSPECIFIED, COST_OPTIMIZED, RELIABILITY_OPTIMIZED.
        Defaults to COST_OPTIMIZED.

    .PARAMETER Tags
        A set of key-value pairs that will be tagged on all resources associated with this SQL warehouse.
        Number of tags must be less than 45.

    .PARAMETER WarehouseType
        Warehouse type: PRO or CLASSIC. If you want to use serverless compute, you must set
        to PRO and also set EnableServerlessCompute to $true.

    .PARAMETER _exist
        Specifies whether the SQL warehouse should exist in the workspace. Defaults to `$true`.
        Set to `$false` to remove the warehouse.

    .EXAMPLE
        $token = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
        Invoke-DscResource -ModuleName DatabricksDsc -Name DatabricksSqlWarehouse -Method Set -Property @{
            WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
            AccessToken  = $token
            Name         = 'My SQL Warehouse'
            ClusterSize  = 'Small'
            MinNumClusters = 1
            MaxNumClusters = 2
        }

        This example shows how to create a SQL warehouse using Invoke-DscResource.
#>
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
[DscResource(RunAsCredential = 'NotSupported')]
class DatabricksSqlWarehouse : DatabricksResourceBase
{
    [DscProperty(Key)]
    [ValidateLength(1, 100)]
    [System.String]
    $Name

    [DscProperty()]
    [ValidateSet('2X-Small', 'X-Small', 'Small', 'Medium', 'Large', 'X-Large', '2X-Large', '3X-Large', '4X-Large')]
    [System.String]
    $ClusterSize

    [DscProperty()]
    [Nullable[System.Int32]]
    $AutoStopMins

    [DscProperty()]
    [SqlWarehouseChannel]
    $Channel

    [DscProperty()]
    [Nullable[System.Boolean]]
    $EnablePhoton

    [DscProperty()]
    [Nullable[System.Boolean]]
    $EnableServerlessCompute

    [DscProperty()]
    [ValidateRange(1, 40)]
    [Nullable[System.Int32]]
    $MaxNumClusters

    [DscProperty()]
    [ValidateRange(1, 30)]
    [Nullable[System.Int32]]
    $MinNumClusters

    [DscProperty()]
    [ValidateSet('POLICY_UNSPECIFIED', 'COST_OPTIMIZED', 'RELIABILITY_OPTIMIZED')]
    [System.String]
    $SpotInstancePolicy

    [DscProperty()]
    [SqlWarehouseTags]
    $Tags

    [DscProperty()]
    [ValidateSet('TYPE_UNSPECIFIED', 'CLASSIC', 'PRO')]
    [System.String]
    $WarehouseType

    [DscProperty(NotConfigurable)]
    [System.String]
    $WarehouseId

    [DscProperty()]
    [System.Boolean]
    $_exist = $true

    DatabricksSqlWarehouse () : base ()
    {
        # These properties will not be enforced.
        $this.ExcludeDscProperties = @(
            'WorkspaceUrl'
            'Name'
            'AccessToken'
        )
    }

    [DatabricksSqlWarehouse] Get()
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
            $this.localizedData.EvaluatingWarehouseState -f @(
                $properties.Name,
                $this.WorkspaceUrl
            )
        )

        $currentState = @{
            WorkspaceUrl = $this.WorkspaceUrl
            AccessToken  = $this.AccessToken
            Name         = $properties.Name
            _exist       = $false
        }

        try
        {
            # Get all SQL warehouses and filter by name
            $response = $this.InvokeDatabricksApi(
                'GET',
                '/api/2.0/sql/warehouses',
                $null
            )

            $warehouse = $response.warehouses | Where-Object -FilterScript {
                $_.name -eq $properties.Name
            } | Select-Object -First 1

            if ($warehouse)
            {
                $currentState._exist = $true
                $currentState.WarehouseId = $warehouse.id
                $currentState.ClusterSize = $warehouse.cluster_size

                if ($null -ne $warehouse.auto_stop_mins)
                {
                    $currentState.AutoStopMins = $warehouse.auto_stop_mins
                }

                if ($null -ne $warehouse.enable_photon)
                {
                    $currentState.EnablePhoton = $warehouse.enable_photon
                }

                if ($null -ne $warehouse.enable_serverless_compute)
                {
                    $currentState.EnableServerlessCompute = $warehouse.enable_serverless_compute
                }

                if ($null -ne $warehouse.max_num_clusters)
                {
                    $currentState.MaxNumClusters = $warehouse.max_num_clusters
                }

                if ($null -ne $warehouse.min_num_clusters)
                {
                    $currentState.MinNumClusters = $warehouse.min_num_clusters
                }

                if ($warehouse.spot_instance_policy)
                {
                    $currentState.SpotInstancePolicy = $warehouse.spot_instance_policy
                }

                if ($warehouse.warehouse_type)
                {
                    $currentState.WarehouseType = $warehouse.warehouse_type
                }

                # Convert channel
                if ($warehouse.channel)
                {
                    $currentState.Channel = [SqlWarehouseChannel]@{
                        Name        = $warehouse.channel.name
                        DbsqlVersion = $warehouse.channel.dbsql_version
                    }
                }

                # Convert tags
                if ($warehouse.tags -and $warehouse.tags.custom_tags)
                {
                    $customTags = @()

                    foreach ($tag in $warehouse.tags.custom_tags)
                    {
                        $customTags += [SqlWarehouseTag]@{
                            Key   = $tag.key
                            Value = $tag.value
                        }
                    }

                    $currentState.Tags = [SqlWarehouseTags]@{
                        CustomTags = $customTags
                    }
                }
            }
            else
            {
                # When warehouse doesn't exist, set all other properties to $null
                # so they don't get compared (only _exist should matter)
                $currentState.ClusterSize = $null
                $currentState.AutoStopMins = $null
                $currentState.Channel = $null
                $currentState.EnablePhoton = $null
                $currentState.EnableServerlessCompute = $null
                $currentState.MaxNumClusters = $null
                $currentState.MinNumClusters = $null
                $currentState.SpotInstancePolicy = $null
                $currentState.Tags = $null
                $currentState.WarehouseType = $null
                $currentState.WarehouseId = $null

                Write-Verbose -Message (
                    $this.localizedData.WarehouseNotFound -f $properties.Name
                )
            }
        }
        catch
        {
            Write-Verbose -Message (
                $this.localizedData.ErrorGettingWarehouse -f @(
                    $properties.Name,
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
        # Check if _exist property needs to be changed (warehouse should be created or removed)
        if ($properties.ContainsKey('_exist'))
        {
            # Evaluate the desired state for property _exist
            if ($properties._exist -eq $true)
            {
                # Create the warehouse since it doesn't exist
                Write-Verbose -Message (
                    $this.localizedData.CreatingWarehouse -f $this.Name
                )

                $body = $this.BuildWarehousePayload($properties)

                $response = $this.InvokeDatabricksApi(
                    'POST',
                    '/api/2.0/sql/warehouses',
                    $body
                )

                Write-Verbose -Message (
                    $this.localizedData.WarehouseCreated -f $this.Name
                )
            }
            else
            {
                # Remove the warehouse since it exists but shouldn't
                Write-Verbose -Message (
                    $this.localizedData.RemovingWarehouse -f $this.Name
                )

                # Get current warehouse ID if not already set
                if ([System.String]::IsNullOrEmpty($this.WarehouseId))
                {
                    $currentState = $this.GetCurrentState(@{
                        Name = $this.Name
                    })

                    $id = $currentState.WarehouseId
                }
                else
                {
                    $id = $this.WarehouseId
                }

                $this.InvokeDatabricksApi(
                    'DELETE',
                    ('/api/2.0/sql/warehouses/{0}' -f $id),
                    $null
                )

                Write-Verbose -Message (
                    $this.localizedData.WarehouseRemoved -f $this.Name
                )
            }
        }
        else
        {
            # Update existing warehouse
            if ($this._exist -eq $true)
            {
                Write-Verbose -Message (
                    $this.localizedData.UpdatingWarehouse -f $this.Name
                )

                # Get current warehouse ID if not already set
                if ([System.String]::IsNullOrEmpty($this.WarehouseId))
                {
                    $currentState = $this.GetCurrentState(@{
                        Name = $this.Name
                    })

                    $id = $currentState.WarehouseId
                }
                else
                {
                    $id = $this.WarehouseId
                }

                $body = $this.BuildWarehousePayload($properties)

                $this.InvokeDatabricksApi(
                    'POST',
                    ('/api/2.0/sql/warehouses/{0}/edit' -f $id),
                    $body
                )

                Write-Verbose -Message (
                    $this.localizedData.WarehouseUpdated -f $this.Name
                )
            }
        }
    }

    <#
        Helper method to build the warehouse payload for create/update operations.
    #>
    hidden [System.Collections.Hashtable] BuildWarehousePayload([System.Collections.Hashtable] $properties)
    {
        $payload = @{
            name = $this.Name
        }

        # ClusterSize
        if ($properties.ContainsKey('ClusterSize') -and -not [System.String]::IsNullOrEmpty($properties.ClusterSize))
        {
            $payload.cluster_size = $properties.ClusterSize
        }
        elseif (-not [System.String]::IsNullOrEmpty($this.ClusterSize))
        {
            $payload.cluster_size = $this.ClusterSize
        }

        # AutoStopMins
        if ($properties.ContainsKey('AutoStopMins') -and $null -ne $properties.AutoStopMins)
        {
            $payload.auto_stop_mins = $properties.AutoStopMins
        }
        elseif ($null -ne $this.AutoStopMins)
        {
            $payload.auto_stop_mins = $this.AutoStopMins
        }

        # EnablePhoton
        if ($properties.ContainsKey('EnablePhoton') -and $null -ne $properties.EnablePhoton)
        {
            $payload.enable_photon = $properties.EnablePhoton
        }
        elseif ($null -ne $this.EnablePhoton)
        {
            $payload.enable_photon = $this.EnablePhoton
        }

        # EnableServerlessCompute
        if ($properties.ContainsKey('EnableServerlessCompute') -and $null -ne $properties.EnableServerlessCompute)
        {
            $payload.enable_serverless_compute = $properties.EnableServerlessCompute
        }
        elseif ($null -ne $this.EnableServerlessCompute)
        {
            $payload.enable_serverless_compute = $this.EnableServerlessCompute
        }

        # MaxNumClusters
        if ($properties.ContainsKey('MaxNumClusters') -and $null -ne $properties.MaxNumClusters)
        {
            $payload.max_num_clusters = $properties.MaxNumClusters
        }
        elseif ($null -ne $this.MaxNumClusters)
        {
            $payload.max_num_clusters = $this.MaxNumClusters
        }

        # MinNumClusters
        if ($properties.ContainsKey('MinNumClusters') -and $null -ne $properties.MinNumClusters)
        {
            $payload.min_num_clusters = $properties.MinNumClusters
        }
        elseif ($null -ne $this.MinNumClusters)
        {
            $payload.min_num_clusters = $this.MinNumClusters
        }

        # SpotInstancePolicy
        if ($properties.ContainsKey('SpotInstancePolicy') -and -not [System.String]::IsNullOrEmpty($properties.SpotInstancePolicy))
        {
            $payload.spot_instance_policy = $properties.SpotInstancePolicy
        }
        elseif (-not [System.String]::IsNullOrEmpty($this.SpotInstancePolicy))
        {
            $payload.spot_instance_policy = $this.SpotInstancePolicy
        }

        # WarehouseType
        if ($properties.ContainsKey('WarehouseType') -and -not [System.String]::IsNullOrEmpty($properties.WarehouseType))
        {
            $payload.warehouse_type = $properties.WarehouseType
        }
        elseif (-not [System.String]::IsNullOrEmpty($this.WarehouseType))
        {
            $payload.warehouse_type = $this.WarehouseType
        }

        # Channel
        if ($properties.ContainsKey('Channel') -and $null -ne $properties.Channel)
        {
            $payload.channel = $this.ConvertChannelToApiFormat($properties.Channel)
        }
        elseif ($null -ne $this.Channel)
        {
            $payload.channel = $this.ConvertChannelToApiFormat($this.Channel)
        }

        # Tags
        if ($properties.ContainsKey('Tags') -and $null -ne $properties.Tags)
        {
            $payload.tags = $this.ConvertTagsToApiFormat($properties.Tags)
        }
        elseif ($null -ne $this.Tags)
        {
            $payload.tags = $this.ConvertTagsToApiFormat($this.Tags)
        }

        return $payload
    }

    <#
        Helper method to convert SqlWarehouseChannel to API format.
    #>
    hidden [System.Collections.Hashtable] ConvertChannelToApiFormat([SqlWarehouseChannel] $channel)
    {
        $apiChannel = @{}

        if (-not [System.String]::IsNullOrEmpty($channel.Name))
        {
            $apiChannel.name = $channel.Name
        }

        if (-not [System.String]::IsNullOrEmpty($channel.DbsqlVersion))
        {
            $apiChannel.dbsql_version = $channel.DbsqlVersion
        }

        return $apiChannel
    }

    <#
        Helper method to convert SqlWarehouseTags to API format.
    #>
    hidden [System.Collections.Hashtable] ConvertTagsToApiFormat([SqlWarehouseTags] $tags)
    {
        $apiTags = @{
            custom_tags = @()
        }

        if ($null -ne $tags.CustomTags)
        {
            foreach ($tag in $tags.CustomTags)
            {
                $apiTags.custom_tags += @{
                    key   = $tag.Key
                    value = $tag.Value
                }
            }
        }

        return $apiTags
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

        # Validate AutoStopMins (must be 0 or >= 10)
        if ($null -ne $this.AutoStopMins)
        {
            if ($this.AutoStopMins -ne 0 -and $this.AutoStopMins -lt 10)
            {
                $errorMessage = $this.localizedData.InvalidAutoStopMins -f $this.AutoStopMins

                New-ArgumentException -ArgumentName 'AutoStopMins' -Message $errorMessage
            }
        }

        # Validate MaxNumClusters >= MinNumClusters
        if ($null -ne $this.MaxNumClusters -and $null -ne $this.MinNumClusters)
        {
            if ($this.MaxNumClusters -lt $this.MinNumClusters)
            {
                $errorMessage = $this.localizedData.MaxClustersMustBeGreaterOrEqualToMin -f @(
                    $this.MaxNumClusters,
                    $this.MinNumClusters
                )

                New-ArgumentException -ArgumentName 'MaxNumClusters' -Message $errorMessage
            }
        }

        # Validate tags count (max 45)
        if ($null -ne $this.Tags -and $null -ne $this.Tags.CustomTags)
        {
            if ($this.Tags.CustomTags.Count -ge 45)
            {
                $errorMessage = $this.localizedData.TooManyTags -f $this.Tags.CustomTags.Count

                New-ArgumentException -ArgumentName 'Tags' -Message $errorMessage
            }
        }

        # Validate serverless compute requires PRO warehouse type
        if ($null -ne $this.EnableServerlessCompute -and $this.EnableServerlessCompute -eq $true)
        {
            if (-not [System.String]::IsNullOrEmpty($this.WarehouseType) -and $this.WarehouseType -ne 'PRO')
            {
                $errorMessage = $this.localizedData.ServerlessRequiresProWarehouseType

                New-ArgumentException -ArgumentName 'EnableServerlessCompute' -Message $errorMessage
            }
        }
    }

    <#
        .SYNOPSIS
            Exports all SQL warehouses from the Databricks workspace.

        .DESCRIPTION
            The Export() static method retrieves all SQL warehouses from the
            Databricks workspace and returns them as an array of
            DatabricksSqlWarehouse instances.

        .EXAMPLE
            # Export all SQL warehouses
            $instance = [DatabricksSqlWarehouse]::new()
            $instance.WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
            $instance.AccessToken = $token
            [DatabricksSqlWarehouse]::Export($instance)

        .EXAMPLE
            # Export filtered SQL warehouses by WarehouseType
            $instance = [DatabricksSqlWarehouse]::new()
            $instance.WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
            $instance.AccessToken = $token
            $instance.WarehouseType = 'PRO'
            [DatabricksSqlWarehouse]::Export($instance)

        .OUTPUTS
            [DatabricksSqlWarehouse[]] Array of instances matching the filter criteria.
    #>
    static [DatabricksResourceBase[]] Export([DatabricksResourceBase] $FilteringInstance)
    {
        $resourceType = $FilteringInstance.GetType().Name

        try
        {
            Write-Verbose -Message (
                $FilteringInstance.localizedData.ExportingResources -f $resourceType
            )

            # Get all SQL warehouses from the workspace
            $response = $FilteringInstance.InvokeDatabricksApi(
                'GET',
                '/api/2.0/sql/warehouses',
                $null
            )

            if ($null -eq $response -or $null -eq $response.warehouses -or $response.warehouses.Count -eq 0)
            {
                Write-Verbose -Message (
                    $FilteringInstance.localizedData.NoResourcesFound -f $resourceType
                )
                return @()
            }

            # Convert each API warehouse to a resource instance
            [DatabricksResourceBase[]] $allResources = $response.warehouses.ForEach{
                $warehouse = $_

                $exportInstance = [DatabricksSqlWarehouse]::new()
                $exportInstance.WorkspaceUrl = $FilteringInstance.WorkspaceUrl
                $exportInstance.AccessToken = $FilteringInstance.AccessToken
                $exportInstance.Name = $warehouse.name
                $exportInstance.WarehouseId = $warehouse.id

                if (-not [System.String]::IsNullOrEmpty($warehouse.cluster_size))
                {
                    $exportInstance.ClusterSize = $warehouse.cluster_size
                }

                if ($null -ne $warehouse.auto_stop_mins)
                {
                    $exportInstance.AutoStopMins = $warehouse.auto_stop_mins
                }

                if ($null -ne $warehouse.enable_photon)
                {
                    $exportInstance.EnablePhoton = $warehouse.enable_photon
                }

                if ($null -ne $warehouse.enable_serverless_compute)
                {
                    $exportInstance.EnableServerlessCompute = $warehouse.enable_serverless_compute
                }

                if ($null -ne $warehouse.max_num_clusters)
                {
                    $exportInstance.MaxNumClusters = $warehouse.max_num_clusters
                }

                if ($null -ne $warehouse.min_num_clusters)
                {
                    $exportInstance.MinNumClusters = $warehouse.min_num_clusters
                }

                if (-not [System.String]::IsNullOrEmpty($warehouse.spot_instance_policy))
                {
                    $exportInstance.SpotInstancePolicy = $warehouse.spot_instance_policy
                }

                if (-not [System.String]::IsNullOrEmpty($warehouse.warehouse_type))
                {
                    $exportInstance.WarehouseType = $warehouse.warehouse_type
                }

                # Convert channel
                if ($warehouse.channel)
                {
                    $exportInstance.Channel = [SqlWarehouseChannel]@{
                        Name         = $warehouse.channel.name
                        DbsqlVersion = $warehouse.channel.dbsql_version
                    }
                }

                # Convert tags
                if ($warehouse.tags -and $warehouse.tags.custom_tags)
                {
                    $customTags = @()

                    foreach ($tag in $warehouse.tags.custom_tags)
                    {
                        $customTags += [SqlWarehouseTag]@{
                            Key   = $tag.key
                            Value = $tag.value
                        }
                    }

                    $exportInstance.Tags = [SqlWarehouseTags]@{
                        CustomTags = $customTags
                    }
                }

                $exportInstance._exist = $true

                $exportInstance
            }

            # Get all properties from the filtering instance that have values
            # Exclude common base properties and DSC framework properties
            $filterProperties = $FilteringInstance.PSObject.Properties.Where{
                $_.Name -notin @('WorkspaceUrl', 'AccessToken', 'Reasons', 'Name', 'WarehouseId', 'localizedData', '_exist', 'ExcludeDscProperties') -and
                $null -ne $_.Value -and
                -not [string]::IsNullOrEmpty($_.Value)
            }

            # If no filter properties, return all resources
            if ($filterProperties.Count -eq 0)
            {
                Write-Verbose -Message (
                    "Returning all {0} SQL warehouse(s)" -f $allResources.Count
                )
                return $allResources
            }

            # Filter resources based on the properties set in FilteringInstance
            $filteredResources = $allResources.Where{
                $resource = $_
                $matches = $true

                foreach ($property in $filterProperties)
                {
                    $resourceValue = $resource.($property.Name)
                    $filterValue = $property.Value

                    # Handle complex types with Equals method
                    if ($property.Name -eq 'Channel' -and $null -ne $resourceValue -and $null -ne $filterValue)
                    {
                        if (-not $resourceValue.Equals($filterValue))
                        {
                            $matches = $false
                            break
                        }
                    }
                    elseif ($property.Name -eq 'Tags' -and $null -ne $resourceValue -and $null -ne $filterValue)
                    {
                        if (-not $resourceValue.Equals($filterValue))
                        {
                            $matches = $false
                            break
                        }
                    }
                    elseif ($resourceValue -ne $filterValue)
                    {
                        $matches = $false
                        break
                    }
                }

                $matches
            }

            Write-Verbose -Message (
                "Returning {0} filtered SQL warehouse(s)" -f $filteredResources.Count
            )

            return $filteredResources
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
