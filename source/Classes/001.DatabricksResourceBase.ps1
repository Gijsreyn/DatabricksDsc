<#
    .SYNOPSIS
        The DatabricksResourceBase class provides a common base for all Databricks
        DSC resources.

    .DESCRIPTION
        This base class provides common functionality for connecting to and
        interacting with Databricks workspace APIs. All Databricks DSC resources
        should inherit from this class.

    .PARAMETER WorkspaceUrl
        The URL of the Databricks workspace to connect to.
        Example: 'https://adb-1234567890123456.12.azuredatabricks.net'

    .PARAMETER AccessToken
        The Personal Access Token (PAT) used to authenticate with the Databricks workspace.
        This should be provided as a SecureString.

    .PARAMETER Reasons
        Returns the reason a property is not in desired state.
#>
class DatabricksResourceBase : ResourceBase
{
    [DscProperty(Key)]
    [System.String]
    $WorkspaceUrl

    [DscProperty(Mandatory)]
    [System.Security.SecureString]
    $AccessToken

    [DscProperty(NotConfigurable)]
    [DatabricksReason[]]
    $Reasons

    # Passing the module's base directory to the base constructor.
    DatabricksResourceBase () : base ($PSScriptRoot)
    {
    }

    <#
        Makes an API call to the Databricks workspace.

        .PARAMETER Method
            The HTTP method to use (GET, POST, PATCH, DELETE, etc.)

        .PARAMETER ApiPath
            The API path relative to the workspace URL.
            Example: '/api/2.0/preview/scim/v2/Users'

        .PARAMETER Body
            The request body as a hashtable. Will be converted to JSON.

        .RETURNS
            The response from the API call.
    #>
    hidden [System.Object] InvokeDatabricksApi([System.String]$Method, [System.String]$ApiPath, [System.Collections.Hashtable]$Body)
    {
        $uri = '{0}{1}' -f $this.WorkspaceUrl.TrimEnd('/'), $ApiPath

        $headers = @{
            'Authorization' = ConvertTo-DatabricksAuthHeader -AccessToken $this.AccessToken
            'Content-Type'  = 'application/json'
        }

        $invokeParams = @{
            Uri     = $uri
            Method  = $Method
            Headers = $headers
        }

        if ($Body)
        {
            $invokeParams.Body = $Body | ConvertTo-Json -Depth 10 -Compress

            Write-Debug -Message "Request Body: $($invokeParams.Body)"
        }

        try
        {
            Write-Verbose -Message (
                $this.localizedData.InvokingDatabricksApi -f @(
                    $Method,
                    $ApiPath
                )
            )

            Write-Debug -Message "Full URI: $uri"
            Write-Debug -Message "Method: $Method"

            $response = Invoke-RestMethod @invokeParams

            Write-Debug -Message "Response: $($response | ConvertTo-Json -Depth 5 -Compress)"

            return $response
        }
        catch
        {
            Write-Debug -Message "Error Details: $($_.Exception | Format-List * -Force | Out-String)"
            Write-Debug -Message "Error Response: $($_.ErrorDetails.Message)"

            $errorMessage = $this.localizedData.FailedToInvokeDatabricksApi -f @(
                $Method,
                $ApiPath,
                $_.Exception.Message
            )

            New-InvalidOperationException -Message $errorMessage -ErrorRecord $_

            # This line should never be reached, but satisfies the compiler
            return $null
        }
    }

    <#
        Virtual method for child classes to override and retrieve all resources from Databricks.

        .PARAMETER Instance
            An instance of the resource with WorkspaceUrl and AccessToken populated.

        .RETURNS
            Array of PSObjects representing the raw API response data.

        .NOTES
            Child classes must override this method to implement export functionality.
            Return empty array if no resources found.
            Throw exceptions for API errors - they will be caught by Export().
    #>
    static [PSObject[]] GetAllResourcesFromApi([DatabricksResourceBase] $Instance)
    {
        $resourceType = $Instance.GetType().Name
        $errorMessage = $Instance.localizedData.ExportNotImplemented -f $resourceType

        Write-Warning -Message $errorMessage
        return @()
    }

    <#
        Virtual method for child classes to override and convert API data to resource instances.

        .PARAMETER ApiData
            A PSCustomObject containing the raw API response data for a single resource.

        .PARAMETER Instance
            An instance of the resource with WorkspaceUrl and AccessToken populated.

        .RETURNS
            A resource instance populated with data from the API.

        .NOTES
            Child classes must override this method to implement export functionality.
            The returned instance should have all relevant properties populated.
    #>
    static [DatabricksResourceBase] CreateExportInstance([PSObject] $ApiData, [DatabricksResourceBase] $Instance)
    {
        $resourceType = $Instance.GetType().Name
        $errorMessage = $Instance.localizedData.ExportNotImplemented -f $resourceType

        Write-Warning -Message $errorMessage
        return $null
    }

    <#
        Exports all resources of this type from the Databricks workspace.

        .RETURNS
            Array of resource instances representing all resources in the workspace.

        .NOTES
            Child classes must override GetAllResourcesFromApi() and CreateExportInstance()
            for this method to function properly.
    #>
    static [DatabricksResourceBase[]] Export()
    {
        # Create a temporary instance to access instance methods and localization
        $tempInstance = [DatabricksResourceBase]::new()
        $resourceType = $tempInstance.GetType().Name

        try
        {
            Write-Verbose -Message (
                $tempInstance.localizedData.ExportingResources -f $resourceType
            )

            # Call virtual method to get all resources
            $apiResources = [DatabricksResourceBase]::GetAllResourcesFromApi($tempInstance)

            if ($null -eq $apiResources -or $apiResources.Count -eq 0)
            {
                Write-Verbose -Message (
                    $tempInstance.localizedData.NoResourcesFound -f $resourceType
                )
                return @()
            }

            # Convert each API resource to a resource instance
            [DatabricksResourceBase[]] $result = $apiResources.ForEach{
                [DatabricksResourceBase]::CreateExportInstance($_, $tempInstance)
            }

            Write-Verbose -Message (
                $tempInstance.localizedData.ExportedResourceCount -f $result.Count, $resourceType
            )

            return $result
        }
        catch
        {
            $errorMessage = $tempInstance.localizedData.ExportFailed -f @(
                $resourceType,
                $_.Exception.Message
            )

            Write-Verbose -Message $errorMessage
            return @()
        }
    }

    <#
        Exports resources from the Databricks workspace filtered by the provided instance.

        .PARAMETER FilteringInstance
            A resource instance with properties set to filter the export.
            Only resources matching the filtering criteria will be returned.

        .RETURNS
            Array of resource instances matching the filter criteria.

        .NOTES
            Child classes must override GetAllResourcesFromApi() and CreateExportInstance()
            for this method to function properly. The filtering logic should be implemented
            in the child class's override.
    #>
    static [DatabricksResourceBase[]] Export([DatabricksResourceBase] $FilteringInstance)
    {
        # Validate required authentication properties
        if ([string]::IsNullOrEmpty($FilteringInstance.WorkspaceUrl))
        {
            throw [System.ArgumentException]::new('WorkspaceUrl is required for Export. Set the WorkspaceUrl property on the instance before calling Export.')
        }

        if ($null -eq $FilteringInstance.AccessToken)
        {
            throw [System.ArgumentException]::new('AccessToken is required for Export. Set the AccessToken property on the instance before calling Export.')
        }

        $resourceType = $FilteringInstance.GetType().Name

        try
        {
            Write-Verbose -Message (
                $FilteringInstance.localizedData.ExportingResourcesFiltered -f $resourceType
            )

            # Call virtual method to get all resources
            $apiResources = [DatabricksResourceBase]::GetAllResourcesFromApi($FilteringInstance)

            if ($null -eq $apiResources -or $apiResources.Count -eq 0)
            {
                Write-Verbose -Message (
                    $FilteringInstance.localizedData.NoResourcesFound -f $resourceType
                )
                return @()
            }

            # Convert and filter resources
            [DatabricksResourceBase[]] $allResources = $apiResources.ForEach{
                [DatabricksResourceBase]::CreateExportInstance($_, $FilteringInstance)
            }

            # Apply filtering based on properties set in FilteringInstance
            # This implements the pattern from ChocolateyPackage reference
            $result = $allResources.Where{
                $currentResource = $_
                $matches = $true

                # Get all properties from the filtering instance that have values
                # Exclude common base properties and DSC framework properties
                $filterProperties = $FilteringInstance.PSObject.Properties.Where{
                    $_.Name -notin @('AccountHost', 'WorkspaceHost', 'AccessToken', 'Reasons', 'Ensure', 'localizedData') -and
                    -not [string]::IsNullOrEmpty($_.Value)
                }

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
