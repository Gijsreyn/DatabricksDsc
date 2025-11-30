<#
    .SYNOPSIS
        The `DatabricksSecretScope` DSC resource is used to create, modify, or remove
        secret scopes in a Databricks workspace.

    .DESCRIPTION
        The `DatabricksSecretScope` DSC resource is used to create, modify, or remove
        secret scopes in a Databricks workspace using the Secrets API.

        A secret scope is a collection of secrets identified by a scope name. Databricks
        supports two types of secret scopes: Databricks-backed scopes and Azure Key Vault-backed scopes.

        ## Requirements

        * Target machine must have network connectivity to the Databricks workspace.
        * A valid Databricks Personal Access Token (PAT) with appropriate privileges.
        * For Azure Key Vault-backed scopes, the workspace must have proper access to the Key Vault.

        ## Known issues

        All issues are not listed here, see [all open issues](https://github.com/Gijsreyn/DatabricksDsc/issues?q=is%3Aissue+is%3Aopen+in%3Atitle+DatabricksSecretScope).

        ### Using `AccessToken` property

        The `AccessToken` must be provided as a SecureString containing the
        Personal Access Token.

        ### Limitations

        * Secret scopes cannot be updated once created. If properties need to change, the scope must be deleted and recreated.
        * The scope name must consist of alphanumeric characters, dashes, underscores, and periods, and may not exceed 128 characters.

    .PARAMETER ScopeName
        The name of the secret scope. This is the unique identifier.
        Must consist of alphanumeric characters, dashes, underscores, and periods, and may not exceed 128 characters.

    .PARAMETER ScopeBackendType
        The type of secret scope backend. Valid values are 'DATABRICKS' or 'AZURE_KEYVAULT'.
        If set to 'DATABRICKS', an empty secret scope is created in Databricks-managed storage.
        If set to 'AZURE_KEYVAULT', a secret scope is created with secrets from the specified Azure Key Vault.

    .PARAMETER InitialManagePrincipal
        The principal (user or group) that will have MANAGE permissions on the scope.
        The only supported value is 'users', which contains all users in the workspace.
        If not specified, MANAGE permission is assigned to the API request issuer's user identity.

    .PARAMETER BackendAzureKeyVault
        The Azure Key Vault backend configuration. Required when ScopeBackendType is 'AZURE_KEYVAULT'.
        This is an AzureKeyVaultBackend object containing DnsName and ResourceId properties.

    .PARAMETER _exist
        Specifies whether the secret scope should exist in the workspace. Defaults to `$true`.
        Set to `$false` to remove the scope.

    .EXAMPLE
        $token = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
        Invoke-DscResource -ModuleName DatabricksDsc -Name DatabricksSecretScope -Method Set -Property @{
            WorkspaceUrl         = 'https://adb-1234567890123456.12.azuredatabricks.net'
            AccessToken          = $token
            ScopeName            = 'my-databricks-scope'
            ScopeBackendType     = 'DATABRICKS'
            InitialManagePrincipal = 'users'
        }

        This example shows how to create a Databricks-backed secret scope using Invoke-DscResource.

    .EXAMPLE
        $token = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
        $backend = [AzureKeyVaultBackend] @{
            DnsName    = 'https://myvault.vault.azure.net/'
            ResourceId = '/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/myRg/providers/Microsoft.KeyVault/vaults/myVault'
        }
        Invoke-DscResource -ModuleName DatabricksDsc -Name DatabricksSecretScope -Method Set -Property @{
            WorkspaceUrl           = 'https://adb-1234567890123456.12.azuredatabricks.net'
            AccessToken            = $token
            ScopeName              = 'my-akv-scope'
            ScopeBackendType       = 'AZURE_KEYVAULT'
            BackendAzureKeyVault   = $backend
        }

        This example shows how to create an Azure Key Vault-backed secret scope using Invoke-DscResource.
#>
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
[DscResource(RunAsCredential = 'NotSupported')]
class DatabricksSecretScope : DatabricksResourceBase
{
    [DscProperty(Key)]
    [ValidateLength(1, 128)]
    [ValidatePattern('^[a-zA-Z0-9_.-]+$')]
    [System.String]
    $ScopeName

    [DscProperty(Mandatory)]
    [ValidateSet('DATABRICKS', 'AZURE_KEYVAULT')]
    [System.String]
    $ScopeBackendType

    [DscProperty()]
    [System.String]
    $InitialManagePrincipal

    [DscProperty()]
    [AzureKeyVaultBackend]
    $BackendAzureKeyVault

    [DscProperty()]
    [System.Boolean]
    $_exist = $true

    DatabricksSecretScope () : base ()
    {
        # These properties will not be enforced.
        $this.ExcludeDscProperties = @(
            'WorkspaceUrl'
            'ScopeName'
            'AccessToken'
        )
    }

    [DatabricksSecretScope] Get()
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
            $this.localizedData.EvaluatingSecretScopeState -f @(
                $properties.ScopeName,
                $this.WorkspaceUrl
            )
        )

        $currentState = @{
            WorkspaceUrl = $this.WorkspaceUrl
            AccessToken  = $this.AccessToken
            ScopeName    = $properties.ScopeName
            _exist       = $false
        }

        try
        {
            $scope = Get-DatabricksSecretScope -WorkspaceUrl $this.WorkspaceUrl -AccessToken $this.AccessToken -ScopeName $properties.ScopeName

            if ($scope)
            {
                $currentState._exist = $true

                # Map backend_type to ScopeBackendType
                if ($scope.backend_type -eq 'DATABRICKS')
                {
                    $currentState.ScopeBackendType = 'DATABRICKS'
                }
                elseif ($scope.backend_type -eq 'AZURE_KEYVAULT')
                {
                    $currentState.ScopeBackendType = 'AZURE_KEYVAULT'

                    # Parse Azure Key Vault metadata if available
                    if ($scope.keyvault_metadata)
                    {
                        $currentState.BackendAzureKeyVault = [AzureKeyVaultBackend] @{
                            ResourceId = $scope.keyvault_metadata.resource_id
                            DnsName    = $scope.keyvault_metadata.dns_name
                        }
                    }
                }

                # Note: InitialManagePrincipal is only used during creation and cannot be retrieved
                # Setting it to null so it won't be compared
                $currentState.InitialManagePrincipal = $null
            }
            else
            {
                # When scope doesn't exist, set all other properties to $null
                # so they don't get compared (only _exist should matter)
                $currentState.ScopeBackendType = $null
                $currentState.InitialManagePrincipal = $null
                $currentState.BackendAzureKeyVault = $null

                Write-Verbose -Message (
                    $this.localizedData.SecretScopeNotFound -f $properties.ScopeName
                )
            }
        }
        catch
        {
            Write-Verbose -Message (
                $this.localizedData.ErrorGettingSecretScope -f @(
                    $properties.ScopeName,
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
        # Check if _exist property needs to be changed (scope should be created or removed)
        if ($properties.ContainsKey('_exist'))
        {
            # Evaluate the desired state for property _exist
            if ($properties._exist -eq $true)
            {
                # Create the scope since it doesn't exist
                Write-Verbose -Message (
                    $this.localizedData.CreatingSecretScope -f $this.ScopeName
                )

                $createParams = @{
                    WorkspaceUrl       = $this.WorkspaceUrl
                    AccessToken        = $this.AccessToken
                    ScopeName          = $this.ScopeName
                    ScopeBackendType   = $this.ScopeBackendType
                }

                if (-not [System.String]::IsNullOrEmpty($this.InitialManagePrincipal))
                {
                    $createParams.InitialManagePrincipal = $this.InitialManagePrincipal
                }

                if ($this.ScopeBackendType -eq 'AZURE_KEYVAULT' -and $null -ne $this.BackendAzureKeyVault)
                {
                    $createParams.BackendAzureKeyVault = @{
                        ResourceId = $this.BackendAzureKeyVault.ResourceId
                        DnsName    = $this.BackendAzureKeyVault.DnsName
                    }
                }

                New-DatabricksSecretScope @createParams

                Write-Verbose -Message (
                    $this.localizedData.SecretScopeCreated -f $this.ScopeName
                )
            }
            else
            {
                # Remove the scope since it exists but shouldn't
                Write-Verbose -Message (
                    $this.localizedData.RemovingSecretScope -f $this.ScopeName
                )

                Remove-DatabricksSecretScope -WorkspaceUrl $this.WorkspaceUrl -AccessToken $this.AccessToken -ScopeName $this.ScopeName

                Write-Verbose -Message (
                    $this.localizedData.SecretScopeRemoved -f $this.ScopeName
                )
            }
        }
        else
        {
            # Secret scopes cannot be updated - they must be deleted and recreated
            if ($this._exist -eq $true)
            {
                Write-Verbose -Message (
                    $this.localizedData.SecretScopeCannotBeUpdated -f $this.ScopeName
                )

                # Remove existing scope
                Write-Verbose -Message (
                    $this.localizedData.RemovingSecretScope -f $this.ScopeName
                )

                Remove-DatabricksSecretScope -WorkspaceUrl $this.WorkspaceUrl -AccessToken $this.AccessToken -ScopeName $this.ScopeName

                Write-Verbose -Message (
                    $this.localizedData.SecretScopeRemoved -f $this.ScopeName
                )

                # Recreate with new properties
                Write-Verbose -Message (
                    $this.localizedData.CreatingSecretScope -f $this.ScopeName
                )

                $createParams = @{
                    WorkspaceUrl       = $this.WorkspaceUrl
                    AccessToken        = $this.AccessToken
                    ScopeName          = $this.ScopeName
                    ScopeBackendType   = $this.ScopeBackendType
                }

                if (-not [System.String]::IsNullOrEmpty($this.InitialManagePrincipal))
                {
                    $createParams.InitialManagePrincipal = $this.InitialManagePrincipal
                }

                if ($this.ScopeBackendType -eq 'AZURE_KEYVAULT' -and $null -ne $this.BackendAzureKeyVault)
                {
                    $createParams.BackendAzureKeyVault = @{
                        ResourceId = $this.BackendAzureKeyVault.ResourceId
                        DnsName    = $this.BackendAzureKeyVault.DnsName
                    }
                }

                New-DatabricksSecretScope @createParams

                Write-Verbose -Message (
                    $this.localizedData.SecretScopeCreated -f $this.ScopeName
                )
            }
        }
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

        # Validate that BackendAzureKeyVault is provided when ScopeBackendType is AZURE_KEYVAULT
        if ($this.ScopeBackendType -eq 'AZURE_KEYVAULT' -and $null -eq $this.BackendAzureKeyVault)
        {
            $errorMessage = $this.localizedData.AzureKeyVaultBackendRequired

            New-ArgumentException -ArgumentName 'BackendAzureKeyVault' -Message $errorMessage
        }

        # Validate scope name pattern (alphanumeric, dashes, underscores, periods only)
        if ($this.ScopeName -notmatch '^[a-zA-Z0-9_.-]+$')
        {
            $errorMessage = $this.localizedData.InvalidScopeName -f $this.ScopeName

            New-ArgumentException -ArgumentName 'ScopeName' -Message $errorMessage
        }
    }

    <#
        .SYNOPSIS
            Exports all secret scopes from the Databricks workspace.

        .DESCRIPTION
            The Export() static method retrieves all secret scopes from the
            Databricks workspace and returns them as an array of
            DatabricksSecretScope instances.

        .EXAMPLE
            # Export all secret scopes
            $instance = [DatabricksSecretScope]::new()
            $instance.WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
            $instance.AccessToken = $token
            [DatabricksSecretScope]::Export($instance)

        .EXAMPLE
            # Export filtered secret scopes
            $instance = [DatabricksSecretScope]::new()
            $instance.WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
            $instance.AccessToken = $token
            $instance.ScopeBackendType = 'DATABRICKS'
            [DatabricksSecretScope]::Export($instance)

        .OUTPUTS
            [DatabricksSecretScope[]] Array of instances matching the filter criteria.
    #>
    static [DatabricksResourceBase[]] Export([DatabricksResourceBase] $FilteringInstance)
    {
        $resourceType = $FilteringInstance.GetType().Name

        try
        {
            Write-Verbose -Message (
                $FilteringInstance.localizedData.ExportingResources -f $resourceType
            )

            # Get all secret scopes from the workspace
            $response = Get-DatabricksSecretScope -WorkspaceUrl $FilteringInstance.WorkspaceUrl -AccessToken $FilteringInstance.AccessToken

            if ($null -eq $response -or $null -eq $response.scopes -or $response.scopes.Count -eq 0)
            {
                Write-Verbose -Message (
                    $FilteringInstance.localizedData.NoResourcesFound -f $resourceType
                )
                return @()
            }

            # Convert each API scope to a resource instance
            [DatabricksResourceBase[]] $allResources = $response.scopes.ForEach{
                $scope = $_

                $exportInstance = [DatabricksSecretScope]::new()
                $exportInstance.WorkspaceUrl = $FilteringInstance.WorkspaceUrl
                $exportInstance.AccessToken = $FilteringInstance.AccessToken
                $exportInstance.ScopeName = $scope.name

                # Map backend_type to ScopeBackendType
                if ($scope.backend_type -eq 'DATABRICKS')
                {
                    $exportInstance.ScopeBackendType = 'DATABRICKS'
                }
                elseif ($scope.backend_type -eq 'AZURE_KEYVAULT')
                {
                    $exportInstance.ScopeBackendType = 'AZURE_KEYVAULT'

                    # Parse Azure Key Vault metadata if available
                    if ($scope.keyvault_metadata)
                    {
                        $exportInstance.BackendAzureKeyVault = [AzureKeyVaultBackend] @{
                            ResourceId = $scope.keyvault_metadata.resource_id
                            DnsName    = $scope.keyvault_metadata.dns_name
                        }
                    }
                }

                $exportInstance._exist = $true

                $exportInstance
            }

            # Get all properties from the filtering instance that have values
            # Exclude common base properties and DSC framework properties
            $filterProperties = $FilteringInstance.PSObject.Properties.Where{
                $_.Name -notin @('WorkspaceUrl', 'AccessToken', 'Reasons', 'ScopeName', 'InitialManagePrincipal', 'localizedData', '_exist', 'ExcludeDscProperties') -and
                -not [string]::IsNullOrEmpty($_.Value)
            }

            # If no filter properties, return all resources
            if ($filterProperties.Count -eq 0)
            {
                Write-Verbose -Message (
                    "Returning all {0} secret scope(s)" -f $allResources.Count
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

                    # Handle AzureKeyVaultBackend complex type
                    if ($property.Name -eq 'BackendAzureKeyVault' -and $null -ne $resourceValue -and $null -ne $filterValue)
                    {
                        # Compare using Equals method
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
                "Returning {0} filtered secret scope(s)" -f $filteredResources.Count
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
