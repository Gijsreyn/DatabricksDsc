<#
    .SYNOPSIS
        Creates a new Databricks secret scope in a workspace.

    .DESCRIPTION
        The New-DatabricksSecretScope function creates a new secret scope in a
        Databricks workspace using the Secrets API.

    .PARAMETER WorkspaceUrl
        The URL of the Databricks workspace.
        Example: 'https://adb-1234567890123456.12.azuredatabricks.net'

    .PARAMETER AccessToken
        The Personal Access Token (PAT) used to authenticate with the Databricks workspace.
        This should be provided as a SecureString.

    .PARAMETER ScopeName
        The name of the secret scope to create.

    .PARAMETER ScopeBackendType
        The type of secret scope backend. Valid values are 'DATABRICKS' or 'AZURE_KEYVAULT'.

    .PARAMETER InitialManagePrincipal
        The principal (user or group) that will have MANAGE permissions on the scope.
        Default is 'users' which grants access to all workspace users.

    .PARAMETER BackendAzureKeyVault
        The Azure Key Vault backend configuration. Required when ScopeBackendType is 'AZURE_KEYVAULT'.

    .OUTPUTS
        System.Object
        Returns the API response from the create operation.

    .EXAMPLE
        $token = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
        New-DatabricksSecretScope -WorkspaceUrl 'https://adb-1234567890123456.12.azuredatabricks.net' -AccessToken $token -ScopeName 'my-scope' -ScopeBackendType 'DATABRICKS'

        Creates a new Databricks-backed secret scope.

    .EXAMPLE
        $token = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
        $backend = @{
            DnsName = 'https://myvault.vault.azure.net/'
            ResourceId = '/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/myRg/providers/Microsoft.KeyVault/vaults/myVault'
        }
        New-DatabricksSecretScope -WorkspaceUrl 'https://adb-1234567890123456.12.azuredatabricks.net' -AccessToken $token -ScopeName 'my-akv-scope' -ScopeBackendType 'AZURE_KEYVAULT' -BackendAzureKeyVault $backend

        Creates a new Azure Key Vault-backed secret scope.

    .NOTES
        This is a private function and should not be called directly outside of the module.
#>
function New-DatabricksSecretScope
{
    [CmdletBinding()]
    [OutputType([System.Object])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $WorkspaceUrl,

        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]
        $AccessToken,

        [Parameter(Mandatory = $true)]
        [System.String]
        $ScopeName,

        [Parameter(Mandatory = $true)]
        [ValidateSet('DATABRICKS', 'AZURE_KEYVAULT')]
        [System.String]
        $ScopeBackendType,

        [Parameter()]
        [System.String]
        $InitialManagePrincipal,

        [Parameter()]
        [System.Collections.Hashtable]
        $BackendAzureKeyVault
    )

    $uri = '{0}/api/2.0/secrets/scopes/create' -f $WorkspaceUrl.TrimEnd('/')

    $headers = @{
        'Authorization' = ConvertTo-DatabricksAuthHeader -AccessToken $AccessToken
        'Content-Type'  = 'application/json'
    }

    $body = @{
        scope              = $ScopeName
        scope_backend_type = $ScopeBackendType
    }

    if ($PSBoundParameters.ContainsKey('InitialManagePrincipal'))
    {
        $body.initial_manage_principal = $InitialManagePrincipal
    }

    if ($ScopeBackendType -eq 'AZURE_KEYVAULT')
    {
        if ($null -eq $BackendAzureKeyVault)
        {
            $errorMessage = $script:localizedData.AzureKeyVaultBackendRequired

            New-ArgumentException -ArgumentName 'BackendAzureKeyVault' -Message $errorMessage
        }

        $body.backend_azure_keyvault = @{
            resource_id = $BackendAzureKeyVault.ResourceId
            dns_name    = $BackendAzureKeyVault.DnsName
        }
    }

    $invokeParams = @{
        Uri     = $uri
        Method  = 'POST'
        Headers = $headers
        Body    = $body | ConvertTo-Json -Depth 10 -Compress
    }

    try
    {
        Write-Verbose -Message (
            $script:localizedData.CreatingSecretScope -f $ScopeName
        )

        $response = Invoke-RestMethod @invokeParams

        Write-Verbose -Message (
            $script:localizedData.SecretScopeCreated -f $ScopeName
        )

        return $response
    }
    catch
    {
        $errorMessage = $script:localizedData.ErrorCreatingSecretScope -f @(
            $ScopeName,
            $_.Exception.Message
        )

        Write-Error -Message $errorMessage -ErrorRecord $_
        throw
    }
}
