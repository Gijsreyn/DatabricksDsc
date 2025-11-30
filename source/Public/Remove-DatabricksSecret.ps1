<#
    .SYNOPSIS
        Removes a Databricks secret from a secret scope.

    .DESCRIPTION
        The Remove-DatabricksSecret function removes a secret from a Databricks
        secret scope using the Secrets API.

    .PARAMETER WorkspaceUrl
        The URL of the Databricks workspace.
        Example: 'https://adb-1234567890123456.12.azuredatabricks.net'

    .PARAMETER AccessToken
        The Personal Access Token (PAT) used to authenticate with the Databricks workspace.
        This should be provided as a SecureString.

    .PARAMETER ScopeName
        The name of the secret scope that contains the secret to delete.

    .PARAMETER SecretKey
        The key name of the secret to delete.

    .OUTPUTS
        System.Object
        Returns the API response from the delete operation.

    .EXAMPLE
        $token = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
        Remove-DatabricksSecret -WorkspaceUrl 'https://adb-1234567890123456.12.azuredatabricks.net' -AccessToken $token -ScopeName 'my-scope' -SecretKey 'my-key'

        Removes the secret with key 'my-key' from the 'my-scope' secret scope.

    .NOTES
        This function cannot be used against Azure Key Vault-backed scopes.
#>
function Remove-DatabricksSecret
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
        [System.String]
        $SecretKey
    )

    $uri = '{0}/api/2.0/secrets/delete' -f $WorkspaceUrl.TrimEnd('/')

    $headers = @{
        'Authorization' = ConvertTo-DatabricksAuthHeader -AccessToken $AccessToken
        'Content-Type'  = 'application/json'
    }

    $body = @{
        scope = $ScopeName
        key   = $SecretKey
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
            $script:localizedData.RemovingSecret -f @($SecretKey, $ScopeName)
        )

        $null = Invoke-RestMethod @invokeParams

        Write-Verbose -Message (
            $script:localizedData.SecretRemoved -f @($SecretKey, $ScopeName)
        )

        return @{}
    }
    catch
    {
        $errorMessage = $script:localizedData.ErrorRemovingSecret -f @(
            $SecretKey,
            $ScopeName,
            $_.Exception.Message
        )

        Write-Error -Message $errorMessage
        throw
    }
}
