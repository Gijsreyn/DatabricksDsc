<#
    .SYNOPSIS
        Removes a Databricks secret scope from a workspace.

    .DESCRIPTION
        The Remove-DatabricksSecretScope function removes a secret scope from a
        Databricks workspace using the Secrets API.

    .PARAMETER WorkspaceUrl
        The URL of the Databricks workspace.
        Example: 'https://adb-1234567890123456.12.azuredatabricks.net'

    .PARAMETER AccessToken
        The Personal Access Token (PAT) used to authenticate with the Databricks workspace.
        This should be provided as a SecureString.

    .PARAMETER ScopeName
        The name of the secret scope to remove.

    .OUTPUTS
        System.Object
        Returns the API response from the delete operation.

    .EXAMPLE
        $token = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
        Remove-DatabricksSecretScope -WorkspaceUrl 'https://adb-1234567890123456.12.azuredatabricks.net' -AccessToken $token -ScopeName 'my-scope'

        Removes the secret scope named 'my-scope' from the workspace.

    .NOTES
        This is a private function and should not be called directly outside of the module.
#>
function Remove-DatabricksSecretScope
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
        $ScopeName
    )

    $uri = '{0}/api/2.0/secrets/scopes/delete' -f $WorkspaceUrl.TrimEnd('/')

    $headers = @{
        'Authorization' = ConvertTo-DatabricksAuthHeader -AccessToken $AccessToken
        'Content-Type'  = 'application/json'
    }

    $body = @{
        scope = $ScopeName
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
            $script:localizedData.RemovingSecretScope -f $ScopeName
        )

        $response = Invoke-RestMethod @invokeParams

        Write-Verbose -Message (
            $script:localizedData.SecretScopeRemoved -f $ScopeName
        )

        return $response
    }
    catch
    {
        $errorMessage = $script:localizedData.ErrorRemovingSecretScope -f @(
            $ScopeName,
            $_.Exception.Message
        )

        Write-Error -Message $errorMessage -ErrorRecord $_
        throw
    }
}
