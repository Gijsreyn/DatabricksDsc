<#
    .SYNOPSIS
        Gets Databricks secrets from a secret scope.

    .DESCRIPTION
        The Get-DatabricksSecret function retrieves secrets from a Databricks
        secret scope using the Secrets API.

    .PARAMETER WorkspaceUrl
        The URL of the Databricks workspace.
        Example: 'https://adb-1234567890123456.12.azuredatabricks.net'

    .PARAMETER AccessToken
        The Personal Access Token (PAT) used to authenticate with the Databricks workspace.
        This should be provided as a SecureString.

    .PARAMETER ScopeName
        The name of the secret scope to retrieve secrets from.

    .PARAMETER SecretKey
        The key name of a specific secret to retrieve. If not specified, all secrets in the scope are returned.

    .OUTPUTS
        System.Object
        Returns the API response containing secret information.

    .EXAMPLE
        $token = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
        Get-DatabricksSecret -WorkspaceUrl 'https://adb-1234567890123456.12.azuredatabricks.net' -AccessToken $token -ScopeName 'my-scope'

        Retrieves all secrets from the 'my-scope' secret scope.

    .EXAMPLE
        $token = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
        Get-DatabricksSecret -WorkspaceUrl 'https://adb-1234567890123456.12.azuredatabricks.net' -AccessToken $token -ScopeName 'my-scope' -SecretKey 'my-key'

        Retrieves a specific secret with key 'my-key' from the 'my-scope' secret scope.

    .NOTES
        This function returns secret metadata only. Secret values are never returned by the API for security reasons.
#>
function Get-DatabricksSecret
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

        [Parameter()]
        [System.String]
        $SecretKey
    )

    $uri = '{0}/api/2.0/secrets/list' -f $WorkspaceUrl.TrimEnd('/')

    $headers = @{
        'Authorization' = ConvertTo-DatabricksAuthHeader -AccessToken $AccessToken
        'Content-Type'  = 'application/json'
    }

    $body = @{
        scope = $ScopeName
    }

    $invokeParams = @{
        Uri     = $uri
        Method  = 'GET'
        Headers = $headers
        Body    = $body
    }

    try
    {
        Write-Verbose -Message (
            $script:localizedData.GettingSecret -f $ScopeName
        )

        $response = Invoke-RestMethod @invokeParams

        if ($PSBoundParameters.ContainsKey('SecretKey'))
        {
            $secret = $response.secrets | Where-Object -FilterScript {
                $_.key -eq $SecretKey
            } | Select-Object -First 1

            return $secret
        }
        else
        {
            return $response
        }
    }
    catch
    {
        $errorMessage = $script:localizedData.ErrorGettingSecret -f @(
            $ScopeName,
            $_.Exception.Message
        )

        Write-Error -Message $errorMessage
        throw
    }
}
