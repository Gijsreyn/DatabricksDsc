<#
    .SYNOPSIS
        Gets Databricks secret scopes from a workspace.

    .DESCRIPTION
        The Get-DatabricksSecretScope function retrieves secret scopes from a
        Databricks workspace using the Secrets API.

    .PARAMETER WorkspaceUrl
        The URL of the Databricks workspace.
        Example: 'https://adb-1234567890123456.12.azuredatabricks.net'

    .PARAMETER AccessToken
        The Personal Access Token (PAT) used to authenticate with the Databricks workspace.
        This should be provided as a SecureString.

    .PARAMETER ScopeName
        The name of the secret scope to retrieve. If not specified, all scopes are returned.

    .OUTPUTS
        System.Object
        Returns the API response containing scope information.

    .EXAMPLE
        $token = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
        Get-DatabricksSecretScope -WorkspaceUrl 'https://adb-1234567890123456.12.azuredatabricks.net' -AccessToken $token

        Retrieves all secret scopes from the workspace.

    .EXAMPLE
        $token = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
        Get-DatabricksSecretScope -WorkspaceUrl 'https://adb-1234567890123456.12.azuredatabricks.net' -AccessToken $token -ScopeName 'my-scope'

        Retrieves a specific secret scope named 'my-scope'.

    .NOTES
        This is a private function and should not be called directly outside of the module.
#>
function Get-DatabricksSecretScope
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

        [Parameter()]
        [System.String]
        $ScopeName
    )

    $uri = '{0}/api/2.0/secrets/scopes/list' -f $WorkspaceUrl.TrimEnd('/')

    $headers = @{
        'Authorization' = ConvertTo-DatabricksAuthHeader -AccessToken $AccessToken
        'Content-Type'  = 'application/json'
    }

    $invokeParams = @{
        Uri     = $uri
        Method  = 'GET'
        Headers = $headers
    }

    try
    {
        Write-Verbose -Message (
            $script:localizedData.GettingSecretScope -f $WorkspaceUrl
        )

        $response = Invoke-RestMethod @invokeParams

        if ($PSBoundParameters.ContainsKey('ScopeName'))
        {
            $scope = $response.scopes | Where-Object -FilterScript {
                $_.name -eq $ScopeName
            } | Select-Object -First 1

            return $scope
        }
        else
        {
            return $response
        }
    }
    catch
    {
        $errorMessage = $script:localizedData.ErrorGettingSecretScope -f @(
            $WorkspaceUrl,
            $_.Exception.Message
        )

        Write-Error -Message $errorMessage -ErrorRecord $_
        throw
    }
}
