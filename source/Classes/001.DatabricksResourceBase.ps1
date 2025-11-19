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
}
