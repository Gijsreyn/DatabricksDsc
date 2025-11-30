<#
    .SYNOPSIS
        Creates or updates a Databricks secret in a secret scope.

    .DESCRIPTION
        The New-DatabricksSecret function creates or updates a secret in a Databricks
        secret scope using the Secrets API. If a secret already exists with the same
        name, this command overwrites the existing secret's value.

    .PARAMETER WorkspaceUrl
        The URL of the Databricks workspace.
        Example: 'https://adb-1234567890123456.12.azuredatabricks.net'

    .PARAMETER AccessToken
        The Personal Access Token (PAT) used to authenticate with the Databricks workspace.
        This should be provided as a SecureString.

    .PARAMETER ScopeName
        The name of the secret scope.

    .PARAMETER SecretKey
        A unique name to identify the secret. Must consist of alphanumeric characters,
        dashes, underscores, and periods, and cannot exceed 128 characters.

    .PARAMETER StringValue
        The secret value as a string. If specified, value will be stored in UTF-8 (MB4) form.
        Cannot be used together with BytesValue. Maximum size is 128 KB.

    .PARAMETER BytesValue
        The secret value as bytes. If specified, value will be stored as bytes.
        Cannot be used together with StringValue. Maximum size is 128 KB.

    .OUTPUTS
        System.Object
        Returns the API response from the put operation.

    .EXAMPLE
        $token = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
        New-DatabricksSecret -WorkspaceUrl 'https://adb-1234567890123456.12.azuredatabricks.net' -AccessToken $token -ScopeName 'my-scope' -SecretKey 'my-key' -StringValue 'my-secret-value'

        Creates or updates a secret with a string value.

    .NOTES
        This function cannot be used against Azure Key Vault-backed scopes.
#>
function New-DatabricksSecret
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
        $SecretKey,

        [Parameter(ParameterSetName = 'String')]
        [System.String]
        $StringValue,

        [Parameter(ParameterSetName = 'Bytes')]
        [System.String]
        $BytesValue
    )

    $uri = '{0}/api/2.0/secrets/put' -f $WorkspaceUrl.TrimEnd('/')

    $headers = @{
        'Authorization' = ConvertTo-DatabricksAuthHeader -AccessToken $AccessToken
        'Content-Type'  = 'application/json'
    }

    $body = @{
        scope = $ScopeName
        key   = $SecretKey
    }

    if ($PSCmdlet.ParameterSetName -eq 'String')
    {
        if (-not [string]::IsNullOrEmpty($StringValue))
        {
            $body.string_value = $StringValue
        }
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'Bytes')
    {
        if (-not [string]::IsNullOrEmpty($BytesValue))
        {
            $body.bytes_value = $BytesValue
        }
    }

    # Validate that at least one value is specified
    if (-not $body.ContainsKey('string_value') -and -not $body.ContainsKey('bytes_value'))
    {
        $errorMessage = $script:localizedData.SecretValueRequired

        New-ArgumentException -ArgumentName 'StringValue/BytesValue' -Message $errorMessage
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
            $script:localizedData.CreatingSecret -f @($SecretKey, $ScopeName)
        )

        $response = Invoke-RestMethod @invokeParams

        Write-Verbose -Message (
            $script:localizedData.SecretCreated -f @($SecretKey, $ScopeName)
        )

        return $response
    }
    catch
    {
        $errorMessage = $script:localizedData.ErrorCreatingSecret -f @(
            $SecretKey,
            $ScopeName,
            $_.Exception.Message
        )

        Write-Error -Message $errorMessage
        throw
    }
}
