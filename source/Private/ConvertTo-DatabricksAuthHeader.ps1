<#
    .SYNOPSIS
        Converts a SecureString to a plain text authorization header value.

    .DESCRIPTION
        The ConvertTo-DatabricksAuthHeader function converts a SecureString
        containing a Databricks Personal Access Token (PAT) to a properly
        formatted Bearer authorization header value.

    .PARAMETER AccessToken
        The Personal Access Token as a SecureString.

    .EXAMPLE
        $token = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
        $authHeader = ConvertTo-DatabricksAuthHeader -AccessToken $token

        Returns: 'Bearer dapi1234567890abcdef'

    .OUTPUTS
        System.String
#>
function ConvertTo-DatabricksAuthHeader
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]
        $AccessToken
    )

    # Convert SecureString to plain text for the Authorization header
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessToken)

    try
    {
        $token = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)

        return "Bearer $token"
    }
    finally
    {
        # Always zero out and free the BSTR for security
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}
