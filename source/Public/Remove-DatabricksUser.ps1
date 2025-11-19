<#
    .SYNOPSIS
        Removes a user from a Databricks workspace.

    .DESCRIPTION
        The Remove-DatabricksUser command removes a user from a Databricks
        workspace using the SCIM API.

    .PARAMETER WorkspaceUrl
        The URL of the Databricks workspace.

    .PARAMETER AccessToken
        The Personal Access Token (PAT) for authentication. Should be provided
        as a SecureString.

    .PARAMETER Id
        The ID of the user to remove.

    .PARAMETER Force
        Forces the removal without prompting for confirmation.

    .EXAMPLE
        $token = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
        Remove-DatabricksUser -WorkspaceUrl 'https://adb-123.azuredatabricks.net' -AccessToken $token -Id '1234567890' -Force

        Removes a user from the workspace without confirmation.

    .OUTPUTS
        None
#>
function Remove-DatabricksUser
{
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
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
        $Id,

        [Parameter()]
        [Switch]
        $Force
    )

    $uri = '{0}/api/2.0/preview/scim/v2/Users/{1}' -f $WorkspaceUrl.TrimEnd('/'), $Id

    $headers = @{
        'Authorization' = ConvertTo-DatabricksAuthHeader -AccessToken $AccessToken
        'Content-Type'  = 'application/json'
    }

    if ($Force -or $PSCmdlet.ShouldProcess($Id, 'Remove Databricks user'))
    {
        try
        {
            Write-Verbose -Message ($script:localizedData.Remove_DatabricksUser_RemovingUser -f $Id)

            $null = Invoke-RestMethod -Uri $uri -Method Delete -Headers $headers

            Write-Verbose -Message ($script:localizedData.Remove_DatabricksUser_UserRemoved -f $Id)
        }
        catch
        {
            $errorMessage = $script:localizedData.Remove_DatabricksUser_ErrorRemovingUser -f @(
                $Id,
                $_.Exception.Message
            )

            Write-Error -Message $errorMessage -Exception $_.Exception
        }
    }
}
