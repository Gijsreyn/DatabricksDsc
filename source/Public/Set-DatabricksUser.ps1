<#
    .SYNOPSIS
        Updates an existing user in a Databricks workspace.

    .DESCRIPTION
        The Set-DatabricksUser command updates an existing user in a Databricks
        workspace using the SCIM API.

    .PARAMETER WorkspaceUrl
        The URL of the Databricks workspace.

    .PARAMETER AccessToken
        The Personal Access Token (PAT) for authentication. Should be provided
        as a SecureString.

    .PARAMETER Id
        The ID of the user to update.

    .PARAMETER DisplayName
        The display name of the user.

    .PARAMETER Active
        Specifies if the user account should be active.

    .PARAMETER GivenName
        The given (first) name of the user.

    .PARAMETER FamilyName
        The family (last) name of the user.

    .PARAMETER Entitlements
        An array of entitlement values to assign to the user.

    .EXAMPLE
        $token = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
        Set-DatabricksUser -WorkspaceUrl 'https://adb-123.azuredatabricks.net' -AccessToken $token -Id '1234567890' -DisplayName 'Jane Doe'

        Updates the display name of a user.

    .OUTPUTS
        System.Object
#>
function Set-DatabricksUser
{
    [CmdletBinding(SupportsShouldProcess = $true)]
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
        $Id,

        [Parameter()]
        [System.String]
        $DisplayName,

        [Parameter()]
        [System.Boolean]
        $Active,

        [Parameter()]
        [System.String]
        $GivenName,

        [Parameter()]
        [System.String]
        $FamilyName,

        [Parameter()]
        [System.String[]]
        $Entitlements
    )

    $uri = '{0}/api/2.0/preview/scim/v2/Users/{1}' -f $WorkspaceUrl.TrimEnd('/'), $Id

    $headers = @{
        'Authorization' = ConvertTo-DatabricksAuthHeader -AccessToken $AccessToken
        'Content-Type'  = 'application/json'
    }

    $body = @{
        schemas = @('urn:ietf:params:scim:api:messages:2.0:PatchOp')
        Operations = @()
    }

    if ($PSBoundParameters.ContainsKey('DisplayName'))
    {
        $body.Operations += @{
            op    = 'replace'
            path  = 'displayName'
            value = $DisplayName
        }
    }

    if ($PSBoundParameters.ContainsKey('Active'))
    {
        $body.Operations += @{
            op    = 'replace'
            path  = 'active'
            value = $Active
        }
    }

    if ($GivenName -or $FamilyName)
    {
        $nameValue = @{}

        if ($GivenName)
        {
            $nameValue.givenName = $GivenName
        }

        if ($FamilyName)
        {
            $nameValue.familyName = $FamilyName
        }

        $body.Operations += @{
            op    = 'replace'
            path  = 'name'
            value = $nameValue
        }
    }

    if ($Entitlements)
    {
        $entitlementsValue = @()

        foreach ($entitlement in $Entitlements)
        {
            $entitlementsValue += @{
                value = $entitlement
            }
        }

        $body.Operations += @{
            op    = 'replace'
            path  = 'entitlements'
            value = $entitlementsValue
        }
    }

    if ($PSCmdlet.ShouldProcess($Id, 'Update Databricks user'))
    {
        try
        {
            Write-Verbose -Message ($script:localizedData.Set_DatabricksUser_UpdatingUser -f $Id)

            $bodyJson = $body | ConvertTo-Json -Depth 10 -Compress

            $response = Invoke-RestMethod -Uri $uri -Method Patch -Headers $headers -Body $bodyJson

            Write-Verbose -Message ($script:localizedData.Set_DatabricksUser_UserUpdated -f $Id)

            return $response
        }
        catch
        {
            $errorMessage = $script:localizedData.Set_DatabricksUser_ErrorUpdatingUser -f @(
                $Id,
                $_.Exception.Message
            )

            Write-Error -Message $errorMessage -Exception $_.Exception
        }
    }
}
