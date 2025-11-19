<#
    .SYNOPSIS
        Creates a new user in a Databricks workspace.

    .DESCRIPTION
        The New-DatabricksUser command creates a new user in a Databricks
        workspace using the SCIM API.

    .PARAMETER WorkspaceUrl
        The URL of the Databricks workspace.

    .PARAMETER AccessToken
        The Personal Access Token (PAT) for authentication. Should be provided
        as a SecureString.

    .PARAMETER UserName
        The username (email) of the user to create.

    .PARAMETER DisplayName
        The display name of the user.

    .PARAMETER Active
        Specifies if the user account should be active. Defaults to $true.

    .PARAMETER GivenName
        The given (first) name of the user.

    .PARAMETER FamilyName
        The family (last) name of the user.

    .PARAMETER Entitlements
        An array of entitlement values to assign to the user.

    .EXAMPLE
        $token = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
        New-DatabricksUser -WorkspaceUrl 'https://adb-123.azuredatabricks.net' -AccessToken $token -UserName 'user@example.com' -DisplayName 'John Doe' -GivenName 'John' -FamilyName 'Doe'

        Creates a new user in the workspace.

    .OUTPUTS
        System.Object
#>
function New-DatabricksUser
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
        $UserName,

        [Parameter()]
        [System.String]
        $DisplayName,

        [Parameter()]
        [System.Boolean]
        $Active = $true,

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

    $uri = '{0}/api/2.0/preview/scim/v2/Users' -f $WorkspaceUrl.TrimEnd('/')

    $headers = @{
        'Authorization' = ConvertTo-DatabricksAuthHeader -AccessToken $AccessToken
        'Content-Type'  = 'application/json'
    }

    $body = @{
        schemas  = @('urn:ietf:params:scim:schemas:core:2.0:User')
        userName = $UserName
        active   = $Active
    }

    if ($DisplayName)
    {
        $body.displayName = $DisplayName
    }

    if ($GivenName -or $FamilyName)
    {
        $body.name = @{}

        if ($GivenName)
        {
            $body.name.givenName = $GivenName
        }

        if ($FamilyName)
        {
            $body.name.familyName = $FamilyName
        }
    }

    if ($Entitlements)
    {
        $body.entitlements = @()

        foreach ($entitlement in $Entitlements)
        {
            $body.entitlements += @{
                value = $entitlement
            }
        }
    }

    if ($PSCmdlet.ShouldProcess($UserName, 'Create Databricks user'))
    {
        try
        {
            Write-Verbose -Message ($script:localizedData.New_DatabricksUser_CreatingUser -f $UserName)

            $bodyJson = $body | ConvertTo-Json -Depth 10 -Compress

            $response = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $bodyJson

            Write-Verbose -Message ($script:localizedData.New_DatabricksUser_UserCreated -f $UserName)

            return $response
        }
        catch
        {
            $errorMessage = $script:localizedData.New_DatabricksUser_ErrorCreatingUser -f @(
                $UserName,
                $_.Exception.Message
            )

            Write-Error -Message $errorMessage -Exception $_.Exception
        }
    }
}
