<#
    .SYNOPSIS
        Gets users from a Databricks workspace.

    .DESCRIPTION
        The Get-DatabricksUser command gets one or more users from a Databricks
        workspace using the SCIM API.

    .PARAMETER WorkspaceUrl
        The URL of the Databricks workspace.

    .PARAMETER AccessToken
        The Personal Access Token (PAT) for authentication. Should be provided
        as a SecureString.

    .PARAMETER UserName
        The username (email) of a specific user to retrieve. If not specified,
        all users will be returned.

    .PARAMETER Id
        The ID of a specific user to retrieve.

    .EXAMPLE
        $token = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
        Get-DatabricksUser -WorkspaceUrl 'https://adb-123.azuredatabricks.net' -AccessToken $token

        Gets all users from the workspace.

    .EXAMPLE
        $token = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
        Get-DatabricksUser -WorkspaceUrl 'https://adb-123.azuredatabricks.net' -AccessToken $token -UserName 'user@example.com'

        Gets a specific user by username.

    .OUTPUTS
        System.Object
#>
function Get-DatabricksUser
{
    [CmdletBinding(DefaultParameterSetName = 'All')]
    [OutputType([System.Object])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $WorkspaceUrl,

        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]
        $AccessToken,

        [Parameter(ParameterSetName = 'ByUserName')]
        [System.String]
        $UserName,

        [Parameter(ParameterSetName = 'ById')]
        [System.String]
        $Id
    )

    $uri = '{0}/api/2.0/preview/scim/v2/Users' -f $WorkspaceUrl.TrimEnd('/')

    $headers = @{
        'Authorization' = ConvertTo-DatabricksAuthHeader -AccessToken $AccessToken
        'Content-Type'  = 'application/json'
    }

    try
    {
        if ($Id)
        {
            # Get specific user by ID
            $uri = '{0}/{1}' -f $uri, $Id

            Write-Verbose -Message ($script:localizedData.Get_DatabricksUser_GettingUserById -f $Id)

            $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers

            return $response
        }
        elseif ($UserName)
        {
            # Get all users and filter by userName
            Write-Verbose -Message ($script:localizedData.Get_DatabricksUser_GettingUserByName -f $UserName)

            $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers

            $user = $response.Resources | Where-Object -FilterScript {
                $_.userName -eq $UserName
            }

            return $user
        }
        else
        {
            # Get all users
            Write-Verbose -Message $script:localizedData.Get_DatabricksUser_GettingAllUsers

            $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers

            return $response.Resources
        }
    }
    catch
    {
        $errorMessage = $script:localizedData.Get_DatabricksUser_ErrorGettingUser -f $_.Exception.Message

        Write-Error -Message $errorMessage -Exception $_.Exception
    }
}
