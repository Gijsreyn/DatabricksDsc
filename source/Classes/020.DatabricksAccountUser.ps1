<#
    .SYNOPSIS
        The `DatabricksAccountUser` DSC resource is used to create, modify, or remove
        users in a Databricks account at the account level.

    .DESCRIPTION
        The `DatabricksAccountUser` DSC resource is used to create, modify, or remove
        users in a Databricks account using the account-level SCIM API.

        This resource manages users at the account level, making them available across
        all workspaces in the account. For workspace-specific user management, use the
        `DatabricksUser` resource.

        ## Requirements

        * Target machine must have network connectivity to the Databricks account console.
        * A valid Databricks Account API token with admin privileges.

        ## Known issues

        All issues are not listed here, see [all open issues](https://github.com/Gijsreyn/DatabricksDsc/issues?q=is%3Aissue+is%3Aopen+in%3Atitle+DatabricksAccountUser).

        ### Using `AccessToken` property

        The `AccessToken` must be provided as a SecureString containing the
        Account API token.

    .PARAMETER AccountId
        The Databricks account ID (UUID format). This identifies the target account.

    .PARAMETER UserName
        The username (email) of the user. This is the unique identifier.

    .PARAMETER DisplayName
        The display name of the user.

    .PARAMETER Active
        Specifies if the user account should be active. Defaults to `$true`.

    .PARAMETER Emails
        Array of email addresses associated with the user. Each email should include
        value, type, and primary properties.

    .PARAMETER Name
        The user's name containing givenName and familyName properties.

    .PARAMETER Roles
        Array of roles assigned to the user. Typically used for admin role assignment.

    .PARAMETER ExternalId
        External ID of the user. This is read-only and reserved for future use.

    .PARAMETER Id
        The internal Databricks user ID. This is read-only.

    .PARAMETER AccountsUrl
        The URL of the Databricks Account Console. Defaults to
        'https://accounts.azuredatabricks.net' and typically does not need to be specified.

    .PARAMETER AccessToken
        The Account API token used to authenticate to the Databricks account.
        Must be provided as a SecureString.

    .PARAMETER _exist
        Specifies if the user should exist or not. Used internally by DSC.

    .EXAMPLE
        DatabricksAccountUser AccountUserExample
        {
            AccountId   = '12345678-1234-1234-1234-123456789012'
            UserName    = 'user@example.com'
            DisplayName = 'Example User'
            Active      = $true
            AccessToken = $accessToken
        }

        Creates or updates a user at the account level.
#>

[DscResource()]
class DatabricksAccountUser : DatabricksAccountResourceBase
{
    [DscProperty(Key)]
    [System.String]
    $AccountId

    [DscProperty(Key)]
    [System.String]
    $UserName

    [DscProperty()]
    [System.String]
    $DisplayName

    [DscProperty()]
    [System.Boolean]
    $Active = $true

    [DscProperty()]
    [UserEmail[]]
    $Emails

    [DscProperty()]
    [UserName]
    $Name

    [DscProperty()]
    [UserRole[]]
    $Roles

    [DscProperty(NotConfigurable)]
    [System.String]
    $ExternalId

    [DscProperty(NotConfigurable)]
    [System.String]
    $Id

    [DscProperty()]
    [System.Boolean]
    $_exist = $true

    DatabricksAccountUser() : base ()
    {
        $this.ExcludeDscProperties = @(
            'AccountsUrl'
            'WorkspaceUrl'
            'AccountId'
            'UserName'
            'AccessToken'
            'Id'
            'ExternalId'
        )
    }

    [DatabricksAccountUser] Get()
    {
        return ([ResourceBase] $this).Get()
    }

    [System.Boolean] Test()
    {
        return ([ResourceBase] $this).Test()
    }

    [void] Set()
    {
        ([ResourceBase] $this).Set()
    }

    <#
        Base method Get() call this method to get the current state as a hashtable.
        The parameter properties will contain the key properties.
    #>
    hidden [System.Collections.Hashtable] GetCurrentState([System.Collections.Hashtable] $properties)
    {
        Write-Verbose -Message (
            $this.localizedData.EvaluatingAccountUserState -f @(
                $properties.UserName,
                $properties.AccountId
            )
        )

        $currentState = @{
            WorkspaceUrl = $this.WorkspaceUrl
            AccountId    = $properties.AccountId
            UserName     = $properties.UserName
            _exist       = $false
        }

        try
        {
            # Use SCIM filter to find user by username
            $filter = "userName eq '$($properties.UserName)'"
            $response = $this.InvokeDatabricksApi(
                'GET',
                "/api/2.0/accounts/$($properties.AccountId)/scim/v2/Users?filter=$filter",
                $null
            )

            if ($response -and $response.Resources -and $response.Resources.Count -gt 0)
            {
                $user = $response.Resources[0]

                $currentState.DisplayName = $user.displayName
                $currentState.Active = $user.active
                $currentState.Id = $user.id

                # Convert externalId if present
                if ($user.externalId)
                {
                    $currentState.ExternalId = $user.externalId
                }

                # Convert emails
                if ($user.emails)
                {
                    $currentState.Emails = @()
                    foreach ($email in $user.emails)
                    {
                        $currentState.Emails += [UserEmail]@{
                            Value   = $email.value
                            Type    = $email.type
                            Primary = $email.primary
                        }
                    }

                    # Sort emails for consistent comparison (primary first, then by value)
                    $currentState.Emails = $currentState.Emails | Sort-Object
                }

                # Convert name
                if ($user.name)
                {
                    $currentState.Name = [UserName]@{
                        GivenName  = $user.name.givenName
                        FamilyName = $user.name.familyName
                    }
                }

                # Convert roles
                if ($user.roles)
                {
                    $currentState.Roles = @()
                    foreach ($role in $user.roles)
                    {
                        $currentState.Roles += [UserRole]@{
                            Value = $role.value
                        }
                    }

                    # Sort roles for consistent comparison
                    $currentState.Roles = $currentState.Roles | Sort-Object
                }

                $currentState._exist = $true
            }
            else
            {
                Write-Verbose -Message (
                    $this.localizedData.AccountUserNotFound -f $properties.UserName
                )
            }
        }
        catch
        {
            Write-Verbose -Message (
                $this.localizedData.ErrorGettingAccountUser -f @(
                    $properties.UserName,
                    $_.Exception.Message
                )
            )
        }

        return $currentState
    }

    <#
        Base method Set() call this method with the properties that should be
        enforced are not in desired state. It is not called if all properties
        are in desired state. The variable $properties contain the properties
        that are not in desired state.
    #>
    hidden [void] Modify([System.Collections.Hashtable] $properties)
    {
        # Check if _exist property needs to be changed (user should be created or removed)
        if ($properties.ContainsKey('_exist'))
        {
            # Evaluate the desired state for property _exist
            if ($properties._exist -eq $true)
            {
                # Create the user since it doesn't exist
                Write-Verbose -Message (
                    $this.localizedData.CreatingAccountUser -f $this.UserName
                )

                $body = $this.BuildAccountUserPayload($properties)
                $body.userName = $this.UserName
                $body.schemas = @('urn:ietf:params:scim:schemas:core:2.0:User')

                try
                {
                    $this.InvokeDatabricksApi(
                        'POST',
                        "/api/2.0/accounts/$($this.AccountId)/scim/v2/Users",
                        $body
                    )

                    Write-Verbose -Message (
                        $this.localizedData.AccountUserCreated -f $this.UserName
                    )
                }
                catch
                {
                    $errorMessage = $this.localizedData.FailedToCreateAccountUser -f @(
                        $this.UserName,
                        $_.Exception.Message
                    )

                    New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
                }
            }
            else
            {
                # Remove the user since it exists
                Write-Verbose -Message (
                    $this.localizedData.RemovingAccountUser -f $this.UserName
                )

                try
                {
                    $this.InvokeDatabricksApi(
                        'DELETE',
                        "/api/2.0/accounts/$($this.AccountId)/scim/v2/Users/$($this.Id)",
                        $null
                    )

                    Write-Verbose -Message (
                        $this.localizedData.AccountUserRemoved -f $this.UserName
                    )
                }
                catch
                {
                    $errorMessage = $this.localizedData.FailedToRemoveAccountUser -f @(
                        $this.UserName,
                        $_.Exception.Message
                    )

                    New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
                }
            }
        }
        else
        {
            # Update existing user properties (user exists and should exist)
            # At this point it is assumed the user exists since _exist property was in desired state
            if ($this._exist -eq $true)
            {
                Write-Verbose -Message (
                    $this.localizedData.UpdatingAccountUser -f $this.UserName
                )

                $body = $this.BuildAccountUserPatchPayload($properties)

                try
                {
                    $this.InvokeDatabricksApi(
                        'PATCH',
                        "/api/2.0/accounts/$($this.AccountId)/scim/v2/Users/$($this.Id)",
                        $body
                    )

                    Write-Verbose -Message (
                        $this.localizedData.AccountUserUpdated -f $this.UserName
                    )
                }
                catch
                {
                    $errorMessage = $this.localizedData.FailedToUpdateAccountUser -f @(
                        $this.UserName,
                        $_.Exception.Message
                    )

                    New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
                }
            }
        }
    }

    <#
        Helper method to build the account user payload for API calls.
    #>
    hidden [System.Collections.Hashtable] BuildAccountUserPayload([System.Collections.Hashtable] $properties)
    {
        $body = @{}

        if ($properties.ContainsKey('DisplayName'))
        {
            $body.displayName = $this.DisplayName
        }

        if ($properties.ContainsKey('Active'))
        {
            $body.active = $this.Active
        }

        if ($properties.ContainsKey('Emails') -and $this.Emails)
        {
            $body.emails = @()
            # Sort emails before sending to API (primary first)
            $sortedEmails = $this.Emails | Sort-Object

            foreach ($email in $sortedEmails)
            {
                $emailObj = @{
                    value   = $email.Value
                    type    = $email.Type
                    primary = $email.Primary
                }

                $body.emails += $emailObj
            }
        }

        if ($properties.ContainsKey('Name') -and $this.Name)
        {
            $body.name = @{
                givenName  = $this.Name.GivenName
                familyName = $this.Name.FamilyName
            }
        }

        if ($properties.ContainsKey('Roles') -and $this.Roles)
        {
            $body.roles = @()
            # Sort roles before sending to API
            $sortedRoles = $this.Roles | Sort-Object

            foreach ($role in $sortedRoles)
            {
                $body.roles += @{
                    value = $role.Value
                }
            }
        }

        return $body
    }

    <#
        Helper method to build the SCIM PATCH payload for account user updates.
        Uses SCIM PatchOp format as per documentation.
    #>
    hidden [System.Collections.Hashtable] BuildAccountUserPatchPayload([System.Collections.Hashtable] $properties)
    {
        $body = @{
            schemas    = @('urn:ietf:params:scim:api:messages:2.0:PatchOp')
            Operations = @()
        }

        # Handle Roles updates
        if ($properties.ContainsKey('Roles') -and $null -ne $this.Roles)
        {
            # Sort roles before sending to API
            $sortedRoles = $this.Roles | Sort-Object

            $roleValues = @()
            foreach ($role in $sortedRoles)
            {
                $roleValues += @{
                    value = $role.Value
                }
            }

            $body.Operations += @{
                op    = 'add'
                path  = 'roles'
                value = $roleValues
            }
        }

        return $body
    }

    <#
        Base method Assert() call this method with the properties that was assigned
        a value.
    #>
    hidden [void] AssertProperties([System.Collections.Hashtable] $properties)
    {
        # Validate WorkspaceUrl format
        if ($properties.WorkspaceUrl -notmatch '^https://')
        {
            $errorMessage = $this.localizedData.InvalidWorkspaceUrl -f $properties.WorkspaceUrl

            New-ArgumentException -ArgumentName 'WorkspaceUrl' -Message $errorMessage
        }

        # Validate AccountId is a valid GUID
        if ($this.AccountId -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')
        {
            $errorMessage = $this.localizedData.InvalidAccountId -f $this.AccountId

            New-ArgumentException -ArgumentName 'AccountId' -Message $errorMessage
        }

        # Validate UserName is an email format
        if ($this.UserName -notmatch '@')
        {
            $errorMessage = $this.localizedData.InvalidUserName -f $this.UserName

            New-ArgumentException -ArgumentName 'UserName' -Message $errorMessage
        }
    }
}
