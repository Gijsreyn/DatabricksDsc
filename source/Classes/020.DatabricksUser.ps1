<#
    .SYNOPSIS
        The `DatabricksUser` DSC resource is used to create, modify, or remove
        users in a Databricks workspace at the workspace level.

    .DESCRIPTION
        The `DatabricksUser` DSC resource is used to create, modify, or remove
        users in a Databricks workspace using the workspace-level SCIM API.

        This resource manages users within a specific workspace. For account-level
        user management across all workspaces, use the `DatabricksAccountUser` resource.

        ## Requirements

        * Target machine must have network connectivity to the Databricks workspace.
        * A valid Databricks Personal Access Token (PAT) with admin privileges.

        ## Known issues

        All issues are not listed here, see [all open issues](https://github.com/Gijsreyn/DatabricksDsc/issues?q=is%3Aissue+is%3Aopen+in%3Atitle+DatabricksUser).

        ### Using `AccessToken` property

        The `AccessToken` must be provided as a SecureString containing the
        Personal Access Token.

    .PARAMETER UserName
        The username (email) of the user. This is the unique identifier.

    .PARAMETER DisplayName
        The display name of the user.

    .PARAMETER Active
        Specifies if the user account should be active. Defaults to `$true`.

    .PARAMETER Emails
        An array of email addresses for the user.

    .PARAMETER Name
        The name object containing given name and family name.

    .PARAMETER Entitlements
        An array of entitlements assigned to the user.

    .PARAMETER Roles
        An array of roles assigned to the user.

    .PARAMETER ExternalId
        An external identifier for the user (optional).

    .PARAMETER _exist
        Specifies whether the user should exist in the workspace. Defaults to `$true`.
        Set to `$false` to remove the user.

    .EXAMPLE
        $token = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
        Invoke-DscResource -ModuleName DatabricksDsc -Name DatabricksUser -Method Get -Property @{
            WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
            AccessToken  = $token
            UserName     = 'user@example.com'
        }

        This example shows how to call the resource using Invoke-DscResource.
#>
[DscResource(RunAsCredential = 'NotSupported')]
class DatabricksUser : DatabricksResourceBase
{
    [DscProperty(Key)]
    [System.String]
    $UserName

    [DscProperty()]
    [System.String]
    $DisplayName

    [DscProperty()]
    [Nullable[System.Boolean]]
    $Active = $true

    [DscProperty()]
    [UserEmail[]]
    $Emails

    [DscProperty()]
    [UserName]
    $Name

    [DscProperty()]
    [UserEntitlement[]]
    $Entitlements

    [DscProperty()]
    [UserRole[]]
    $Roles

    [DscProperty()]
    [System.String]
    $ExternalId

    [DscProperty(NotConfigurable)]
    [System.String]
    $Id

    [DscProperty()]
    [System.Boolean]
    $_exist = $true

    hidden [System.Boolean] $_inDesiredState = $true

    DatabricksUser () : base ()
    {
        # These properties will not be enforced.
        $this.ExcludeDscProperties = @(
            'WorkspaceUrl'
            'UserName'
            'AccessToken'
            'Id'
        )
    }

    [DatabricksUser] Get()
    {
        # Call the base method to return the properties.
        return ([ResourceBase] $this).Get()
    }

    [System.Boolean] Test()
    {
        # Call the base method to test all of the properties that should be enforced.
        return ([ResourceBase] $this).Test()
    }

    [void] Set()
    {
        # Call the base method to enforce the properties.
        ([ResourceBase] $this).Set()
    }

    <#
        Base method Get() call this method to get the current state as a hashtable.
        The parameter properties will contain the key properties.
    #>
    hidden [System.Collections.Hashtable] GetCurrentState([System.Collections.Hashtable] $properties)
    {
        Write-Verbose -Message (
            $this.localizedData.EvaluatingUserState -f @(
                $properties.UserName,
                $this.WorkspaceUrl
            )
        )

        $currentState = @{
            WorkspaceUrl = $this.WorkspaceUrl
            AccessToken  = $this.AccessToken
            UserName     = $properties.UserName
            _exist       = $false
        }

        try
        {
            # Get all users and filter by userName
            $response = $this.InvokeDatabricksApi(
                'GET',
                '/api/2.0/preview/scim/v2/Users',
                $null
            )

            $user = $response.Resources | Where-Object -FilterScript {
                $_.userName -eq $properties.UserName
            } | Select-Object -First 1

            if ($user)
            {
                $currentState._exist = $true
                $currentState.Id = $user.id
                $currentState.DisplayName = $user.displayName
                $currentState.Active = $user.active
                $currentState.ExternalId = $user.externalId

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

                # Convert entitlements
                if ($user.entitlements)
                {
                    $currentState.Entitlements = @()
                    foreach ($entitlement in $user.entitlements)
                    {
                        $currentState.Entitlements += [UserEntitlement]@{
                            Value = $entitlement.value
                        }
                    }

                    # Sort entitlements for consistent comparison
                    $currentState.Entitlements = $currentState.Entitlements | Sort-Object
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
            }
            else
            {
                # When user doesn't exist, set all other properties to $null
                # so they don't get compared (only _exist should matter)
                $currentState.DisplayName = $null
                $currentState.Active = $null
                $currentState.Emails = $null
                $currentState.Name = $null
                $currentState.Entitlements = $null
                $currentState.Roles = $null
                $currentState.ExternalId = $null
                $currentState.Id = $null

                Write-Verbose -Message (
                    $this.localizedData.UserNotFound -f $properties.UserName
                )
            }
        }
        catch
        {
            Write-Verbose -Message (
                $this.localizedData.ErrorGettingUser -f @(
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
                    $this.localizedData.CreatingUser -f $this.UserName
                )

                $body = $this.BuildUserPayload($properties)
                $body.userName = $this.UserName
                # TODO: Have to validate the schemas
                $body.schemas = @('urn:ietf:params:scim:schemas:core:2.0:User')

                try
                {
                    $this.InvokeDatabricksApi(
                        'POST',
                        '/api/2.0/preview/scim/v2/Users',
                        $body
                    )

                    Write-Verbose -Message (
                        $this.localizedData.UserCreated -f $this.UserName
                    )
                }
                catch
                {
                    $errorMessage = $this.localizedData.FailedToCreateUser -f @(
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
                    $this.localizedData.RemovingUser -f $this.UserName
                )

                try
                {
                    $this.InvokeDatabricksApi(
                        'DELETE',
                        "/api/2.0/preview/scim/v2/Users/$($this.Id)",
                        $null
                    )

                    Write-Verbose -Message (
                        $this.localizedData.UserRemoved -f $this.UserName
                    )
                }
                catch
                {
                    $errorMessage = $this.localizedData.FailedToRemoveUser -f @(
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
                    $this.localizedData.UpdatingUser -f $this.UserName
                )

                $body = $this.BuildUserPatchPayload($properties)

                try
                {
                    $this.InvokeDatabricksApi(
                        'PATCH',
                        "/api/2.0/preview/scim/v2/Users/$($this.Id)",
                        $body
                    )

                    Write-Verbose -Message (
                        $this.localizedData.UserUpdated -f $this.UserName
                    )
                }
                catch
                {
                    $errorMessage = $this.localizedData.FailedToUpdateUser -f @(
                        $this.UserName,
                        $_.Exception.Message
                    )

                    New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
                }
            }
        }
    }

    <#
        Helper method to build the user payload for API calls.
    #>
    hidden [System.Collections.Hashtable] BuildUserPayload([System.Collections.Hashtable] $properties)
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

        if ($properties.ContainsKey('ExternalId'))
        {
            $body.externalId = $this.ExternalId
        }

        if ($properties.ContainsKey('Emails') -and $this.Emails)
        {
            $body.emails = @()
            # Sort emails before sending to API (primary first, then by value)
            $sortedEmails = $this.Emails | Sort-Object

            foreach ($email in $sortedEmails)
            {
                $emailObj = @{
                    value = $email.Value
                }

                if ($email.Type)
                {
                    $emailObj.type = $email.Type
                }

                if ($null -ne $email.Primary)
                {
                    $emailObj.primary = $email.Primary
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

        if ($properties.ContainsKey('Entitlements') -and $this.Entitlements)
        {
            $body.entitlements = @()
            # Sort entitlements before sending to API
            $sortedEntitlements = $this.Entitlements | Sort-Object

            foreach ($entitlement in $sortedEntitlements)
            {
                $body.entitlements += @{
                    value = $entitlement.Value
                }
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
        Helper method to build the SCIM PATCH payload for user updates.
        Uses SCIM PatchOp format as per documentation.
    #>
    hidden [System.Collections.Hashtable] BuildUserPatchPayload([System.Collections.Hashtable] $properties)
    {
        $body = @{
            schemas = @('urn:ietf:params:scim:api:messages:2.0:PatchOp')
            Operations = @()
        }

        # Handle Entitlements updates
        if ($properties.ContainsKey('Entitlements') -and $null -ne $this.Entitlements)
        {
            # Sort entitlements before sending to API
            $sortedEntitlements = $this.Entitlements | Sort-Object

            $entitlementValues = @()
            foreach ($entitlement in $sortedEntitlements)
            {
                $entitlementValues += @{
                    value = $entitlement.Value
                }
            }

            $body.Operations += @{
                op = 'add'
                path = 'entitlements'
                value = $entitlementValues
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

        # Validate UserName format (should be an email)
        if ($properties.UserName -notmatch '^[\w\.-]+@[\w\.-]+\.\w+$')
        {
            $errorMessage = $this.localizedData.InvalidUserName -f $properties.UserName

            New-ArgumentException -ArgumentName 'UserName' -Message $errorMessage
        }
    }
}
