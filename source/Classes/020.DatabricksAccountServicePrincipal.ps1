<#
    .SYNOPSIS
        The `DatabricksAccountServicePrincipal` DSC resource is used to create, modify, or remove
        service principals in a Databricks account at the account level.

    .DESCRIPTION
        The `DatabricksAccountServicePrincipal` DSC resource is used to create, modify, or remove
        service principals in a Databricks account using the account-level SCIM API.

        This resource manages service principals at the account level, making them available across
        all workspaces in the account. For workspace-specific service principal management, use the
        `DatabricksServicePrincipal` resource.

        ## Requirements

        * Target machine must have network connectivity to the Databricks account console.
        * A valid Databricks Account API token with admin privileges.

        ## Known issues

        All issues are not listed here, see [all open issues](https://github.com/Gijsreyn/DatabricksDsc/issues?q=is%3Aissue+is%3Aopen+in%3Atitle+DatabricksAccountServicePrincipal).

        ### Using `AccessToken` property

        The `AccessToken` must be provided as a SecureString containing the
        Account API token.

    .PARAMETER AccountId
        The Databricks account ID (UUID format). This identifies the target account.

    .PARAMETER ApplicationId
        The application ID (GUID) of the service principal. This is the unique identifier.

    .PARAMETER DisplayName
        The display name of the service principal.

    .PARAMETER Active
        Specifies if the service principal account should be active. Defaults to `$true`.

    .PARAMETER Roles
        Array of roles assigned to the service principal. Typically used for admin role assignment.

    .PARAMETER ExternalId
        External ID of the service principal. This is read-only and reserved for future use.

    .PARAMETER Id
        The internal Databricks service principal ID. This is read-only.

    .PARAMETER WorkspaceUrl
        The URL of the Databricks workspace. Required for API calls.

    .PARAMETER AccessToken
        The Account API Token used to authenticate to the Databricks account.
        Must be provided as a SecureString.

    .PARAMETER _exist
        Specifies if the service principal should exist or not. Used internally by DSC.

    .EXAMPLE
        DatabricksAccountServicePrincipal AccountServicePrincipalExample
        {
            AccountId     = '12345678-1234-1234-1234-123456789012'
            ApplicationId = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
            DisplayName   = 'ETL Service Principal'
            Active        = $true
            WorkspaceUrl  = 'https://accounts.azuredatabricks.net'
            AccessToken   = $accessToken
        }

        Creates or updates a service principal at the account level.
#>

[DscResource()]
class DatabricksAccountServicePrincipal : DatabricksResourceBase
{
    [DscProperty(Key)]
    [System.String]
    $AccountId

    [DscProperty(Key)]
    [System.String]
    $ApplicationId

    [DscProperty()]
    [System.String]
    $DisplayName

    [DscProperty()]
    [System.Boolean]
    $Active = $true

    [DscProperty()]
    [UserRole[]]
    $Roles

    [DscProperty(NotConfigurable)]
    [System.String]
    $ExternalId

    [DscProperty(NotConfigurable)]
    [System.String]
    $Id

    DatabricksAccountServicePrincipal() : base ()
    {
        $this.ExcludeDscProperties = @(
            'WorkspaceUrl'
            'AccountId'
            'ApplicationId'
            'AccessToken'
            'Id'
            'ExternalId'
        )
    }

    [DatabricksAccountServicePrincipal] Get()
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
            $this.localizedData.EvaluatingAccountServicePrincipalState -f @(
                $properties.ApplicationId,
                $properties.AccountId
            )
        )

        $currentState = @{
            WorkspaceUrl  = $this.WorkspaceUrl
            AccountId     = $properties.AccountId
            ApplicationId = $properties.ApplicationId
            _exist        = $false
        }

        try
        {
            # Use SCIM filter to find service principal by applicationId
            $filter = "applicationId eq '$($properties.ApplicationId)'"
            $response = $this.InvokeDatabricksApi(
                'GET',
                "/api/2.0/accounts/$($properties.AccountId)/scim/v2/ServicePrincipals?filter=$filter",
                $null
            )

            if ($response -and $response.Resources -and $response.Resources.Count -gt 0)
            {
                $servicePrincipal = $response.Resources[0]

                $currentState.DisplayName = $servicePrincipal.displayName
                $currentState.Active = $servicePrincipal.active
                $currentState.Id = $servicePrincipal.id

                # Convert externalId if present
                if ($servicePrincipal.externalId)
                {
                    $currentState.ExternalId = $servicePrincipal.externalId
                }

                # Convert roles
                if ($servicePrincipal.roles)
                {
                    $currentState.Roles = @()
                    foreach ($role in $servicePrincipal.roles)
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
                    $this.localizedData.AccountServicePrincipalNotFound -f $properties.ApplicationId
                )
            }
        }
        catch
        {
            Write-Verbose -Message (
                $this.localizedData.ErrorGettingAccountServicePrincipal -f @(
                    $properties.ApplicationId,
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
        # Check if _exist property needs to be changed (service principal should be created or removed)
        if ($properties.ContainsKey('_exist'))
        {
            # Evaluate the desired state for property _exist
            if ($properties._exist -eq $true)
            {
                # Create the service principal since it doesn't exist
                Write-Verbose -Message (
                    $this.localizedData.CreatingAccountServicePrincipal -f $this.ApplicationId
                )

                $body = $this.BuildAccountServicePrincipalPayload($properties)
                $body.applicationId = $this.ApplicationId
                $body.schemas = @('urn:ietf:params:scim:schemas:core:2.0:ServicePrincipal')

                try
                {
                    $this.InvokeDatabricksApi(
                        'POST',
                        "/api/2.0/accounts/$($this.AccountId)/scim/v2/ServicePrincipals",
                        $body
                    )

                    Write-Verbose -Message (
                        $this.localizedData.AccountServicePrincipalCreated -f $this.ApplicationId
                    )
                }
                catch
                {
                    $errorMessage = $this.localizedData.FailedToCreateAccountServicePrincipal -f @(
                        $this.ApplicationId,
                        $_.Exception.Message
                    )

                    New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
                }
            }
            else
            {
                # Remove the service principal since it exists
                Write-Verbose -Message (
                    $this.localizedData.RemovingAccountServicePrincipal -f $this.ApplicationId
                )

                try
                {
                    $this.InvokeDatabricksApi(
                        'DELETE',
                        "/api/2.0/accounts/$($this.AccountId)/scim/v2/ServicePrincipals/$($this.Id)",
                        $null
                    )

                    Write-Verbose -Message (
                        $this.localizedData.AccountServicePrincipalRemoved -f $this.ApplicationId
                    )
                }
                catch
                {
                    $errorMessage = $this.localizedData.FailedToRemoveAccountServicePrincipal -f @(
                        $this.ApplicationId,
                        $_.Exception.Message
                    )

                    New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
                }
            }
        }
        else
        {
            # Update existing service principal properties (service principal exists and should exist)
            # At this point it is assumed the service principal exists since _exist property was in desired state
            if ($this._exist -eq $true)
            {
                Write-Verbose -Message (
                    $this.localizedData.UpdatingAccountServicePrincipal -f $this.ApplicationId
                )

                $body = $this.BuildAccountServicePrincipalPatchPayload($properties)

                try
                {
                    $this.InvokeDatabricksApi(
                        'PATCH',
                        "/api/2.0/accounts/$($this.AccountId)/scim/v2/ServicePrincipals/$($this.Id)",
                        $body
                    )

                    Write-Verbose -Message (
                        $this.localizedData.AccountServicePrincipalUpdated -f $this.ApplicationId
                    )
                }
                catch
                {
                    $errorMessage = $this.localizedData.FailedToUpdateAccountServicePrincipal -f @(
                        $this.ApplicationId,
                        $_.Exception.Message
                    )

                    New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
                }
            }
        }
    }

    <#
        Helper method to build the account service principal payload for API calls.
    #>
    hidden [System.Collections.Hashtable] BuildAccountServicePrincipalPayload([System.Collections.Hashtable] $properties)
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
        Helper method to build the SCIM PATCH payload for account service principal updates.
        Uses SCIM PatchOp format as per documentation.
    #>
    hidden [System.Collections.Hashtable] BuildAccountServicePrincipalPatchPayload([System.Collections.Hashtable] $properties)
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

        # Validate ApplicationId is a valid GUID
        if ($this.ApplicationId -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')
        {
            $errorMessage = $this.localizedData.InvalidApplicationId -f $this.ApplicationId

            New-ArgumentException -ArgumentName 'ApplicationId' -Message $errorMessage
        }
    }
}
