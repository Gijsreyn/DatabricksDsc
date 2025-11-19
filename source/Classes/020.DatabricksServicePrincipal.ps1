<#
    .SYNOPSIS
        The `DatabricksServicePrincipal` DSC resource is used to create, modify, or remove
        service principals in a Databricks workspace at the workspace level.

    .DESCRIPTION
        The `DatabricksServicePrincipal` DSC resource is used to create, modify, or remove
        service principals in a Databricks workspace using the workspace-level SCIM API.

        This resource manages service principals within a specific workspace. For account-level
        service principal management across all workspaces, use the `DatabricksAccountServicePrincipal` resource.

        ## Requirements

        * Target machine must have network connectivity to the Databricks workspace.
        * A valid Databricks Personal Access Token (PAT) with admin privileges.

        ## Known issues

        All issues are not listed here, see [all open issues](https://github.com/Gijsreyn/DatabricksDsc/issues?q=is%3Aissue+is%3Aopen+in%3Atitle+DatabricksServicePrincipal).

        ### Using `AccessToken` property

        The `AccessToken` must be provided as a SecureString containing the
        Personal Access Token.

    .PARAMETER ApplicationId
        The application ID (GUID) of the service principal. This is the unique identifier.

    .PARAMETER DisplayName
        The display name of the service principal.

    .PARAMETER Active
        Specifies if the service principal account should be active. Defaults to `$true`.

    .PARAMETER Entitlements
        An array of entitlements assigned to the service principal.

    .PARAMETER Roles
        An array of roles assigned to the service principal.

    .PARAMETER ExternalId
        An external identifier for the service principal (optional).

    .PARAMETER _exist
        Specifies whether the service principal should exist in the workspace. Defaults to `$true`.
        Set to `$false` to remove the service principal.

    .EXAMPLE
        $token = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
        Invoke-DscResource -ModuleName DatabricksDsc -Name DatabricksServicePrincipal -Method Get -Property @{
            WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
            AccessToken  = $token
            ApplicationId = '12345678-1234-1234-1234-123456789012'
        }

        This example shows how to call the resource using Invoke-DscResource.
#>
[DscResource(RunAsCredential = 'NotSupported')]
class DatabricksServicePrincipal : DatabricksResourceBase
{
    [DscProperty(Key)]
    [System.String]
    $ApplicationId

    [DscProperty()]
    [System.String]
    $DisplayName

    [DscProperty()]
    [Nullable[System.Boolean]]
    $Active = $true

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

    DatabricksServicePrincipal () : base ()
    {
        # These properties will not be enforced.
        $this.ExcludeDscProperties = @(
            'WorkspaceUrl'
            'ApplicationId'
            'AccessToken'
            'Id'
        )
    }

    [DatabricksServicePrincipal] Get()
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
            $this.localizedData.EvaluatingServicePrincipalState -f @(
                $properties.ApplicationId,
                $this.WorkspaceUrl
            )
        )

        $currentState = @{
            WorkspaceUrl = $this.WorkspaceUrl
            AccessToken = $this.AccessToken
            ApplicationId = $properties.ApplicationId
            _exist = $false
        }

        try
        {
            # Get all service principals and filter by applicationId
            $response = $this.InvokeDatabricksApi(
                'GET',
                '/api/2.0/preview/scim/v2/ServicePrincipals',
                $null
            )

            $servicePrincipal = $response.Resources | Where-Object -FilterScript {
                $_.applicationId -eq $properties.ApplicationId
            } | Select-Object -First 1

            if ($servicePrincipal)
            {
                $currentState._exist = $true
                $currentState.Id = $servicePrincipal.id
                $currentState.DisplayName = $servicePrincipal.displayName
                $currentState.Active = $servicePrincipal.active
                $currentState.ExternalId = $servicePrincipal.externalId

                # Convert entitlements
                if ($servicePrincipal.entitlements)
                {
                    $currentState.Entitlements = @()
                    foreach ($entitlement in $servicePrincipal.entitlements)
                    {
                        $currentState.Entitlements += [UserEntitlement]@{
                            Value = $entitlement.value
                        }
                    }

                    # Sort entitlements for consistent comparison
                    $currentState.Entitlements = $currentState.Entitlements | Sort-Object
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
            }
            else
            {
                # When service principal doesn't exist, set all other properties to $null
                # so they don't get compared (only _exist should matter)
                $currentState.DisplayName = $null
                $currentState.Active = $null
                $currentState.Entitlements = $null
                $currentState.Roles = $null
                $currentState.ExternalId = $null
                $currentState.Id = $null

                Write-Verbose -Message (
                    $this.localizedData.ServicePrincipalNotFound -f $properties.ApplicationId
                )
            }
        }
        catch
        {
            Write-Verbose -Message (
                $this.localizedData.ErrorGettingServicePrincipal -f @(
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
                    $this.localizedData.CreatingServicePrincipal -f $this.ApplicationId
                )

                $body = $this.BuildServicePrincipalPayload($properties)
                $body.applicationId = $this.ApplicationId
                $body.schemas = @('urn:ietf:params:scim:schemas:core:2.0:ServicePrincipal')

                try
                {
                    $this.InvokeDatabricksApi(
                        'POST',
                        '/api/2.0/preview/scim/v2/ServicePrincipals',
                        $body
                    )

                    Write-Verbose -Message (
                        $this.localizedData.ServicePrincipalCreated -f $this.ApplicationId
                    )
                }
                catch
                {
                    $errorMessage = $this.localizedData.FailedToCreateServicePrincipal -f @(
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
                    $this.localizedData.RemovingServicePrincipal -f $this.ApplicationId
                )

                try
                {
                    $this.InvokeDatabricksApi(
                        'DELETE',
                        "/api/2.0/preview/scim/v2/ServicePrincipals/$($this.Id)",
                        $null
                    )

                    Write-Verbose -Message (
                        $this.localizedData.ServicePrincipalRemoved -f $this.ApplicationId
                    )
                }
                catch
                {
                    $errorMessage = $this.localizedData.FailedToRemoveServicePrincipal -f @(
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
                    $this.localizedData.UpdatingServicePrincipal -f $this.ApplicationId
                )

                $body = $this.BuildServicePrincipalPatchPayload($properties)

                try
                {
                    $this.InvokeDatabricksApi(
                        'PATCH',
                        "/api/2.0/preview/scim/v2/ServicePrincipals/$($this.Id)",
                        $body
                    )

                    Write-Verbose -Message (
                        $this.localizedData.ServicePrincipalUpdated -f $this.ApplicationId
                    )
                }
                catch
                {
                    $errorMessage = $this.localizedData.FailedToUpdateServicePrincipal -f @(
                        $this.ApplicationId,
                        $_.Exception.Message
                    )

                    New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
                }
            }
        }
    }

    <#
        Helper method to build the service principal payload for API calls.
    #>
    hidden [System.Collections.Hashtable] BuildServicePrincipalPayload([System.Collections.Hashtable] $properties)
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
        Helper method to build the SCIM PATCH payload for service principal updates.
        Uses SCIM PatchOp format as per documentation.
    #>
    hidden [System.Collections.Hashtable] BuildServicePrincipalPatchPayload([System.Collections.Hashtable] $properties)
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
        This method is called to validate the properties before they are set.
    #>
    hidden [void] AssertProperties([System.Collections.Hashtable] $properties)
    {
        # Validate WorkspaceUrl format
        if ($properties.WorkspaceUrl -notmatch '^https://')
        {
            $errorMessage = $this.localizedData.InvalidWorkspaceUrl -f $properties.WorkspaceUrl

            New-ArgumentException -ArgumentName 'WorkspaceUrl' -Message $errorMessage
        }

        # Validate ApplicationId format (should be a GUID)
        if ($properties.ApplicationId -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')
        {
            $errorMessage = $this.localizedData.InvalidApplicationId -f $properties.ApplicationId

            New-ArgumentException -ArgumentName 'ApplicationId' -Message $errorMessage
        }
    }
}
