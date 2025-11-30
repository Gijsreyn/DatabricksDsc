<#
    .SYNOPSIS
        The `DatabricksSecret` DSC resource is used to create, modify, or remove
        secrets in a Databricks secret scope.

    .DESCRIPTION
        The `DatabricksSecret` DSC resource is used to create, modify, or remove
        secrets in a Databricks secret scope using the Secrets API.

        A secret is a key-value pair that is stored within a secret scope. Secrets
        store credentials and other sensitive information securely. This resource
        supports both string values (UTF-8) and byte values (base64-encoded).

        ## Requirements

        * Target machine must have network connectivity to the Databricks workspace.
        * A valid Databricks Personal Access Token (PAT) with appropriate privileges.
        * The secret scope must exist before creating secrets within it.
        * Cannot be used with Azure Key Vault-backed scopes (use Azure Key Vault directly).

        ## Known issues

        All issues are not listed here, see [all open issues](https://github.com/Gijsreyn/DatabricksDsc/issues?q=is%3Aissue+is%3Aopen+in%3Atitle+DatabricksSecret).

        ### Using `AccessToken` property

        The `AccessToken` must be provided as a SecureString containing the
        Personal Access Token.

        ### Limitations

        * The Databricks Secrets API does not return secret values, so this resource
          cannot detect if a secret's value has changed. When Set() is called on an
          existing secret, it will be deleted and recreated to ensure desired state.
        * Secret keys must consist of alphanumeric characters, dashes, underscores,
          and periods, and cannot exceed 128 characters.
        * Maximum secret size is 128 KB.
        * Maximum of 1000 secrets per scope.

    .PARAMETER ScopeName
        The name of the secret scope containing the secret. This is a key parameter.

    .PARAMETER SecretKey
        A unique name to identify the secret. Must consist of alphanumeric characters,
        dashes, underscores, and periods, and cannot exceed 128 characters.
        This is a key parameter.

    .PARAMETER StringValue
        The secret value as a string. If specified, value will be stored in UTF-8 (MB4) form.
        Cannot be used together with BytesValue. Maximum size is 128 KB.

    .PARAMETER BytesValue
        The secret value as bytes (base64 encoded). If specified, value will be stored as bytes.
        Cannot be used together with StringValue. Maximum size is 128 KB.

    .PARAMETER _exist
        Specifies whether the secret should exist in the secret scope. Defaults to `$true`.
        Set to `$false` to remove the secret.

    .EXAMPLE
        $token = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
        Invoke-DscResource -ModuleName DatabricksDsc -Name DatabricksSecret -Method Set -Property @{
            WorkspaceUrl  = 'https://adb-1234567890123456.12.azuredatabricks.net'
            AccessToken   = $token
            ScopeName     = 'my-scope'
            SecretKey     = 'my-secret-key'
            StringValue   = 'my-secret-value'
        }

        This example shows how to create a secret with a string value using Invoke-DscResource.

    .EXAMPLE
        $token = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
        Invoke-DscResource -ModuleName DatabricksDsc -Name DatabricksSecret -Method Set -Property @{
            WorkspaceUrl  = 'https://adb-1234567890123456.12.azuredatabricks.net'
            AccessToken   = $token
            ScopeName     = 'my-scope'
            SecretKey     = 'my-binary-secret'
            BytesValue    = 'dGVzdC1ieXRlcw=='
        }

        This example shows how to create a secret with a byte value using Invoke-DscResource.
#>
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
[DscResource(RunAsCredential = 'NotSupported')]
class DatabricksSecret : DatabricksResourceBase
{
    [DscProperty(Key)]
    [System.String]
    $ScopeName

    [DscProperty(Key)]
    [System.String]
    [ValidateLength(1, 128)]
    [ValidatePattern('^[a-zA-Z0-9._-]+$')]
    $SecretKey

    [DscProperty()]
    [System.String]
    $StringValue

    [DscProperty()]
    [System.String]
    $BytesValue

    [DscProperty()]
    [System.Boolean]
    $_exist = $true

    DatabricksSecret () : base ()
    {
        # These properties will not be enforced.
        $this.ExcludeDscProperties = @(
            'WorkspaceUrl'
            'ScopeName'
            'SecretKey'
            'AccessToken'
        )
    }

    [DatabricksSecret] Get()
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
            $this.localizedData.GetCurrentState -f @(
                $properties.SecretKey,
                $properties.ScopeName
            )
        )

        $currentState = @{
            WorkspaceUrl = $this.WorkspaceUrl
            AccessToken  = $this.AccessToken
            ScopeName    = $properties.ScopeName
            SecretKey    = $properties.SecretKey
            _exist       = $false
        }

        try
        {
            $secret = Get-DatabricksSecret -WorkspaceUrl $this.WorkspaceUrl -AccessToken $this.AccessToken -ScopeName $properties.ScopeName -SecretKey $properties.SecretKey

            if ($secret)
            {
                $currentState._exist = $true

                Write-Verbose -Message (
                    $this.localizedData.SecretExists -f @(
                        $properties.SecretKey,
                        $properties.ScopeName
                    )
                )

                # Note: The API does not return secret values for security reasons
                # StringValue and BytesValue cannot be retrieved and remain null
                $currentState.StringValue = $null
                $currentState.BytesValue = $null
            }
            else
            {
                # When secret doesn't exist, set all other properties to $null
                $currentState.StringValue = $null
                $currentState.BytesValue = $null

                Write-Verbose -Message (
                    $this.localizedData.SecretDoesNotExist -f @(
                        $properties.SecretKey,
                        $properties.ScopeName
                    )
                )
            }
        }
        catch
        {
            Write-Verbose -Message (
                $this.localizedData.ErrorGettingSecret -f @(
                    $properties.ScopeName,
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
        # Check if _exist property needs to be changed (secret should be created or removed)
        if ($properties.ContainsKey('_exist'))
        {
            # Evaluate the desired state for property _exist
            if ($properties._exist -eq $true)
            {
                # Create the secret since it doesn't exist
                Write-Verbose -Message (
                    $this.localizedData.CreatingNewSecret -f @($this.SecretKey, $this.ScopeName)
                )

                # Validate that at least one value is provided
                $hasStringValue = -not [string]::IsNullOrEmpty($this.StringValue)
                $hasBytesValue = -not [string]::IsNullOrEmpty($this.BytesValue)

                if (-not $hasStringValue -and -not $hasBytesValue)
                {
                    $errorMessage = $this.localizedData.NoValueSpecified

                    New-ArgumentException -ArgumentName 'StringValue/BytesValue' -Message $errorMessage
                }

                $createParams = @{
                    WorkspaceUrl = $this.WorkspaceUrl
                    AccessToken  = $this.AccessToken
                    ScopeName    = $this.ScopeName
                    SecretKey    = $this.SecretKey
                }

                if ($hasStringValue)
                {
                    $createParams.StringValue = $this.StringValue
                }
                elseif ($hasBytesValue)
                {
                    $createParams.BytesValue = $this.BytesValue
                }

                New-DatabricksSecret @createParams

                Write-Verbose -Message (
                    $this.localizedData.SecretCreated -f @($this.SecretKey, $this.ScopeName)
                )
            }
            else
            {
                # Remove the secret since it exists but shouldn't
                Write-Verbose -Message (
                    $this.localizedData.DeletingSecret -f @($this.SecretKey, $this.ScopeName)
                )

                Remove-DatabricksSecret -WorkspaceUrl $this.WorkspaceUrl -AccessToken $this.AccessToken -ScopeName $this.ScopeName -SecretKey $this.SecretKey

                Write-Verbose -Message (
                    $this.localizedData.SecretRemoved -f @($this.SecretKey, $this.ScopeName)
                )
            }
        }
        else
        {
            # Secrets cannot be updated - they must be deleted and recreated
            # This handles the case where StringValue or BytesValue has changed
            if ($this._exist -eq $true)
            {
                Write-Verbose -Message (
                    $this.localizedData.ValueCannotBeChanged -f $this.SecretKey
                )

                # Remove existing secret
                Write-Verbose -Message (
                    $this.localizedData.RemovingSecret -f @($this.SecretKey, $this.ScopeName)
                )

                Remove-DatabricksSecret -WorkspaceUrl $this.WorkspaceUrl -AccessToken $this.AccessToken -ScopeName $this.ScopeName -SecretKey $this.SecretKey

                Write-Verbose -Message (
                    $this.localizedData.SecretRemoved -f @($this.SecretKey, $this.ScopeName)
                )

                # Recreate with new value
                Write-Verbose -Message (
                    $this.localizedData.CreatingSecret -f @($this.SecretKey, $this.ScopeName)
                )

                # Validate that at least one value is provided
                $hasStringValue = -not [string]::IsNullOrEmpty($this.StringValue)
                $hasBytesValue = -not [string]::IsNullOrEmpty($this.BytesValue)

                if (-not $hasStringValue -and -not $hasBytesValue)
                {
                    $errorMessage = $this.localizedData.NoValueSpecified

                    New-ArgumentException -ArgumentName 'StringValue/BytesValue' -Message $errorMessage
                }

                $createParams = @{
                    WorkspaceUrl = $this.WorkspaceUrl
                    AccessToken  = $this.AccessToken
                    ScopeName    = $this.ScopeName
                    SecretKey    = $this.SecretKey
                }

                if ($hasStringValue)
                {
                    $createParams.StringValue = $this.StringValue
                }
                elseif ($hasBytesValue)
                {
                    $createParams.BytesValue = $this.BytesValue
                }

                New-DatabricksSecret @createParams

                Write-Verbose -Message (
                    $this.localizedData.SecretCreated -f @($this.SecretKey, $this.ScopeName)
                )
            }
        }
    }

    <#
        This method is called to validate the properties before they are set.
    #>
    hidden [void] AssertProperties([System.Collections.Hashtable] $properties)
    {
        # Validate WorkspaceUrl format
        if ($this.WorkspaceUrl -notmatch '^https://')
        {
            $errorMessage = $this.localizedData.InvalidWorkspaceUrl -f $this.WorkspaceUrl

            New-ArgumentException -ArgumentName 'WorkspaceUrl' -Message $errorMessage
        }

        # Validate secret key pattern
        if ($this.SecretKey -notmatch '^[a-zA-Z0-9._-]+$')
        {
            $errorMessage = $this.localizedData.InvalidSecretKey -f $this.SecretKey

            New-ArgumentException -ArgumentName 'SecretKey' -Message $errorMessage
        }

        # Check that only one value type is specified
        $hasStringValue = -not [string]::IsNullOrEmpty($this.StringValue)
        $hasBytesValue = -not [string]::IsNullOrEmpty($this.BytesValue)

        if ($hasStringValue -and $hasBytesValue)
        {
            $errorMessage = $this.localizedData.BothValuesSpecified

            New-InvalidOperationException -Message $errorMessage
        }
    }

    <#
        .SYNOPSIS
            Exports all secrets from the Databricks workspace.

        .DESCRIPTION
            The Export() static method retrieves all secrets from secret scopes
            in the Databricks workspace and returns them as an array of
            DatabricksSecret instances.

            Note: Secret values are not exported as the API does not return them
            for security reasons. Users must populate StringValue or BytesValue
            manually after export.

        .EXAMPLE
            # Export all secrets from all scopes
            $instance = [DatabricksSecret]::new()
            $instance.WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
            $instance.AccessToken = $token
            [DatabricksSecret]::Export($instance)

        .EXAMPLE
            # Export secrets from a specific scope
            $instance = [DatabricksSecret]::new()
            $instance.WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
            $instance.AccessToken = $token
            $instance.ScopeName = 'my-scope'
            [DatabricksSecret]::Export($instance)

        .OUTPUTS
            [DatabricksSecret[]] Array of instances matching the filter criteria.
    #>
    static [DatabricksResourceBase[]] Export([DatabricksResourceBase] $FilteringInstance)
    {
        $resourceType = $FilteringInstance.GetType().Name

        try
        {
            Write-Verbose -Message (
                $FilteringInstance.localizedData.ExportingResources -f $resourceType
            )

            $exportedSecrets = [System.Collections.Generic.List[DatabricksResourceBase]]::new()

            # Get all scopes or the specified scope
            $scopes = @()

            if (-not [string]::IsNullOrEmpty($FilteringInstance.ScopeName))
            {
                $scopeParams = @{
                    WorkspaceUrl = $FilteringInstance.WorkspaceUrl
                    AccessToken  = $FilteringInstance.AccessToken
                    ScopeName    = $FilteringInstance.ScopeName
                }

                $scope = Get-DatabricksSecretScope @scopeParams

                if ($null -ne $scope)
                {
                    $scopes = @($scope)
                }
            }
            else
            {
                $scopeParams = @{
                    WorkspaceUrl = $FilteringInstance.WorkspaceUrl
                    AccessToken  = $FilteringInstance.AccessToken
                }

                $response = Get-DatabricksSecretScope @scopeParams

                if ($null -ne $response.scopes)
                {
                    $scopes = $response.scopes
                }
            }

            if ($scopes.Count -eq 0)
            {
                Write-Verbose -Message (
                    $FilteringInstance.localizedData.NoResourcesFound -f $resourceType
                )
                return @()
            }

            # Process each scope
            foreach ($scope in $scopes)
            {
                Write-Verbose -Message (
                    $FilteringInstance.localizedData.ExportingSecretsFromScope -f $scope.name
                )

                try
                {
                    $secretParams = @{
                        WorkspaceUrl = $FilteringInstance.WorkspaceUrl
                        AccessToken  = $FilteringInstance.AccessToken
                        ScopeName    = $scope.name
                    }

                    $response = Get-DatabricksSecret @secretParams

                    if ($null -ne $response.secrets -and $response.secrets.Count -gt 0)
                    {
                        Write-Verbose -Message (
                            $FilteringInstance.localizedData.FoundSecrets -f @(
                                $response.secrets.Count,
                                $scope.name
                            )
                        )

                        foreach ($secret in $response.secrets)
                        {
                            $exportInstance = [DatabricksSecret]::new()
                            $exportInstance.WorkspaceUrl = $FilteringInstance.WorkspaceUrl
                            $exportInstance.AccessToken = $FilteringInstance.AccessToken
                            $exportInstance.ScopeName = $scope.name
                            $exportInstance.SecretKey = $secret.key
                            $exportInstance._exist = $true

                            # Note: StringValue and BytesValue are not set because
                            # the API doesn't return them for security reasons
                            # Users will need to populate these manually

                            $exportedSecrets.Add($exportInstance)
                        }
                    }
                    else
                    {
                        Write-Verbose -Message (
                            $FilteringInstance.localizedData.NoSecretsFound -f $scope.name
                        )
                    }
                }
                catch
                {
                    Write-Verbose -Message (
                        $FilteringInstance.localizedData.NoSecretsFound -f $scope.name
                    )
                }
            }

            # Get all properties from the filtering instance that have values
            # Exclude common base properties and DSC framework properties
            $filterProperties = $FilteringInstance.PSObject.Properties.Where{
                $_.Name -notin @('WorkspaceUrl', 'AccessToken', 'Reasons', 'ScopeName', 'SecretKey', 'StringValue', 'BytesValue', 'localizedData', '_exist', 'ExcludeDscProperties') -and
                -not [string]::IsNullOrEmpty($_.Value)
            }

            # If no filter properties or only ScopeName (already filtered), return all resources
            if ($filterProperties.Count -eq 0)
            {
                Write-Verbose -Message (
                    "Returning all {0} secret(s)" -f $exportedSecrets.Count
                )
                return $exportedSecrets.ToArray()
            }

            # Additional filtering based on other properties (future extensibility)
            $filteredResources = $exportedSecrets.Where{
                $resource = $_
                $matches = $true

                foreach ($property in $filterProperties)
                {
                    $resourceValue = $resource.($property.Name)
                    $filterValue = $property.Value

                    if ($resourceValue -ne $filterValue)
                    {
                        $matches = $false
                        break
                    }
                }

                $matches
            }

            Write-Verbose -Message (
                "Returning {0} filtered secret(s)" -f $filteredResources.Count
            )

            return $filteredResources
        }
        catch
        {
            $errorMessage = $FilteringInstance.localizedData.ExportFailed -f @(
                $resourceType,
                $_.Exception.Message
            )

            Write-Verbose -Message $errorMessage
            return @()
        }
    }
}
