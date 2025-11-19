<#
    .SYNOPSIS
        The `DatabricksClusterPolicy` DSC resource is used to create, modify, or remove
        cluster policies in a Databricks workspace.

    .DESCRIPTION
        The `DatabricksClusterPolicy` DSC resource is used to create, modify, or remove
        cluster policies in a Databricks workspace using the Policies API.

        ## Requirements

        * Target machine must have network connectivity to the Databricks workspace.
        * A valid Databricks Personal Access Token (PAT) with admin privileges.

        ## Known issues

        All issues are not listed here, see [all open issues](https://github.com/Gijsreyn/DatabricksDsc/issues?q=is%3Aissue+is%3Aopen+in%3Atitle+DatabricksClusterPolicy).

        ### Using `AccessToken` property

        The `AccessToken` must be provided as a SecureString containing the
        Personal Access Token.

    .PARAMETER Name
        The name of the cluster policy. This is the unique identifier.

    .PARAMETER Definition
        Policy definition document expressed in Databricks Cluster Policy Definition Language.
        This should be a hashtable that will be converted to JSON.

    .PARAMETER Description
        Additional human-readable description of the cluster policy. Maximum 1000 characters.

    .PARAMETER MaxClustersPerUser
        Max number of clusters per user that can be active using this policy. If not present, there is no max limit.

    .PARAMETER PolicyFamilyDefinitionOverrides
        Policy family definition overrides expressed as a hashtable. Cannot be used with Definition.

    .PARAMETER PolicyFamilyId
        ID of the policy family. Cannot be used with Definition.

    .PARAMETER Libraries
        A list of libraries to be installed on the next cluster restart that uses this policy. Maximum of 500 libraries.

    .PARAMETER _exist
        Specifies whether the cluster policy should exist in the workspace. Defaults to `$true`.
        Set to `$false` to remove the policy.

    .EXAMPLE
        $token = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
        $definition = @{
            'custom_tags.test_tag' = @{
                type  = 'fixed'
                value = 'test_value'
            }
        }
        Invoke-DscResource -ModuleName DatabricksDsc -Name DatabricksClusterPolicy -Method Set -Property @{
            WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
            AccessToken  = $token
            Name         = 'Test Policy'
            Definition   = $definition
            Description  = 'A test cluster policy'
        }

        This example shows how to create a cluster policy using Invoke-DscResource.
#>
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
[DscResource(RunAsCredential = 'NotSupported')]
class DatabricksClusterPolicy : DatabricksResourceBase
{
    [DscProperty(Key)]
    [System.String]
    $Name

    [DscProperty()]
    [System.Collections.Hashtable]
    $Definition

    [DscProperty()]
    [ValidateLength(0, 1000)]
    [System.String]
    $Description

    [DscProperty()]
    [ValidateRange(1, [System.Int64]::MaxValue)]
    [Nullable[System.Int64]]
    $MaxClustersPerUser

    [DscProperty()]
    [System.Collections.Hashtable]
    $PolicyFamilyDefinitionOverrides

    [DscProperty()]
    [System.String]
    $PolicyFamilyId

    [DscProperty()]
    [ClusterPolicyLibrary[]]
    $Libraries

    [DscProperty(NotConfigurable)]
    [System.String]
    $PolicyId

    [DscProperty()]
    [System.Boolean]
    $_exist = $true

    DatabricksClusterPolicy () : base ()
    {
        # These properties will not be enforced.
        $this.ExcludeDscProperties = @(
            'WorkspaceUrl'
            'Name'
            'AccessToken'
        )
    }

    [DatabricksClusterPolicy] Get()
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
            $this.localizedData.EvaluatingPolicyState -f @(
                $properties.Name,
                $this.WorkspaceUrl
            )
        )

        $currentState = @{
            WorkspaceUrl = $this.WorkspaceUrl
            AccessToken  = $this.AccessToken
            Name         = $properties.Name
            _exist       = $false
        }

        try
        {
            # Get all cluster policies and filter by name
            $response = $this.InvokeDatabricksApi(
                'GET',
                '/api/2.0/policies/clusters/list',
                $null
            )

            $policy = $response.policies | Where-Object -FilterScript {
                $_.name -eq $properties.Name
            } | Select-Object -First 1

            if ($policy)
            {
                $currentState._exist = $true
                $currentState.PolicyId = $policy.policy_id
                $currentState.Description = $policy.description
                $currentState.PolicyFamilyId = $policy.policy_family_id

                if ($policy.max_clusters_per_user)
                {
                    $currentState.MaxClustersPerUser = $policy.max_clusters_per_user
                }

                # Parse definition JSON string to hashtable
                if ($policy.definition)
                {
                    $currentState.Definition = $policy.definition | ConvertFrom-Json -AsHashtable
                }

                # Parse policy family definition overrides
                if ($policy.policy_family_definition_overrides)
                {
                    $currentState.PolicyFamilyDefinitionOverrides = $policy.policy_family_definition_overrides | ConvertFrom-Json -AsHashtable
                }

                # Convert libraries
                if ($policy.libraries)
                {
                    $currentState.Libraries = @()
                    foreach ($library in $policy.libraries)
                    {
                        $lib = [ClusterPolicyLibrary]::new()

                        if ($library.cran)
                        {
                            $lib.Cran = [CranLibrary]@{
                                Package = $library.cran.package
                                Repo    = $library.cran.repo
                            }
                        }
                        elseif ($library.jar)
                        {
                            $lib.Jar = $library.jar
                        }
                        elseif ($library.maven)
                        {
                            $lib.Maven = [MavenLibrary]@{
                                Coordinates = $library.maven.coordinates
                                Exclusions  = $library.maven.exclusions
                                Repo        = $library.maven.repo
                            }
                        }
                        elseif ($library.pypi)
                        {
                            $lib.PyPi = [PyPiLibrary]@{
                                Package = $library.pypi.package
                                Repo    = $library.pypi.repo
                            }
                        }
                        elseif ($library.requirements)
                        {
                            $lib.Requirements = $library.requirements
                        }
                        elseif ($library.whl)
                        {
                            $lib.Whl = $library.whl
                        }

                        $currentState.Libraries += $lib
                    }
                }
            }
            else
            {
                # When policy doesn't exist, set all other properties to $null
                # so they don't get compared (only _exist should matter)
                $currentState.Description = $null
                $currentState.Definition = $null
                $currentState.MaxClustersPerUser = $null
                $currentState.PolicyFamilyDefinitionOverrides = $null
                $currentState.PolicyFamilyId = $null
                $currentState.Libraries = $null
                $currentState.PolicyId = $null

                Write-Verbose -Message (
                    $this.localizedData.PolicyNotFound -f $properties.Name
                )
            }
        }
        catch
        {
            Write-Verbose -Message (
                $this.localizedData.ErrorGettingPolicy -f @(
                    $properties.Name,
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
        # Check if _exist property needs to be changed (policy should be created or removed)
        if ($properties.ContainsKey('_exist'))
        {
            # Evaluate the desired state for property _exist
            if ($properties._exist -eq $true)
            {
                # Create the policy since it doesn't exist
                Write-Verbose -Message (
                    $this.localizedData.CreatingPolicy -f $this.Name
                )

                $body = $this.BuildPolicyPayload($properties)

                $response = $this.InvokeDatabricksApi(
                    'POST',
                    '/api/2.0/policies/clusters/create',
                    $body
                )

                Write-Verbose -Message (
                    $this.localizedData.PolicyCreated -f $this.Name
                )
            }
            else
            {
                # Remove the policy since it exists but shouldn't
                Write-Verbose -Message (
                    $this.localizedData.RemovingPolicy -f $this.Name
                )

                # Get current policy ID if not already set
                if ([System.String]::IsNullOrEmpty($this.PolicyId))
                {
                    $currentState = $this.GetCurrentState(@{
                        Name = $this.Name
                    })

                    $id = $currentState.PolicyId
                }
                else
                {
                    $id = $this.PolicyId
                }

                $body = @{
                    policy_id = $id
                }

                $this.InvokeDatabricksApi(
                    'POST',
                    '/api/2.0/policies/clusters/delete',
                    $body
                )

                Write-Verbose -Message (
                    $this.localizedData.PolicyRemoved -f $this.Name
                )
            }
        }
        else
        {
            # Update existing policy
            if ($this._exist -eq $true)
            {
                Write-Verbose -Message (
                    $this.localizedData.UpdatingPolicy -f $this.Name
                )

                # Get current policy ID if not already set
                if ([System.String]::IsNullOrEmpty($this.PolicyId))
                {
                    $currentState = $this.GetCurrentState(@{
                        Name = $this.Name
                    })

                    $id = $currentState.PolicyId
                }
                else
                {
                    $id = $this.PolicyId
                }

                $body = $this.BuildPolicyPayload($properties)

                # Add policy_id for update
                $body.policy_id = $id

                $this.InvokeDatabricksApi(
                    'POST',
                    '/api/2.0/policies/clusters/edit',
                    $body
                )

                Write-Verbose -Message (
                    $this.localizedData.PolicyUpdated -f $this.Name
                )
            }
        }
    }

    <#
        Helper method to build the policy payload for create/update operations.
    #>
    hidden [System.Collections.Hashtable] BuildPolicyPayload([System.Collections.Hashtable] $properties)
    {
        $payload = @{
            name = $this.Name
        }

        if ($properties.ContainsKey('Definition') -and $null -ne $properties.Definition)
        {
            $payload.definition = ($properties.Definition | ConvertTo-Json -Depth 10 -Compress)
        }
        elseif ($null -ne $this.Definition)
        {
            $payload.definition = ($this.Definition | ConvertTo-Json -Depth 10 -Compress)
        }

        if ($properties.ContainsKey('Description') -and $null -ne $properties.Description)
        {
            $payload.description = $properties.Description
        }
        elseif ($null -ne $this.Description)
        {
            $payload.description = $this.Description
        }

        if ($properties.ContainsKey('MaxClustersPerUser') -and $null -ne $properties.MaxClustersPerUser)
        {
            $payload.max_clusters_per_user = $properties.MaxClustersPerUser
        }
        elseif ($null -ne $this.MaxClustersPerUser)
        {
            $payload.max_clusters_per_user = $this.MaxClustersPerUser
        }

        if ($properties.ContainsKey('PolicyFamilyDefinitionOverrides') -and $null -ne $properties.PolicyFamilyDefinitionOverrides)
        {
            $payload.policy_family_definition_overrides = ($properties.PolicyFamilyDefinitionOverrides | ConvertTo-Json -Depth 10 -Compress)
        }
        elseif ($null -ne $this.PolicyFamilyDefinitionOverrides)
        {
            $payload.policy_family_definition_overrides = ($this.PolicyFamilyDefinitionOverrides | ConvertTo-Json -Depth 10 -Compress)
        }

        if ($properties.ContainsKey('PolicyFamilyId') -and $null -ne $properties.PolicyFamilyId)
        {
            $payload.policy_family_id = $properties.PolicyFamilyId
        }
        elseif ($null -ne $this.PolicyFamilyId)
        {
            $payload.policy_family_id = $this.PolicyFamilyId
        }

        if ($properties.ContainsKey('Libraries') -and $null -ne $properties.Libraries)
        {
            $payload.libraries = $this.ConvertLibrariesToApiFormat($properties.Libraries)
        }
        elseif ($null -ne $this.Libraries)
        {
            $payload.libraries = $this.ConvertLibrariesToApiFormat($this.Libraries)
        }

        return $payload
    }

    <#
        Helper method to convert ClusterPolicyLibrary objects to API format.
    #>
    hidden [System.Array] ConvertLibrariesToApiFormat([ClusterPolicyLibrary[]] $libraries)
    {
        $apiLibraries = @()

        foreach ($library in $libraries)
        {
            $apiLib = @{}

            if ($null -ne $library.Cran)
            {
                $apiLib.cran = @{
                    package = $library.Cran.Package
                }
                if ($library.Cran.Repo)
                {
                    $apiLib.cran.repo = $library.Cran.Repo
                }
            }
            elseif ($null -ne $library.Jar)
            {
                $apiLib.jar = $library.Jar
            }
            elseif ($null -ne $library.Maven)
            {
                $apiLib.maven = @{
                    coordinates = $library.Maven.Coordinates
                }
                if ($library.Maven.Exclusions)
                {
                    $apiLib.maven.exclusions = $library.Maven.Exclusions
                }
                if ($library.Maven.Repo)
                {
                    $apiLib.maven.repo = $library.Maven.Repo
                }
            }
            elseif ($null -ne $library.PyPi)
            {
                $apiLib.pypi = @{
                    package = $library.PyPi.Package
                }
                if ($library.PyPi.Repo)
                {
                    $apiLib.pypi.repo = $library.PyPi.Repo
                }
            }
            elseif ($null -ne $library.Requirements)
            {
                $apiLib.requirements = $library.Requirements
            }
            elseif ($null -ne $library.Whl)
            {
                $apiLib.whl = $library.Whl
            }

            $apiLibraries += $apiLib
        }

        return $apiLibraries
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

        # Validate that Definition and PolicyFamilyId are not both specified
        if ($null -ne $this.Definition -and $null -ne $this.PolicyFamilyId)
        {
            $errorMessage = $this.localizedData.DefinitionAndPolicyFamilyIdMutuallyExclusive

            New-ArgumentException -ArgumentName 'Definition' -Message $errorMessage
        }

        # Validate libraries count (max 500)
        if ($null -ne $this.Libraries -and $this.Libraries.Count -gt 500)
        {
            $errorMessage = $this.localizedData.TooManyLibraries -f $this.Libraries.Count

            New-ArgumentException -ArgumentName 'Libraries' -Message $errorMessage
        }
    }
}
