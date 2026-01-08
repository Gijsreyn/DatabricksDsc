<#
    .SYNOPSIS
        The `DatabricksAccountRuleset` DSC resource manages access control rule sets
        for Databricks account-level resources.

    .DESCRIPTION
        The `DatabricksAccountRuleset` DSC resource is used to manage rule sets that
        control access to account-level resources such as service principals, groups,
        and tag policies.

        A rule set contains a list of grant rules that specify which principals
        (users, groups, service principals) have which roles on a particular resource.

        The resource follows the read-modify-write pattern recommended by Databricks,
        using ETags for optimistic concurrency control to prevent conflicts between
        concurrent updates.

        ## Requirements

        * Target machine must have network connectivity to the Databricks account console.
        * A valid Databricks Account API token with account admin privileges.
        * The resource (service principal, group, or tag policy) must exist before
          creating a rule set for it.

        ## Known issues

        All issues are not listed here, see [all open issues](https://github.com/Gijsreyn/DatabricksDsc/issues?q=is%3Aissue+is%3Aopen+in%3Atitle+DatabricksAccountRuleset).

        ### Using `AccessToken` property

        The `AccessToken` must be provided as a SecureString containing the
        Account API token with appropriate permissions.

    .PARAMETER AccountId
        The Databricks account ID (UUID format). This identifies the target account.

    .PARAMETER Name
        The full name of the rule set in the format:
        - accounts/<ACCOUNT_ID>/ruleSets/default (for account-level)
        - accounts/<ACCOUNT_ID>/groups/<GROUP_ID>/ruleSets/default (for groups)
        - accounts/<ACCOUNT_ID>/servicePrincipals/<SERVICE_PRINCIPAL_APPLICATION_ID>/ruleSets/default (for service principals)
        - accounts/<ACCOUNT_ID>/tagPolicies/<TAG_POLICY_ID>/ruleSets/default (for tag policies)

    .PARAMETER GrantRules
        Array of grant rules that define access permissions. Each rule specifies:
        - Principals: Array of principal identifiers (e.g., "users/user@company.com", "groups/groupname")
        - Role: The role being granted (e.g., "roles/servicePrincipal.user")

    .PARAMETER AccountsUrl
        The URL of the Databricks Account Console. Defaults to
        'https://accounts.azuredatabricks.net' and typically does not need to be specified.

    .PARAMETER AccessToken
        The Account API token used to authenticate to the Databricks account.
        Must be provided as a SecureString.

    .EXAMPLE
        $accessToken = ConvertTo-SecureString -String $env:DATABRICKS_TOKEN -AsPlainText -Force

        DatabricksAccountRuleset ServicePrincipalRuleset
        {
            AccountId  = '12345678-1234-1234-1234-123456789012'
            Name       = 'accounts/12345678-1234-1234-1234-123456789012/servicePrincipals/app-id-guid/ruleSets/default'
            GrantRules = @(
                [RulesetGrantRule] @{
                    Principals = @('users/user@company.com', 'groups/researchers')
                    Role       = 'roles/servicePrincipal.user'
                }
            )
            AccessToken = $accessToken
        }

        Configures a rule set for a service principal with the specified grant rules.

    .EXAMPLE
        $accessToken = ConvertTo-SecureString -String $env:DATABRICKS_TOKEN -AsPlainText -Force

        DatabricksAccountRuleset GroupRuleset
        {
            AccountId  = '12345678-1234-1234-1234-123456789012'
            Name       = 'accounts/12345678-1234-1234-1234-123456789012/groups/12345/ruleSets/default'
            GrantRules = @(
                [RulesetGrantRule] @{
                    Principals = @('users/admin@company.com')
                    Role       = 'roles/group.admin'
                }
            )
            AccessToken = $accessToken
        }

        Configures a rule set for a group with the specified grant rules.
#>

[DscResource()]
class DatabricksAccountRuleset : DatabricksAccountResourceBase
{
    [DscProperty(Key)]
    [System.String]
    $AccountId

    [DscProperty(Key)]
    [System.String]
    $Name

    [DscProperty()]
    [RulesetGrantRule[]]
    $GrantRules

    DatabricksAccountRuleset() : base ()
    {
        $this.ExcludeDscProperties = @(
            'AccountsUrl'
            'WorkspaceUrl'
            'AccountId'
            'Name'
            'AccessToken'
        )
    }

    [DatabricksAccountRuleset] Get()
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
            $this.localizedData.Get_Ruleset_EvaluatingRuleset -f @(
                $properties.Name,
                $properties.AccountId
            )
        )

        $currentState = @{
            WorkspaceUrl = $this.WorkspaceUrl
            AccountId    = $properties.AccountId
            Name         = $properties.Name
            GrantRules   = @()
        }

        try
        {
            # Get the current rule set using the name and an empty etag
            $encodedName = [System.Uri]::EscapeDataString($properties.Name)
            $apiPath = "/api/2.0/preview/accounts/access-control/rule-sets?name=$encodedName&etag="

            $response = $this.InvokeDatabricksApi(
                'GET',
                $apiPath,
                $null
            )

            if ($response -and $response.grant_rules)
            {
                Write-Verbose -Message (
                    $this.localizedData.Get_Ruleset_RulesetFound -f @(
                        $properties.Name,
                        $response.grant_rules.Count
                    )
                )

                # Store the full ruleset for later merge in Set() method
                $this | Add-Member -NotePropertyName '_fullRuleset' -NotePropertyValue $response.grant_rules -Force
                # Store the etag for use in Set() method
                $this | Add-Member -NotePropertyName '_etag' -NotePropertyValue $response.etag -Force

                # Return all grant rules from the current state
                $currentState.GrantRules = @()

                foreach ($rule in $response.grant_rules)
                {
                    $grantRule = [RulesetGrantRule]::new()
                    $grantRule.Principals = $rule.principals
                    $grantRule.Role = $rule.role
                    $currentState.GrantRules += $grantRule
                }

                Write-Verbose -Message (
                    "Found $($currentState.GrantRules.Count) grant rule(s) in current state"
                )
            }
            else
            {
                Write-Verbose -Message (
                    $this.localizedData.Get_Ruleset_RulesetNotFound -f $properties.Name
                )
            }
        }
        catch
        {
            Write-Verbose -Message (
                $this.localizedData.Get_Ruleset_ErrorGettingRuleset -f @(
                    $properties.Name,
                    $_.Exception.Message
                )
            )
        }

        return $currentState
    }

    <#
        Base method Set() call this method with the properties that should be enforced
        and that are not in desired state. The properties that are not in desired state
        will also be returned as reason's in the property Reasons.
    #>
    hidden [void] Modify([System.Collections.Hashtable] $properties)
    {
        Write-Verbose -Message (
            $this.localizedData.Set_Ruleset_UpdatingRuleset -f @(
                $properties.Name,
                $properties.GrantRules.Count
            )
        )

        try
        {
            # First, get the current state to retrieve the latest etag
            $currentStateProperties = @{
                AccountId = $this.AccountId
                Name      = $this.Name
            }

            $currentState = $this.GetCurrentState($currentStateProperties)

            # Get the etag from the previous Get call
            $etag = if ($this.PSObject.Properties.Name -contains '_etag')
            {
                $this._etag
            }
            else
            {
                ''
            }

            Write-Debug -Message (
                $this.localizedData.Set_Ruleset_UsingEtag -f $etag
            )

            # Get the full ruleset from the current state
            $fullRuleset = if ($this.PSObject.Properties.Name -contains '_fullRuleset')
            {
                $this._fullRuleset
            }
            else
            {
                @()
            }

            # Convert existing rules to a list we can modify
            $mergedRules = [System.Collections.Generic.List[hashtable]]::new()
            $managedRoles = $properties.GrantRules | ForEach-Object { $_.Role }

            # Add existing rules that we're not managing
            foreach ($existingRule in $fullRuleset)
            {
                if ($managedRoles -notcontains $existingRule.role)
                {
                    $mergedRules.Add(@{
                        principals = $existingRule.principals
                        role       = $existingRule.role
                    })
                }
            }

            # Add our managed rules (this replaces any existing rules with same role)
            foreach ($managedRule in $properties.GrantRules)
            {
                $mergedRules.Add(@{
                    principals = $managedRule.Principals
                    role       = $managedRule.Role
                })
            }

            Write-Verbose -Message (
                "Merged ruleset contains $($mergedRules.Count) total rules ($($properties.GrantRules.Count) managed, $($mergedRules.Count - $properties.GrantRules.Count) existing)"
            )

            # Prepare the request body following the read-modify-write pattern
            $requestBody = @{
                name     = $this.Name
                rule_set = @{
                    etag        = $etag
                    grant_rules = $mergedRules.ToArray()
                    name        = $this.Name
                }
            }

            Write-Debug -Message (
                $this.localizedData.Set_Ruleset_RequestBody -f ($requestBody | ConvertTo-Json -Depth 10)
            )

            $response = $this.InvokeDatabricksApi(
                'PUT',
                "/api/2.0/preview/accounts/access-control/rule-sets",
                $requestBody
            )

            if ($response)
            {
                Write-Verbose -Message (
                    $this.localizedData.Set_Ruleset_RulesetUpdated -f @(
                        $properties.Name,
                        $response.grant_rules.Count
                    )
                )
            }
        }
        catch
        {
            $errorMessage = $this.localizedData.Set_Ruleset_ErrorUpdatingRuleset -f @(
                $properties.Name,
                $_.Exception.Message
            )

            throw $errorMessage
        }
    }
}
