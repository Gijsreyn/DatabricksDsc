<#
    .SYNOPSIS
        Represents a grant rule in a ruleset.

    .PARAMETER Principals
        Array of principal identifiers (e.g., "users/user@company.com", "groups/groupname").

    .PARAMETER Role
        The role being granted (e.g., "roles/servicePrincipal.user").

    .NOTES
        This class cannot inherit a parent class. If it would have, then the
        DSC resource that uses the complex type fails with the error:

            "The 'GrantRules' property with type 'RulesetGrantRule' of DSC resource
            class 'DatabricksAccountRuleset' is not supported."

        The method Equals() returns $false if type is not the same on both sides
        of the comparison.

    .EXAMPLE
        [RulesetGrantRule] @{
            Principals = @('users/user@company.com', 'groups/researchers')
            Role = 'roles/servicePrincipal.user'
        }

        Initializes a new instance of the RulesetGrantRule class with property values.
#>
class RulesetGrantRule : System.IEquatable[Object]
{
    [DscProperty()]
    [System.String[]]
    $Principals

    [DscProperty()]
    [System.String]
    $Role

    RulesetGrantRule()
    {
    }

    [System.Boolean] Equals([System.Object] $object)
    {
        $isEqual = $false

        if ($object -is $this.GetType())
        {
            if ($this.Role -eq $object.Role)
            {
                # Handle null principals
                if ($null -eq $this.Principals -and $null -eq $object.Principals)
                {
                    $isEqual = $true
                }
                elseif ($null -ne $this.Principals -and $null -ne $object.Principals)
                {
                    # Compare principals as sorted arrays
                    $thisPrincipals = @($this.Principals | Sort-Object)
                    $otherPrincipals = @($object.Principals | Sort-Object)

                    if ($thisPrincipals.Count -eq $otherPrincipals.Count)
                    {
                        $isEqual = $true
                        for ($i = 0; $i -lt $thisPrincipals.Count; $i++)
                        {
                            if ($thisPrincipals[$i] -ne $otherPrincipals[$i])
                            {
                                $isEqual = $false
                                break
                            }
                        }
                    }
                }
            }
        }

        return $isEqual
    }

    [System.String] ToString()
    {
        return ('{0}: {1}' -f $this.Role, ($this.Principals -join ', '))
    }
}
