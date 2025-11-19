<#
    .SYNOPSIS
        Represents a Databricks user email address.

    .PARAMETER Value
        The email address value.

    .PARAMETER Type
        The type of email address (e.g., 'work', 'home').

    .PARAMETER Primary
        Indicates if this is the primary email address.

    .NOTES
        This class cannot inherit a parent class. If it would have, then the
        DSC resource (e.g. DatabricksUser) that uses the complex type fail
        with the error:

            "The 'Emails' property with type 'UserEmail' of DSC resource
            class 'DatabricksUser' is not supported."

        The method Equals() returns $false if type is not the same on both sides
        of the comparison.

    .EXAMPLE
        [UserEmail] @{}

        Initializes a new instance of the UserEmail class without any
        property values.

    .EXAMPLE
        [UserEmail] @{ Value = 'user@example.com'; Type = 'work'; Primary = $true }

        Initializes a new instance of the UserEmail class with property values.
#>
class UserEmail : IComparable, System.IEquatable[Object]
{
    [DscProperty()]
    [System.String]
    $Value

    [DscProperty()]
    [System.String]
    $Type

    [DscProperty()]
    [Nullable[System.Boolean]]
    $Primary

    UserEmail()
    {
    }

    [System.Boolean] Equals([System.Object] $object)
    {
        $isEqual = $false

        if ($object -is $this.GetType())
        {
            if ($this.Value -eq $object.Value)
            {
                if ($this.Type -eq $object.Type)
                {
                    if ($this.Primary -eq $object.Primary)
                    {
                        $isEqual = $true
                    }
                }
            }
        }

        return $isEqual
    }

    [System.Int32] CompareTo([Object] $object)
    {
        [System.Int32] $returnValue = 0

        if ($null -eq $object)
        {
            return 1
        }

        if ($object -is $this.GetType())
        {
            # Compare by Primary first (primary emails come first)
            if ($this.Primary -and -not $object.Primary)
            {
                $returnValue = -1
            }
            elseif (-not $this.Primary -and $object.Primary)
            {
                $returnValue = 1
            }
            else
            {
                # If both primary or both not primary, compare by Value
                $returnValue = [System.String]::Compare($this.Value, $object.Value, [System.StringComparison]::OrdinalIgnoreCase)
            }
        }
        else
        {
            $errorMessage = $script:localizedData.InvalidTypeForCompare -f @(
                $this.GetType().FullName,
                $object.GetType().FullName
            )

            New-ArgumentException -ArgumentName 'Object' -Message $errorMessage
        }

        return $returnValue
    }

    [System.String] ToString()
    {
        if ($this.Primary)
        {
            return ('{0} ({1}, Primary)' -f $this.Value, $this.Type)
        }
        else
        {
            return ('{0} ({1})' -f $this.Value, $this.Type)
        }
    }
}

<#
    .SYNOPSIS
        Represents a Databricks user name.

    .PARAMETER FamilyName
        The family (last) name of the user.

    .PARAMETER GivenName
        The given (first) name of the user.

    .NOTES
        This class cannot inherit a parent class. If it would have, then the
        DSC resource (e.g. DatabricksUser) that uses the complex type fail
        with the error:

            "The 'Name' property with type 'UserName' of DSC resource
            class 'DatabricksUser' is not supported."

        The method Equals() returns $false if type is not the same on both sides
        of the comparison.

    .EXAMPLE
        [UserName] @{}

        Initializes a new instance of the UserName class without any
        property values.

    .EXAMPLE
        [UserName] @{ GivenName = 'John'; FamilyName = 'Doe' }

        Initializes a new instance of the UserName class with property values.
#>
class UserName : IComparable, System.IEquatable[Object]
{
    [DscProperty()]
    [System.String]
    $FamilyName

    [DscProperty()]
    [System.String]
    $GivenName

    UserName()
    {
    }

    [System.Boolean] Equals([System.Object] $object)
    {
        $isEqual = $false

        if ($object -is $this.GetType())
        {
            if ($this.FamilyName -eq $object.FamilyName)
            {
                if ($this.GivenName -eq $object.GivenName)
                {
                    $isEqual = $true
                }
            }
        }

        return $isEqual
    }

    [System.Int32] CompareTo([Object] $object)
    {
        [System.Int32] $returnValue = 0

        if ($null -eq $object)
        {
            return 1
        }

        if ($object -is $this.GetType())
        {
            # Compare by FamilyName first
            $returnValue = [System.String]::Compare($this.FamilyName, $object.FamilyName, [System.StringComparison]::OrdinalIgnoreCase)

            # If FamilyName is equal, compare by GivenName
            if ($returnValue -eq 0)
            {
                $returnValue = [System.String]::Compare($this.GivenName, $object.GivenName, [System.StringComparison]::OrdinalIgnoreCase)
            }
        }
        else
        {
            $errorMessage = $script:localizedData.InvalidTypeForCompare -f @(
                $this.GetType().FullName,
                $object.GetType().FullName
            )

            New-ArgumentException -ArgumentName 'Object' -Message $errorMessage
        }

        return $returnValue
    }

    [System.String] ToString()
    {
        return ('{0}, {1}' -f $this.FamilyName, $this.GivenName)
    }
}

<#
    .SYNOPSIS
        Represents a Databricks user entitlement.

    .PARAMETER Value
        The entitlement value (e.g., 'allow-cluster-create', 'workspace-access').

    .NOTES
        This class cannot inherit a parent class. If it would have, then the
        DSC resource (e.g. DatabricksUser) that uses the complex type fail
        with the error:

            "The 'Entitlements' property with type 'UserEntitlement' of DSC resource
            class 'DatabricksUser' is not supported."

        The method Equals() returns $false if type is not the same on both sides
        of the comparison.

    .EXAMPLE
        [UserEntitlement] @{}

        Initializes a new instance of the UserEntitlement class without any
        property values.

    .EXAMPLE
        [UserEntitlement] @{ Value = 'allow-cluster-create' }

        Initializes a new instance of the UserEntitlement class with property values.
#>
class UserEntitlement : IComparable, System.IEquatable[Object]
{
    [DscProperty(Mandatory)]
    # https://learn.microsoft.com/en-us/azure/databricks/security/auth/entitlements#api
    [ValidateSet('allow-cluster-create', 'allow-instance-pool-create', 'databricks-sql-access', 'workspace-access', 'workspace-consume')]
    [System.String]
    $Value

    UserEntitlement()
    {
    }

    [System.Boolean] Equals([System.Object] $object)
    {
        $isEqual = $false

        if ($object -is $this.GetType())
        {
            if ($this.Value -eq $object.Value)
            {
                $isEqual = $true
            }
        }

        return $isEqual
    }

    [System.Int32] CompareTo([Object] $object)
    {
        [System.Int32] $returnValue = 0

        if ($null -eq $object)
        {
            return 1
        }

        if ($object -is $this.GetType())
        {
            $returnValue = [System.String]::Compare($this.Value, $object.Value, [System.StringComparison]::OrdinalIgnoreCase)
        }
        else
        {
            $errorMessage = $script:localizedData.InvalidTypeForCompare -f @(
                $this.GetType().FullName,
                $object.GetType().FullName
            )

            New-ArgumentException -ArgumentName 'Object' -Message $errorMessage
        }

        return $returnValue
    }

    [System.String] ToString()
    {
        return $this.Value
    }
}

<#
    .SYNOPSIS
        Represents a Databricks user role.

    .PARAMETER Value
        The role value (e.g., 'account_admin').

    .NOTES
        This class cannot inherit a parent class. If it would have, then the
        DSC resource (e.g. DatabricksUser) that uses the complex type fail
        with the error:

            "The 'Roles' property with type 'UserRole' of DSC resource
            class 'DatabricksUser' is not supported."

        The method Equals() returns $false if type is not the same on both sides
        of the comparison.

    .EXAMPLE
        [UserRole] @{}

        Initializes a new instance of the UserRole class without any
        property values.

    .EXAMPLE
        [UserRole] @{ Value = 'account_admin' }

        Initializes a new instance of the UserRole class with property values.
#>
class UserRole : IComparable, System.IEquatable[Object]
{
    [DscProperty()]
    [System.String]
    $Value

    UserRole()
    {
    }

    [System.Boolean] Equals([System.Object] $object)
    {
        $isEqual = $false

        if ($object -is $this.GetType())
        {
            if ($this.Value -eq $object.Value)
            {
                $isEqual = $true
            }
        }

        return $isEqual
    }

    [System.Int32] CompareTo([Object] $object)
    {
        [System.Int32] $returnValue = 0

        if ($null -eq $object)
        {
            return 1
        }

        if ($object -is $this.GetType())
        {
            $returnValue = [System.String]::Compare($this.Value, $object.Value, [System.StringComparison]::OrdinalIgnoreCase)
        }
        else
        {
            $errorMessage = $script:localizedData.InvalidTypeForCompare -f @(
                $this.GetType().FullName,
                $object.GetType().FullName
            )

            New-ArgumentException -ArgumentName 'Object' -Message $errorMessage
        }

        return $returnValue
    }

    [System.String] ToString()
    {
        return $this.Value
    }
}
