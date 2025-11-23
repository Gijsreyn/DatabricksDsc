<#
    .SYNOPSIS
        Represents a Databricks group member.

    .PARAMETER Value
        The unique identifier of the member (user or group ID).

    .PARAMETER Display
        The display name of the member.

    .PARAMETER Ref
        The resource reference URL for the member.

    .PARAMETER Type
        The type of member (optional).

    .PARAMETER Primary
        Indicates if this is a primary member (optional).

    .NOTES
        This class cannot inherit a parent class. If it would have, then the
        DSC resource (e.g. DatabricksGroup) that uses the complex type fail
        with the error:

            "The 'Members' property with type 'GroupMember' of DSC resource
            class 'DatabricksGroup' is not supported."

        The method Equals() returns $false if type is not the same on both sides
        of the comparison.

    .EXAMPLE
        [GroupMember] @{}

        Initializes a new instance of the GroupMember class without any
        property values.

    .EXAMPLE
        [GroupMember] @{ Value = '1234567890'; Display = 'user@example.com' }

        Initializes a new instance of the GroupMember class with property values.
#>
class GroupMember : IComparable, System.IEquatable[Object]
{
    [DscProperty(Mandatory)]
    [System.String]
    $Value

    [DscProperty()]
    [System.String]
    $Display

    [DscProperty()]
    [System.String]
    $Ref

    [DscProperty()]
    [System.String]
    $Type

    [DscProperty()]
    [Nullable[System.Boolean]]
    $Primary

    GroupMember()
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
        if ($this.Display)
        {
            return ('{0} ({1})' -f $this.Display, $this.Value)
        }
        else
        {
            return $this.Value
        }
    }
}

<#
    .SYNOPSIS
        Represents a Databricks group entitlement.

    .PARAMETER Value
        The entitlement value (e.g., 'allow-cluster-create', 'workspace-access').

    .NOTES
        This class cannot inherit a parent class. If it would have, then the
        DSC resource (e.g. DatabricksGroup) that uses the complex type fail
        with the error:

            "The 'Entitlements' property with type 'GroupEntitlement' of DSC resource
            class 'DatabricksGroup' is not supported."

        The method Equals() returns $false if type is not the same on both sides
        of the comparison.

    .EXAMPLE
        [GroupEntitlement] @{}

        Initializes a new instance of the GroupEntitlement class without any
        property values.

    .EXAMPLE
        [GroupEntitlement] @{ Value = 'allow-cluster-create' }

        Initializes a new instance of the GroupEntitlement class with property values.
#>
class GroupEntitlement : IComparable, System.IEquatable[Object]
{
    [DscProperty(Mandatory)]
    [ValidateSet('allow-cluster-create', 'allow-instance-pool-create', 'databricks-sql-access', 'workspace-access', 'workspace-consume')]
    [System.String]
    $Value

    GroupEntitlement()
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
        Represents a Databricks group role.

    .PARAMETER Value
        The role value (e.g., 'account_admin').

    .NOTES
        This class cannot inherit a parent class. If it would have, then the
        DSC resource (e.g. DatabricksGroup) that uses the complex type fail
        with the error:

            "The 'Roles' property with type 'GroupRole' of DSC resource
            class 'DatabricksGroup' is not supported."

        The method Equals() returns $false if type is not the same on both sides
        of the comparison.

    .EXAMPLE
        [GroupRole] @{}

        Initializes a new instance of the GroupRole class without any
        property values.

    .EXAMPLE
        [GroupRole] @{ Value = 'account_admin' }

        Initializes a new instance of the GroupRole class with property values.
#>
class GroupRole : IComparable, System.IEquatable[Object]
{
    [DscProperty()]
    [System.String]
    $Value

    GroupRole()
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
        Represents a Databricks parent group reference.

    .PARAMETER Value
        The unique identifier of the parent group.

    .PARAMETER Display
        The display name of the parent group.

    .PARAMETER Ref
        The resource reference URL for the parent group.

    .PARAMETER Type
        The type of group (optional).

    .PARAMETER Primary
        Indicates if this is a primary group (optional).

    .NOTES
        This class cannot inherit a parent class. If it would have, then the
        DSC resource (e.g. DatabricksGroup) that uses the complex type fail
        with the error:

            "The 'Groups' property with type 'ParentGroup' of DSC resource
            class 'DatabricksGroup' is not supported."

        The method Equals() returns $false if type is not the same on both sides
        of the comparison.

    .EXAMPLE
        [ParentGroup] @{}

        Initializes a new instance of the ParentGroup class without any
        property values.

    .EXAMPLE
        [ParentGroup] @{ Value = '1234567890'; Display = 'admins' }

        Initializes a new instance of the ParentGroup class with property values.
#>
class ParentGroup : IComparable, System.IEquatable[Object]
{
    [DscProperty(Mandatory)]
    [System.String]
    $Value

    [DscProperty()]
    [System.String]
    $Display

    [DscProperty()]
    [System.String]
    $Ref

    [DscProperty()]
    [System.String]
    $Type

    [DscProperty()]
    [Nullable[System.Boolean]]
    $Primary

    ParentGroup()
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
        if ($this.Display)
        {
            return ('{0} ({1})' -f $this.Display, $this.Value)
        }
        else
        {
            return $this.Value
        }
    }
}
