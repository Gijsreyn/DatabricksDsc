<#
    .SYNOPSIS
        Represents a Databricks SQL Warehouse access control entry.

    .PARAMETER GroupName
        The name of the group to grant permission to. Mutually exclusive with
        UserName and ServicePrincipalName.

    .PARAMETER UserName
        The username (email) to grant permission to. Mutually exclusive with
        GroupName and ServicePrincipalName. Identified by containing '@' character.

    .PARAMETER ServicePrincipalName
        The service principal application ID (GUID) to grant permission to.
        Mutually exclusive with GroupName and UserName. Identified by GUID format.

    .PARAMETER PermissionLevel
        The permission level to grant. Valid values are 'CAN_MANAGE', 'CAN_MONITOR',
        'CAN_USE', 'CAN_VIEW', and 'IS_OWNER'.

    .NOTES
        This class cannot inherit a parent class. If it would have, then the
        DSC resource that uses the complex type fail with the error:

            "The 'AccessControlList' property with type 'SqlWarehouseAccessControlEntry'
            of DSC resource class 'DatabricksSqlWarehousePermission' is not supported."

        The method Equals() returns $false if type is not the same on both sides
        of the comparison.

        Only one of GroupName, UserName, or ServicePrincipalName should be specified.
        UserName is identified by the presence of '@' character.
        ServicePrincipalName is identified by GUID format.

    .EXAMPLE
        [SqlWarehouseAccessControlEntry] @{ UserName = 'user@example.com'; PermissionLevel = 'CAN_USE' }

        Initializes a new access control entry for a user with CAN_USE permission.

    .EXAMPLE
        [SqlWarehouseAccessControlEntry] @{ GroupName = 'data-engineers'; PermissionLevel = 'CAN_MANAGE' }

        Initializes a new access control entry for a group with CAN_MANAGE permission.

    .EXAMPLE
        [SqlWarehouseAccessControlEntry] @{ ServicePrincipalName = '12345678-1234-1234-1234-123456789012'; PermissionLevel = 'CAN_USE' }

        Initializes a new access control entry for a service principal with CAN_USE permission.
#>
class SqlWarehouseAccessControlEntry : IComparable, System.IEquatable[Object]
{
    [DscProperty()]
    [System.String]
    $GroupName

    [DscProperty()]
    [System.String]
    $UserName

    [DscProperty()]
    [System.String]
    $ServicePrincipalName

    [DscProperty(Mandatory)]
    [ValidateSet('CAN_MANAGE', 'CAN_MONITOR', 'CAN_USE', 'CAN_VIEW', 'IS_OWNER')]
    [System.String]
    $PermissionLevel

    SqlWarehouseAccessControlEntry()
    {
    }

    [System.Boolean] Equals([System.Object] $object)
    {
        $isEqual = $false

        if ($object -is $this.GetType())
        {
            if ($this.PermissionLevel -eq $object.PermissionLevel)
            {
                # Check if the same principal is specified
                if ($this.GroupName -eq $object.GroupName -and
                    $this.UserName -eq $object.UserName -and
                    $this.ServicePrincipalName -eq $object.ServicePrincipalName)
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
            # Compare by principal type first (Group, User, ServicePrincipal)
            # Then by principal name
            $thisPrincipal = $this.GetPrincipalForComparison()
            $objectPrincipal = $object.GetPrincipalForComparison()

            $returnValue = [System.String]::Compare($thisPrincipal, $objectPrincipal, [System.StringComparison]::OrdinalIgnoreCase)

            # If principals are equal, compare by permission level
            if ($returnValue -eq 0)
            {
                $returnValue = [System.String]::Compare($this.PermissionLevel, $object.PermissionLevel, [System.StringComparison]::OrdinalIgnoreCase)
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

    hidden [System.String] GetPrincipalForComparison()
    {
        if (-not [System.String]::IsNullOrEmpty($this.GroupName))
        {
            return "Group:$($this.GroupName)"
        }
        elseif (-not [System.String]::IsNullOrEmpty($this.UserName))
        {
            return "User:$($this.UserName)"
        }
        elseif (-not [System.String]::IsNullOrEmpty($this.ServicePrincipalName))
        {
            return "ServicePrincipal:$($this.ServicePrincipalName)"
        }
        else
        {
            return [System.String]::Empty
        }
    }

    [System.String] ToString()
    {
        $principal = [System.String]::Empty

        if (-not [System.String]::IsNullOrEmpty($this.GroupName))
        {
            $principal = "Group: $($this.GroupName)"
        }
        elseif (-not [System.String]::IsNullOrEmpty($this.UserName))
        {
            $principal = "User: $($this.UserName)"
        }
        elseif (-not [System.String]::IsNullOrEmpty($this.ServicePrincipalName))
        {
            $principal = "ServicePrincipal: $($this.ServicePrincipalName)"
        }

        return "$principal - $($this.PermissionLevel)"
    }
}
