<#
    .SYNOPSIS
        Represents a workspace object permission level.

    .DESCRIPTION
        The WorkspaceObjectPermissionLevel enum defines the permission levels that can be assigned
        to workspace objects (notebooks, directories, repos).
#>
enum WorkspaceObjectPermissionLevel
{
    CAN_MANAGE
    CAN_READ
    CAN_RUN
    CAN_EDIT
}

<#
    .SYNOPSIS
        Represents an access control entry for workspace object permissions.

    .DESCRIPTION
        The WorkspaceObjectAccessControlEntry class represents a single access control entry
        that defines permissions for a specific principal (user, group, or service principal)
        on a workspace object.

    .PARAMETER GroupName
        The name of the group to grant permissions to. Mutually exclusive with UserName and ServicePrincipalName.

    .PARAMETER UserName
        The username (email) to grant permissions to. Mutually exclusive with GroupName and ServicePrincipalName.

    .PARAMETER ServicePrincipalName
        The application ID of the service principal to grant permissions to.
        Mutually exclusive with GroupName and UserName.

    .PARAMETER PermissionLevel
        The permission level to grant (CAN_MANAGE, CAN_READ, CAN_RUN, CAN_EDIT).
#>
class WorkspaceObjectAccessControlEntry : System.IComparable, System.IEquatable[Object]
{
    [System.String]
    $GroupName

    [System.String]
    $UserName

    [System.String]
    $ServicePrincipalName

    [WorkspaceObjectPermissionLevel]
    $PermissionLevel

    WorkspaceObjectAccessControlEntry()
    {
    }

    [System.Int32] CompareTo([System.Object] $obj)
    {
        if ($null -eq $obj)
        {
            return 1
        }

        if ($obj -isnot [WorkspaceObjectAccessControlEntry])
        {
            throw 'Object is not a WorkspaceObjectAccessControlEntry'
        }

        $compareResult = 0

        # Compare by principal (GroupName, UserName, or ServicePrincipalName)
        if ($this.GroupName)
        {
            $compareResult = $this.GroupName.CompareTo($obj.GroupName)
        }
        elseif ($this.UserName)
        {
            $compareResult = $this.UserName.CompareTo($obj.UserName)
        }
        elseif ($this.ServicePrincipalName)
        {
            $compareResult = $this.ServicePrincipalName.CompareTo($obj.ServicePrincipalName)
        }

        if ($compareResult -ne 0)
        {
            return $compareResult
        }

        # If principals are equal, compare by permission level
        return $this.PermissionLevel.CompareTo($obj.PermissionLevel)
    }

    [System.Boolean] Equals([System.Object] $obj)
    {
        if ($null -eq $obj)
        {
            return $false
        }

        if ($obj -isnot [WorkspaceObjectAccessControlEntry])
        {
            return $false
        }

        return $this.GroupName -eq $obj.GroupName -and
               $this.UserName -eq $obj.UserName -and
               $this.ServicePrincipalName -eq $obj.ServicePrincipalName -and
               $this.PermissionLevel -eq $obj.PermissionLevel
    }

    [System.String] ToString()
    {
        $principal = if ($this.GroupName)
        {
            "Group:$($this.GroupName)"
        }
        elseif ($this.UserName)
        {
            "User:$($this.UserName)"
        }
        elseif ($this.ServicePrincipalName)
        {
            "ServicePrincipal:$($this.ServicePrincipalName)"
        }
        else
        {
            'Unknown'
        }

        return "$principal - $($this.PermissionLevel)"
    }
}
