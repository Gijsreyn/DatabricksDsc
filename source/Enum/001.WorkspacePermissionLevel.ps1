<#
    .SYNOPSIS
        Enum for workspace permission levels.

    .DESCRIPTION
        Enum for workspace permission levels that can be assigned to principals
        (users, service principals, or groups) in a Databricks workspace.
#>

enum WorkspacePermissionLevel
{
    User
    Admin
}
