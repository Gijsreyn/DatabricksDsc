<#
    .SYNOPSIS
        The `DatabricksGroupMember` DSC resource is used to add or remove
        individual members from groups in a Databricks workspace.

    .DESCRIPTION
        The `DatabricksGroupMember` DSC resource is used to add or remove
        individual members (users or service principals) from groups in a
        Databricks workspace using the workspace-level SCIM API PATCH operations.

        This resource provides granular control over group membership, allowing
        you to manage individual member additions and removals without affecting
        other group properties.

        ## Requirements

        * Target machine must have network connectivity to the Databricks workspace.
        * A valid Databricks Personal Access Token (PAT) with admin privileges.

        ## Known issues

        All issues are not listed here, see [all open issues](https://github.com/Gijsreyn/DatabricksDsc/issues?q=is%3Aissue+is%3Aopen+in%3Atitle+DatabricksGroupMember).

        ### Using `AccessToken` property

        The `AccessToken` must be provided as a SecureString containing the
        Personal Access Token.

    .PARAMETER GroupDisplayName
        The display name of the group to which the member belongs.

    .PARAMETER MemberIdentifier
        The unique identifier of the member to add or remove.

        **Important**: Use the unique identifier, not the display name:
        - For Users: Use the `userName` property (e.g., 'user@example.com')
        - For ServicePrincipals: Use the `applicationId` property (GUID format)

        Display names are not unique and should not be used as identifiers.

    .PARAMETER MemberType
        The type of member: 'User' or 'ServicePrincipal'.

    .PARAMETER _exist
        Specifies whether the member should exist in the group. Defaults to `$true`.
        Set to `$false` to remove the member from the group.

    .EXAMPLE
        $token = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
        Invoke-DscResource -ModuleName DatabricksDsc -Name DatabricksGroupMember -Method Get -Property @{
            WorkspaceUrl      = 'https://adb-1234567890123456.12.azuredatabricks.net'
            AccessToken       = $token
            GroupDisplayName  = 'data-engineers'
            MemberIdentifier  = 'user@example.com'
            MemberType        = 'User'
        }

        This example shows how to call the resource using Invoke-DscResource.
#>
[DscResource(RunAsCredential = 'NotSupported')]
class DatabricksGroupMember : DatabricksResourceBase
{
    [DscProperty(Key)]
    [System.String]
    $GroupDisplayName

    # MemberIdentifier must be the unique identifier:
    # - For Users: the userName property (email address)
    # - For ServicePrincipals: the applicationId property (GUID)
    [DscProperty(Key)]
    [System.String]
    $MemberIdentifier

    [DscProperty(Mandatory)]
    [ValidateSet('User', 'ServicePrincipal')]
    [System.String]
    $MemberType

    [DscProperty(NotConfigurable)]
    [System.String]
    $GroupId

    [DscProperty(NotConfigurable)]
    [System.String]
    $MemberId

    [DscProperty()]
    [System.Boolean]
    $_exist = $true

    DatabricksGroupMember () : base ()
    {
        # These properties will not be enforced.
        $this.ExcludeDscProperties = @(
            'WorkspaceUrl'
            'AccessToken'
            'GroupDisplayName'
            'MemberIdentifier'
            'MemberType'
            'GroupId'
            'MemberId'
        )
    }

    [DatabricksGroupMember] Get()
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
            $this.localizedData.EvaluatingGroupMemberState -f @(
                $properties.MemberIdentifier,
                $properties.GroupDisplayName,
                $this.WorkspaceUrl
            )
        )

        $currentState = @{
            WorkspaceUrl     = $this.WorkspaceUrl
            AccessToken      = $this.AccessToken
            GroupDisplayName = $properties.GroupDisplayName
            MemberIdentifier = $properties.MemberIdentifier
            MemberType       = $this.MemberType
            _exist           = $false
        }

        try
        {
            # Get all groups and find the target group
            $response = $this.InvokeDatabricksApi(
                'GET',
                '/api/2.0/preview/scim/v2/Groups',
                $null
            )

            $group = $response.Resources | Where-Object -FilterScript {
                $_.displayName -eq $properties.GroupDisplayName
            } | Select-Object -First 1

            if ($group)
            {
                $currentState.GroupId = $group.id

                # Get member ID based on type - use $this.MemberType since it's not in $properties
                $currentMemberId = $this.GetMemberId($this.MemberIdentifier, $this.MemberType)
                if ($currentMemberId)
                {
                    $currentState.MemberId = $currentMemberId

                    # Check if member exists in group
                    if ($group.members)
                    {
                        $memberExists = $group.members | Where-Object -FilterScript {
                            $_.value -eq $currentMemberId
                        }

                        if ($memberExists)
                        {
                            $currentState._exist = $true
                        }
                    }
                }
                else
                {
                    Write-Verbose -Message (
                        $this.localizedData.MemberNotFound -f @(
                            $properties.MemberType,
                            $properties.MemberIdentifier
                        )
                    )
                }
            }
            else
            {
                Write-Verbose -Message (
                    $this.localizedData.GroupNotFound -f $properties.GroupDisplayName
                )
            }
        }
        catch
        {
            Write-Verbose -Message (
                $this.localizedData.ErrorGettingGroupMember -f @(
                    $properties.MemberIdentifier,
                    $properties.GroupDisplayName,
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
        # Get group ID if not already set
        $currentGroupId = $this.GroupId
        if ([string]::IsNullOrEmpty($currentGroupId))
        {
            $response = $this.InvokeDatabricksApi(
                'GET',
                '/api/2.0/preview/scim/v2/Groups',
                $null
            )

            $group = $response.Resources | Where-Object -FilterScript {
                $_.displayName -eq $this.GroupDisplayName
            } | Select-Object -First 1

            if ($group)
            {
                $currentGroupId = $group.id
            }
            else
            {
                $errorMessage = $this.localizedData.GroupNotFoundForModify -f $this.GroupDisplayName

                New-ObjectNotFoundException -Message $errorMessage
            }
        }

        # Get member ID if not already set
        $currentMemberId = $this.MemberId
        if ([string]::IsNullOrEmpty($currentMemberId))
        {
            $currentMemberId = $this.GetMemberId($this.MemberIdentifier, $this.MemberType)

            if ([string]::IsNullOrEmpty($currentMemberId))
            {
                $errorMessage = $this.localizedData.MemberNotFoundForModify -f @(
                    $this.MemberType,
                    $this.MemberIdentifier
                )

                New-ObjectNotFoundException -Message $errorMessage
            }
        }

        # Check if _exist property needs to be changed
        if ($properties.ContainsKey('_exist'))
        {
            if ($properties._exist -eq $true)
            {
                # Add member to group
                Write-Verbose -Message (
                    $this.localizedData.AddingMemberToGroup -f @(
                        $this.MemberIdentifier,
                        $this.GroupDisplayName
                    )
                )

                $body = @{
                    schemas    = @('urn:ietf:params:scim:api:messages:2.0:PatchOp')
                    Operations = @(
                        @{
                            op    = 'add'
                            value = @{
                                members = @(
                                    @{
                                        value = $currentMemberId
                                    }
                                )
                            }
                        }
                    )
                }

                try
                {
                    $this.InvokeDatabricksApi(
                        'PATCH',
                        "/api/2.0/preview/scim/v2/Groups/$currentGroupId",
                        $body
                    )

                    Write-Verbose -Message (
                        $this.localizedData.MemberAddedToGroup -f @(
                            $this.MemberIdentifier,
                            $this.GroupDisplayName
                        )
                    )
                }
                catch
                {
                    $errorMessage = $this.localizedData.FailedToAddMember -f @(
                        $this.MemberIdentifier,
                        $this.GroupDisplayName,
                        $_.Exception.Message
                    )

                    New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
                }
            }
            else
            {
                # Remove member from group
                Write-Verbose -Message (
                    $this.localizedData.RemovingMemberFromGroup -f @(
                        $this.MemberIdentifier,
                        $this.GroupDisplayName
                    )
                )

                $body = @{
                    schemas    = @('urn:ietf:params:scim:api:messages:2.0:PatchOp')
                    Operations = @(
                        @{
                            op   = 'remove'
                            path = "members[value eq `"$currentMemberId`"]"
                        }
                    )
                }

                try
                {
                    $this.InvokeDatabricksApi(
                        'PATCH',
                        "/api/2.0/preview/scim/v2/Groups/$currentGroupId",
                        $body
                    )

                    Write-Verbose -Message (
                        $this.localizedData.MemberRemovedFromGroup -f @(
                            $this.MemberIdentifier,
                            $this.GroupDisplayName
                        )
                    )
                }
                catch
                {
                    $errorMessage = $this.localizedData.FailedToRemoveMember -f @(
                        $this.MemberIdentifier,
                        $this.GroupDisplayName,
                        $_.Exception.Message
                    )

                    New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
                }
            }
        }
    }

    <#
        Helper method to retrieve member ID based on identifier and type.

        The identifier parameter must be:
        - For Users: the userName property (email address)
        - For ServicePrincipals: the applicationId property (GUID)
    #>
    hidden [System.String] GetMemberId([System.String] $identifier, [System.String] $type)
    {
        try
        {
            if ($type -eq 'User')
            {
                # Get user by userName (email address, not display name)
                $response = $this.InvokeDatabricksApi(
                    'GET',
                    '/api/2.0/preview/scim/v2/Users',
                    $null
                )

                $user = $response.Resources | Where-Object -FilterScript {
                    $_.userName -eq $identifier
                } | Select-Object -First 1

                if ($user)
                {
                    return $user.id
                }
            }
            elseif ($type -eq 'ServicePrincipal')
            {
                # Get service principal by applicationId
                $response = $this.InvokeDatabricksApi(
                    'GET',
                    '/api/2.0/preview/scim/v2/ServicePrincipals',
                    $null
                )

                $sp = $response.Resources | Where-Object -FilterScript {
                    $_.applicationId -eq $identifier
                } | Select-Object -First 1

                if ($sp)
                {
                    return $sp.id
                }
            }

            return $null
        }
        catch
        {
            Write-Verbose -Message (
                $this.localizedData.ErrorGettingMemberId -f @(
                    $type,
                    $identifier,
                    $_.Exception.Message
                )
            )

            return $null
        }
    }

    <#
        Base method Assert() call this method with the properties that was assigned
        a value.
    #>
    hidden [void] AssertProperties([System.Collections.Hashtable] $properties)
    {
        # Validate WorkspaceUrl format
        if ($properties.WorkspaceUrl -notmatch '^https://')
        {
            $errorMessage = $this.localizedData.InvalidWorkspaceUrl -f $properties.WorkspaceUrl

            New-ArgumentException -ArgumentName 'WorkspaceUrl' -Message $errorMessage
        }

        # Validate GroupDisplayName is not empty
        if ([string]::IsNullOrWhiteSpace($properties.GroupDisplayName))
        {
            $errorMessage = $this.localizedData.InvalidGroupDisplayName

            New-ArgumentException -ArgumentName 'GroupDisplayName' -Message $errorMessage
        }

        # Validate MemberIdentifier is not empty
        if ([string]::IsNullOrWhiteSpace($properties.MemberIdentifier))
        {
            $errorMessage = $this.localizedData.InvalidMemberIdentifier

            New-ArgumentException -ArgumentName 'MemberIdentifier' -Message $errorMessage
        }
    }
}
