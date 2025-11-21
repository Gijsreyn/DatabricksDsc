<#
    .SYNOPSIS
        The `DatabricksAccountMetastoreAssignment` DSC resource manages the assignment
        of a Unity Catalog metastore to a Databricks workspace.

    .DESCRIPTION
        The `DatabricksAccountMetastoreAssignment` DSC resource is used to assign or
        unassign a Unity Catalog metastore to/from a specific Databricks workspace at
        the account level.

        This resource manages workspace-to-metastore assignments, which is a prerequisite
        for using Unity Catalog features within a workspace.

        ## Requirements

        * Target machine must have network connectivity to the Databricks account console.
        * A valid Databricks Account API token with account admin privileges.
        * The metastore must already exist before assignment.
        * The workspace must already exist before assignment.

        ## Known issues

        All issues are not listed here, see [all open issues](https://github.com/Gijsreyn/DatabricksDsc/issues?q=is%3Aissue+is%3Aopen+in%3Atitle+DatabricksAccountMetastoreAssignment).

        ### Using `AccessToken` property

        The `AccessToken` must be provided as a SecureString containing the
        Account API token with appropriate permissions.

    .PARAMETER AccountId
        The Databricks account ID (UUID format). This identifies the target account.

    .PARAMETER WorkspaceId
        The Databricks workspace ID (integer). This identifies the workspace to assign
        the metastore to.

    .PARAMETER MetastoreId
        The Unity Catalog metastore ID (UUID format). This identifies the metastore
        to assign to the workspace.

    .PARAMETER AccountsUrl
        The URL of the Databricks Account Console. Defaults to
        'https://accounts.azuredatabricks.net' and typically does not need to be specified.

    .PARAMETER AccessToken
        The Account API token used to authenticate to the Databricks account.
        Must be provided as a SecureString.

    .PARAMETER _exist
        Specifies if the assignment should exist or not. Used internally by DSC.
        Set to $false to remove the assignment.

    .EXAMPLE
        DatabricksAccountMetastoreAssignment MetastoreAssignmentExample
        {
            AccountId    = '12345678-1234-1234-1234-123456789012'
            WorkspaceId  = '1234567890123456'
            MetastoreId  = '87654321-4321-4321-4321-210987654321'
            AccessToken  = $accessToken
        }

        Assigns the specified metastore to the workspace.

    .EXAMPLE
        DatabricksAccountMetastoreAssignment RemoveMetastoreAssignment
        {
            AccountId    = '12345678-1234-1234-1234-123456789012'
            WorkspaceId  = '1234567890123456'
            MetastoreId  = '87654321-4321-4321-4321-210987654321'
            AccessToken  = $accessToken
            _exist       = $false
        }

        Removes the metastore assignment from the workspace.
#>

[DscResource()]
class DatabricksAccountMetastoreAssignment : DatabricksAccountResourceBase
{
    [DscProperty(Key)]
    [System.String]
    $AccountId

    [DscProperty(Key)]
    [System.String]
    $WorkspaceId

    [DscProperty(Key)]
    [System.String]
    $MetastoreId

    [DscProperty()]
    [System.Boolean]
    $_exist = $true

    DatabricksAccountMetastoreAssignment() : base ()
    {
        $this.ExcludeDscProperties = @(
            'AccountsUrl'
            'WorkspaceUrl'
            'AccountId'
            'WorkspaceId'
            'MetastoreId'
            'AccessToken'
        )
    }

    [DatabricksAccountMetastoreAssignment] Get()
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
            $this.localizedData.EvaluatingMetastoreAssignment -f @(
                $properties.WorkspaceId,
                $properties.MetastoreId,
                $properties.AccountId
            )
        )

        $currentState = @{
            WorkspaceUrl = $this.WorkspaceUrl
            AccountId    = $properties.AccountId
            WorkspaceId  = $properties.WorkspaceId
            MetastoreId  = $properties.MetastoreId
            _exist       = $false
        }

        try
        {
            # Try to get the current metastore assignment for the workspace
            $response = $this.InvokeDatabricksApi(
                'GET',
                "/api/2.0/accounts/$($properties.AccountId)/workspaces/$($properties.WorkspaceId)/metastore",
                $null
            )

            if ($response -and $response.metastore_assignment -and $response.metastore_assignment.metastore_id)
            {
                # Check if the assigned metastore matches the desired one
                if ($response.metastore_assignment.metastore_id -eq $properties.MetastoreId)
                {
                    $currentState._exist = $true

                    Write-Verbose -Message (
                        $this.localizedData.MetastoreAssignmentFound -f @(
                            $properties.MetastoreId,
                            $properties.WorkspaceId
                        )
                    )
                }
                else
                {
                    Write-Verbose -Message (
                        $this.localizedData.DifferentMetastoreAssigned -f @(
                            $response.metastore_assignment.metastore_id,
                            $properties.WorkspaceId,
                            $properties.MetastoreId
                        )
                    )
                }
            }
            else
            {
                Write-Verbose -Message (
                    $this.localizedData.NoMetastoreAssigned -f $properties.WorkspaceId
                )
            }
        }
        catch
        {
            # If we get a 404 or similar, no metastore is assigned
            Write-Verbose -Message (
                $this.localizedData.ErrorGettingMetastoreAssignment -f @(
                    $properties.WorkspaceId,
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
        # Check if _exist property needs to be changed (assignment should be created or removed)
        if ($properties.ContainsKey('_exist'))
        {
            # Evaluate the desired state for property _exist
            if ($properties._exist -eq $true)
            {
                # Create/Update the metastore assignment
                Write-Verbose -Message (
                    $this.localizedData.AssigningMetastore -f @(
                        $this.MetastoreId,
                        $this.WorkspaceId
                    )
                )

                $body = @{
                    metastore_id = $this.MetastoreId
                }

                try
                {
                    # Use POST for both create and update (upsert operation)
                    $this.InvokeDatabricksApi(
                        'POST',
                        "/api/2.0/accounts/$($this.AccountId)/workspaces/$($this.WorkspaceId)/metastores/$($this.MetastoreId)",
                        $body
                    )

                    Write-Verbose -Message (
                        $this.localizedData.MetastoreAssigned -f @(
                            $this.MetastoreId,
                            $this.WorkspaceId
                        )
                    )
                }
                catch
                {
                    $errorMessage = $this.localizedData.FailedToAssignMetastore -f @(
                        $this.MetastoreId,
                        $this.WorkspaceId,
                        $_.Exception.Message
                    )

                    New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
                }
            }
            else
            {
                # Remove the metastore assignment
                Write-Verbose -Message (
                    $this.localizedData.UnassigningMetastore -f @(
                        $this.MetastoreId,
                        $this.WorkspaceId
                    )
                )

                try
                {
                    $this.InvokeDatabricksApi(
                        'DELETE',
                        "/api/2.0/accounts/$($this.AccountId)/workspaces/$($this.WorkspaceId)/metastores/$($this.MetastoreId)",
                        $null
                    )

                    Write-Verbose -Message (
                        $this.localizedData.MetastoreUnassigned -f @(
                            $this.MetastoreId,
                            $this.WorkspaceId
                        )
                    )
                }
                catch
                {
                    $errorMessage = $this.localizedData.FailedToUnassignMetastore -f @(
                        $this.MetastoreId,
                        $this.WorkspaceId,
                        $_.Exception.Message
                    )

                    New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
                }
            }
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

        # Validate AccountId format (must be a GUID)
        if ($properties.AccountId -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')
        {
            $errorMessage = $this.localizedData.InvalidAccountId -f $properties.AccountId

            New-ArgumentException -ArgumentName 'AccountId' -Message $errorMessage
        }

        # Validate WorkspaceId format (must be numeric)
        if ($properties.WorkspaceId -notmatch '^\d+$')
        {
            $errorMessage = $this.localizedData.InvalidWorkspaceId -f $properties.WorkspaceId

            New-ArgumentException -ArgumentName 'WorkspaceId' -Message $errorMessage
        }

        # Validate MetastoreId format (must be a GUID)
        if ($properties.MetastoreId -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')
        {
            $errorMessage = $this.localizedData.InvalidMetastoreId -f $properties.MetastoreId

            New-ArgumentException -ArgumentName 'MetastoreId' -Message $errorMessage
        }
    }
}
