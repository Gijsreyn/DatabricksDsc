<#
    .SYNOPSIS
        The DatabricksAccountResourceBase class provides a common base for all
        Databricks account-level DSC resources.

    .DESCRIPTION
        This base class extends DatabricksResourceBase and provides common functionality
        for connecting to and interacting with Databricks Account APIs. All account-level
        Databricks DSC resources should inherit from this class.

        The key difference from DatabricksResourceBase is that it uses AccountsUrl instead
        of WorkspaceUrl, which defaults to the Databricks Account Console URL
        (https://accounts.azuredatabricks.net), making it more intuitive for account-level
        resources.

    .PARAMETER AccountsUrl
        The URL of the Databricks Account Console. Defaults to
        'https://accounts.azuredatabricks.net' and typically does not need to be changed.

    .PARAMETER AccessToken
        The Account API token used to authenticate to the Databricks account.
        This should be provided as a SecureString and must have appropriate
        account admin privileges.

    .PARAMETER Reasons
        Returns the reason a property is not in desired state.
#>
class DatabricksAccountResourceBase : DatabricksResourceBase
{
    [DscProperty()]
    [System.String]
    $AccountsUrl = 'https://accounts.azuredatabricks.net'

    # Constructor that sets WorkspaceUrl from AccountsUrl for compatibility with base class
    DatabricksAccountResourceBase () : base ()
    {
        # Set WorkspaceUrl from AccountsUrl to maintain compatibility with base class API methods
        if ([string]::IsNullOrEmpty($this.WorkspaceUrl))
        {
            $this.WorkspaceUrl = $this.AccountsUrl
        }
    }
}
