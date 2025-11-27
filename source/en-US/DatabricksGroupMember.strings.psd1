<#
    .SYNOPSIS
        The localized resource strings in English (en-US) for the
        resource DatabricksGroupMember.
#>

ConvertFrom-StringData @'
    EvaluatingGroupMemberState = Evaluating if member '{0}' exists in group '{1}' in workspace '{2}'. (DGM0001)
    GroupNotFound = Group '{0}' was not found in the workspace. (DGM0002)
    MemberNotFound = {0} '{1}' was not found in the workspace. (DGM0003)
    ErrorGettingGroupMember = Error getting member '{0}' from group '{1}': {2} (DGM0004)
    GroupNotFoundForModify = Group '{0}' does not exist and cannot be modified. (DGM0005)
    MemberNotFoundForModify = {0} '{1}' does not exist and cannot be added to the group. (DGM0006)
    AddingMemberToGroup = Adding member '{0}' to group '{1}'. (DGM0007)
    MemberAddedToGroup = Member '{0}' has been added to group '{1}'. (DGM0008)
    FailedToAddMember = Failed to add member '{0}' to group '{1}': {2} (DGM0009)
    RemovingMemberFromGroup = Removing member '{0}' from group '{1}'. (DGM0010)
    MemberRemovedFromGroup = Member '{0}' has been removed from group '{1}'. (DGM0011)
    FailedToRemoveMember = Failed to remove member '{0}' from group '{1}': {2} (DGM0012)
    ErrorGettingMemberId = Error getting ID for {0} '{1}': {2} (DGM0013)
    InvalidWorkspaceUrl = The WorkspaceUrl '{0}' is not valid. It must start with 'https://'. (DGM0014)
    InvalidGroupDisplayName = The GroupDisplayName cannot be empty. (DGM0015)
    InvalidMemberIdentifier = The MemberIdentifier cannot be empty. (DGM0016)
'@
