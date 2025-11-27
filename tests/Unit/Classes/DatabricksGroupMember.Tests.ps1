<#
    .SYNOPSIS
        Unit tests for the DatabricksGroupMember DSC resource.

    .NOTES
#>

BeforeAll {
    $script:dscModuleName = 'DatabricksDsc'

    Import-Module -Name $script:dscModuleName

    $PSDefaultParameterValues['InModuleScope:ModuleName'] = $script:dscModuleName
    $PSDefaultParameterValues['Mock:ModuleName'] = $script:dscModuleName
    $PSDefaultParameterValues['Should:ModuleName'] = $script:dscModuleName
}

AfterAll {
    $PSDefaultParameterValues.Remove('InModuleScope:ModuleName')
    $PSDefaultParameterValues.Remove('Mock:ModuleName')
    $PSDefaultParameterValues.Remove('Should:ModuleName')

    # Unload the module being tested so that it doesn't impact any other tests.
    Get-Module -Name $script:dscModuleName -All | Remove-Module -Force
}

Describe 'DatabricksGroupMember\GetCurrentState()' -Tag 'GetCurrentState' {
    Context 'When member exists in group' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupMemberInstance = [DatabricksGroupMember] @{
                    WorkspaceUrl      = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken       = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    GroupDisplayName  = 'data-engineers'
                    MemberIdentifier  = 'user@example.com'
                    MemberType        = 'User'
                }

                $script:mockDatabricksGroupMemberInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param ($Method, $Path, $Body)

                        if ($Path -eq '/api/2.0/preview/scim/v2/Groups')
                        {
                            return @{
                                Resources = @(
                                    @{
                                        id          = 'group-123'
                                        displayName = 'data-engineers'
                                        members     = @(
                                            @{
                                                value   = 'user-456'
                                                display = 'user@example.com'
                                            }
                                        )
                                    }
                                )
                            }
                        }
                        elseif ($Path -eq '/api/2.0/preview/scim/v2/Users')
                        {
                            return @{
                                Resources = @(
                                    @{
                                        id       = 'user-456'
                                        userName = 'user@example.com'
                                    }
                                )
                            }
                        }
                    }
            }
        }

        It 'Should return _exist as true' {
            InModuleScope -ScriptBlock {
                $result = $script:mockDatabricksGroupMemberInstance.GetCurrentState(@{
                        GroupDisplayName = 'data-engineers'
                        MemberIdentifier = 'user@example.com'
                        MemberType       = 'User'
                    })

                $result._exist | Should -BeTrue
                $result.GroupId | Should -Be 'group-123'
                $result.MemberId | Should -Be 'user-456'
            }
        }
    }

    Context 'When member does not exist in group' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupMemberInstance = [DatabricksGroupMember] @{
                    WorkspaceUrl      = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken       = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    GroupDisplayName  = 'data-engineers'
                    MemberIdentifier  = 'user@example.com'
                    MemberType        = 'User'
                }

                $script:mockDatabricksGroupMemberInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param ($Method, $Path, $Body)

                        if ($Path -eq '/api/2.0/preview/scim/v2/Groups')
                        {
                            return @{
                                Resources = @(
                                    @{
                                        id          = 'group-123'
                                        displayName = 'data-engineers'
                                        members     = @()
                                    }
                                )
                            }
                        }
                        elseif ($Path -eq '/api/2.0/preview/scim/v2/Users')
                        {
                            return @{
                                Resources = @(
                                    @{
                                        id       = 'user-456'
                                        userName = 'user@example.com'
                                    }
                                )
                            }
                        }
                    }
            }
        }

        It 'Should return _exist as false' {
            InModuleScope -ScriptBlock {
                $result = $script:mockDatabricksGroupMemberInstance.GetCurrentState(@{
                        GroupDisplayName = 'data-engineers'
                        MemberIdentifier = 'user@example.com'
                        MemberType       = 'User'
                    })

                $result._exist | Should -BeFalse
                $result.GroupId | Should -Be 'group-123'
                $result.MemberId | Should -Be 'user-456'
            }
        }
    }

    Context 'When group does not exist' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupMemberInstance = [DatabricksGroupMember] @{
                    WorkspaceUrl      = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken       = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    GroupDisplayName  = 'nonexistent-group'
                    MemberIdentifier  = 'user@example.com'
                    MemberType        = 'User'
                }

                $script:mockDatabricksGroupMemberInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param ($Method, $Path, $Body)

                        return @{
                            Resources = @()
                        }
                    }
            }
        }

        It 'Should return _exist as false with no GroupId' {
            InModuleScope -ScriptBlock {
                $result = $script:mockDatabricksGroupMemberInstance.GetCurrentState(@{
                        GroupDisplayName = 'nonexistent-group'
                        MemberIdentifier = 'user@example.com'
                        MemberType       = 'User'
                    })

                $result._exist | Should -BeFalse
                $result.GroupId | Should -BeNullOrEmpty
            }
        }
    }

    Context 'When service principal member exists in group' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupMemberInstance = [DatabricksGroupMember] @{
                    WorkspaceUrl      = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken       = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    GroupDisplayName  = 'data-engineers'
                    MemberIdentifier  = '12345678-1234-1234-1234-123456789012'
                    MemberType        = 'ServicePrincipal'
                }

                $script:mockDatabricksGroupMemberInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param ($Method, $Path, $Body)

                        if ($Path -eq '/api/2.0/preview/scim/v2/Groups')
                        {
                            return @{
                                Resources = @(
                                    @{
                                        id          = 'group-123'
                                        displayName = 'data-engineers'
                                        members     = @(
                                            @{
                                                value   = 'sp-789'
                                                display = 'my-service-principal'
                                            }
                                        )
                                    }
                                )
                            }
                        }
                        elseif ($Path -eq '/api/2.0/preview/scim/v2/ServicePrincipals')
                        {
                            return @{
                                Resources = @(
                                    @{
                                        id            = 'sp-789'
                                        applicationId = '12345678-1234-1234-1234-123456789012'
                                        displayName   = 'my-service-principal'
                                    }
                                )
                            }
                        }
                    }
            }
        }

        It 'Should return _exist as true for service principal' {
            InModuleScope -ScriptBlock {
                $result = $script:mockDatabricksGroupMemberInstance.GetCurrentState(@{
                        GroupDisplayName = 'data-engineers'
                        MemberIdentifier = '12345678-1234-1234-1234-123456789012'
                        MemberType       = 'ServicePrincipal'
                    })

                $result._exist | Should -BeTrue
                $result.GroupId | Should -Be 'group-123'
                $result.MemberId | Should -Be 'sp-789'
            }
        }
    }
}

Describe 'DatabricksGroupMember\Modify()' -Tag 'Modify' {
    Context 'When adding a user member to a group' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupMemberInstance = [DatabricksGroupMember] @{
                    WorkspaceUrl      = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken       = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    GroupDisplayName  = 'data-engineers'
                    MemberIdentifier  = 'user@example.com'
                    MemberType        = 'User'
                    GroupId           = 'group-123'
                    MemberId          = 'user-456'
                    _exist            = $true
                }

                $script:apiCalled = $false
                $script:apiMethod = $null
                $script:apiPath = $null
                $script:apiBody = $null

                $script:mockDatabricksGroupMemberInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param ($Method, $Path, $Body)

                        $script:apiCalled = $true
                        $script:apiMethod = $Method
                        $script:apiPath = $Path
                        $script:apiBody = $Body
                    }
            }
        }

        It 'Should call PATCH API with add operation' {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupMemberInstance.Modify(@{
                        _exist = $true
                    })

                $script:apiCalled | Should -BeTrue
                $script:apiMethod | Should -Be 'PATCH'
                $script:apiPath | Should -Be '/api/2.0/preview/scim/v2/Groups/group-123'
                $script:apiBody.schemas | Should -Contain 'urn:ietf:params:scim:api:messages:2.0:PatchOp'
                $script:apiBody.Operations[0].op | Should -Be 'add'
                $script:apiBody.Operations[0].value.members[0].value | Should -Be 'user-456'
            }
        }
    }

    Context 'When removing a user member from a group' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupMemberInstance = [DatabricksGroupMember] @{
                    WorkspaceUrl      = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken       = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    GroupDisplayName  = 'data-engineers'
                    MemberIdentifier  = 'user@example.com'
                    MemberType        = 'User'
                    GroupId           = 'group-123'
                    MemberId          = 'user-456'
                    _exist            = $false
                }

                $script:apiCalled = $false
                $script:apiMethod = $null
                $script:apiPath = $null
                $script:apiBody = $null

                $script:mockDatabricksGroupMemberInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param ($Method, $Path, $Body)

                        $script:apiCalled = $true
                        $script:apiMethod = $Method
                        $script:apiPath = $Path
                        $script:apiBody = $Body
                    }
            }
        }

        It 'Should call PATCH API with remove operation' {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupMemberInstance.Modify(@{
                        _exist = $false
                    })

                $script:apiCalled | Should -BeTrue
                $script:apiMethod | Should -Be 'PATCH'
                $script:apiPath | Should -Be '/api/2.0/preview/scim/v2/Groups/group-123'
                $script:apiBody.schemas | Should -Contain 'urn:ietf:params:scim:api:messages:2.0:PatchOp'
                $script:apiBody.Operations[0].op | Should -Be 'remove'
                $script:apiBody.Operations[0].path | Should -Be 'members[value eq "user-456"]'
            }
        }
    }

    Context 'When adding member without GroupId set' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupMemberInstance = [DatabricksGroupMember] @{
                    WorkspaceUrl      = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken       = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    GroupDisplayName  = 'data-engineers'
                    MemberIdentifier  = 'user@example.com'
                    MemberType        = 'User'
                    MemberId          = 'user-456'
                    _exist            = $true
                }

                $script:getCallMade = $false
                $script:patchCallMade = $false

                $script:mockDatabricksGroupMemberInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param ($Method, $Path, $Body)

                        if ($Method -eq 'GET')
                        {
                            $script:getCallMade = $true
                            return @{
                                Resources = @(
                                    @{
                                        id          = 'group-123'
                                        displayName = 'data-engineers'
                                    }
                                )
                            }
                        }
                        elseif ($Method -eq 'PATCH')
                        {
                            $script:patchCallMade = $true
                        }
                    }
            }
        }

        It 'Should retrieve group ID before PATCH' {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupMemberInstance.Modify(@{
                        _exist = $true
                    })

                $script:getCallMade | Should -BeTrue
                $script:patchCallMade | Should -BeTrue
            }
        }
    }

    Context 'When adding member without MemberId set' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupMemberInstance = [DatabricksGroupMember] @{
                    WorkspaceUrl      = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken       = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    GroupDisplayName  = 'data-engineers'
                    MemberIdentifier  = 'user@example.com'
                    MemberType        = 'User'
                    GroupId           = 'group-123'
                    _exist            = $true
                }

                $script:getMemberCallMade = $false
                $script:patchCallMade = $false

                $script:mockDatabricksGroupMemberInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param ($Method, $Path, $Body)

                        if ($Method -eq 'PATCH')
                        {
                            $script:patchCallMade = $true
                        }
                    } -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetMemberId' -Value {
                        param ($Identifier, $Type)

                        $script:getMemberCallMade = $true
                        return 'user-456'
                    }
            }
        }

        It 'Should retrieve member ID before PATCH' {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupMemberInstance.Modify(@{
                        _exist = $true
                    })

                $script:getMemberCallMade | Should -BeTrue
                $script:patchCallMade | Should -BeTrue
            }
        }
    }

    Context 'When group does not exist' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupMemberInstance = [DatabricksGroupMember] @{
                    WorkspaceUrl      = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken       = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    GroupDisplayName  = 'nonexistent-group'
                    MemberIdentifier  = 'user@example.com'
                    MemberType        = 'User'
                    MemberId          = 'user-456'
                    _exist            = $true
                }

                $script:mockDatabricksGroupMemberInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param ($Method, $Path, $Body)

                        return @{
                            Resources = @()
                        }
                    }
            }
        }

        It 'Should throw ObjectNotFoundException' {
            InModuleScope -ScriptBlock {
                {
                    $script:mockDatabricksGroupMemberInstance.Modify(@{
                            _exist = $true
                        })
                } | Should -Throw '*does not exist*'
            }
        }
    }

    Context 'When member does not exist' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupMemberInstance = [DatabricksGroupMember] @{
                    WorkspaceUrl      = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken       = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    GroupDisplayName  = 'data-engineers'
                    MemberIdentifier  = 'nonexistent@example.com'
                    MemberType        = 'User'
                    GroupId           = 'group-123'
                    _exist            = $true
                }

                $script:mockDatabricksGroupMemberInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param ($Method, $Path, $Body)
                    } -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetMemberId' -Value {
                        param ($Identifier, $Type)

                        return $null
                    }
            }
        }

        It 'Should throw ObjectNotFoundException' {
            InModuleScope -ScriptBlock {
                {
                    $script:mockDatabricksGroupMemberInstance.Modify(@{
                            _exist = $true
                        })
                } | Should -Throw '*does not exist*'
            }
        }
    }

    Context 'When API call fails during add' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupMemberInstance = [DatabricksGroupMember] @{
                    WorkspaceUrl      = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken       = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    GroupDisplayName  = 'data-engineers'
                    MemberIdentifier  = 'user@example.com'
                    MemberType        = 'User'
                    GroupId           = 'group-123'
                    MemberId          = 'user-456'
                    _exist            = $true
                }

                $script:mockDatabricksGroupMemberInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param ($Method, $Path, $Body)

                        throw 'API Error: Failed to add member'
                    }
            }
        }

        It 'Should throw with proper error message' {
            InModuleScope -ScriptBlock {
                {
                    $script:mockDatabricksGroupMemberInstance.Modify(@{
                            _exist = $true
                        })
                } | Should -Throw '*Failed to add member*'
            }
        }
    }

    Context 'When API call fails during remove' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupMemberInstance = [DatabricksGroupMember] @{
                    WorkspaceUrl      = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken       = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    GroupDisplayName  = 'data-engineers'
                    MemberIdentifier  = 'user@example.com'
                    MemberType        = 'User'
                    GroupId           = 'group-123'
                    MemberId          = 'user-456'
                    _exist            = $false
                }

                $script:mockDatabricksGroupMemberInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param ($Method, $Path, $Body)

                        throw 'API Error: Failed to remove member'
                    }
            }
        }

        It 'Should throw with proper error message' {
            InModuleScope -ScriptBlock {
                {
                    $script:mockDatabricksGroupMemberInstance.Modify(@{
                            _exist = $false
                        })
                } | Should -Throw '*Failed to remove member*'
            }
        }
    }
}

Describe 'DatabricksGroupMember\GetMemberId()' -Tag 'GetMemberId' {
    Context 'When getting user ID' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupMemberInstance = [DatabricksGroupMember] @{
                    WorkspaceUrl      = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken       = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    GroupDisplayName  = 'data-engineers'
                    MemberIdentifier  = 'user@example.com'
                    MemberType        = 'User'
                }

                $script:mockDatabricksGroupMemberInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param ($Method, $Path, $Body)

                        return @{
                            Resources = @(
                                @{
                                    id       = 'user-123'
                                    userName = 'user@example.com'
                                }
                            )
                        }
                    }
            }
        }

        It 'Should return user ID' {
            InModuleScope -ScriptBlock {
                $result = $script:mockDatabricksGroupMemberInstance.GetMemberId('user@example.com', 'User')

                $result | Should -Be 'user-123'
            }
        }
    }

    Context 'When getting service principal ID' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupMemberInstance = [DatabricksGroupMember] @{
                    WorkspaceUrl      = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken       = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    GroupDisplayName  = 'data-engineers'
                    MemberIdentifier  = '12345678-1234-1234-1234-123456789012'
                    MemberType        = 'ServicePrincipal'
                }

                $script:mockDatabricksGroupMemberInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param ($Method, $Path, $Body)

                        return @{
                            Resources = @(
                                @{
                                    id            = 'sp-789'
                                    applicationId = '12345678-1234-1234-1234-123456789012'
                                    displayName   = 'my-service-principal'
                                }
                            )
                        }
                    }
            }
        }

        It 'Should return service principal ID' {
            InModuleScope -ScriptBlock {
                $result = $script:mockDatabricksGroupMemberInstance.GetMemberId('12345678-1234-1234-1234-123456789012', 'ServicePrincipal')

                $result | Should -Be 'sp-789'
            }
        }
    }

    Context 'When member is not found' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupMemberInstance = [DatabricksGroupMember] @{
                    WorkspaceUrl      = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken       = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    GroupDisplayName  = 'data-engineers'
                    MemberIdentifier  = 'nonexistent@example.com'
                    MemberType        = 'User'
                }

                $script:mockDatabricksGroupMemberInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param ($Method, $Path, $Body)

                        return @{
                            Resources = @()
                        }
                    }
            }
        }

        It 'Should return null' {
            InModuleScope -ScriptBlock {
                $result = $script:mockDatabricksGroupMemberInstance.GetMemberId('nonexistent@example.com', 'User')

                $result | Should -BeNullOrEmpty
            }
        }
    }
}

Describe 'DatabricksGroupMember\AssertProperties()' -Tag 'AssertProperties' {
    Context 'When validating properties' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupMemberInstance = [DatabricksGroupMember] @{
                    WorkspaceUrl      = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken       = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    GroupDisplayName  = 'data-engineers'
                    MemberIdentifier  = 'user@example.com'
                    MemberType        = 'User'
                }
            }
        }

        It 'Should not throw for valid properties' {
            InModuleScope -ScriptBlock {
                {
                    $script:mockDatabricksGroupMemberInstance.AssertProperties(@{
                            WorkspaceUrl      = 'https://adb-1234567890123456.12.azuredatabricks.net'
                            GroupDisplayName  = 'data-engineers'
                            MemberIdentifier  = 'user@example.com'
                        })
                } | Should -Not -Throw
            }
        }

        It 'Should throw for invalid WorkspaceUrl' {
            InModuleScope -ScriptBlock {
                {
                    $script:mockDatabricksGroupMemberInstance.AssertProperties(@{
                            WorkspaceUrl      = 'http://invalid-url'
                            GroupDisplayName  = 'data-engineers'
                            MemberIdentifier  = 'user@example.com'
                        })
                } | Should -Throw '*not valid*'
            }
        }

        It 'Should throw for empty GroupDisplayName' {
            InModuleScope -ScriptBlock {
                {
                    $script:mockDatabricksGroupMemberInstance.AssertProperties(@{
                            WorkspaceUrl      = 'https://adb-1234567890123456.12.azuredatabricks.net'
                            GroupDisplayName  = ''
                            MemberIdentifier  = 'user@example.com'
                        })
                } | Should -Throw '*cannot be empty*'
            }
        }

        It 'Should throw for empty MemberIdentifier' {
            InModuleScope -ScriptBlock {
                {
                    $script:mockDatabricksGroupMemberInstance.AssertProperties(@{
                            WorkspaceUrl      = 'https://adb-1234567890123456.12.azuredatabricks.net'
                            GroupDisplayName  = 'data-engineers'
                            MemberIdentifier  = ''
                        })
                } | Should -Throw '*cannot be empty*'
            }
        }
    }
}
