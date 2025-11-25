<#
    .SYNOPSIS
        Unit test for DatabricksGroup DSC resource.
#>

# Suppressing this rule because Script Analyzer does not understand Pester's syntax.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
# Suppressing this rule because tests are mocking passwords in clear text.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
param ()

BeforeDiscovery {
    try
    {
        if (-not (Get-Module -Name 'DscResource.Test'))
        {
            # Assumes dependencies has been resolved, so if this module is not available, run 'noop' task.
            if (-not (Get-Module -Name 'DscResource.Test' -ListAvailable))
            {
                # Redirect all streams to $null, except the error stream (stream 2)
                & "$PSScriptRoot/../../../build.ps1" -Tasks 'noop' 3>&1 4>&1 5>&1 6>&1 > $null
            }

            # If the dependencies has not been resolved, this will throw an error.
            Import-Module -Name 'DscResource.Test' -Force -ErrorAction 'Stop'
        }
    }
    catch [System.IO.FileNotFoundException]
    {
        throw 'DscResource.Test module dependency not found. Please run ".\build.ps1 -ResolveDependency -Tasks build" first.'
    }
}

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

Describe 'GroupMember' {
    Context 'When creating instances' {
        It 'Should create instance with Value' {
            InModuleScope -ScriptBlock {
                $member = [GroupMember]@{ Value = 'user-001' }
                $member.Value | Should -Be 'user-001'
            }
        }

        It 'Should create instance with Display' {
            InModuleScope -ScriptBlock {
                $member = [GroupMember]@{ Value = 'user-001'; Display = 'test@example.com' }
                $member.Display | Should -Be 'test@example.com'
            }
        }
    }

    Context 'When comparing instances using Equals()' {
        It 'Should return true for same Value' {
            InModuleScope -ScriptBlock {
                $member1 = [GroupMember]@{ Value = 'user-001' }
                $member2 = [GroupMember]@{ Value = 'user-001' }
                $member1.Equals($member2) | Should -BeTrue
            }
        }

        It 'Should return false for different Value' {
            InModuleScope -ScriptBlock {
                $member1 = [GroupMember]@{ Value = 'user-001' }
                $member2 = [GroupMember]@{ Value = 'user-002' }
                $member1.Equals($member2) | Should -BeFalse
            }
        }

        It 'Should return false for different type' {
            InModuleScope -ScriptBlock {
                $member1 = [GroupMember]@{ Value = 'user-001' }
                $member1.Equals('user-001') | Should -BeFalse
            }
        }
    }

    Context 'When comparing instances using CompareTo()' {
        It 'Should return 1 when comparing to null' {
            InModuleScope -ScriptBlock {
                $member = [GroupMember]@{ Value = 'user-001' }
                $member.CompareTo($null) | Should -Be 1
            }
        }

        It 'Should throw for invalid type' {
            InModuleScope -ScriptBlock {
                $member = [GroupMember]@{ Value = 'user-001' }
                { $member.CompareTo('string') } | Should -Throw
            }
        }
    }

    Context 'When calling ToString()' {
        It 'Should return Value when Display is not set' {
            InModuleScope -ScriptBlock {
                $member = [GroupMember]@{ Value = 'user-001' }
                $member.ToString() | Should -Be 'user-001'
            }
        }

        It 'Should return Display and Value when Display is set' {
            InModuleScope -ScriptBlock {
                $member = [GroupMember]@{ Value = 'user-001'; Display = 'Test User' }
                $member.ToString() | Should -Be 'Test User (user-001)'
            }
        }
    }
}

Describe 'GroupEntitlement' {
    Context 'When comparing instances using Equals()' {
        It 'Should return true for same Value' {
            InModuleScope -ScriptBlock {
                $ent1 = [GroupEntitlement]@{ Value = 'allow-cluster-create' }
                $ent2 = [GroupEntitlement]@{ Value = 'allow-cluster-create' }
                $ent1.Equals($ent2) | Should -BeTrue
            }
        }

        It 'Should return false for different Value' {
            InModuleScope -ScriptBlock {
                $ent1 = [GroupEntitlement]@{ Value = 'allow-cluster-create' }
                $ent2 = [GroupEntitlement]@{ Value = 'workspace-access' }
                $ent1.Equals($ent2) | Should -BeFalse
            }
        }

        It 'Should return false for different type' {
            InModuleScope -ScriptBlock {
                $ent = [GroupEntitlement]@{ Value = 'allow-cluster-create' }
                $ent.Equals('allow-cluster-create') | Should -BeFalse
            }
        }
    }

    Context 'When comparing instances using CompareTo()' {
        It 'Should return 1 when comparing to null' {
            InModuleScope -ScriptBlock {
                $ent = [GroupEntitlement]@{ Value = 'allow-cluster-create' }
                $ent.CompareTo($null) | Should -Be 1
            }
        }

        It 'Should throw for invalid type' {
            InModuleScope -ScriptBlock {
                $ent = [GroupEntitlement]@{ Value = 'allow-cluster-create' }
                { $ent.CompareTo('string') } | Should -Throw
            }
        }
    }

    Context 'When calling ToString()' {
        It 'Should return Value' {
            InModuleScope -ScriptBlock {
                $ent = [GroupEntitlement]@{ Value = 'allow-cluster-create' }
                $ent.ToString() | Should -Be 'allow-cluster-create'
            }
        }
    }
}

Describe 'GroupRole' {
    Context 'When comparing instances using Equals()' {
        It 'Should return true for same Value' {
            InModuleScope -ScriptBlock {
                $role1 = [GroupRole]@{ Value = 'arn:aws:iam::123:instance-profile/test' }
                $role2 = [GroupRole]@{ Value = 'arn:aws:iam::123:instance-profile/test' }
                $role1.Equals($role2) | Should -BeTrue
            }
        }

        It 'Should return false for different Value' {
            InModuleScope -ScriptBlock {
                $role1 = [GroupRole]@{ Value = 'arn:aws:iam::123:instance-profile/test1' }
                $role2 = [GroupRole]@{ Value = 'arn:aws:iam::123:instance-profile/test2' }
                $role1.Equals($role2) | Should -BeFalse
            }
        }
    }

    Context 'When comparing instances using CompareTo()' {
        It 'Should return 1 when comparing to null' {
            InModuleScope -ScriptBlock {
                $role = [GroupRole]@{ Value = 'arn:aws:iam::123:instance-profile/test' }
                $role.CompareTo($null) | Should -Be 1
            }
        }

        It 'Should throw for invalid type' {
            InModuleScope -ScriptBlock {
                $role = [GroupRole]@{ Value = 'arn:aws:iam::123:instance-profile/test' }
                { $role.CompareTo('string') } | Should -Throw
            }
        }
    }

    Context 'When calling ToString()' {
        It 'Should return Value' {
            InModuleScope -ScriptBlock {
                $role = [GroupRole]@{ Value = 'arn:aws:iam::123:instance-profile/test' }
                $role.ToString() | Should -Be 'arn:aws:iam::123:instance-profile/test'
            }
        }
    }
}

Describe 'DatabricksGroup' {
    Context 'When class is instantiated' {
        It 'Should not throw an exception' {
            InModuleScope -ScriptBlock {
                { [DatabricksGroup]::new() } | Should -Not -Throw
            }
        }

        It 'Should have a default or empty constructor' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksGroup]::new()
                $instance | Should -Not -BeNullOrEmpty
            }
        }

        It 'Should be the correct type' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksGroup]::new()
                $instance.GetType().Name | Should -Be 'DatabricksGroup'
            }
        }

        It 'Should have ExcludeDscProperties set' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksGroup]::new()
                $instance.ExcludeDscProperties | Should -Contain 'WorkspaceUrl'
                $instance.ExcludeDscProperties | Should -Contain 'DisplayName'
                $instance.ExcludeDscProperties | Should -Contain 'AccessToken'
                $instance.ExcludeDscProperties | Should -Contain 'Id'
                $instance.ExcludeDscProperties | Should -Contain 'Groups'
            }
        }
    }
}

Describe 'DatabricksGroup\Get()' -Tag 'Get' {
    Context 'When the system is in the desired state' {
        Context 'When group exists with minimal properties' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:mockDatabricksGroupInstance = [DatabricksGroup] @{
                        WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                        AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                        DisplayName  = 'data-engineers'
                    }

                    <#
                        This mocks the method GetCurrentState().

                        Method Get() will call the base method Get() which will
                        call back to the derived class method GetCurrentState()
                        to get the current state.
                    #>
                    $script:mockDatabricksGroupInstance |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                            return @{
                                WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                                AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                                DisplayName  = 'data-engineers'
                                Id           = '12345'
                                _exist       = $true
                            }
                        } -PassThru
                }
            }

            It 'Should return the correct values' {
                InModuleScope -ScriptBlock {
                    $currentState = $script:mockDatabricksGroupInstance.Get()

                    $currentState.WorkspaceUrl | Should -Be 'https://adb-1234567890123456.12.azuredatabricks.net'
                    $currentState.DisplayName | Should -Be 'data-engineers'
                    $currentState.Id | Should -Be '12345'
                    $currentState._exist | Should -BeTrue
                }
            }
        }

        Context 'When group exists with members' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:mockDatabricksGroupInstance = [DatabricksGroup] @{
                        WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                        AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                        DisplayName  = 'data-engineers'
                    }

                    $script:mockDatabricksGroupInstance |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                            return @{
                                WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                                AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                                DisplayName  = 'data-engineers'
                                Id           = '12345'
                                Members      = @(
                                    [GroupMember]@{ Value = 'user-001'; Display = 'user1@example.com' }
                                    [GroupMember]@{ Value = 'user-002'; Display = 'user2@example.com' }
                                )
                                _exist       = $true
                            }
                        } -PassThru
                }
            }

            It 'Should return the correct values' {
                InModuleScope -ScriptBlock {
                    $currentState = $script:mockDatabricksGroupInstance.Get()

                    $currentState.Members.Count | Should -Be 2
                    $currentState.Members[0].Value | Should -Be 'user-001'
                    $currentState.Members[1].Value | Should -Be 'user-002'
                }
            }
        }

        Context 'When group exists with entitlements' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:mockDatabricksGroupInstance = [DatabricksGroup] @{
                        WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                        AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                        DisplayName  = 'data-engineers'
                    }

                    $script:mockDatabricksGroupInstance |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                            return @{
                                WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                                AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                                DisplayName  = 'data-engineers'
                                Id           = '12345'
                                Entitlements = @(
                                    [GroupEntitlement]@{ Value = 'allow-cluster-create' }
                                )
                                _exist       = $true
                            }
                        } -PassThru
                }
            }

            It 'Should return the correct values' {
                InModuleScope -ScriptBlock {
                    $currentState = $script:mockDatabricksGroupInstance.Get()

                    $currentState.Entitlements.Count | Should -Be 1
                    $currentState.Entitlements[0].Value | Should -Be 'allow-cluster-create'
                }
            }
        }
    }

    Context 'When the system is not in the desired state' {
        Context 'When group does not exist' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:mockDatabricksGroupInstance = [DatabricksGroup] @{
                        WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                        AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                        DisplayName  = 'nonexistent-group'
                    }

                    $script:mockDatabricksGroupInstance |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                            return @{
                                WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                                AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                                DisplayName  = 'nonexistent-group'
                                _exist       = $false
                            }
                        } -PassThru
                }
            }

            It 'Should return the correct values' {
                InModuleScope -ScriptBlock {
                    $currentState = $script:mockDatabricksGroupInstance.Get()

                    $currentState.DisplayName | Should -Be 'nonexistent-group'
                    $currentState._exist | Should -BeFalse
                }
            }
        }
    }
}

Describe 'DatabricksGroup\Test()' -Tag 'Test' {
    BeforeAll {
        InModuleScope -ScriptBlock {
            $script:mockDatabricksGroupInstance = [DatabricksGroup] @{
                WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                DisplayName  = 'data-engineers'
            }
        }
    }

    Context 'When the system is in the desired state' {
        Context 'When group exists and properties match' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:mockDatabricksGroupInstance |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'Compare' -Value {
                            return $null
                        } -PassThru |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'AssertProperties' -Value {
                            return
                        }
                }
            }

            It 'Should return $true' {
                InModuleScope -ScriptBlock {
                    $script:mockDatabricksGroupInstance.Test() | Should -BeTrue
                }
            }
        }
    }

    Context 'When the system is not in the desired state' {
        Context 'When group exists but properties do not match' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:mockDatabricksGroupInstance |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'Compare' -Value {
                            return @{
                                Members = @(
                                    [GroupMember]@{ Value = 'user-001' }
                                )
                            }
                        } -PassThru |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'AssertProperties' -Value {
                            return
                        }
                }
            }

            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    $script:mockDatabricksGroupInstance.Test() | Should -BeFalse
                }
            }
        }

        Context 'When group does not exist but should' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:mockDatabricksGroupInstance._exist = $true

                    $script:mockDatabricksGroupInstance |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'Compare' -Value {
                            return @{
                                _exist = $true
                            }
                        } -PassThru |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'AssertProperties' -Value {
                            return
                        }
                }
            }

            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    $script:mockDatabricksGroupInstance.Test() | Should -BeFalse
                }
            }
        }
    }
}

Describe 'DatabricksGroup\Set()' -Tag 'Set' {
    BeforeAll {
        InModuleScope -ScriptBlock {
            $script:mockDatabricksGroupInstance = [DatabricksGroup] @{
                WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                DisplayName  = 'data-engineers'
            }
        }
    }

    BeforeEach {
        InModuleScope -ScriptBlock {
            $script:mockMethodModifyCallCount = 0
        }
    }

    Context 'When the system is not in the desired state' {
        Context 'When group properties need to be changed' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:mockDatabricksGroupInstance |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'Compare' -Value {
                            return @{
                                Property      = 'Members'
                                ExpectedValue = @([GroupMember]@{ Value = 'user-001' })
                                ActualValue   = @()
                            }
                        } -PassThru |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'AssertProperties' -Value {
                            return
                        } -PassThru |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'Modify' -Value {
                            $script:mockMethodModifyCallCount += 1
                        }
                }
            }

            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    { $script:mockDatabricksGroupInstance.Set() } | Should -Not -Throw
                }
            }

            It 'Should call method Modify()' {
                InModuleScope -ScriptBlock {
                    $script:mockDatabricksGroupInstance.Set()

                    $script:mockMethodModifyCallCount | Should -Be 1
                }
            }
        }
    }
}

Describe 'DatabricksGroup\GetCurrentState()' -Tag 'GetCurrentState' {
    Context 'When getting current state of existing group' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupInstance = [DatabricksGroup] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    DisplayName  = 'data-engineers'
                }

                # Mock InvokeDatabricksApi
                $script:mockDatabricksGroupInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param ($Method, $Path, $Body)

                        # Verify the filter parameter is used
                        if ($Path -like '*filter=*')
                        {
                            $Path | Should -Match 'filter=displayName%20eq%20%22data-engineers%22'
                        }

                        return @{
                            Resources = @(
                                @{
                                    id          = '12345'
                                    displayName = 'data-engineers'
                                    externalId  = 'ext-123'
                                    members     = @(
                                        @{
                                            value   = 'user-001'
                                            display = 'user1@example.com'
                                            '$ref'  = 'Users/user-001'
                                        }
                                    )
                                    entitlements = @(
                                        @{ value = 'allow-cluster-create' }
                                    )
                                    roles       = @(
                                        @{ value = 'arn:aws:iam::123456789012:instance-profile/my-profile' }
                                    )
                                    groups      = @(
                                        @{
                                            value   = 'group-001'
                                            display = 'admins'
                                            '$ref'  = 'Groups/group-001'
                                        }
                                    )
                                }
                            )
                        }
                    }
            }
        }

        It 'Should return the correct current state' {
            InModuleScope -ScriptBlock {
                $result = $script:mockDatabricksGroupInstance.GetCurrentState(@{
                        DisplayName = 'data-engineers'
                    })

                $result._exist | Should -BeTrue
                $result.DisplayName | Should -Be 'data-engineers'
                $result.Id | Should -Be '12345'
                $result.ExternalId | Should -Be 'ext-123'
                $result.Members.Count | Should -Be 1
                $result.Members[0].Value | Should -Be 'user-001'
                $result.Members[0].Display | Should -Be 'user1@example.com'
                $result.Entitlements.Count | Should -Be 1
                $result.Entitlements[0].Value | Should -Be 'allow-cluster-create'
                $result.Roles.Count | Should -Be 1
                $result.Groups.Count | Should -Be 1
                $result.Groups[0].Value | Should -Be 'group-001'
            }
        }
    }

    Context 'When getting current state of non-existent group' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupInstance = [DatabricksGroup] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    DisplayName  = 'nonexistent-group'
                }

                # Mock InvokeDatabricksApi to return empty resources
                $script:mockDatabricksGroupInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param ($Method, $Path, $Body)

                        return @{
                            Resources = @()
                        }
                    }
            }
        }

        It 'Should return _exist as false' {
            InModuleScope -ScriptBlock {
                $result = $script:mockDatabricksGroupInstance.GetCurrentState(@{
                        DisplayName = 'nonexistent-group'
                    })

                $result._exist | Should -BeFalse
                $result.Members | Should -BeNullOrEmpty
                $result.Entitlements | Should -BeNullOrEmpty
                $result.Id | Should -BeNullOrEmpty
            }
        }
    }
}

Describe 'DatabricksGroup\Modify()' -Tag 'Modify' {
    Context 'When creating a new group' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupInstance = [DatabricksGroup] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    DisplayName  = 'new-group'
                    Members      = @(
                        [GroupMember]@{ Value = 'user-001' }
                    )
                    _exist       = $true
                }

                $script:apiCallMade = $false

                $script:mockDatabricksGroupInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param ($Method, $Path, $Body)

                        $script:apiCallMade = $true
                        $script:apiMethod = $Method
                        $script:apiPath = $Path
                        $script:apiBody = $Body
                    } -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'BuildGroupPayload' -Value {
                        param ($Properties)

                        return @{
                            members = @(
                                @{ value = 'user-001' }
                            )
                        }
                    }
            }
        }

        It 'Should call API with POST method' {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupInstance.Modify(@{
                        _exist  = $true
                        Members = @([GroupMember]@{ Value = 'user-001' })
                    })

                $script:apiCallMade | Should -BeTrue
                $script:apiMethod | Should -Be 'POST'
                $script:apiPath | Should -Be '/api/2.0/preview/scim/v2/Groups'
                $script:apiBody.displayName | Should -Be 'new-group'
                $script:apiBody.schemas | Should -Contain 'urn:ietf:params:scim:schemas:core:2.0:Group'
            }
        }
    }

    Context 'When updating an existing group without Id' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupInstance = [DatabricksGroup] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    DisplayName  = 'existing-group'
                    Members      = @(
                        [GroupMember]@{ Value = 'user-002' }
                    )
                    _exist       = $true
                }

                $script:apiCallCount = 0
                $script:getCallMade = $false
                $script:patchCallMade = $false

                $script:mockDatabricksGroupInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param ($Method, $Path, $Body)

                        $script:apiCallCount++

                        if ($Method -eq 'GET')
                        {
                            $script:getCallMade = $true
                            return @{
                                Resources = @(
                                    @{
                                        id          = '12345'
                                        displayName = 'existing-group'
                                    }
                                )
                            }
                        }
                        elseif ($Method -eq 'PATCH')
                        {
                            $script:patchCallMade = $true
                            $script:patchPath = $Path
                        }
                    } -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'BuildGroupPatchPayload' -Value {
                        param ($Properties)

                        return @{
                            schemas    = @('urn:ietf:params:scim:api:messages:2.0:PatchOp')
                            Operations = @(
                                @{
                                    op    = 'add'
                                    path  = 'members'
                                    value = @(@{ value = 'user-002' })
                                }
                            )
                        }
                    }
            }
        }

        It 'Should retrieve group ID before PATCH' {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupInstance.Modify(@{
                        Members = @([GroupMember]@{ Value = 'user-002' })
                    })

                $script:getCallMade | Should -BeTrue
                $script:patchCallMade | Should -BeTrue
                $script:patchPath | Should -Be '/api/2.0/preview/scim/v2/Groups/12345'
                $script:apiCallCount | Should -Be 2
            }
        }
    }

    Context 'When updating an existing group' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupInstance = [DatabricksGroup] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    DisplayName  = 'existing-group'
                    Id           = '12345'
                    Members      = @(
                        [GroupMember]@{ Value = 'user-002' }
                    )
                    _exist       = $true
                }

                $script:apiCallMade = $false

                $script:mockDatabricksGroupInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param ($Method, $Path, $Body)

                        $script:apiCallMade = $true
                        $script:apiMethod = $Method
                        $script:apiPath = $Path
                        $script:apiBody = $Body
                    } -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'BuildGroupPatchPayload' -Value {
                        param ($Properties)

                        return @{
                            schemas    = @('urn:ietf:params:scim:api:messages:2.0:PatchOp')
                            Operations = @(
                                @{
                                    op    = 'add'
                                    path  = 'members'
                                    value = @(@{ value = 'user-002' })
                                }
                            )
                        }
                    }
            }
        }

        It 'Should call API with PATCH method' {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupInstance.Modify(@{
                        Members = @([GroupMember]@{ Value = 'user-002' })
                    })

                $script:apiCallMade | Should -BeTrue
                $script:apiMethod | Should -Be 'PATCH'
                $script:apiPath | Should -Be '/api/2.0/preview/scim/v2/Groups/12345'
                $script:apiBody.schemas | Should -Contain 'urn:ietf:params:scim:api:messages:2.0:PatchOp'
            }
        }
    }

    Context 'When removing a group without Id' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupInstance = [DatabricksGroup] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    DisplayName  = 'group-to-remove'
                    _exist       = $false
                }

                $script:apiCallCount = 0
                $script:getCallMade = $false
                $script:deleteCallMade = $false

                $script:mockDatabricksGroupInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param ($Method, $Path, $Body)

                        $script:apiCallCount++

                        if ($Method -eq 'GET')
                        {
                            $script:getCallMade = $true
                            return @{
                                Resources = @(
                                    @{
                                        id          = '12345'
                                        displayName = 'group-to-remove'
                                    }
                                )
                            }
                        }
                        elseif ($Method -eq 'DELETE')
                        {
                            $script:deleteCallMade = $true
                            $script:deletePath = $Path
                        }
                    }
            }
        }

        It 'Should retrieve group ID before DELETE' {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupInstance.Modify(@{
                        _exist = $false
                    })

                $script:getCallMade | Should -BeTrue
                $script:deleteCallMade | Should -BeTrue
                $script:deletePath | Should -Be '/api/2.0/preview/scim/v2/Groups/12345'
                $script:apiCallCount | Should -Be 2
            }
        }
    }

    Context 'When removing a group' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupInstance = [DatabricksGroup] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    DisplayName  = 'group-to-remove'
                    Id           = '12345'
                    _exist       = $false
                }

                $script:apiCallMade = $false

                $script:mockDatabricksGroupInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param ($Method, $Path, $Body)

                        $script:apiCallMade = $true
                        $script:apiMethod = $Method
                        $script:apiPath = $Path
                    }
            }
        }

        It 'Should call API with DELETE method' {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupInstance.Modify(@{
                        _exist = $false
                    })

                $script:apiCallMade | Should -BeTrue
                $script:apiMethod | Should -Be 'DELETE'
                $script:apiPath | Should -Be '/api/2.0/preview/scim/v2/Groups/12345'
            }
        }
    }

    Context 'When creating a group fails' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupInstance = [DatabricksGroup] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    DisplayName  = 'new-group'
                    _exist       = $true
                }

                $script:mockDatabricksGroupInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param ($Method, $Path, $Body)

                        throw 'API Error: Group creation failed'
                    } -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'BuildGroupPayload' -Value {
                        param ($Properties)

                        return @{}
                    }
            }
        }

        It 'Should throw with proper error message' {
            InModuleScope -ScriptBlock {
                {
                    $script:mockDatabricksGroupInstance.Modify(@{
                            _exist = $true
                        })
                } | Should -Throw '*Failed to create the group*'
            }
        }
    }

    Context 'When removing a group fails' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupInstance = [DatabricksGroup] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    DisplayName  = 'group-to-remove'
                    Id           = '12345'
                    _exist       = $false
                }

                $script:mockDatabricksGroupInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param ($Method, $Path, $Body)

                        throw 'API Error: Group removal failed'
                    }
            }
        }

        It 'Should throw with proper error message' {
            InModuleScope -ScriptBlock {
                {
                    $script:mockDatabricksGroupInstance.Modify(@{
                            _exist = $false
                        })
                } | Should -Throw '*Failed to remove the group*'
            }
        }
    }

    Context 'When updating a group fails' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupInstance = [DatabricksGroup] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    DisplayName  = 'existing-group'
                    Id           = '12345'
                    _exist       = $true
                }

                $script:mockDatabricksGroupInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param ($Method, $Path, $Body)

                        throw 'API Error: Group update failed'
                    } -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'BuildGroupPatchPayload' -Value {
                        param ($Properties)

                        return @{}
                    }
            }
        }

        It 'Should throw with proper error message' {
            InModuleScope -ScriptBlock {
                {
                    $script:mockDatabricksGroupInstance.Modify(@{
                            Members = @([GroupMember]@{ Value = 'user-002' })
                        })
                } | Should -Throw '*Failed to update the group*'
            }
        }
    }
}

Describe 'DatabricksGroup\BuildGroupPayload()' -Tag 'BuildGroupPayload' {
    Context 'When building payload with members' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupInstance = [DatabricksGroup] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    DisplayName  = 'test-group'
                    Members      = @(
                        [GroupMember]@{ Value = 'user-001' }
                        [GroupMember]@{ Value = 'user-002' }
                    )
                }
            }
        }

        It 'Should return payload with members' {
            InModuleScope -ScriptBlock {
                $result = $script:mockDatabricksGroupInstance.BuildGroupPayload(@{
                        Members = $script:mockDatabricksGroupInstance.Members
                    })

                $result.members.Count | Should -Be 2
                $result.members[0].value | Should -Be 'user-001'
                $result.members[1].value | Should -Be 'user-002'
            }
        }
    }

    Context 'When building payload with entitlements' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupInstance = [DatabricksGroup] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    DisplayName  = 'test-group'
                    Entitlements = @(
                        [GroupEntitlement]@{ Value = 'allow-cluster-create' }
                    )
                }
            }
        }

        It 'Should return payload with entitlements' {
            InModuleScope -ScriptBlock {
                $result = $script:mockDatabricksGroupInstance.BuildGroupPayload(@{
                        Entitlements = $script:mockDatabricksGroupInstance.Entitlements
                    })

                $result.entitlements.Count | Should -Be 1
                $result.entitlements[0].value | Should -Be 'allow-cluster-create'
            }
        }
    }

    Context 'When building payload with ExternalId' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupInstance = [DatabricksGroup] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    DisplayName  = 'test-group'
                    ExternalId   = 'ext-123'
                }
            }
        }

        It 'Should return payload with ExternalId' {
            InModuleScope -ScriptBlock {
                $result = $script:mockDatabricksGroupInstance.BuildGroupPayload(@{
                        ExternalId = $script:mockDatabricksGroupInstance.ExternalId
                    })

                $result.externalId | Should -Be 'ext-123'
            }
        }
    }

    Context 'When building payload with Roles' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupInstance = [DatabricksGroup] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    DisplayName  = 'test-group'
                    Roles        = @(
                        [GroupRole]@{ Value = 'arn:aws:iam::123:instance-profile/test' }
                    )
                }
            }
        }

        It 'Should return payload with Roles' {
            InModuleScope -ScriptBlock {
                $result = $script:mockDatabricksGroupInstance.BuildGroupPayload(@{
                        Roles = $script:mockDatabricksGroupInstance.Roles
                    })

                $result.roles.Count | Should -Be 1
                $result.roles[0].value | Should -Be 'arn:aws:iam::123:instance-profile/test'
            }
        }
    }
}

Describe 'DatabricksGroup\BuildGroupPatchPayload()' -Tag 'BuildGroupPatchPayload' {
    Context 'When building PATCH payload with members' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupInstance = [DatabricksGroup] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    DisplayName  = 'test-group'
                    Members      = @(
                        [GroupMember]@{ Value = 'user-001' }
                    )
                }
            }
        }

        It 'Should return PATCH payload with operations' {
            InModuleScope -ScriptBlock {
                $result = $script:mockDatabricksGroupInstance.BuildGroupPatchPayload(@{
                        Members = $script:mockDatabricksGroupInstance.Members
                    })

                $result.schemas | Should -Contain 'urn:ietf:params:scim:api:messages:2.0:PatchOp'
                $result.Operations.Count | Should -Be 1
                $result.Operations[0].op | Should -Be 'add'
                $result.Operations[0].path | Should -Be 'members'
                $result.Operations[0].value.Count | Should -Be 1
            }
        }
    }

    Context 'When building PATCH payload with Entitlements' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupInstance = [DatabricksGroup] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    DisplayName  = 'test-group'
                    Entitlements = @(
                        [GroupEntitlement]@{ Value = 'allow-cluster-create' }
                    )
                }
            }
        }

        It 'Should return PATCH payload with entitlements operations' {
            InModuleScope -ScriptBlock {
                $result = $script:mockDatabricksGroupInstance.BuildGroupPatchPayload(@{
                        Entitlements = $script:mockDatabricksGroupInstance.Entitlements
                    })

                $result.schemas | Should -Contain 'urn:ietf:params:scim:api:messages:2.0:PatchOp'
                $result.Operations.Count | Should -Be 1
                $result.Operations[0].op | Should -Be 'add'
                $result.Operations[0].path | Should -Be 'entitlements'
                $result.Operations[0].value.Count | Should -Be 1
                $result.Operations[0].value[0].value | Should -Be 'allow-cluster-create'
            }
        }
    }

    Context 'When building PATCH payload with Roles' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupInstance = [DatabricksGroup] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    DisplayName  = 'test-group'
                    Roles        = @(
                        [GroupRole]@{ Value = 'arn:aws:iam::123:instance-profile/test' }
                    )
                }
            }
        }

        It 'Should return PATCH payload with roles operations' {
            InModuleScope -ScriptBlock {
                $result = $script:mockDatabricksGroupInstance.BuildGroupPatchPayload(@{
                        Roles = $script:mockDatabricksGroupInstance.Roles
                    })

                $result.schemas | Should -Contain 'urn:ietf:params:scim:api:messages:2.0:PatchOp'
                $result.Operations.Count | Should -Be 1
                $result.Operations[0].op | Should -Be 'add'
                $result.Operations[0].path | Should -Be 'roles'
                $result.Operations[0].value.Count | Should -Be 1
                $result.Operations[0].value[0].value | Should -Be 'arn:aws:iam::123:instance-profile/test'
            }
        }
    }
}

Describe 'DatabricksGroup\AssertProperties()' -Tag 'AssertProperties' {
    Context 'When validating properties' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupInstance = [DatabricksGroup] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    DisplayName  = 'test-group'
                }
            }
        }

        It 'Should not throw for valid properties' {
            InModuleScope -ScriptBlock {
                {
                    $script:mockDatabricksGroupInstance.AssertProperties(@{
                            WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                            DisplayName  = 'test-group'
                        })
                } | Should -Not -Throw
            }
        }

        It 'Should throw for invalid WorkspaceUrl' {
            InModuleScope -ScriptBlock {
                {
                    $script:mockDatabricksGroupInstance.AssertProperties(@{
                            WorkspaceUrl = 'http://invalid-url'
                            DisplayName  = 'test-group'
                        })
                } | Should -Throw
            }
        }

        It 'Should throw for empty DisplayName' {
            InModuleScope -ScriptBlock {
                {
                    $script:mockDatabricksGroupInstance.AssertProperties(@{
                            WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                            DisplayName  = ''
                        })
                } | Should -Throw
            }
        }
    }
}

Describe 'DatabricksGroup\Export()' -Tag 'Export' {
    Context 'When exporting all groups' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupInstance = [DatabricksGroup] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    DisplayName  = ''
                }

                # Mock InvokeDatabricksApi to return groups
                $script:mockDatabricksGroupInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param ($Method, $Path, $Body)

                        return @{
                            Resources = @(
                                @{
                                    id          = '12345'
                                    displayName = 'group1'
                                    members     = @(
                                        @{
                                            value   = 'user-001'
                                            display = 'user1@example.com'
                                            '$ref'  = 'Users/user-001'
                                        }
                                    )
                                }
                                @{
                                    id          = '67890'
                                    displayName = 'group2'
                                    entitlements = @(
                                        @{ value = 'allow-cluster-create' }
                                    )
                                }
                            )
                        }
                    }
            }
        }

        It 'Should return array of DatabricksGroup instances' {
            InModuleScope -ScriptBlock {
                $result = [DatabricksGroup]::Export($script:mockDatabricksGroupInstance)

                $result.Count | Should -Be 2
                $result[0].DisplayName | Should -Be 'group1'
                $result[0].Members.Count | Should -Be 1
                $result[1].DisplayName | Should -Be 'group2'
                $result[1].Entitlements.Count | Should -Be 1
            }
        }
    }

    Context 'When exporting with no groups found' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupInstance = [DatabricksGroup] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    DisplayName  = ''
                }

                # Mock InvokeDatabricksApi to return empty resources
                $script:mockDatabricksGroupInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param ($Method, $Path, $Body)

                        return @{
                            Resources = @()
                        }
                    }
            }
        }

        It 'Should return empty array' {
            InModuleScope -ScriptBlock {
                $result = [DatabricksGroup]::Export($script:mockDatabricksGroupInstance)

                $result.Count | Should -Be 0
            }
        }
    }

    Context 'When calling Export() without parameters' {
        It 'Should throw an exception' {
            InModuleScope -ScriptBlock {
                { [DatabricksGroup]::Export() } | Should -Throw '*requires authentication*'
            }
        }
    }

    Context 'When filtering exported groups' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksGroupInstance = [DatabricksGroup] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    DisplayName  = 'group1'
                }

                # Mock InvokeDatabricksApi to return groups
                $script:mockDatabricksGroupInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param ($Method, $Path, $Body)

                        return @{
                            Resources = @(
                                @{
                                    id          = '12345'
                                    displayName = 'group1'
                                }
                                @{
                                    id          = '67890'
                                    displayName = 'group2'
                                }
                            )
                        }
                    }
            }
        }

        It 'Should return filtered results' {
            InModuleScope -ScriptBlock {
                $result = [DatabricksGroup]::Export($script:mockDatabricksGroupInstance)

                $result.Count | Should -Be 1
                $result[0].DisplayName | Should -Be 'group1'
            }
        }
    }
}
