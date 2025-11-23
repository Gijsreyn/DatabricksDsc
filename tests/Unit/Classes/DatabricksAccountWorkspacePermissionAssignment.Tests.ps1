<#
    .SYNOPSIS
        Unit test for DatabricksAccountWorkspacePermissionAssignment DSC resource.
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

Describe 'DatabricksAccountWorkspacePermissionAssignment' {
    Context 'When class is instantiated' {
        It 'Should not throw an exception' {
            InModuleScope -ScriptBlock {
                { [DatabricksAccountWorkspacePermissionAssignment]::new() } | Should -Not -Throw
            }
        }

        It 'Should have a default or empty constructor' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksAccountWorkspacePermissionAssignment]::new()
                $instance | Should -Not -BeNullOrEmpty
            }
        }

        It 'Should be the correct type' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksAccountWorkspacePermissionAssignment]::new()
                $instance.GetType().Name | Should -Be 'DatabricksAccountWorkspacePermissionAssignment'
            }
        }

        It 'Should have ExcludeDscProperties set' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksAccountWorkspacePermissionAssignment]::new()
                $instance.ExcludeDscProperties | Should -Contain 'WorkspaceUrl'
                $instance.ExcludeDscProperties | Should -Contain 'AccountId'
                $instance.ExcludeDscProperties | Should -Contain 'WorkspaceId'
                $instance.ExcludeDscProperties | Should -Contain 'PrincipalId'
                $instance.ExcludeDscProperties | Should -Contain 'AccessToken'
            }
        }

        It 'Should have _exist default to true' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksAccountWorkspacePermissionAssignment]::new()
                $instance._exist | Should -Be $true
            }
        }
    }
}

Describe 'DatabricksAccountWorkspacePermissionAssignment\Get()' -Tag 'Get' {
    Context 'When the system is in the desired state' {
        Context 'When permission assignment exists' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:mockInstance = [DatabricksAccountWorkspacePermissionAssignment] @{
                        WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                        AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                        AccountId    = '12345678-1234-1234-1234-123456789012'
                        WorkspaceId  = '1234567890123456'
                        PrincipalId  = '9876543210'
                        Permissions  = @([WorkspacePermissionLevel]::Admin)
                    }

                    $script:mockInstance |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                            return [System.Collections.Hashtable] @{
                                WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                                AccountId    = '12345678-1234-1234-1234-123456789012'
                                WorkspaceId  = '1234567890123456'
                                PrincipalId  = '9876543210'
                                Permissions  = @([WorkspacePermissionLevel]::Admin)
                                _exist       = $true
                            }
                        } -PassThru |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'AssertProperties' -Value {
                            return
                        } -PassThru |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'Compare' -Value {
                            return $null
                        }
                }
            }

            It 'Should return the correct values' {
                InModuleScope -ScriptBlock {
                    $currentState = $script:mockInstance.Get()

                    $currentState.AccountId | Should -Be '12345678-1234-1234-1234-123456789012'
                    $currentState.WorkspaceId | Should -Be '1234567890123456'
                    $currentState.PrincipalId | Should -Be '9876543210'
                    $currentState.Permissions | Should -Contain 'ADMIN'
                    $currentState.Reasons | Should -BeNullOrEmpty
                }
            }
        }
    }

    Context 'When the system is not in the desired state' {
        Context 'When permission assignment does not exist' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:mockInstance = [DatabricksAccountWorkspacePermissionAssignment] @{
                        WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                        AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                        AccountId    = '12345678-1234-1234-1234-123456789012'
                        WorkspaceId  = '1234567890123456'
                        PrincipalId  = '9876543210'
                        Permissions  = @([WorkspacePermissionLevel]::User)
                    }

                    $script:mockInstance |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                            return [System.Collections.Hashtable] @{
                                WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                                AccountId    = '12345678-1234-1234-1234-123456789012'
                                WorkspaceId  = '1234567890123456'
                                PrincipalId  = '9876543210'
                                Permissions  = @()
                                _exist       = $false
                            }
                        } -PassThru |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'AssertProperties' -Value {
                            return
                        }
                }
            }

            It 'Should return _exist = $false' {
                InModuleScope -ScriptBlock {
                    $currentState = $script:mockInstance.Get()

                    $currentState._exist | Should -BeFalse
                }
            }
        }
    }
}

Describe 'DatabricksAccountWorkspacePermissionAssignment\Set()' -Tag 'Set' {
    BeforeAll {
        InModuleScope -ScriptBlock {
            $script:mockInstance = [DatabricksAccountWorkspacePermissionAssignment] @{
                WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                AccountId    = '12345678-1234-1234-1234-123456789012'
                WorkspaceId  = '1234567890123456'
                PrincipalId  = '9876543210'
                Permissions  = @([WorkspacePermissionLevel]::Admin)
            } |
                Add-Member -Force -MemberType 'ScriptMethod' -Name 'Modify' -Value {
                    $script:mockMethodModifyCallCount += 1
                } -PassThru
        }
    }

    BeforeEach {
        InModuleScope -ScriptBlock {
            $script:mockMethodModifyCallCount = 0
        }
    }

    Context 'When the system is in the desired state' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'Compare' -Value {
                        return $null
                    } -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'AssertProperties' -Value {
                        return
                    }
            }
        }

        It 'Should not call method Modify()' {
            InModuleScope -ScriptBlock {
                $script:mockInstance.Set()

                $script:mockMethodModifyCallCount | Should -Be 0
            }
        }
    }

    Context 'When the system is not in the desired state' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'Compare' -Value {
                        return @{
                            Property      = 'Permissions'
                            ExpectedValue = @('ADMIN')
                            ActualValue   = @('USER')
                        }
                    } -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'AssertProperties' -Value {
                        return
                    }
            }
        }

        It 'Should call method Modify()' {
            InModuleScope -ScriptBlock {
                $script:mockInstance.Set()

                $script:mockMethodModifyCallCount | Should -Be 1
            }
        }
    }
}

Describe 'DatabricksAccountWorkspacePermissionAssignment\Test()' -Tag 'Test' {
    BeforeAll {
        InModuleScope -ScriptBlock {
            $script:mockInstance = [DatabricksAccountWorkspacePermissionAssignment] @{
                WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                AccountId    = '12345678-1234-1234-1234-123456789012'
                WorkspaceId  = '1234567890123456'
                PrincipalId  = '9876543210'
                Permissions  = @([WorkspacePermissionLevel]::Admin)
            }
        }
    }

    Context 'When the system is in the desired state' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance |
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
                $script:mockInstance.Test() | Should -BeTrue
            }
        }
    }

    Context 'When the system is not in the desired state' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'Compare' -Value {
                        return @(
                            @{
                                Property      = 'Permissions'
                                ExpectedValue = @('ADMIN')
                                ActualValue   = @('USER')
                            }
                        )
                    } -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'AssertProperties' -Value {
                        return
                    }
            }
        }

        It 'Should return $false' {
            InModuleScope -ScriptBlock {
                $script:mockInstance.Test() | Should -BeFalse
            }
        }
    }
}

Describe 'DatabricksAccountWorkspacePermissionAssignment\GetCurrentState()' -Tag 'GetCurrentState' {
    Context 'When permission assignment exists' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountWorkspacePermissionAssignment] @{
                    WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId    = '12345678-1234-1234-1234-123456789012'
                    WorkspaceId  = '1234567890123456'
                    PrincipalId  = '9876543210'
                }

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            permission_assignments = @(
                                @{
                                    principal   = @{
                                        principal_id = 9876543210
                                        user_name    = 'test@example.com'
                                    }
                                    permissions = @('ADMIN')
                                }
                            )
                        }
                    }
            }
        }

        It 'Should return the correct values with _exist = $true' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockInstance.GetCurrentState(
                    @{
                        AccountId   = '12345678-1234-1234-1234-123456789012'
                        WorkspaceId = '1234567890123456'
                        PrincipalId = '9876543210'
                    }
                )

                $currentState.AccountId | Should -Be '12345678-1234-1234-1234-123456789012'
                $currentState.WorkspaceId | Should -Be '1234567890123456'
                $currentState.PrincipalId | Should -Be '9876543210'
                $currentState.Permissions | Should -Contain 'ADMIN'
                $currentState._exist | Should -BeTrue
            }
        }
    }

    Context 'When principal has different permissions' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountWorkspacePermissionAssignment] @{
                    WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId    = '12345678-1234-1234-1234-123456789012'
                    WorkspaceId  = '1234567890123456'
                    PrincipalId  = '9876543210'
                }

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            permission_assignments = @(
                                @{
                                    principal   = @{
                                        principal_id = 9876543210
                                        user_name    = 'test@example.com'
                                    }
                                    permissions = @('USER')
                                }
                            )
                        }
                    }
            }
        }

        It 'Should return current permissions with _exist = $true' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockInstance.GetCurrentState(
                    @{
                        AccountId   = '12345678-1234-1234-1234-123456789012'
                        WorkspaceId = '1234567890123456'
                        PrincipalId = '9876543210'
                    }
                )

                $currentState.Permissions | Should -Contain 'USER'
                $currentState._exist | Should -BeTrue
            }
        }
    }

    Context 'When no permissions are assigned' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountWorkspacePermissionAssignment] @{
                    WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId    = '12345678-1234-1234-1234-123456789012'
                    WorkspaceId  = '1234567890123456'
                    PrincipalId  = '9876543210'
                }

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            permission_assignments = @()
                        }
                    }
            }
        }

        It 'Should return empty permissions with _exist = $false' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockInstance.GetCurrentState(
                    @{
                        AccountId   = '12345678-1234-1234-1234-123456789012'
                        WorkspaceId = '1234567890123456'
                        PrincipalId = '9876543210'
                    }
                )

                $currentState.Permissions.Count | Should -Be 0
                $currentState._exist | Should -BeFalse
            }
        }
    }

    Context 'When API call fails' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountWorkspacePermissionAssignment] @{
                    WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId    = '12345678-1234-1234-1234-123456789012'
                    WorkspaceId  = '1234567890123456'
                    PrincipalId  = '9876543210'
                }

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        throw 'API Error: Not Found'
                    }
            }
        }

        It 'Should handle error gracefully and return _exist = $false' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockInstance.GetCurrentState(
                    @{
                        AccountId   = '12345678-1234-1234-1234-123456789012'
                        WorkspaceId = '1234567890123456'
                        PrincipalId = '9876543210'
                    }
                )

                $currentState._exist | Should -BeFalse
                Should -Invoke -CommandName Write-Verbose -ParameterFilter {
                    $Message -like '*Error getting permission assignment*'
                } -Exactly -Times 1 -Scope It
            }
        }
    }

    Context 'When principal is a service principal' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountWorkspacePermissionAssignment] @{
                    WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId    = '12345678-1234-1234-1234-123456789012'
                    WorkspaceId  = '1234567890123456'
                    PrincipalId  = '9876543210'
                }

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            permission_assignments = @(
                                @{
                                    principal   = @{
                                        principal_id = 9876543210
                                        service_principal_name = 'test-sp'
                                    }
                                    permissions = @('ADMIN')
                                }
                            )
                        }
                    }
            }
        }

        It 'Should find service principal by service_principal_id' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockInstance.GetCurrentState(
                    @{
                        AccountId   = '12345678-1234-1234-1234-123456789012'
                        WorkspaceId = '1234567890123456'
                        PrincipalId = '9876543210'
                    }
                )

                $currentState._exist | Should -BeTrue
                $currentState.Permissions | Should -Contain 'ADMIN'
            }
        }
    }

    Context 'When principal is a group' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountWorkspacePermissionAssignment] @{
                    WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId    = '12345678-1234-1234-1234-123456789012'
                    WorkspaceId  = '1234567890123456'
                    PrincipalId  = '9876543210'
                }

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            permission_assignments = @(
                                @{
                                    principal   = @{
                                        principal_id = 9876543210
                                        group_name   = 'test-group'
                                    }
                                    permissions = @('USER')
                                }
                            )
                        }
                    }
            }
        }

        It 'Should find group by group_id' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockInstance.GetCurrentState(
                    @{
                        AccountId   = '12345678-1234-1234-1234-123456789012'
                        WorkspaceId = '1234567890123456'
                        PrincipalId = '9876543210'
                    }
                )

                $currentState._exist | Should -BeTrue
                $currentState.Permissions | Should -Contain 'USER'
            }
        }
    }
}

Describe 'DatabricksAccountWorkspacePermissionAssignment\Modify()' -Tag 'Modify' {
    Context 'When permission assignment needs to be created' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountWorkspacePermissionAssignment] @{
                    WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId    = '12345678-1234-1234-1234-123456789012'
                    WorkspaceId  = '1234567890123456'
                    PrincipalId  = '9876543210'
                    Permissions  = @([WorkspacePermissionLevel]::Admin)
                } | Add-Member -Force -MemberType 'NoteProperty' -Name '_exist' -Value $false -PassThru

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param($Method, $Path, $Body)

                        $script:mockInvokeApiMethod = $Method
                        $script:mockInvokeApiPath = $Path
                        $script:mockInvokeApiBody = $Body
                    }
            }
        }

        It 'Should call InvokeDatabricksApi with PUT method' {
            InModuleScope -ScriptBlock {
                $script:mockInstance.Modify(@{ _exist = $true })

                $script:mockInvokeApiMethod | Should -Be 'PUT'
                $script:mockInvokeApiPath | Should -Match '/api/2.0/accounts/.*/workspaces/.*/permissionassignments/principals/.*'
                $script:mockInvokeApiBody.permissions.Count | Should -Be 1
                $script:mockInvokeApiBody.permissions[0] | Should -Be 'ADMIN'
            }
        }

        It 'Should write verbose messages' {
            InModuleScope -ScriptBlock {
                $script:mockInstance.Modify(@{ _exist = $true })

                Should -Invoke -CommandName Write-Verbose -ParameterFilter {
                    $Message -like '*Assigning permissions*'
                } -Exactly -Times 1 -Scope It

                Should -Invoke -CommandName Write-Verbose -ParameterFilter {
                    $Message -like '*have been successfully assigned*'
                } -Exactly -Times 1 -Scope It
            }
        }
    }

    Context 'When permission assignment needs to be updated' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountWorkspacePermissionAssignment] @{
                    WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId    = '12345678-1234-1234-1234-123456789012'
                    WorkspaceId  = '1234567890123456'
                    PrincipalId  = '9876543210'
                    Permissions  = @([WorkspacePermissionLevel]::User)
                } | Add-Member -Force -MemberType 'NoteProperty' -Name '_exist' -Value $true -PassThru

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param($Method, $Path, $Body)

                        $script:mockInvokeApiMethod = $Method
                        $script:mockInvokeApiPath = $Path
                        $script:mockInvokeApiBody = $Body
                    }
            }
        }

        It 'Should call InvokeDatabricksApi with PUT method and new permissions' {
            InModuleScope -ScriptBlock {
                $script:mockInstance.Modify(@{ Permissions = @([WorkspacePermissionLevel]::Admin) })

                $script:mockInvokeApiMethod | Should -Be 'PUT'
                $script:mockInvokeApiBody.permissions.Count | Should -Be 1
                $script:mockInvokeApiBody.permissions[0] | Should -Be 'ADMIN'
            }
        }
    }

    Context 'When permission assignment needs to be removed' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountWorkspacePermissionAssignment] @{
                    WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId    = '12345678-1234-1234-1234-123456789012'
                    WorkspaceId  = '1234567890123456'
                    PrincipalId  = '9876543210'
                    Permissions  = @([WorkspacePermissionLevel]::Admin)
                } | Add-Member -Force -MemberType 'NoteProperty' -Name '_exist' -Value $true -PassThru

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param($Method, $Path, $Body)

                        $script:mockInvokeApiMethod = $Method
                        $script:mockInvokeApiPath = $Path
                        $script:mockInvokeApiBody = $Body
                    }
            }
        }

        It 'Should call InvokeDatabricksApi with DELETE method' {
            InModuleScope -ScriptBlock {
                $script:mockInstance.Modify(@{ _exist = $false })

                $script:mockInvokeApiMethod | Should -Be 'DELETE'
                $script:mockInvokeApiPath | Should -Match '/api/2.0/accounts/.*/workspaces/.*/permissionassignments/principals/.*'
                $script:mockInvokeApiBody | Should -BeNullOrEmpty
            }
        }

        It 'Should write verbose messages' {
            InModuleScope -ScriptBlock {
                $script:mockInstance.Modify(@{ _exist = $false })

                Should -Invoke -CommandName Write-Verbose -ParameterFilter {
                    $Message -like '*Unassigning permissions*'
                } -Exactly -Times 1 -Scope It

                Should -Invoke -CommandName Write-Verbose -ParameterFilter {
                    $Message -like '*have been successfully unassigned*'
                } -Exactly -Times 1 -Scope It
            }
        }
    }

    Context 'When assignment creation fails' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountWorkspacePermissionAssignment] @{
                    WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId    = '12345678-1234-1234-1234-123456789012'
                    WorkspaceId  = '1234567890123456'
                    PrincipalId  = '9876543210'
                    Permissions  = @([WorkspacePermissionLevel]::Admin)
                } | Add-Member -Force -MemberType 'NoteProperty' -Name '_exist' -Value $false -PassThru

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        throw 'API Error: Principal not found'
                    }
            }
        }

        It 'Should throw with localized error message' {
            InModuleScope -ScriptBlock {
                {
                    $script:mockInstance.Modify(@{ _exist = $true })
                } | Should -Throw -ExpectedMessage '*Failed to assign permissions*'
            }
        }
    }

    Context 'When Permissions property is not set' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountWorkspacePermissionAssignment] @{
                    WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId    = '12345678-1234-1234-1234-123456789012'
                    WorkspaceId  = '1234567890123456'
                    PrincipalId  = '9876543210'
                } | Add-Member -Force -MemberType 'NoteProperty' -Name '_exist' -Value $false -PassThru
            }
        }

        It 'Should throw when trying to create assignment without permissions' {
            InModuleScope -ScriptBlock {
                {
                    $script:mockInstance.Modify(@{ _exist = $true })
                } | Should -Throw -ExpectedMessage '*Permissions property must be set*'
            }
        }
    }

    Context 'When assignment removal fails' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountWorkspacePermissionAssignment] @{
                    WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId    = '12345678-1234-1234-1234-123456789012'
                    WorkspaceId  = '1234567890123456'
                    PrincipalId  = '9876543210'
                    Permissions  = @([WorkspacePermissionLevel]::Admin)
                } | Add-Member -Force -MemberType 'NoteProperty' -Name '_exist' -Value $true -PassThru

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        throw 'API Error: Permission denied'
                    }
            }
        }

        It 'Should throw with localized error message' {
            InModuleScope -ScriptBlock {
                {
                    $script:mockInstance.Modify(@{ _exist = $false })
                } | Should -Throw -ExpectedMessage '*Failed to unassign permissions*'
            }
        }
    }
}

Describe 'DatabricksAccountWorkspacePermissionAssignment\AssertProperties()' -Tag 'AssertProperties' {
    BeforeAll {
        InModuleScope -ScriptBlock {
            $script:mockInstance = [DatabricksAccountWorkspacePermissionAssignment] @{
                WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                AccountId    = '12345678-1234-1234-1234-123456789012'
                WorkspaceId  = '1234567890123456'
                PrincipalId  = '9876543210'
                Permissions  = @([WorkspacePermissionLevel]::Admin)
            }
        }
    }

    Context 'When all properties are valid' {
        It 'Should not throw' {
            InModuleScope -ScriptBlock {
                {
                    $script:mockInstance.AssertProperties(@{
                            WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                            AccountId    = '12345678-1234-1234-1234-123456789012'
                            WorkspaceId  = '1234567890123456'
                            PrincipalId  = '9876543210'
                            Permissions  = @([WorkspacePermissionLevel]::Admin)
                            _exist       = $true
                        })
                } | Should -Not -Throw
            }
        }
    }

    Context 'When WorkspaceUrl is invalid' {
        It 'Should throw for non-https URL' {
            InModuleScope -ScriptBlock {
                {
                    $script:mockInstance.AssertProperties(@{
                            WorkspaceUrl = 'http://invalid.com'
                            AccountId    = '12345678-1234-1234-1234-123456789012'
                            WorkspaceId  = '1234567890123456'
                            PrincipalId  = '9876543210'
                            Permissions  = @([WorkspacePermissionLevel]::Admin)
                            _exist       = $true
                        })
                } | Should -Throw -ExpectedMessage '*WorkspaceUrl*'
            }
        }
    }

    Context 'When AccountId is invalid' {
        It 'Should throw for non-GUID format' {
            InModuleScope -ScriptBlock {
                {
                    $script:mockInstance.AssertProperties(@{
                            WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                            AccountId    = 'not-a-guid'
                            WorkspaceId  = '1234567890123456'
                            PrincipalId  = '9876543210'
                            Permissions  = @([WorkspacePermissionLevel]::Admin)
                            _exist       = $true
                        })
                } | Should -Throw -ExpectedMessage '*AccountId*'
            }
        }
    }

    Context 'When WorkspaceId is invalid' {
        It 'Should throw for non-numeric value' {
            InModuleScope -ScriptBlock {
                {
                    $script:mockInstance.AssertProperties(@{
                            WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                            AccountId    = '12345678-1234-1234-1234-123456789012'
                            WorkspaceId  = 'not-numeric'
                            PrincipalId  = '9876543210'
                            Permissions  = @([WorkspacePermissionLevel]::Admin)
                            _exist       = $true
                        })
                } | Should -Throw -ExpectedMessage '*WorkspaceId*'
            }
        }
    }

    Context 'When PrincipalId is invalid' {
        It 'Should throw for non-numeric value' {
            InModuleScope -ScriptBlock {
                {
                    $script:mockInstance.AssertProperties(@{
                            WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                            AccountId    = '12345678-1234-1234-1234-123456789012'
                            WorkspaceId  = '1234567890123456'
                            PrincipalId  = 'not-numeric'
                            Permissions  = @([WorkspacePermissionLevel]::Admin)
                            _exist       = $true
                        })
                } | Should -Throw -ExpectedMessage '*PrincipalId*'
            }
        }
    }
}
