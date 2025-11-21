<#
    .SYNOPSIS
        Unit test for DatabricksAccountMetastoreAssignment DSC resource.
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

Describe 'DatabricksAccountMetastoreAssignment' {
    Context 'When class is instantiated' {
        It 'Should not throw an exception' {
            InModuleScope -ScriptBlock {
                { [DatabricksAccountMetastoreAssignment]::new() } | Should -Not -Throw
            }
        }

        It 'Should have a default or empty constructor' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksAccountMetastoreAssignment]::new()
                $instance | Should -Not -BeNullOrEmpty
            }
        }

        It 'Should be the correct type' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksAccountMetastoreAssignment]::new()
                $instance.GetType().Name | Should -Be 'DatabricksAccountMetastoreAssignment'
            }
        }

        It 'Should have ExcludeDscProperties set' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksAccountMetastoreAssignment]::new()
                $instance.ExcludeDscProperties | Should -Contain 'WorkspaceUrl'
                $instance.ExcludeDscProperties | Should -Contain 'AccountId'
                $instance.ExcludeDscProperties | Should -Contain 'WorkspaceId'
                $instance.ExcludeDscProperties | Should -Contain 'MetastoreId'
                $instance.ExcludeDscProperties | Should -Contain 'AccessToken'
            }
        }

        It 'Should have _exist default to true' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksAccountMetastoreAssignment]::new()
                $instance._exist | Should -Be $true
            }
        }
    }
}

Describe 'DatabricksAccountMetastoreAssignment\Get()' -Tag 'Get' {
    Context 'When the system is in the desired state' {
        Context 'When metastore assignment exists' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:mockInstance = [DatabricksAccountMetastoreAssignment] @{
                        WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                        AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                        AccountId    = '12345678-1234-1234-1234-123456789012'
                        WorkspaceId  = '1234567890123456'
                        MetastoreId  = '87654321-4321-4321-4321-210987654321'
                    }

                    $script:mockInstance |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                            return [System.Collections.Hashtable] @{
                                WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                                AccountId    = '12345678-1234-1234-1234-123456789012'
                                WorkspaceId  = '1234567890123456'
                                MetastoreId  = '87654321-4321-4321-4321-210987654321'
                                _exist       = $true
                            }
                        } -PassThru |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'AssertProperties' -Value {
                            return
                        }
                }
            }

            It 'Should return the correct values' {
                InModuleScope -ScriptBlock {
                    $currentState = $script:mockInstance.Get()

                    $currentState.AccountId | Should -Be '12345678-1234-1234-1234-123456789012'
                    $currentState.WorkspaceId | Should -Be '1234567890123456'
                    $currentState.MetastoreId | Should -Be '87654321-4321-4321-4321-210987654321'
                    $currentState.Reasons | Should -BeNullOrEmpty
                }
            }
        }
    }

    Context 'When the system is not in the desired state' {
        Context 'When metastore assignment does not exist' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:mockInstance = [DatabricksAccountMetastoreAssignment] @{
                        WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                        AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                        AccountId    = '12345678-1234-1234-1234-123456789012'
                        WorkspaceId  = '1234567890123456'
                        MetastoreId  = '87654321-4321-4321-4321-210987654321'
                    }

                    $script:mockInstance |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                            return [System.Collections.Hashtable] @{
                                WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                                AccountId    = '12345678-1234-1234-1234-123456789012'
                                WorkspaceId  = '1234567890123456'
                                MetastoreId  = '87654321-4321-4321-4321-210987654321'
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

Describe 'DatabricksAccountMetastoreAssignment\Set()' -Tag 'Set' {
    BeforeAll {
        InModuleScope -ScriptBlock {
            $script:mockInstance = [DatabricksAccountMetastoreAssignment] @{
                WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                AccountId    = '12345678-1234-1234-1234-123456789012'
                WorkspaceId  = '1234567890123456'
                MetastoreId  = '87654321-4321-4321-4321-210987654321'
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
                            Property      = '_exist'
                            ExpectedValue = $true
                            ActualValue   = $false
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

Describe 'DatabricksAccountMetastoreAssignment\Test()' -Tag 'Test' {
    BeforeAll {
        InModuleScope -ScriptBlock {
            $script:mockInstance = [DatabricksAccountMetastoreAssignment] @{
                WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                AccountId    = '12345678-1234-1234-1234-123456789012'
                WorkspaceId  = '1234567890123456'
                MetastoreId  = '87654321-4321-4321-4321-210987654321'
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
                                Property      = '_exist'
                                ExpectedValue = $true
                                ActualValue   = $false
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

Describe 'DatabricksAccountMetastoreAssignment\GetCurrentState()' -Tag 'GetCurrentState' {
    Context 'When metastore is assigned to workspace' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountMetastoreAssignment] @{
                    WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId    = '12345678-1234-1234-1234-123456789012'
                    WorkspaceId  = '1234567890123456'
                    MetastoreId  = '87654321-4321-4321-4321-210987654321'
                }

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            metastore_assignment = @{
                                workspace_id = '1234567890123456'
                                metastore_id = '87654321-4321-4321-4321-210987654321'
                            }
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
                        MetastoreId = '87654321-4321-4321-4321-210987654321'
                    }
                )

                $currentState.AccountId | Should -Be '12345678-1234-1234-1234-123456789012'
                $currentState.WorkspaceId | Should -Be '1234567890123456'
                $currentState.MetastoreId | Should -Be '87654321-4321-4321-4321-210987654321'
                $currentState._exist | Should -BeTrue
            }
        }
    }

    Context 'When different metastore is assigned' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountMetastoreAssignment] @{
                    WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId    = '12345678-1234-1234-1234-123456789012'
                    WorkspaceId  = '1234567890123456'
                    MetastoreId  = '87654321-4321-4321-4321-210987654321'
                }

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            metastore_assignment = @{
                                workspace_id = '1234567890123456'
                                metastore_id = 'different-meta-store-id-here-1234'
                            }
                        }
                    }
            }
        }

        It 'Should return _exist = $false when metastore IDs do not match' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockInstance.GetCurrentState(
                    @{
                        AccountId   = '12345678-1234-1234-1234-123456789012'
                        WorkspaceId = '1234567890123456'
                        MetastoreId = '87654321-4321-4321-4321-210987654321'
                    }
                )

                $currentState._exist | Should -BeFalse
            }
        }
    }

    Context 'When no metastore is assigned' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountMetastoreAssignment] @{
                    WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId    = '12345678-1234-1234-1234-123456789012'
                    WorkspaceId  = '1234567890123456'
                    MetastoreId  = '87654321-4321-4321-4321-210987654321'
                }

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{}
                    }
            }
        }

        It 'Should return _exist = $false' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockInstance.GetCurrentState(
                    @{
                        AccountId   = '12345678-1234-1234-1234-123456789012'
                        WorkspaceId = '1234567890123456'
                        MetastoreId = '87654321-4321-4321-4321-210987654321'
                    }
                )

                $currentState._exist | Should -BeFalse
            }
        }
    }

    Context 'When API call fails' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountMetastoreAssignment] @{
                    WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId    = '12345678-1234-1234-1234-123456789012'
                    WorkspaceId  = '1234567890123456'
                    MetastoreId  = '87654321-4321-4321-4321-210987654321'
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
                        MetastoreId = '87654321-4321-4321-4321-210987654321'
                    }
                )

                $currentState._exist | Should -BeFalse
                Should -Invoke -CommandName Write-Verbose -ParameterFilter {
                    $Message -like '*Error getting metastore assignment*'
                } -Exactly -Times 1 -Scope It
            }
        }
    }
}

Describe 'DatabricksAccountMetastoreAssignment\Modify()' -Tag 'Modify' {
    Context 'When metastore assignment needs to be created' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountMetastoreAssignment] @{
                    WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId    = '12345678-1234-1234-1234-123456789012'
                    WorkspaceId  = '1234567890123456'
                    MetastoreId  = '87654321-4321-4321-4321-210987654321'
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

        It 'Should call InvokeDatabricksApi with POST method' {
            InModuleScope -ScriptBlock {
                $script:mockInstance.Modify(@{ _exist = $true })

                $script:mockInvokeApiMethod | Should -Be 'POST'
                $script:mockInvokeApiPath | Should -Match '/api/2.0/accounts/.*/workspaces/.*/metastores'
                $script:mockInvokeApiBody.metastore_id | Should -Be '87654321-4321-4321-4321-210987654321'
            }
        }

        It 'Should write verbose messages' {
            InModuleScope -ScriptBlock {
                $script:mockInstance.Modify(@{ _exist = $true })

                Should -Invoke -CommandName Write-Verbose -ParameterFilter {
                    $Message -like '*Assigning metastore*'
                } -Exactly -Times 1 -Scope It

                Should -Invoke -CommandName Write-Verbose -ParameterFilter {
                    $Message -like '*has been successfully assigned*'
                } -Exactly -Times 1 -Scope It
            }
        }
    }

    Context 'When metastore assignment needs to be removed' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountMetastoreAssignment] @{
                    WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId    = '12345678-1234-1234-1234-123456789012'
                    WorkspaceId  = '1234567890123456'
                    MetastoreId  = '87654321-4321-4321-4321-210987654321'
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
                $script:mockInvokeApiPath | Should -Match '/api/2.0/accounts/.*/workspaces/.*/metastores/.*'
                $script:mockInvokeApiBody | Should -BeNullOrEmpty
            }
        }

        It 'Should write verbose messages' {
            InModuleScope -ScriptBlock {
                $script:mockInstance.Modify(@{ _exist = $false })

                Should -Invoke -CommandName Write-Verbose -ParameterFilter {
                    $Message -like '*Unassigning metastore*'
                } -Exactly -Times 1 -Scope It

                Should -Invoke -CommandName Write-Verbose -ParameterFilter {
                    $Message -like '*has been successfully unassigned*'
                } -Exactly -Times 1 -Scope It
            }
        }
    }

    Context 'When assignment creation fails' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountMetastoreAssignment] @{
                    WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId    = '12345678-1234-1234-1234-123456789012'
                    WorkspaceId  = '1234567890123456'
                    MetastoreId  = '87654321-4321-4321-4321-210987654321'
                } | Add-Member -Force -MemberType 'NoteProperty' -Name '_exist' -Value $false -PassThru

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        throw 'API Error: Metastore not found'
                    }
            }
        }

        It 'Should throw with localized error message' {
            InModuleScope -ScriptBlock {
                {
                    $script:mockInstance.Modify(@{ _exist = $true })
                } | Should -Throw -ExpectedMessage '*Failed to assign metastore*'
            }
        }
    }

    Context 'When assignment removal fails' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountMetastoreAssignment] @{
                    WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId    = '12345678-1234-1234-1234-123456789012'
                    WorkspaceId  = '1234567890123456'
                    MetastoreId  = '87654321-4321-4321-4321-210987654321'
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
                } | Should -Throw -ExpectedMessage '*Failed to unassign metastore*'
            }
        }
    }
}

Describe 'DatabricksAccountMetastoreAssignment\AssertProperties()' -Tag 'AssertProperties' {
    BeforeAll {
        InModuleScope -ScriptBlock {
            $script:mockInstance = [DatabricksAccountMetastoreAssignment] @{
                WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                AccountId    = '12345678-1234-1234-1234-123456789012'
                WorkspaceId  = '1234567890123456'
                MetastoreId  = '87654321-4321-4321-4321-210987654321'
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
                            MetastoreId  = '87654321-4321-4321-4321-210987654321'
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
                            MetastoreId  = '87654321-4321-4321-4321-210987654321'
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
                            MetastoreId  = '87654321-4321-4321-4321-210987654321'
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
                            MetastoreId  = '87654321-4321-4321-4321-210987654321'
                        })
                } | Should -Throw -ExpectedMessage '*WorkspaceId*'
            }
        }
    }

    Context 'When MetastoreId is invalid' {
        It 'Should throw for non-GUID format' {
            InModuleScope -ScriptBlock {
                {
                    $script:mockInstance.AssertProperties(@{
                            WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                            AccountId    = '12345678-1234-1234-1234-123456789012'
                            WorkspaceId  = '1234567890123456'
                            MetastoreId  = 'not-a-guid'
                        })
                } | Should -Throw -ExpectedMessage '*MetastoreId*'
            }
        }
    }
}
