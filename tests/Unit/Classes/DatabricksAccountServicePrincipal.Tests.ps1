<#
    .SYNOPSIS
        Unit test for DatabricksAccountServicePrincipal DSC resource.
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
}

Describe 'DatabricksAccountServicePrincipal' {
    Context 'When class is instantiated' {
        It 'Should not throw an exception' {
            InModuleScope -ScriptBlock {
                { [DatabricksAccountServicePrincipal]::new() } | Should -Not -Throw
            }
        }

        It 'Should have a default or empty constructor' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksAccountServicePrincipal]::new()
                $instance | Should -Not -BeNullOrEmpty
            }
        }

        It 'Should be the correct type' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksAccountServicePrincipal]::new()
                $instance.GetType().Name | Should -Be 'DatabricksAccountServicePrincipal'
            }
        }

        It 'Should have ExcludeDscProperties set' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksAccountServicePrincipal]::new()
                $instance.ExcludeDscProperties | Should -Contain 'WorkspaceUrl'
                $instance.ExcludeDscProperties | Should -Contain 'AccountId'
                $instance.ExcludeDscProperties | Should -Contain 'ApplicationId'
                $instance.ExcludeDscProperties | Should -Contain 'AccessToken'
                $instance.ExcludeDscProperties | Should -Contain 'Id'
                $instance.ExcludeDscProperties | Should -Contain 'ExternalId'
            }
        }

        It 'Should have Active default to true' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksAccountServicePrincipal]::new()
                $instance.Active | Should -Be $true
            }
        }
    }
}

Describe 'DatabricksAccountServicePrincipal\Get()' {
    Context 'When the system is in the desired state' {
        Context 'When account service principal exists with minimal properties' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:mockInstance = [DatabricksAccountServicePrincipal] @{
                        WorkspaceUrl  = 'https://accounts.azuredatabricks.net'
                        AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                        AccountId     = '12345678-1234-1234-1234-123456789012'
                        ApplicationId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                    }

                    $script:mockInstance |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                            return [System.Collections.Hashtable] @{
                                WorkspaceUrl  = 'https://accounts.azuredatabricks.net'
                                AccountId     = '12345678-1234-1234-1234-123456789012'
                                ApplicationId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                                DisplayName   = 'Test Service Principal'
                                Active        = $true
                                _exist        = $true
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
                    $currentState.ApplicationId | Should -Be 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                    $currentState.DisplayName | Should -Be 'Test Service Principal'
                    $currentState.Active | Should -BeTrue
                    $currentState.Reasons | Should -BeNullOrEmpty
                }
            }
        }

        Context 'When account service principal exists with all properties' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:mockInstance = [DatabricksAccountServicePrincipal] @{
                        WorkspaceUrl  = 'https://accounts.azuredatabricks.net'
                        AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                        AccountId     = '12345678-1234-1234-1234-123456789012'
                        ApplicationId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                    }

                    $script:mockInstance |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                            return [System.Collections.Hashtable] @{
                                WorkspaceUrl  = 'https://accounts.azuredatabricks.net'
                                AccountId     = '12345678-1234-1234-1234-123456789012'
                                ApplicationId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                                DisplayName   = 'Test Service Principal'
                                Active        = $true
                                ExternalId    = 'ext-sp-123'
                                Roles         = @(
                                    [UserRole] @{ Value = 'account_admin' }
                                )
                                _exist        = $true
                            }
                        } -PassThru |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'AssertProperties' -Value {
                            return
                        }
                }
            }

            It 'Should return the correct values with all properties' {
                InModuleScope -ScriptBlock {
                    $currentState = $script:mockInstance.Get()

                    $currentState.ApplicationId | Should -Be 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                    $currentState.DisplayName | Should -Be 'Test Service Principal'
                    $currentState.Active | Should -BeTrue
                    $currentState.ExternalId | Should -Be 'ext-sp-123'
                    $currentState.Roles | Should -HaveCount 1
                    $currentState.Roles[0].Value | Should -Be 'account_admin'
                    $currentState.Reasons | Should -BeNullOrEmpty
                }
            }
        }
    }

    Context 'When the system is not in the desired state' {
        Context 'When account service principal DisplayName has wrong value' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:mockInstance = [DatabricksAccountServicePrincipal] @{
                        WorkspaceUrl  = 'https://accounts.azuredatabricks.net'
                        AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                        AccountId     = '12345678-1234-1234-1234-123456789012'
                        ApplicationId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                        DisplayName   = 'Expected Name'
                    }

                    $script:mockInstance |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                            return [System.Collections.Hashtable] @{
                                WorkspaceUrl  = 'https://accounts.azuredatabricks.net'
                                AccountId     = '12345678-1234-1234-1234-123456789012'
                                ApplicationId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                                DisplayName   = 'Actual Name'
                                Active        = $true
                                _exist        = $true
                            }
                        } -PassThru |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'AssertProperties' -Value {
                            return
                        }
                }
            }

            It 'Should return the correct values with reasons' {
                InModuleScope -ScriptBlock {
                    $currentState = $script:mockInstance.Get()

                    $currentState.ApplicationId | Should -Be 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                    $currentState.DisplayName | Should -Be 'Actual Name'
                    $currentState.Reasons | Should -Not -BeNullOrEmpty
                    $currentState.Reasons[0].Code | Should -Be 'DatabricksAccountServicePrincipal:DatabricksAccountServicePrincipal:DisplayName'
                }
            }
        }
    }
}

Describe 'DatabricksAccountServicePrincipal\Set()' {
    Context 'When the system is in the desired state' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountServicePrincipal] @{
                    WorkspaceUrl  = 'https://accounts.azuredatabricks.net'
                    AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId     = '12345678-1234-1234-1234-123456789012'
                    ApplicationId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                }

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'AssertProperties' -Value {
                        return
                    } -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'Modify' -Value {
                        param([hashtable]$properties)
                    } -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                        return [System.Collections.Hashtable] @{
                            WorkspaceUrl  = 'https://accounts.azuredatabricks.net'
                            AccountId     = '12345678-1234-1234-1234-123456789012'
                            ApplicationId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                            DisplayName   = 'Test Service Principal'
                            Active        = $true
                            _exist        = $true
                        }
                    }

                Mock -CommandName Should -Verifiable
            }
        }

        It 'Should not call method Modify()' {
            InModuleScope -ScriptBlock {
                $script:mockInstance.Set()

                Should -Invoke -CommandName Should -Exactly -Times 0 -Scope It
            }
        }
    }

    Context 'When the system is not in the desired state' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountServicePrincipal] @{
                    WorkspaceUrl  = 'https://accounts.azuredatabricks.net'
                    AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId     = '12345678-1234-1234-1234-123456789012'
                    ApplicationId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                    DisplayName   = 'Expected Name'
                }

                $script:modifyCalled = $false

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'AssertProperties' -Value {
                        return
                    } -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'Modify' -Value {
                        param([hashtable]$properties)
                        $script:modifyCalled = $true
                    } -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                        return [System.Collections.Hashtable] @{
                            WorkspaceUrl  = 'https://accounts.azuredatabricks.net'
                            AccountId     = '12345678-1234-1234-1234-123456789012'
                            ApplicationId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                            DisplayName   = 'Actual Name'
                            Active        = $true
                            _exist        = $true
                        }
                    }
            }
        }

        It 'Should call method Modify()' {
            InModuleScope -ScriptBlock {
                $script:mockInstance.Set()

                $script:modifyCalled | Should -BeTrue
            }
        }
    }
}

Describe 'DatabricksAccountServicePrincipal\Test()' {
    Context 'When the system is in the desired state' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountServicePrincipal] @{
                    WorkspaceUrl  = 'https://accounts.azuredatabricks.net'
                    AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId     = '12345678-1234-1234-1234-123456789012'
                    ApplicationId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                }

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'AssertProperties' -Value {
                        return
                    } -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                        return [System.Collections.Hashtable] @{
                            WorkspaceUrl  = 'https://accounts.azuredatabricks.net'
                            AccountId     = '12345678-1234-1234-1234-123456789012'
                            ApplicationId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                            DisplayName   = 'Test Service Principal'
                            Active        = $true
                            _exist        = $true
                        }
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
                $script:mockInstance = [DatabricksAccountServicePrincipal] @{
                    WorkspaceUrl  = 'https://accounts.azuredatabricks.net'
                    AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId     = '12345678-1234-1234-1234-123456789012'
                    ApplicationId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                    DisplayName   = 'Expected Name'
                }

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'AssertProperties' -Value {
                        return
                    } -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                        return [System.Collections.Hashtable] @{
                            WorkspaceUrl  = 'https://accounts.azuredatabricks.net'
                            AccountId     = '12345678-1234-1234-1234-123456789012'
                            ApplicationId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                            DisplayName   = 'Actual Name'
                            Active        = $true
                            _exist        = $true
                        }
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

Describe 'DatabricksAccountServicePrincipal\GetCurrentState()' {
    Context 'When account service principal does not exist' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountServicePrincipal] @{
                    WorkspaceUrl  = 'https://accounts.azuredatabricks.net'
                    AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId     = '12345678-1234-1234-1234-123456789012'
                    ApplicationId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                }

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            Resources = @()
                        }
                    }
            }
        }

        It 'Should return the correct values with _exist = $false' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockInstance.GetCurrentState(
                    @{
                        AccountId     = '12345678-1234-1234-1234-123456789012'
                        ApplicationId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                    }
                )

                $currentState.AccountId | Should -Be '12345678-1234-1234-1234-123456789012'
                $currentState.ApplicationId | Should -Be 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                $currentState._exist | Should -BeFalse
                $script:mockInstance._exist | Should -BeFalse
            }
        }
    }

    Context 'When account service principal exists with all properties' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountServicePrincipal] @{
                    WorkspaceUrl  = 'https://accounts.azuredatabricks.net'
                    AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId     = '12345678-1234-1234-1234-123456789012'
                    ApplicationId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                }

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            Resources = @(
                                @{
                                    id            = 'sp-123'
                                    applicationId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                                    displayName   = 'Test Service Principal'
                                    active        = $true
                                    externalId    = 'ext-sp-123'
                                    roles         = @(
                                        @{ value = 'account_admin' }
                                    )
                                }
                            )
                        }
                    }
            }
        }

        It 'Should return the correct values with all properties populated' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockInstance.GetCurrentState(
                    @{
                        AccountId     = '12345678-1234-1234-1234-123456789012'
                        ApplicationId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                    }
                )

                $currentState.Id | Should -Be 'sp-123'
                $currentState.DisplayName | Should -Be 'Test Service Principal'
                $currentState.Active | Should -BeTrue
                $currentState.ExternalId | Should -Be 'ext-sp-123'
                $currentState.Roles | Should -HaveCount 1
            }
        }
    }

    Context 'When API call fails' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountServicePrincipal] @{
                    WorkspaceUrl  = 'https://accounts.azuredatabricks.net'
                    AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId     = '12345678-1234-1234-1234-123456789012'
                    ApplicationId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                }

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        throw 'API Error'
                    }
            }
        }

        It 'Should handle error gracefully and return current state with _exist = $false' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockInstance.GetCurrentState(
                    @{
                        AccountId     = '12345678-1234-1234-1234-123456789012'
                        ApplicationId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                    }
                )

                $currentState._exist | Should -BeFalse
            }
        }
    }
}

Describe 'DatabricksAccountServicePrincipal\Modify()' {
    Context 'When account service principal exists and needs to be updated' {
        It 'Should call InvokeDatabricksApi with PATCH method' {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountServicePrincipal] @{
                    WorkspaceUrl  = 'https://accounts.azuredatabricks.net'
                    AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId     = '12345678-1234-1234-1234-123456789012'
                    ApplicationId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                    DisplayName   = 'Updated Service Principal'
                }

                $script:mockInstance | Add-Member -Force -MemberType 'NoteProperty' -Name '_exist' -Value $true -PassThru |
                    Add-Member -Force -MemberType 'NoteProperty' -Name 'Id' -Value 'sp-123' -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param($Method, $ApiPath, $Body)
                        $script:invokedMethod = $Method
                        $script:invokedEndpoint = $ApiPath
                        return @{}
                    }

                $script:mockInstance.Modify(@{
                        AccountId     = '12345678-1234-1234-1234-123456789012'
                        ApplicationId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                        DisplayName   = 'Updated Service Principal'
                    })

                $script:invokedMethod | Should -Be 'PATCH'
                $script:invokedEndpoint | Should -BeLike '*sp-123'
            }
        }
    }

    Context 'When account service principal does not exist and needs to be created' {
        It 'Should call InvokeDatabricksApi with POST method' {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountServicePrincipal] @{
                    WorkspaceUrl  = 'https://accounts.azuredatabricks.net'
                    AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId     = '12345678-1234-1234-1234-123456789012'
                    ApplicationId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                    DisplayName   = 'New Service Principal'
                }

                $script:mockInstance | Add-Member -Force -MemberType 'NoteProperty' -Name '_exist' -Value $false -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param($Method, $ApiPath, $Body)
                        $script:invokedMethod = $Method
                        return @{}
                    }

                $script:mockInstance.Modify(@{
                        AccountId     = '12345678-1234-1234-1234-123456789012'
                        ApplicationId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                        DisplayName   = 'New Service Principal'
                        _exist        = $true
                    })

                $script:invokedMethod | Should -Be 'POST'
            }
        }
    }

    Context 'When account service principal exists and should be removed' {
        It 'Should call InvokeDatabricksApi with DELETE method' {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountServicePrincipal] @{
                    WorkspaceUrl  = 'https://accounts.azuredatabricks.net'
                    AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId     = '12345678-1234-1234-1234-123456789012'
                    ApplicationId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                }

                $script:mockInstance | Add-Member -Force -MemberType 'NoteProperty' -Name '_exist' -Value $true -PassThru |
                    Add-Member -Force -MemberType 'NoteProperty' -Name 'Id' -Value 'sp-123' -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param($Method, $ApiPath, $Body)
                        $script:invokedMethod = $Method
                        return @{}
                    }

                $script:mockInstance.Modify(@{
                        AccountId     = '12345678-1234-1234-1234-123456789012'
                        ApplicationId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                        _exist        = $false
                    })

                $script:invokedMethod | Should -Be 'DELETE'
            }
        }
    }
}

Describe 'DatabricksAccountServicePrincipal\BuildAccountServicePrincipalPatchPayload()' {
    Context 'When building PATCH payload with Roles' {
        It 'Should include sorted roles in SCIM PatchOp format' {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountServicePrincipal] @{
                    WorkspaceUrl  = 'https://accounts.azuredatabricks.net'
                    AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId     = '12345678-1234-1234-1234-123456789012'
                    ApplicationId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                    Roles         = @(
                        [UserRole] @{ Value = 'workspace_creator' }
                        [UserRole] @{ Value = 'account_admin' }
                    )
                }

                $payload = $script:mockInstance.BuildAccountServicePrincipalPatchPayload(@{
                        AccountId     = '12345678-1234-1234-1234-123456789012'
                        ApplicationId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                        Roles         = @(
                            [UserRole] @{ Value = 'workspace_creator' }
                            [UserRole] @{ Value = 'account_admin' }
                        )
                    })

                $payload.schemas | Should -Contain 'urn:ietf:params:scim:api:messages:2.0:PatchOp'
                $payload.Operations | Should -HaveCount 1
                $payload.Operations[0].op | Should -Be 'add'
                $payload.Operations[0].path | Should -Be 'roles'
                $payload.Operations[0].value | Should -HaveCount 2
                $payload.Operations[0].value[0].value | Should -Be 'account_admin'
                $payload.Operations[0].value[1].value | Should -Be 'workspace_creator'
            }
        }
    }

    Context 'When building PATCH payload without Roles' {
        It 'Should return empty Operations array' {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountServicePrincipal] @{
                    WorkspaceUrl  = 'https://accounts.azuredatabricks.net'
                    AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId     = '12345678-1234-1234-1234-123456789012'
                    ApplicationId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                }

                $payload = $script:mockInstance.BuildAccountServicePrincipalPatchPayload(@{
                        AccountId     = '12345678-1234-1234-1234-123456789012'
                        ApplicationId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                    })

                $payload.schemas | Should -Contain 'urn:ietf:params:scim:api:messages:2.0:PatchOp'
                $payload.Operations | Should -HaveCount 0
            }
        }
    }
}

Describe 'DatabricksAccountServicePrincipal\AssertProperties()' {
    Context 'When all properties are valid' {
        It 'Should not throw' {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountServicePrincipal] @{
                    WorkspaceUrl  = 'https://accounts.azuredatabricks.net'
                    AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId     = '12345678-1234-1234-1234-123456789012'
                    ApplicationId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                }

                {
                    $script:mockInstance.AssertProperties(@{
                        WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    })
                } | Should -Not -Throw
            }
        }
    }

    Context 'When WorkspaceUrl is invalid' {
        It 'Should throw' {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountServicePrincipal] @{
                    WorkspaceUrl  = 'https://accounts.azuredatabricks.net'
                    AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId     = '12345678-1234-1234-1234-123456789012'
                    ApplicationId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                }

                {
                    $script:mockInstance.AssertProperties(@{
                        WorkspaceUrl = 'http://invalid.com'
                    })
                } | Should -Throw -ExpectedMessage '*WorkspaceUrl*'
            }
        }
    }

    Context 'When AccountId is invalid' {
        It 'Should throw for non-GUID format' {
            InModuleScope -ScriptBlock {
                $invalidInstance = [DatabricksAccountServicePrincipal] @{
                    WorkspaceUrl  = 'https://accounts.azuredatabricks.net'
                    AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId     = '12345678-1234-1234-1234-123456789012'
                    ApplicationId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                }
                $invalidInstance.AccountId = 'not-a-guid'

                {
                    $invalidInstance.AssertProperties(@{
                        WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    })
                } | Should -Throw -ExpectedMessage '*AccountId*'
            }
        }
    }

    Context 'When ApplicationId is invalid' {
        It 'Should throw for non-GUID format' {
            InModuleScope -ScriptBlock {
                $invalidInstance = [DatabricksAccountServicePrincipal] @{
                    WorkspaceUrl  = 'https://accounts.azuredatabricks.net'
                    AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId     = '12345678-1234-1234-1234-123456789012'
                    ApplicationId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                }
                $invalidInstance.ApplicationId = 'not-a-guid'

                {
                    $invalidInstance.AssertProperties(@{
                        WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    })
                } | Should -Throw -ExpectedMessage '*ApplicationId*'
            }
        }
    }
}
