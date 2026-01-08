<#
    .SYNOPSIS
        Unit test for DatabricksAccountRuleset DSC resource.
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

Describe 'DatabricksAccountRuleset' {
    Context 'When class is instantiated' {
        It 'Should not throw an exception' {
            InModuleScope -ScriptBlock {
                { [DatabricksAccountRuleset]::new() } | Should -Not -Throw
            }
        }

        It 'Should have a default or empty constructor' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksAccountRuleset]::new()
                $instance | Should -Not -BeNullOrEmpty
            }
        }

        It 'Should be the correct type' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksAccountRuleset]::new()
                $instance.GetType().Name | Should -Be 'DatabricksAccountRuleset'
            }
        }

        It 'Should have ExcludeDscProperties set' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksAccountRuleset]::new()
                $instance.ExcludeDscProperties | Should -Contain 'WorkspaceUrl'
                $instance.ExcludeDscProperties | Should -Contain 'AccountId'
                $instance.ExcludeDscProperties | Should -Contain 'Name'
                $instance.ExcludeDscProperties | Should -Contain 'AccessToken'
            }
        }
    }
}

Describe 'DatabricksAccountRuleset\Get()' -Tag 'Get' {
    Context 'When the system is in the desired state' {
        Context 'When ruleset exists with grant rules' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:grantRule = [RulesetGrantRule]::new()
                    $script:grantRule.Principals = @('users/user@company.com', 'groups/researchers')
                    $script:grantRule.Role = 'roles/servicePrincipal.user'

                    $script:mockInstance = [DatabricksAccountRuleset] @{
                        WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                        AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                        AccountId    = '12345678-1234-1234-1234-123456789012'
                        Name         = 'accounts/12345678-1234-1234-1234-123456789012/servicePrincipals/app-id-guid/ruleSets/default'
                        GrantRules   = @($script:grantRule)
                    }

                    $script:mockInstance |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                            return [System.Collections.Hashtable] @{
                                WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                                AccountId    = '12345678-1234-1234-1234-123456789012'
                                Name         = 'accounts/12345678-1234-1234-1234-123456789012/servicePrincipals/app-id-guid/ruleSets/default'
                                GrantRules   = @($script:grantRule)
                            }
                        } -PassThru |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'Compare' -Value {
                            return $null
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
                    $currentState.Name | Should -Be 'accounts/12345678-1234-1234-1234-123456789012/servicePrincipals/app-id-guid/ruleSets/default'
                    $currentState.GrantRules | Should -HaveCount 1
                    $currentState.GrantRules[0].Role | Should -Be 'roles/servicePrincipal.user'
                    $currentState.Reasons | Should -BeNullOrEmpty
                }
            }
        }
    }

    Context 'When the system is not in the desired state' {
        Context 'When ruleset has different grant rules' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:desiredRule = [RulesetGrantRule]::new()
                    $script:desiredRule.Principals = @('users/different@company.com')
                    $script:desiredRule.Role = 'roles/servicePrincipal.admin'

                    $script:currentRule = [RulesetGrantRule]::new()
                    $script:currentRule.Principals = @('users/user@company.com', 'groups/researchers')
                    $script:currentRule.Role = 'roles/servicePrincipal.user'

                    $script:mockInstance = [DatabricksAccountRuleset] @{
                        WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                        AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                        AccountId    = '12345678-1234-1234-1234-123456789012'
                        Name         = 'accounts/12345678-1234-1234-1234-123456789012/servicePrincipals/app-id-guid/ruleSets/default'
                        GrantRules   = @($script:desiredRule)
                    }

                    $script:mockInstance |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                            return [System.Collections.Hashtable] @{
                                WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                                AccountId    = '12345678-1234-1234-1234-123456789012'
                                Name         = 'accounts/12345678-1234-1234-1234-123456789012/servicePrincipals/app-id-guid/ruleSets/default'
                                GrantRules   = @($script:currentRule)
                            }
                        } -PassThru |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'Compare' -Value {
                            return @(
                                @{
                                    Property      = 'GrantRules'
                                    ExpectedValue = @($script:desiredRule)
                                    ActualValue   = @($script:currentRule)
                                }
                            )
                        } -PassThru |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'AssertProperties' -Value {
                            return
                        }
                }
            }

            It 'Should return current state with different grant rules' {
                InModuleScope -ScriptBlock {
                    $currentState = $script:mockInstance.Get()

                    $currentState.GrantRules | Should -HaveCount 1
                    $currentState.GrantRules[0].Role | Should -Be 'roles/servicePrincipal.user'
                }
            }
        }
    }
}

Describe 'DatabricksAccountRuleset\Set()' -Tag 'Set' {
    BeforeAll {
        InModuleScope -ScriptBlock {
            $script:mockInstance = [DatabricksAccountRuleset] @{
                WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                AccountId    = '12345678-1234-1234-1234-123456789012'
                Name         = 'accounts/12345678-1234-1234-1234-123456789012/servicePrincipals/app-id-guid/ruleSets/default'
                GrantRules   = @(
                    [RulesetGrantRule] @{
                        Principals = @('users/user@company.com')
                        Role       = 'roles/servicePrincipal.user'
                    }
                )
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
                            Property      = 'GrantRules'
                            ExpectedValue = @([RulesetGrantRule] @{
                                    Principals = @('users/user@company.com')
                                    Role       = 'roles/servicePrincipal.user'
                                })
                            ActualValue   = @()
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

Describe 'DatabricksAccountRuleset\Test()' -Tag 'Test' {
    BeforeAll {
        InModuleScope -ScriptBlock {
            $script:mockInstance = [DatabricksAccountRuleset] @{
                WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                AccountId    = '12345678-1234-1234-1234-123456789012'
                Name         = 'accounts/12345678-1234-1234-1234-123456789012/servicePrincipals/app-id-guid/ruleSets/default'
                GrantRules   = @(
                    [RulesetGrantRule] @{
                        Principals = @('users/user@company.com')
                        Role       = 'roles/servicePrincipal.user'
                    }
                )
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
                                Property      = 'GrantRules'
                                ExpectedValue = @([RulesetGrantRule] @{
                                        Principals = @('users/user@company.com')
                                        Role       = 'roles/servicePrincipal.user'
                                    })
                                ActualValue   = @()
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

Describe 'DatabricksAccountRuleset\GetCurrentState()' -Tag 'GetCurrentState' {
    Context 'When ruleset exists with grant rules' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountRuleset] @{
                    WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId    = '12345678-1234-1234-1234-123456789012'
                    Name         = 'accounts/12345678-1234-1234-1234-123456789012/servicePrincipals/app-id-guid/ruleSets/default'
                }

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            etag        = 'RENUAAABhSweA4NvVmmUYdiU717H3Tgy0UJdor3gE4a+mq/oj9NjAf8ZsQ=='
                            grant_rules = @(
                                @{
                                    principals = @('users/user@company.com', 'groups/researchers')
                                    role       = 'roles/servicePrincipal.user'
                                }
                            )
                            name        = 'accounts/12345678-1234-1234-1234-123456789012/servicePrincipals/app-id-guid/ruleSets/default'
                        }
                    }
            }
        }

        It 'Should return the correct values with grant rules' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockInstance.GetCurrentState(
                    @{
                        AccountId = '12345678-1234-1234-1234-123456789012'
                        Name      = 'accounts/12345678-1234-1234-1234-123456789012/servicePrincipals/app-id-guid/ruleSets/default'
                    }
                )

                $currentState.AccountId | Should -Be '12345678-1234-1234-1234-123456789012'
                $currentState.Name | Should -Be 'accounts/12345678-1234-1234-1234-123456789012/servicePrincipals/app-id-guid/ruleSets/default'
                $currentState.GrantRules | Should -HaveCount 1
                $currentState.GrantRules[0].Role | Should -Be 'roles/servicePrincipal.user'
                $currentState.GrantRules[0].Principals | Should -HaveCount 2
            }
        }

        It 'Should store the etag for later use' {
            InModuleScope -ScriptBlock {
                $null = $script:mockInstance.GetCurrentState(
                    @{
                        AccountId = '12345678-1234-1234-1234-123456789012'
                        Name      = 'accounts/12345678-1234-1234-1234-123456789012/servicePrincipals/app-id-guid/ruleSets/default'
                    }
                )

                $script:mockInstance._etag | Should -Be 'RENUAAABhSweA4NvVmmUYdiU717H3Tgy0UJdor3gE4a+mq/oj9NjAf8ZsQ=='
            }
        }
    }

    Context 'When ruleset exists but has no grant rules' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountRuleset] @{
                    WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId    = '12345678-1234-1234-1234-123456789012'
                    Name         = 'accounts/12345678-1234-1234-1234-123456789012/servicePrincipals/app-id-guid/ruleSets/default'
                }

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            etag        = 'RENUAAABhSweA4NvVmmUYdiU717H3Tgy0UJdor3gE4a+mq/oj9NjAf8ZsQ=='
                            grant_rules = @()
                            name        = 'accounts/12345678-1234-1234-1234-123456789012/servicePrincipals/app-id-guid/ruleSets/default'
                        }
                    }
            }
        }

        It 'Should return empty grant rules array' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockInstance.GetCurrentState(
                    @{
                        AccountId = '12345678-1234-1234-1234-123456789012'
                        Name      = 'accounts/12345678-1234-1234-1234-123456789012/servicePrincipals/app-id-guid/ruleSets/default'
                    }
                )

                $currentState.GrantRules | Should -BeNullOrEmpty
            }
        }
    }

    Context 'When API call fails' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountRuleset] @{
                    WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId    = '12345678-1234-1234-1234-123456789012'
                    Name         = 'accounts/12345678-1234-1234-1234-123456789012/servicePrincipals/app-id-guid/ruleSets/default'
                }

                Mock -CommandName Write-Verbose

                # Mock localizedData with proper message format
                $script:mockInstance | Add-Member -Force -MemberType NoteProperty -Name 'localizedData' -Value @{
                    Get_Ruleset_ErrorGettingRuleset = 'Failed to get ruleset ''{0}'': {1} (DARSET0001)'
                }

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        throw 'API Error: Not Found'
                    }
            }
        }

        It 'Should handle error gracefully and return empty grant rules' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockInstance.GetCurrentState(
                    @{
                        AccountId = '12345678-1234-1234-1234-123456789012'
                        Name      = 'accounts/12345678-1234-1234-1234-123456789012/servicePrincipals/app-id-guid/ruleSets/default'
                    }
                )

                $currentState.GrantRules | Should -BeNullOrEmpty
                Should -Invoke -CommandName Write-Verbose -ParameterFilter {
                    $Message -like '*Failed to get ruleset*' -or $Message -like '*DARSET0001*'
                } -Exactly -Times 1 -Scope It
            }
        }
    }
}

Describe 'DatabricksAccountRuleset\Modify()' -Tag 'Modify' {
    Context 'When updating ruleset with grant rules' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountRuleset] @{
                    WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId    = '12345678-1234-1234-1234-123456789012'
                    Name         = 'accounts/12345678-1234-1234-1234-123456789012/servicePrincipals/app-id-guid/ruleSets/default'
                    GrantRules   = @(
                        [RulesetGrantRule] @{
                            Principals = @('users/user@company.com', 'groups/researchers')
                            Role       = 'roles/servicePrincipal.user'
                        }
                    )
                }

                Mock -CommandName Write-Verbose
                Mock -CommandName Write-Debug

                $script:apiCallCount = 0

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                        return @{
                            AccountId  = '12345678-1234-1234-1234-123456789012'
                            Name       = 'accounts/12345678-1234-1234-1234-123456789012/servicePrincipals/app-id-guid/ruleSets/default'
                            GrantRules = @()
                        }
                    } -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param ($Method, $Path, $Body)

                        $script:apiCallCount += 1

                        return @{
                            etag        = 'NEW_ETAG_VALUE'
                            grant_rules = @(
                                @{
                                    principals = @('users/user@company.com', 'groups/researchers')
                                    role       = 'roles/servicePrincipal.user'
                                }
                            )
                            name        = 'accounts/12345678-1234-1234-1234-123456789012/servicePrincipals/app-id-guid/ruleSets/default'
                        }
                    } -PassThru |
                    Add-Member -NotePropertyName '_etag' -NotePropertyValue 'RENUAAABhSweA4NvVmmUYdiU717H3Tgy0UJdor3gE4a+mq/oj9NjAf8ZsQ==' -Force
            }
        }

        BeforeEach {
            InModuleScope -ScriptBlock {
                $script:apiCallCount = 0
            }
        }

        It 'Should call InvokeDatabricksApi to update ruleset' {
            InModuleScope -ScriptBlock {
                $script:mockInstance.Modify(
                    @{
                        Name       = 'accounts/12345678-1234-1234-1234-123456789012/servicePrincipals/app-id-guid/ruleSets/default'
                        GrantRules = @(
                            [RulesetGrantRule] @{
                                Principals = @('users/user@company.com', 'groups/researchers')
                                Role       = 'roles/servicePrincipal.user'
                            }
                        )
                    }
                )

                $script:apiCallCount | Should -Be 1
            }
        }

        It 'Should use the stored etag' {
            InModuleScope -ScriptBlock {
                $script:mockInstance.Modify(
                    @{
                        Name       = 'accounts/12345678-1234-1234-1234-123456789012/servicePrincipals/app-id-guid/ruleSets/default'
                        GrantRules = @(
                            [RulesetGrantRule] @{
                                Principals = @('users/user@company.com')
                                Role       = 'roles/servicePrincipal.user'
                            }
                        )
                    }
                )

                Should -Invoke -CommandName Write-Debug -ParameterFilter {
                    $Message -like '*Using etag*RENUAAABhSweA4NvVmmUYdiU717H3Tgy0UJdor3gE4a+mq/oj9NjAf8ZsQ==*'
                } -Exactly -Times 1
            }
        }
    }

    Context 'When API call fails during update' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountRuleset] @{
                    WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId    = '12345678-1234-1234-1234-123456789012'
                    Name         = 'accounts/12345678-1234-1234-1234-123456789012/servicePrincipals/app-id-guid/ruleSets/default'
                    GrantRules   = @(
                        [RulesetGrantRule] @{
                            Principals = @('users/user@company.com')
                            Role       = 'roles/servicePrincipal.user'
                        }
                    )
                }

                Mock -CommandName Write-Verbose
                Mock -CommandName Write-Debug

                # Mock localizedData with proper message formats
                $script:mockInstance | Add-Member -Force -MemberType NoteProperty -Name 'localizedData' -Value @{
                    Set_Ruleset_UpdatingRuleset      = 'Updating ruleset ''{0}'' with {1} grant rule(s). (DARSET0006)'
                    Set_Ruleset_UsingEtag            = 'Using etag for optimistic concurrency control: {0} (DARSET0007)'
                    Set_Ruleset_RequestBody          = 'Request body: {0} (DARSET0008)'
                    Set_Ruleset_ErrorUpdatingRuleset = 'Failed to update ruleset ''{0}'': {1} (DARSET0002)'
                }

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                        return @{
                            AccountId  = '12345678-1234-1234-1234-123456789012'
                            Name       = 'accounts/12345678-1234-1234-1234-123456789012/servicePrincipals/app-id-guid/ruleSets/default'
                            GrantRules = @()
                        }
                    } -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        throw 'API Error: Conflict'
                    } -PassThru |
                    Add-Member -NotePropertyName '_etag' -NotePropertyValue 'OLD_ETAG' -Force
            }
        }

        It 'Should throw an error' {
            InModuleScope -ScriptBlock {
                {
                    $script:mockInstance.Modify(
                        @{
                            Name       = 'accounts/12345678-1234-1234-1234-123456789012/servicePrincipals/app-id-guid/ruleSets/default'
                            GrantRules = @(
                                [RulesetGrantRule] @{
                                    Principals = @('users/user@company.com')
                                    Role       = 'roles/servicePrincipal.user'
                                }
                            )
                        }
                    )
                } | Should -Throw '*Failed to update ruleset*'
            }
        }
    }
}

Describe 'RulesetGrantRule' {
    Context 'When class is instantiated' {
        It 'Should not throw an exception' {
            InModuleScope -ScriptBlock {
                { [RulesetGrantRule]::new() } | Should -Not -Throw
            }
        }

        It 'Should be the correct type' {
            InModuleScope -ScriptBlock {
                $instance = [RulesetGrantRule]::new()
                $instance.GetType().Name | Should -Be 'RulesetGrantRule'
            }
        }
    }

    Context 'When comparing RulesetGrantRule objects' {
        It 'Should return true when objects are equal' {
            InModuleScope -ScriptBlock {
                $rule1 = [RulesetGrantRule]::new()
                $rule1.Principals = @('users/user@company.com', 'groups/researchers')
                $rule1.Role = 'roles/servicePrincipal.user'

                $rule2 = [RulesetGrantRule]::new()
                $rule2.Principals = @('groups/researchers', 'users/user@company.com')
                $rule2.Role = 'roles/servicePrincipal.user'

                $rule1.Equals($rule2) | Should -BeTrue
            }
        }

        It 'Should return false when roles are different' {
            InModuleScope -ScriptBlock {
                $rule1 = [RulesetGrantRule]::new()
                $rule1.Principals = @('users/user@company.com')
                $rule1.Role = 'roles/servicePrincipal.user'

                $rule2 = [RulesetGrantRule]::new()
                $rule2.Principals = @('users/user@company.com')
                $rule2.Role = 'roles/servicePrincipal.admin'

                $rule1.Equals($rule2) | Should -BeFalse
            }
        }

        It 'Should return false when principals are different' {
            InModuleScope -ScriptBlock {
                $rule1 = [RulesetGrantRule]::new()
                $rule1.Principals = @('users/user1@company.com')
                $rule1.Role = 'roles/servicePrincipal.user'

                $rule2 = [RulesetGrantRule]::new()
                $rule2.Principals = @('users/user2@company.com')
                $rule2.Role = 'roles/servicePrincipal.user'

                $rule1.Equals($rule2) | Should -BeFalse
            }
        }
    }

    Context 'When converting to string' {
        It 'Should return correct string representation' {
            InModuleScope -ScriptBlock {
                $rule = [RulesetGrantRule]::new()
                $rule.Principals = @('users/user@company.com', 'groups/researchers')
                $rule.Role = 'roles/servicePrincipal.user'

                $result = $rule.ToString()
                $result | Should -BeLike 'roles/servicePrincipal.user:*'
                $result | Should -BeLike '*users/user@company.com*'
            }
        }
    }
}
