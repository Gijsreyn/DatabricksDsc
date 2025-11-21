<#
    .SYNOPSIS
        Unit test for DatabricksAccountUser DSC resource.
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

Describe 'DatabricksAccountUser' {
    Context 'When class is instantiated' {
        It 'Should not throw an exception' {
            InModuleScope -ScriptBlock {
                { [DatabricksAccountUser]::new() } | Should -Not -Throw
            }
        }

        It 'Should have a default or empty constructor' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksAccountUser]::new()
                $instance | Should -Not -BeNullOrEmpty
            }
        }

        It 'Should be the correct type' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksAccountUser]::new()
                $instance.GetType().Name | Should -Be 'DatabricksAccountUser'
            }
        }

        It 'Should have ExcludeDscProperties set' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksAccountUser]::new()
                $instance.ExcludeDscProperties | Should -Contain 'WorkspaceUrl'
                $instance.ExcludeDscProperties | Should -Contain 'AccountId'
                $instance.ExcludeDscProperties | Should -Contain 'UserName'
                $instance.ExcludeDscProperties | Should -Contain 'AccessToken'
                $instance.ExcludeDscProperties | Should -Contain 'Id'
                $instance.ExcludeDscProperties | Should -Contain 'ExternalId'
            }
        }
    }
}

Describe 'DatabricksAccountUser\Get()' -Tag 'Get' {
    Context 'When the system is in the desired state' {
        Context 'When account user exists with minimal properties' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:mockInstance = [DatabricksAccountUser] @{
                        WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                        AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                        AccountId    = '12345678-1234-1234-1234-123456789012'
                        UserName     = 'testuser@example.com'
                    }

                    $script:mockInstance |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                            return [System.Collections.Hashtable] @{
                                WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                                AccountId    = '12345678-1234-1234-1234-123456789012'
                                UserName     = 'testuser@example.com'
                                DisplayName  = 'Test User'
                                Active       = $true
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
                    $currentState.UserName | Should -Be 'testuser@example.com'
                    $currentState.DisplayName | Should -Be 'Test User'
                    $currentState.Active | Should -BeTrue
                    $currentState.Reasons | Should -BeNullOrEmpty
                }
            }
        }

        Context 'When account user exists with all properties' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:mockInstance = [DatabricksAccountUser] @{
                        WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                        AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                        AccountId    = '12345678-1234-1234-1234-123456789012'
                        UserName     = 'testuser@example.com'
                    }

                    $script:mockInstance |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                            return [System.Collections.Hashtable] @{
                                WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                                AccountId    = '12345678-1234-1234-1234-123456789012'
                                UserName     = 'testuser@example.com'
                                DisplayName  = 'Test User'
                                Active       = $true
                                Id           = 'user-123'
                                ExternalId   = 'ext-123'
                                Emails       = @(
                                    [UserEmail]@{
                                        Value   = 'testuser@example.com'
                                        Type    = 'work'
                                        Primary = $true
                                    }
                                )
                                Name         = [UserName]@{
                                    GivenName  = 'Test'
                                    FamilyName = 'User'
                                }
                                Roles        = @(
                                    [UserRole]@{ Value = 'account_admin' }
                                )
                                _exist       = $true
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

                    $currentState.AccountId | Should -Be '12345678-1234-1234-1234-123456789012'
                    $currentState.UserName | Should -Be 'testuser@example.com'
                    $currentState.DisplayName | Should -Be 'Test User'
                    $currentState.Active | Should -BeTrue
                    $currentState.Id | Should -Be 'user-123'
                    $currentState.ExternalId | Should -Be 'ext-123'
                    $currentState.Emails | Should -HaveCount 1
                    $currentState.Name.GivenName | Should -Be 'Test'
                    $currentState.Roles | Should -HaveCount 1
                }
            }
        }
    }

    Context 'When the system is not in the desired state' {
        Context 'When account user DisplayName has wrong value' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:mockInstance = [DatabricksAccountUser] @{
                        WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                        AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                        AccountId    = '12345678-1234-1234-1234-123456789012'
                        UserName     = 'testuser@example.com'
                        DisplayName  = 'New Display Name'
                    }

                    $script:mockInstance |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                            return [System.Collections.Hashtable] @{
                                WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                                AccountId    = '12345678-1234-1234-1234-123456789012'
                                UserName     = 'testuser@example.com'
                                DisplayName  = 'Old Display Name'
                                Active       = $true
                                _exist       = $true
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

                    $currentState.DisplayName | Should -Be 'Old Display Name'
                    $currentState.Reasons | Should -HaveCount 1
                    $currentState.Reasons[0].Code | Should -Be 'DatabricksAccountUser:DatabricksAccountUser:DisplayName'
                    $currentState.Reasons[0].Phrase | Should -Be 'The property DisplayName should be "New Display Name", but was "Old Display Name"'
                }
            }
        }
    }
}

Describe 'DatabricksAccountUser\Set()' -Tag 'Set' {
    BeforeAll {
        InModuleScope -ScriptBlock {
            $script:mockInstance = [DatabricksAccountUser] @{
                WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                AccountId    = '12345678-1234-1234-1234-123456789012'
                UserName     = 'testuser@example.com'
                DisplayName  = 'Test User'
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
                            Property      = 'DisplayName'
                            ExpectedValue = 'New Display Name'
                            ActualValue   = 'Old Display Name'
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

Describe 'DatabricksAccountUser\Test()' -Tag 'Test' {
    BeforeAll {
        InModuleScope -ScriptBlock {
            $script:mockInstance = [DatabricksAccountUser] @{
                WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                AccountId    = '12345678-1234-1234-1234-123456789012'
                UserName     = 'testuser@example.com'
                DisplayName  = 'Test User'
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
                                Property      = 'DisplayName'
                                ExpectedValue = 'New Display Name'
                                ActualValue   = 'Old Display Name'
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

Describe 'DatabricksAccountUser\GetCurrentState()' -Tag 'GetCurrentState' {
    Context 'When account user does not exist' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountUser] @{
                    WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId    = '12345678-1234-1234-1234-123456789012'
                    UserName     = 'testuser@example.com'
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
                        AccountId = '12345678-1234-1234-1234-123456789012'
                        UserName  = 'testuser@example.com'
                    }
                )

                $currentState.AccountId | Should -Be '12345678-1234-1234-1234-123456789012'
                $currentState.UserName | Should -Be 'testuser@example.com'
                $currentState._exist | Should -BeFalse
                $script:mockInstance._exist | Should -BeFalse
            }
        }
    }

    Context 'When account user exists with all properties' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountUser] @{
                    WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId    = '12345678-1234-1234-1234-123456789012'
                    UserName     = 'testuser@example.com'
                }

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            Resources = @(
                                @{
                                    id          = 'user-123'
                                    userName    = 'testuser@example.com'
                                    displayName = 'Test User'
                                    active      = $true
                                    externalId  = 'ext-123'
                                    emails      = @(
                                        @{
                                            value   = 'testuser@example.com'
                                            type    = 'work'
                                            primary = $true
                                        }
                                    )
                                    name        = @{
                                        givenName  = 'Test'
                                        familyName = 'User'
                                    }
                                    roles       = @(
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
                        AccountId = '12345678-1234-1234-1234-123456789012'
                        UserName  = 'testuser@example.com'
                    }
                )

                $currentState.Id | Should -Be 'user-123'
                $currentState.DisplayName | Should -Be 'Test User'
                $currentState.Active | Should -BeTrue
                $currentState.ExternalId | Should -Be 'ext-123'
                $currentState.Emails | Should -HaveCount 1
                $currentState.Name.GivenName | Should -Be 'Test'
                $currentState.Roles | Should -HaveCount 1
            }
        }
    }

    Context 'When API call fails' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountUser] @{
                    WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId    = '12345678-1234-1234-1234-123456789012'
                    UserName     = 'testuser@example.com'
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
                        AccountId = '12345678-1234-1234-1234-123456789012'
                        UserName  = 'testuser@example.com'
                    }
                )

                $currentState._exist | Should -BeFalse
                Should -Invoke -CommandName Write-Verbose -ParameterFilter {
                    $Message -like '*API Error*'
                } -Exactly -Times 1 -Scope It
            }
        }
    }
}

Describe 'DatabricksAccountUser\Modify()' -Tag 'Modify' {
    Context 'When account user exists and needs to be updated' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountUser] @{
                    WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId    = '12345678-1234-1234-1234-123456789012'
                    UserName     = 'testuser@example.com'
                    DisplayName  = 'New Display Name'
                    Id           = 'user-123'
                } | Add-Member -Force -MemberType 'NoteProperty' -Name '_exist' -Value $true -PassThru

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param($Method, $Path, $Body)

                        $script:mockInvokeApiMethod = $Method
                        $script:mockInvokeApiPath = $Path
                        $script:mockInvokeApiBody = $Body
                    } -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'BuildAccountUserPatchPayload' -Value {
                        return @{
                            schemas    = @('urn:ietf:params:scim:api:messages:2.0:PatchOp')
                            Operations = @()
                        }
                    }
            }
        }

        It 'Should call InvokeDatabricksApi with PATCH method' {
            InModuleScope -ScriptBlock {
                $script:mockInstance.Modify(
                    @{
                        DisplayName = 'New Display Name'
                    }
                )

                $script:mockInvokeApiMethod | Should -Be 'PATCH'
                $script:mockInvokeApiPath | Should -Match '/api/2.0/accounts/.*/scim/v2/Users/user-123'
                $script:mockInvokeApiBody.schemas | Should -Contain 'urn:ietf:params:scim:api:messages:2.0:PatchOp'
            }
        }
    }

    Context 'When account user does not exist and needs to be created' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountUser] @{
                    WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId    = '12345678-1234-1234-1234-123456789012'
                    UserName     = 'newuser@example.com'
                    DisplayName  = 'New User'
                } | Add-Member -Force -MemberType 'NoteProperty' -Name '_exist' -Value $false -PassThru

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param($Method, $Path, $Body)

                        $script:mockInvokeApiMethod = $Method
                        $script:mockInvokeApiPath = $Path
                        $script:mockInvokeApiBody = $Body
                    } -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'BuildAccountUserPayload' -Value {
                        return @{
                            displayName = $this.DisplayName
                        }
                    }
            }
        }

        It 'Should call InvokeDatabricksApi with POST method' {
            InModuleScope -ScriptBlock {
                $script:mockInstance.Modify(
                    @{
                        _exist      = $true
                        DisplayName = 'New User'
                    }
                )

                $script:mockInvokeApiMethod | Should -Be 'POST'
                $script:mockInvokeApiPath | Should -Match '/api/2.0/accounts/.*/scim/v2/Users'
                $script:mockInvokeApiBody.userName | Should -Be 'newuser@example.com'
                $script:mockInvokeApiBody.schemas | Should -Contain 'urn:ietf:params:scim:schemas:core:2.0:User'
            }
        }
    }

    Context 'When account user exists and should be removed' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountUser] @{
                    WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId    = '12345678-1234-1234-1234-123456789012'
                    UserName     = 'testuser@example.com'
                    Id           = 'user-123'
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
                $script:mockInvokeApiPath | Should -Match '/api/2.0/accounts/.*/scim/v2/Users/user-123'
                $script:mockInvokeApiBody | Should -BeNullOrEmpty
            }
        }
    }
}

Describe 'DatabricksAccountUser\BuildAccountUserPatchPayload()' -Tag 'BuildAccountUserPatchPayload' {
    BeforeAll {
        InModuleScope -ScriptBlock {
            $script:mockInstance = [DatabricksAccountUser] @{
                WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                AccountId    = '12345678-1234-1234-1234-123456789012'
                UserName     = 'testuser@example.com'
            }
        }
    }

    Context 'When building PATCH payload with Roles' {
        It 'Should include sorted roles in SCIM PatchOp format' {
            InModuleScope -ScriptBlock {
                $script:mockInstance.Roles = @(
                    [UserRole]@{ Value = 'account_admin' }
                )

                $payload = $script:mockInstance.BuildAccountUserPatchPayload(@{ Roles = $script:mockInstance.Roles })

                $payload.schemas | Should -Contain 'urn:ietf:params:scim:api:messages:2.0:PatchOp'
                $payload.Operations | Should -HaveCount 1
                $payload.Operations[0].op | Should -Be 'add'
                $payload.Operations[0].path | Should -Be 'roles'
                $payload.Operations[0].value | Should -HaveCount 1
                $payload.Operations[0].value[0].value | Should -Be 'account_admin'
            }
        }
    }

    Context 'When building PATCH payload without Roles' {
        It 'Should return empty Operations array' {
            InModuleScope -ScriptBlock {
                $payload = $script:mockInstance.BuildAccountUserPatchPayload(@{ DisplayName = 'Test' })

                $payload.schemas | Should -Contain 'urn:ietf:params:scim:api:messages:2.0:PatchOp'
                $payload.Operations | Should -HaveCount 0
            }
        }
    }
}

Describe 'DatabricksAccountUser\BuildAccountUserPayload()' -Tag 'BuildAccountUserPayload' {
    BeforeAll {
        InModuleScope -ScriptBlock {
            $script:mockInstance = [DatabricksAccountUser] @{
                WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                AccountId    = '12345678-1234-1234-1234-123456789012'
                UserName     = 'testuser@example.com'
            }
        }
    }

    Context 'When building payload with DisplayName' {
        It 'Should include displayName in payload' {
            InModuleScope -ScriptBlock {
                $script:mockInstance.DisplayName = 'Test User'

                $payload = $script:mockInstance.BuildAccountUserPayload(@{ DisplayName = 'Test User' })

                $payload.displayName | Should -Be 'Test User'
            }
        }
    }

    Context 'When building payload with Active' {
        It 'Should include active in payload' {
            InModuleScope -ScriptBlock {
                $script:mockInstance.Active = $true

                $payload = $script:mockInstance.BuildAccountUserPayload(@{ Active = $true })

                $payload.active | Should -BeTrue
            }
        }
    }

    Context 'When building payload with Emails' {
        It 'Should include sorted emails in payload' {
            InModuleScope -ScriptBlock {
                $script:mockInstance.Emails = @(
                    [UserEmail]@{
                        Value   = 'test@example.com'
                        Type    = 'work'
                        Primary = $true
                    }
                )

                $payload = $script:mockInstance.BuildAccountUserPayload(@{ Emails = $script:mockInstance.Emails })

                $payload.emails | Should -HaveCount 1
                $payload.emails[0].value | Should -Be 'test@example.com'
                $payload.emails[0].type | Should -Be 'work'
                $payload.emails[0].primary | Should -BeTrue
            }
        }
    }

    Context 'When building payload with Name' {
        It 'Should include name in payload' {
            InModuleScope -ScriptBlock {
                $script:mockInstance.Name = [UserName]@{
                    GivenName  = 'Test'
                    FamilyName = 'User'
                }

                $payload = $script:mockInstance.BuildAccountUserPayload(@{ Name = $script:mockInstance.Name })

                $payload.name.givenName | Should -Be 'Test'
                $payload.name.familyName | Should -Be 'User'
            }
        }
    }

    Context 'When building payload with Roles' {
        It 'Should include sorted roles in payload' {
            InModuleScope -ScriptBlock {
                $script:mockInstance.Roles = @(
                    [UserRole]@{ Value = 'account_admin' }
                )

                $payload = $script:mockInstance.BuildAccountUserPayload(@{ Roles = $script:mockInstance.Roles })

                $payload.roles | Should -HaveCount 1
                $payload.roles[0].value | Should -Be 'account_admin'
            }
        }
    }
}

Describe 'DatabricksAccountUser\Modify() Error Handling' -Tag 'ModifyErrors' {
    Context 'When create fails' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountUser] @{
                    WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId    = '12345678-1234-1234-1234-123456789012'
                    UserName     = 'newuser@example.com'
                } | Add-Member -Force -MemberType 'NoteProperty' -Name '_exist' -Value $false -PassThru

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        throw 'API Error: User already exists'
                    } -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'BuildAccountUserPayload' -Value {
                        return @{ displayName = 'Test' }
                    }
            }
        }

        It 'Should throw with localized error message' {
            InModuleScope -ScriptBlock {
                {
                    $script:mockInstance.Modify(@{ _exist = $true })
                } | Should -Throw -ExpectedMessage '*Failed to create account user*newuser@example.com*'
            }
        }
    }

    Context 'When update fails' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountUser] @{
                    WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId    = '12345678-1234-1234-1234-123456789012'
                    UserName     = 'testuser@example.com'
                    Id           = 'user-123'
                } | Add-Member -Force -MemberType 'NoteProperty' -Name '_exist' -Value $true -PassThru

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        throw 'API Error: Permission denied'
                    } -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'BuildAccountUserPatchPayload' -Value {
                        return @{ schemas = @(); Operations = @() }
                    }
            }
        }

        It 'Should throw with localized error message' {
            InModuleScope -ScriptBlock {
                {
                    $script:mockInstance.Modify(@{ DisplayName = 'Test' })
                } | Should -Throw -ExpectedMessage '*Failed to update account user*testuser@example.com*'
            }
        }
    }

    Context 'When delete fails' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksAccountUser] @{
                    WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId    = '12345678-1234-1234-1234-123456789012'
                    UserName     = 'testuser@example.com'
                    Id           = 'user-123'
                } | Add-Member -Force -MemberType 'NoteProperty' -Name '_exist' -Value $true -PassThru

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        throw 'API Error: Resource in use'
                    }
            }
        }

        It 'Should throw with localized error message' {
            InModuleScope -ScriptBlock {
                {
                    $script:mockInstance.Modify(@{ _exist = $false })
                } | Should -Throw -ExpectedMessage '*Failed to remove account user*testuser@example.com*'
            }
        }
    }
}

Describe 'DatabricksAccountUser\AssertProperties()' -Tag 'AssertProperties' {
    BeforeAll {
        InModuleScope -ScriptBlock {
            $script:mockInstance = [DatabricksAccountUser] @{
                WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                AccountId    = '12345678-1234-1234-1234-123456789012'
                UserName     = 'testuser@example.com'
            }
        }
    }

    Context 'When all properties are valid' {
        It 'Should not throw' {
            InModuleScope -ScriptBlock {
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
                $invalidInstance = [DatabricksAccountUser] @{
                    WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId    = '12345678-1234-1234-1234-123456789012'
                    UserName     = 'testuser@example.com'
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

    Context 'When UserName is invalid' {
        It 'Should throw for invalid email format' {
            InModuleScope -ScriptBlock {
                $invalidInstance = [DatabricksAccountUser] @{
                    WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    AccountId    = '12345678-1234-1234-1234-123456789012'
                    UserName     = 'testuser@example.com'
                }
                $invalidInstance.UserName = 'notanemail'

                {
                    $invalidInstance.AssertProperties(@{
                        WorkspaceUrl = 'https://accounts.azuredatabricks.net'
                    })
                } | Should -Throw -ExpectedMessage '*UserName*'
            }
        }
    }
}
