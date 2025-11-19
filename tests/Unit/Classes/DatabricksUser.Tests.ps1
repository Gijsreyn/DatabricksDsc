<#
    .SYNOPSIS
        Unit test for DatabricksUser DSC resource.
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

Describe 'DatabricksUser' {
    Context 'When class is instantiated' {
        It 'Should not throw an exception' {
            InModuleScope -ScriptBlock {
                { [DatabricksUser]::new() } | Should -Not -Throw
            }
        }

        It 'Should have a default or empty constructor' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksUser]::new()
                $instance | Should -Not -BeNullOrEmpty
            }
        }

        It 'Should be the correct type' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksUser]::new()
                $instance.GetType().Name | Should -Be 'DatabricksUser'
            }
        }

        It 'Should have ExcludeDscProperties set' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksUser]::new()
                $instance.ExcludeDscProperties | Should -Contain 'WorkspaceUrl'
                $instance.ExcludeDscProperties | Should -Contain 'UserName'
                $instance.ExcludeDscProperties | Should -Contain 'AccessToken'
                $instance.ExcludeDscProperties | Should -Contain 'Id'
            }
        }
    }
}

Describe 'DatabricksUser\Get()' -Tag 'Get' {
    Context 'When the system is in the desired state' {
        Context 'When user exists with minimal properties' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:mockDatabricksUserInstance = [DatabricksUser] @{
                        WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                        AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                        UserName     = 'testuser@example.com'
                    }

                    <#
                        This mocks the method GetCurrentState().

                        Method Get() will call the base method Get() which will
                        call back to the derived class method GetCurrentState()
                        to get the result to return from the derived method Get().
                    #>
                    $script:mockDatabricksUserInstance |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                            return [System.Collections.Hashtable] @{
                                WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
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
                    $currentState = $script:mockDatabricksUserInstance.Get()

                    $currentState.WorkspaceUrl | Should -Be 'https://adb-1234567890123456.12.azuredatabricks.net'
                    $currentState.UserName | Should -Be 'testuser@example.com'
                    $currentState.DisplayName | Should -Be 'Test User'
                    $currentState.Active | Should -BeTrue
                    $currentState.Reasons | Should -BeNullOrEmpty
                }
            }
        }

        Context 'When user exists with all properties' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:mockDatabricksUserInstance = [DatabricksUser] @{
                        WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                        AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                        UserName     = 'testuser@example.com'
                    }

                    $script:mockDatabricksUserInstance |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                            return [System.Collections.Hashtable] @{
                                WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
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
                                Entitlements = @(
                                    [UserEntitlement]@{ Value = 'allow-cluster-create' }
                                )
                                Roles        = @(
                                    [UserRole]@{ Value = 'admin' }
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
                    $currentState = $script:mockDatabricksUserInstance.Get()

                    $currentState.WorkspaceUrl | Should -Be 'https://adb-1234567890123456.12.azuredatabricks.net'
                    $currentState.UserName | Should -Be 'testuser@example.com'
                    $currentState.DisplayName | Should -Be 'Test User'
                    $currentState.Active | Should -BeTrue
                    $currentState.Id | Should -Be 'user-123'
                    $currentState.ExternalId | Should -Be 'ext-123'
                    $currentState.Emails | Should -HaveCount 1
                    $currentState.Emails[0].Value | Should -Be 'testuser@example.com'
                    $currentState.Name.GivenName | Should -Be 'Test'
                    $currentState.Name.FamilyName | Should -Be 'User'
                    $currentState.Entitlements | Should -HaveCount 1
                    $currentState.Roles | Should -HaveCount 1
                }
            }
        }
    }

    Context 'When the system is not in the desired state' {
        Context 'When user DisplayName has wrong value' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:mockDatabricksUserInstance = [DatabricksUser] @{
                        WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                        AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                        UserName     = 'testuser@example.com'
                        DisplayName  = 'New Display Name'
                    }

                    $script:mockDatabricksUserInstance |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                            return [System.Collections.Hashtable] @{
                                WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
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
                    $currentState = $script:mockDatabricksUserInstance.Get()

                    $currentState.DisplayName | Should -Be 'Old Display Name'
                    $currentState.Reasons | Should -HaveCount 1
                    $currentState.Reasons[0].Code | Should -Be 'DatabricksUser:DatabricksUser:DisplayName'
                    $currentState.Reasons[0].Phrase | Should -Be 'The property DisplayName should be "New Display Name", but was "Old Display Name"'
                }
            }
        }
    }
}

Describe 'DatabricksUser\Set()' -Tag 'Set' {
    BeforeAll {
        InModuleScope -ScriptBlock {
            $script:mockDatabricksUserInstance = [DatabricksUser] @{
                WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                UserName     = 'testuser@example.com'
                DisplayName  = 'Test User'
            } |
                # Mock method Modify which is called by the base method Set().
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
                $script:mockDatabricksUserInstance |
                    # Mock method Compare() which is called by the base method Set()
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
                $script:mockDatabricksUserInstance.Set()

                $script:mockMethodModifyCallCount | Should -Be 0
            }
        }
    }

    Context 'When the system is not in the desired state' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksUserInstance |
                    # Mock method Compare() which is called by the base method Set()
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
                $script:mockDatabricksUserInstance.Set()

                $script:mockMethodModifyCallCount | Should -Be 1
            }
        }
    }
}

Describe 'DatabricksUser\Test()' -Tag 'Test' {
    BeforeAll {
        InModuleScope -ScriptBlock {
            $script:mockDatabricksUserInstance = [DatabricksUser] @{
                WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                UserName     = 'testuser@example.com'
                DisplayName  = 'Test User'
            }
        }
    }

    Context 'When the system is in the desired state' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksUserInstance |
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
                $script:mockDatabricksUserInstance.Test() | Should -BeTrue
            }
        }
    }

    Context 'When the system is not in the desired state' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksUserInstance |
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
                $script:mockDatabricksUserInstance.Test() | Should -BeFalse
            }
        }
    }
}

Describe 'DatabricksUser\GetCurrentState()' -Tag 'GetCurrentState' {
    Context 'When user does not exist' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksUserInstance = [DatabricksUser] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    UserName     = 'testuser@example.com'
                }

                Mock -CommandName Write-Verbose

                $script:mockDatabricksUserInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            Resources = @()
                        }
                    }
            }
        }

        It 'Should return the correct values with _exist = $false' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockDatabricksUserInstance.GetCurrentState(
                    @{
                        UserName = 'testuser@example.com'
                    }
                )

                $currentState.WorkspaceUrl | Should -Be 'https://adb-1234567890123456.12.azuredatabricks.net'
                $currentState.UserName | Should -Be 'testuser@example.com'
                $currentState._exist | Should -BeFalse
                # Instance property should remain at default value (desired state)
                $script:mockDatabricksUserInstance._exist | Should -BeTrue
            }
        }
    }

    Context 'When user exists with minimal properties' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksUserInstance = [DatabricksUser] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    UserName     = 'testuser@example.com'
                }

                Mock -CommandName Write-Verbose

                $script:mockDatabricksUserInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            Resources = @(
                                @{
                                    id          = 'user-123'
                                    userName    = 'testuser@example.com'
                                    displayName = 'Test User'
                                    active      = $true
                                }
                            )
                        }
                    }
            }
        }

        It 'Should return the correct values with _exist = $true' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockDatabricksUserInstance.GetCurrentState(
                    @{
                        UserName = 'testuser@example.com'
                    }
                )

                $currentState.WorkspaceUrl | Should -Be 'https://adb-1234567890123456.12.azuredatabricks.net'
                $currentState.UserName | Should -Be 'testuser@example.com'
                $currentState.DisplayName | Should -Be 'Test User'
                $currentState.Active | Should -BeTrue
                $currentState.Id | Should -Be 'user-123'
                $currentState._exist | Should -BeTrue
                $script:mockDatabricksUserInstance._exist | Should -BeTrue
            }
        }
    }

    Context 'When user exists with all properties' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksUserInstance = [DatabricksUser] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    UserName     = 'testuser@example.com'
                }

                Mock -CommandName Write-Verbose

                $script:mockDatabricksUserInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            Resources = @(
                                @{
                                    id           = 'user-123'
                                    userName     = 'testuser@example.com'
                                    displayName  = 'Test User'
                                    active       = $true
                                    externalId   = 'ext-123'
                                    emails       = @(
                                        @{
                                            value   = 'testuser@example.com'
                                            type    = 'work'
                                            primary = $true
                                        }
                                        @{
                                            value   = 'test@company.com'
                                            type    = 'work'
                                            primary = $false
                                        }
                                    )
                                    name         = @{
                                        givenName  = 'Test'
                                        familyName = 'User'
                                    }
                                    entitlements = @(
                                        @{ value = 'allow-cluster-create' }
                                        @{ value = 'databricks-sql-access' }
                                    )
                                    roles        = @(
                                        @{ value = 'admin' }
                                    )
                                }
                            )
                        }
                    }
            }
        }

        It 'Should return the correct values with all properties populated' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockDatabricksUserInstance.GetCurrentState(
                    @{
                        UserName = 'testuser@example.com'
                    }
                )

                $currentState.Id | Should -Be 'user-123'
                $currentState.DisplayName | Should -Be 'Test User'
                $currentState.Active | Should -BeTrue
                $currentState.ExternalId | Should -Be 'ext-123'

                $currentState.Emails | Should -HaveCount 2
                $currentState.Emails[0].Value | Should -Be 'testuser@example.com'
                $currentState.Emails[0].Primary | Should -BeTrue
                $currentState.Emails[1].Value | Should -Be 'test@company.com'

                $currentState.Name | Should -Not -BeNullOrEmpty
                $currentState.Name.GivenName | Should -Be 'Test'
                $currentState.Name.FamilyName | Should -Be 'User'

                $currentState.Entitlements | Should -HaveCount 2
                $currentState.Entitlements[0].Value | Should -Be 'allow-cluster-create'

                $currentState.Roles | Should -HaveCount 1
                $currentState.Roles[0].Value | Should -Be 'admin'
            }
        }

        It 'Should sort emails with primary first' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockDatabricksUserInstance.GetCurrentState(
                    @{
                        UserName = 'testuser@example.com'
                    }
                )

                # Primary email should be first after sorting
                $currentState.Emails[0].Primary | Should -BeTrue
            }
        }
    }

    Context 'When API call fails' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksUserInstance = [DatabricksUser] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    UserName     = 'testuser@example.com'
                }

                Mock -CommandName Write-Verbose

                $script:mockDatabricksUserInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        throw 'API Error'
                    }
            }
        }

        It 'Should handle error gracefully and return current state with _exist = $false' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockDatabricksUserInstance.GetCurrentState(
                    @{
                        UserName = 'testuser@example.com'
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

Describe 'DatabricksUser\Modify()' -Tag 'Modify' {
    Context 'When user exists and needs to be updated' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksUserInstance = [DatabricksUser] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    UserName     = 'testuser@example.com'
                    DisplayName  = 'New Display Name'
                    Id           = 'user-123'
                }

                $script:mockDatabricksUserInstance._exist = $true

                Mock -CommandName Write-Verbose

                $script:mockDatabricksUserInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param($Method, $Path, $Body)

                        $script:mockInvokeApiMethod = $Method
                        $script:mockInvokeApiPath = $Path
                        $script:mockInvokeApiBody = $Body
                    } -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'BuildUserPatchPayload' -Value {
                        return @{
                            schemas = @('urn:ietf:params:scim:api:messages:2.0:PatchOp')
                            Operations = @()
                        }
                    }
            }
        }

        It 'Should call InvokeDatabricksApi with PATCH method' {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksUserInstance.Modify(
                    @{
                        DisplayName = 'New Display Name'
                    }
                )

                $script:mockInvokeApiMethod | Should -Be 'PATCH'
                $script:mockInvokeApiPath | Should -Be '/api/2.0/preview/scim/v2/Users/user-123'
                # PATCH uses SCIM PatchOp format
                $script:mockInvokeApiBody.schemas | Should -Contain 'urn:ietf:params:scim:api:messages:2.0:PatchOp'
            }
        }

        It 'Should write verbose messages' {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksUserInstance.Modify(
                    @{
                        DisplayName = 'New Display Name'
                    }
                )

                Should -Invoke -CommandName Write-Verbose -Exactly -Times 2 -Scope It
            }
        }
    }

    Context 'When user does not exist and needs to be created' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksUserInstance = [DatabricksUser] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    UserName     = 'newuser@example.com'
                    DisplayName  = 'New User'
                }

                $script:mockDatabricksUserInstance._exist = $false

                Mock -CommandName Write-Verbose

                $script:mockDatabricksUserInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param($Method, $Path, $Body)

                        $script:mockInvokeApiMethod = $Method
                        $script:mockInvokeApiPath = $Path
                        $script:mockInvokeApiBody = $Body
                    } -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'BuildUserPayload' -Value {
                        return @{
                            displayName = $this.DisplayName
                        }
                    }
            }
        }

        It 'Should call InvokeDatabricksApi with POST method' {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksUserInstance.Modify(
                    @{
                        _exist      = $true
                        DisplayName = 'New User'
                    }
                )

                $script:mockInvokeApiMethod | Should -Be 'POST'
                $script:mockInvokeApiPath | Should -Be '/api/2.0/preview/scim/v2/Users'
                $script:mockInvokeApiBody.displayName | Should -Be 'New User'
                $script:mockInvokeApiBody.userName | Should -Be 'newuser@example.com'
                $script:mockInvokeApiBody.schemas | Should -Contain 'urn:ietf:params:scim:schemas:core:2.0:User'
            }
        }
    }

    Context 'When update fails' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksUserInstance = [DatabricksUser] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    UserName     = 'testuser@example.com'
                    DisplayName  = 'New Display Name'
                    Id           = 'user-123'
                }

                $script:mockDatabricksUserInstance._exist = $true

                Mock -CommandName Write-Verbose

                $script:mockDatabricksUserInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        throw 'Update failed'
                    } -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'BuildUserPatchPayload' -Value {
                        return @{
                            schemas = @('urn:ietf:params:scim:api:messages:2.0:PatchOp')
                            Operations = @()
                        }
                    }
            }
        }

        It 'Should throw with localized error message' {
            InModuleScope -ScriptBlock {
                $errorMessage = $script:localizedData.FailedToUpdateUser -f @(
                    'testuser@example.com',
                    'Update failed'
                )

                {
                    $script:mockDatabricksUserInstance.Modify(@{ DisplayName = 'New Display Name' })
                } | Should -Throw -ExpectedMessage "*$errorMessage*"
            }
        }
    }

    Context 'When create fails' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksUserInstance = [DatabricksUser] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    UserName     = 'newuser@example.com'
                    DisplayName  = 'New User'
                }

                $script:mockDatabricksUserInstance._exist = $false

                Mock -CommandName Write-Verbose

                $script:mockDatabricksUserInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        throw 'Create failed'
                    } -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'BuildUserPayload' -Value {
                        return @{
                            displayName = $this.DisplayName
                        }
                    }
            }
        }

        It 'Should throw with localized error message' {
            InModuleScope -ScriptBlock {
                $errorMessage = $script:localizedData.FailedToCreateUser -f @(
                    'newuser@example.com',
                    'Create failed'
                )

                {
                    $script:mockDatabricksUserInstance.Modify(@{ _exist = $true; DisplayName = 'New User' })
                } | Should -Throw -ExpectedMessage "*$errorMessage*"
            }
        }
    }

    Context 'When user exists and should be removed' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksUserInstance = [DatabricksUser] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    UserName     = 'testuser@example.com'
                    Id           = 'user-123'
                }

                # Current state: user exists
                $script:mockDatabricksUserInstance._exist = $true

                Mock -CommandName Write-Verbose

                $script:mockDatabricksUserInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param($Method, $Path, $Body)

                        $script:mockInvokeApiMethod = $Method
                        $script:mockInvokeApiPath = $Path
                        $script:mockInvokeApiBody = $Body
                    }
            }
        }

        BeforeEach {
            InModuleScope -ScriptBlock {
                $script:mockInvokeApiMethod = $null
                $script:mockInvokeApiPath = $null
                $script:mockInvokeApiBody = $null
            }
        }

        It 'Should call InvokeDatabricksApi with DELETE method' {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksUserInstance.Modify(@{ _exist = $false })

                $script:mockInvokeApiMethod | Should -Be 'DELETE'
                $script:mockInvokeApiPath | Should -Be '/api/2.0/preview/scim/v2/Users/user-123'
                $script:mockInvokeApiBody | Should -BeNullOrEmpty
            }
        }

        It 'Should write verbose messages' {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksUserInstance.Modify(@{ _exist = $false })

                Should -Invoke -CommandName Write-Verbose -Exactly -Times 2 -Scope It
            }
        }
    }

    Context 'When remove fails' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksUserInstance = [DatabricksUser] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    UserName     = 'testuser@example.com'
                    Id           = 'user-123'
                }

                # Current state: user exists
                $script:mockDatabricksUserInstance._exist = $true

                Mock -CommandName Write-Verbose

                $script:mockDatabricksUserInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        throw 'Remove failed'
                    }
            }
        }

        It 'Should throw with localized error message' {
            InModuleScope -ScriptBlock {
                $errorMessage = $script:localizedData.FailedToRemoveUser -f @(
                    'testuser@example.com',
                    'Remove failed'
                )

                {
                    $script:mockDatabricksUserInstance.Modify(@{ _exist = $false })
                } | Should -Throw -ExpectedMessage "*$errorMessage*"
            }
        }
    }
}

Describe 'DatabricksUser\BuildUserPayload()' -Tag 'BuildUserPayload' {
    BeforeAll {
        InModuleScope -ScriptBlock {
            $script:mockDatabricksUserInstance = [DatabricksUser] @{
                WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                UserName     = 'testuser@example.com'
            }
        }
    }

    Context 'When building payload with DisplayName' {
        It 'Should include displayName in payload' {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksUserInstance.DisplayName = 'Test User'

                $payload = $script:mockDatabricksUserInstance.BuildUserPayload(@{ DisplayName = 'Test User' })

                $payload.displayName | Should -Be 'Test User'
            }
        }
    }

    Context 'When building payload with Active' {
        It 'Should include active in payload' {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksUserInstance.Active = $false

                $payload = $script:mockDatabricksUserInstance.BuildUserPayload(@{ Active = $false })

                $payload.active | Should -BeFalse
            }
        }
    }

    Context 'When building payload with ExternalId' {
        It 'Should include externalId in payload' {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksUserInstance.ExternalId = 'ext-123'

                $payload = $script:mockDatabricksUserInstance.BuildUserPayload(@{ ExternalId = 'ext-123' })

                $payload.externalId | Should -Be 'ext-123'
            }
        }
    }

    Context 'When building payload with Emails' {
        It 'Should include sorted emails in payload' {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksUserInstance.Emails = @(
                    [UserEmail]@{
                        Value   = 'test@company.com'
                        Type    = 'work'
                        Primary = $false
                    }
                    [UserEmail]@{
                        Value   = 'testuser@example.com'
                        Type    = 'work'
                        Primary = $true
                    }
                )

                $payload = $script:mockDatabricksUserInstance.BuildUserPayload(@{ Emails = $script:mockDatabricksUserInstance.Emails })

                $payload.emails | Should -HaveCount 2
                # Primary email should be first
                $payload.emails[0].value | Should -Be 'testuser@example.com'
                $payload.emails[0].primary | Should -BeTrue
                $payload.emails[1].value | Should -Be 'test@company.com'
            }
        }
    }

    Context 'When building payload with Name' {
        It 'Should include name in payload' {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksUserInstance.Name = [UserName]@{
                    GivenName  = 'Test'
                    FamilyName = 'User'
                }

                $payload = $script:mockDatabricksUserInstance.BuildUserPayload(@{ Name = $script:mockDatabricksUserInstance.Name })

                $payload.name.givenName | Should -Be 'Test'
                $payload.name.familyName | Should -Be 'User'
            }
        }
    }

    Context 'When building payload with Entitlements' {
        It 'Should include sorted entitlements in payload' {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksUserInstance.Entitlements = @(
                    [UserEntitlement]@{ Value = 'databricks-sql-access' }
                    [UserEntitlement]@{ Value = 'allow-cluster-create' }
                )

                $payload = $script:mockDatabricksUserInstance.BuildUserPayload(@{ Entitlements = $script:mockDatabricksUserInstance.Entitlements })

                $payload.entitlements | Should -HaveCount 2
                # Should be sorted alphabetically
                $payload.entitlements[0].value | Should -Be 'allow-cluster-create'
                $payload.entitlements[1].value | Should -Be 'databricks-sql-access'
            }
        }
    }

    Context 'When building payload with Roles' {
        It 'Should include sorted roles in payload' {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksUserInstance.Roles = @(
                    [UserRole]@{ Value = 'user' }
                    [UserRole]@{ Value = 'admin' }
                )

                $payload = $script:mockDatabricksUserInstance.BuildUserPayload(@{ Roles = $script:mockDatabricksUserInstance.Roles })

                $payload.roles | Should -HaveCount 2
                # Should be sorted alphabetically
                $payload.roles[0].value | Should -Be 'admin'
                $payload.roles[1].value | Should -Be 'user'
            }
        }
    }

    Context 'When building payload with multiple properties' {
        It 'Should include all specified properties in payload' {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksUserInstance.DisplayName = 'Test User'
                $script:mockDatabricksUserInstance.Active = $true
                $script:mockDatabricksUserInstance.ExternalId = 'ext-123'

                $payload = $script:mockDatabricksUserInstance.BuildUserPayload(@{
                    DisplayName = 'Test User'
                    Active      = $true
                    ExternalId  = 'ext-123'
                })

                $payload.displayName | Should -Be 'Test User'
                $payload.active | Should -BeTrue
                $payload.externalId | Should -Be 'ext-123'
            }
        }
    }
}

Describe 'DatabricksUser\BuildUserPatchPayload()' -Tag 'BuildUserPatchPayload' {
    BeforeAll {
        InModuleScope -ScriptBlock {
            $script:mockDatabricksUserInstance = [DatabricksUser] @{
                WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                UserName     = 'testuser@example.com'
            }
        }
    }

    Context 'When building PATCH payload with Entitlements' {
        It 'Should include sorted entitlements in SCIM PatchOp format' {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksUserInstance.Entitlements = @(
                    [UserEntitlement]@{ Value = 'databricks-sql-access' }
                    [UserEntitlement]@{ Value = 'allow-cluster-create' }
                )

                $payload = $script:mockDatabricksUserInstance.BuildUserPatchPayload(@{ Entitlements = $script:mockDatabricksUserInstance.Entitlements })

                # Verify SCIM PatchOp structure
                $payload.schemas | Should -Contain 'urn:ietf:params:scim:api:messages:2.0:PatchOp'
                $payload.Operations | Should -HaveCount 1
                $payload.Operations[0].op | Should -Be 'add'
                $payload.Operations[0].path | Should -Be 'entitlements'
                $payload.Operations[0].value | Should -HaveCount 2
                # Should be sorted alphabetically
                $payload.Operations[0].value[0].value | Should -Be 'allow-cluster-create'
                $payload.Operations[0].value[1].value | Should -Be 'databricks-sql-access'
            }
        }
    }

    Context 'When building PATCH payload without Entitlements' {
        It 'Should return empty Operations array' {
            InModuleScope -ScriptBlock {
                $payload = $script:mockDatabricksUserInstance.BuildUserPatchPayload(@{ DisplayName = 'Test' })

                $payload.schemas | Should -Contain 'urn:ietf:params:scim:api:messages:2.0:PatchOp'
                $payload.Operations | Should -HaveCount 0
            }
        }
    }
}

Describe 'DatabricksUser\AssertProperties()' -Tag 'AssertProperties' {
    BeforeAll {
        InModuleScope -ScriptBlock {
            $script:mockDatabricksUserInstance = [DatabricksUser] @{
                WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                UserName     = 'testuser@example.com'
            }
        }
    }

    Context 'When WorkspaceUrl is valid' {
        It 'Should not throw an exception' {
            InModuleScope -ScriptBlock {
                {
                    $script:mockDatabricksUserInstance.AssertProperties(@{
                            WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                            UserName     = 'testuser@example.com'
                        })
                } | Should -Not -Throw
            }
        }
    }

    Context 'When WorkspaceUrl is invalid' {
        It 'Should throw an exception for non-https URL' {
            InModuleScope -ScriptBlock {
                $errorMessage = $script:localizedData.InvalidWorkspaceUrl -f 'http://invalid.com'

                {
                    $script:mockDatabricksUserInstance.AssertProperties(@{
                            WorkspaceUrl = 'http://invalid.com'
                            UserName     = 'testuser@example.com'
                        })
                } | Should -Throw -ExpectedMessage "*$errorMessage*"
            }
        }
    }

    Context 'When UserName is valid' {
        It 'Should not throw an exception' {
            InModuleScope -ScriptBlock {
                {
                    $script:mockDatabricksUserInstance.AssertProperties(@{
                            WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                            UserName     = 'testuser@example.com'
                        })
                } | Should -Not -Throw
            }
        }
    }

    Context 'When UserName is invalid' {
        It 'Should throw an exception for invalid email format' {
            InModuleScope -ScriptBlock {
                $errorMessage = $script:localizedData.InvalidUserName -f 'notanemail'

                {
                    $script:mockDatabricksUserInstance.AssertProperties(@{
                            WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                            UserName     = 'notanemail'
                        })
                } | Should -Throw -ExpectedMessage "*$errorMessage*"
            }
        }
    }
}
