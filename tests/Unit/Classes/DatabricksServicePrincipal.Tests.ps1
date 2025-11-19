<#
    .SYNOPSIS
        Unit test for DatabricksServicePrincipal DSC resource.
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

Describe 'DatabricksServicePrincipal' {
    Context 'When class is instantiated' {
        It 'Should not throw an exception' {
            InModuleScope -ScriptBlock {
                { [DatabricksServicePrincipal]::new() } | Should -Not -Throw
            }
        }

        It 'Should have a default or empty constructor' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksServicePrincipal]::new()
                $instance | Should -Not -BeNullOrEmpty
            }
        }

        It 'Should be the correct type' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksServicePrincipal]::new()
                $instance.GetType().Name | Should -Be 'DatabricksServicePrincipal'
            }
        }

        It 'Should have ExcludeDscProperties set' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksServicePrincipal]::new()
                $instance.ExcludeDscProperties | Should -Contain 'WorkspaceUrl'
                $instance.ExcludeDscProperties | Should -Contain 'ApplicationId'
                $instance.ExcludeDscProperties | Should -Contain 'AccessToken'
                $instance.ExcludeDscProperties | Should -Contain 'Id'
            }
        }
    }
}

Describe 'DatabricksServicePrincipal\Get()' -Tag 'Get' {
    Context 'When the system is in the desired state' {
        Context 'When service principal exists with minimal properties' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:mockDatabricksServicePrincipalInstance = [DatabricksServicePrincipal] @{
                        WorkspaceUrl  = 'https://adb-1234567890123456.12.azuredatabricks.net'
                        AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                        ApplicationId = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
                    }

                    <#
                        This mocks the method GetCurrentState().

                        Method Get() will call the base method Get() which will
                        call back to the derived class method GetCurrentState()
                        to get the result to return from the derived method Get().
                    #>
                    $script:mockDatabricksServicePrincipalInstance |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                            return [System.Collections.Hashtable] @{
                                WorkspaceUrl  = 'https://adb-1234567890123456.12.azuredatabricks.net'
                                ApplicationId = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
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
                    $currentState = $script:mockDatabricksServicePrincipalInstance.Get()

                    $currentState.WorkspaceUrl | Should -Be 'https://adb-1234567890123456.12.azuredatabricks.net'
                    $currentState.ApplicationId | Should -Be 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
                    $currentState.DisplayName | Should -Be 'Test Service Principal'
                    $currentState.Active | Should -BeTrue
                    $currentState.Reasons | Should -BeNullOrEmpty
                }
            }
        }

        Context 'When service principal exists with all properties' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:mockDatabricksServicePrincipalInstance = [DatabricksServicePrincipal] @{
                        WorkspaceUrl  = 'https://adb-1234567890123456.12.azuredatabricks.net'
                        AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                        ApplicationId = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
                    }

                    $script:mockDatabricksServicePrincipalInstance |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                            return [System.Collections.Hashtable] @{
                                WorkspaceUrl  = 'https://adb-1234567890123456.12.azuredatabricks.net'
                                ApplicationId = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
                                DisplayName   = 'Test Service Principal'
                                Active        = $true
                                Id            = 'sp-123'
                                ExternalId    = 'ext-123'
                                Entitlements  = @(
                                    [UserEntitlement]@{ Value = 'allow-cluster-create' }
                                )
                                Roles         = @(
                                    [UserRole]@{ Value = 'admin' }
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
                    $currentState = $script:mockDatabricksServicePrincipalInstance.Get()

                    $currentState.WorkspaceUrl | Should -Be 'https://adb-1234567890123456.12.azuredatabricks.net'
                    $currentState.ApplicationId | Should -Be 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
                    $currentState.DisplayName | Should -Be 'Test Service Principal'
                    $currentState.Active | Should -BeTrue
                    $currentState.Id | Should -Be 'sp-123'
                    $currentState.ExternalId | Should -Be 'ext-123'
                    $currentState.Entitlements | Should -HaveCount 1
                    $currentState.Roles | Should -HaveCount 1
                }
            }
        }
    }

    Context 'When the system is not in the desired state' {
        Context 'When service principal DisplayName has wrong value' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:mockDatabricksServicePrincipalInstance = [DatabricksServicePrincipal] @{
                        WorkspaceUrl  = 'https://adb-1234567890123456.12.azuredatabricks.net'
                        AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                        ApplicationId = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
                        DisplayName   = 'New Display Name'
                    }

                    $script:mockDatabricksServicePrincipalInstance |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                            return [System.Collections.Hashtable] @{
                                WorkspaceUrl  = 'https://adb-1234567890123456.12.azuredatabricks.net'
                                ApplicationId = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
                                DisplayName   = 'Old Display Name'
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
                    $currentState = $script:mockDatabricksServicePrincipalInstance.Get()

                    $currentState.DisplayName | Should -Be 'Old Display Name'
                    $currentState.Reasons | Should -HaveCount 1
                    $currentState.Reasons[0].Code | Should -Be 'DatabricksServicePrincipal:DatabricksServicePrincipal:DisplayName'
                    $currentState.Reasons[0].Phrase | Should -Be 'The property DisplayName should be "New Display Name", but was "Old Display Name"'
                }
            }
        }
    }
}

Describe 'DatabricksServicePrincipal\Set()' -Tag 'Set' {
    BeforeAll {
        InModuleScope -ScriptBlock {
            $script:mockDatabricksServicePrincipalInstance = [DatabricksServicePrincipal] @{
                WorkspaceUrl  = 'https://adb-1234567890123456.12.azuredatabricks.net'
                AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                ApplicationId = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
                DisplayName   = 'Test Service Principal'
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
                $script:mockDatabricksServicePrincipalInstance |
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
                $script:mockDatabricksServicePrincipalInstance.Set()

                $script:mockMethodModifyCallCount | Should -Be 0
            }
        }
    }

    Context 'When the system is not in the desired state' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksServicePrincipalInstance |
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
                $script:mockDatabricksServicePrincipalInstance.Set()

                $script:mockMethodModifyCallCount | Should -Be 1
            }
        }
    }
}

Describe 'DatabricksServicePrincipal\Test()' -Tag 'Test' {
    BeforeAll {
        InModuleScope -ScriptBlock {
            $script:mockDatabricksServicePrincipalInstance = [DatabricksServicePrincipal] @{
                WorkspaceUrl  = 'https://adb-1234567890123456.12.azuredatabricks.net'
                AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                ApplicationId = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
                DisplayName   = 'Test Service Principal'
            }
        }
    }

    Context 'When the system is in the desired state' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksServicePrincipalInstance |
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
                $script:mockDatabricksServicePrincipalInstance.Test() | Should -BeTrue
            }
        }
    }

    Context 'When the system is not in the desired state' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksServicePrincipalInstance |
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
                $script:mockDatabricksServicePrincipalInstance.Test() | Should -BeFalse
            }
        }
    }
}

Describe 'DatabricksServicePrincipal\GetCurrentState()' -Tag 'GetCurrentState' {
    Context 'When service principal does not exist' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksServicePrincipalInstance = [DatabricksServicePrincipal] @{
                    WorkspaceUrl  = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    ApplicationId = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
                }

                Mock -CommandName Write-Verbose

                $script:mockDatabricksServicePrincipalInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            Resources = @()
                        }
                    }
            }
        }

        It 'Should return the correct values with _exist = $false' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockDatabricksServicePrincipalInstance.GetCurrentState(
                    @{
                        ApplicationId = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
                    }
                )

                $currentState.WorkspaceUrl | Should -Be 'https://adb-1234567890123456.12.azuredatabricks.net'
                $currentState.ApplicationId | Should -Be 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
                $currentState._exist | Should -BeFalse
                # Instance property should remain at default value (desired state)
                $script:mockDatabricksServicePrincipalInstance._exist | Should -BeTrue
            }
        }
    }

    Context 'When service principal exists with minimal properties' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksServicePrincipalInstance = [DatabricksServicePrincipal] @{
                    WorkspaceUrl  = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    ApplicationId = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
                }

                Mock -CommandName Write-Verbose

                $script:mockDatabricksServicePrincipalInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            Resources = @(
                                @{
                                    id            = 'sp-123'
                                    applicationId = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
                                    displayName   = 'Test Service Principal'
                                    active        = $true
                                }
                            )
                        }
                    }
            }
        }

        It 'Should return the correct values with _exist = $true' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockDatabricksServicePrincipalInstance.GetCurrentState(
                    @{
                        ApplicationId = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
                    }
                )

                $currentState.WorkspaceUrl | Should -Be 'https://adb-1234567890123456.12.azuredatabricks.net'
                $currentState.ApplicationId | Should -Be 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
                $currentState.DisplayName | Should -Be 'Test Service Principal'
                $currentState.Active | Should -BeTrue
                $currentState.Id | Should -Be 'sp-123'
                $currentState._exist | Should -BeTrue
                $script:mockDatabricksServicePrincipalInstance._exist | Should -BeTrue
            }
        }
    }

    Context 'When service principal exists with all properties' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksServicePrincipalInstance = [DatabricksServicePrincipal] @{
                    WorkspaceUrl  = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    ApplicationId = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
                }

                Mock -CommandName Write-Verbose

                $script:mockDatabricksServicePrincipalInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            Resources = @(
                                @{
                                    id            = 'sp-123'
                                    applicationId = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
                                    displayName   = 'Test Service Principal'
                                    active        = $true
                                    externalId    = 'ext-123'
                                    entitlements  = @(
                                        @{ value = 'allow-cluster-create' }
                                        @{ value = 'databricks-sql-access' }
                                    )
                                    roles         = @(
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
                $currentState = $script:mockDatabricksServicePrincipalInstance.GetCurrentState(
                    @{
                        ApplicationId = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
                    }
                )

                $currentState.Id | Should -Be 'sp-123'
                $currentState.DisplayName | Should -Be 'Test Service Principal'
                $currentState.Active | Should -BeTrue
                $currentState.ExternalId | Should -Be 'ext-123'

                $currentState.Entitlements | Should -HaveCount 2
                $currentState.Entitlements[0].Value | Should -Be 'allow-cluster-create'

                $currentState.Roles | Should -HaveCount 1
                $currentState.Roles[0].Value | Should -Be 'admin'
            }
        }
    }

    Context 'When API call fails' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksServicePrincipalInstance = [DatabricksServicePrincipal] @{
                    WorkspaceUrl  = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    ApplicationId = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
                }

                Mock -CommandName Write-Verbose

                $script:mockDatabricksServicePrincipalInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        throw 'API Error'
                    }
            }
        }

        It 'Should handle error gracefully and return current state with _exist = $false' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockDatabricksServicePrincipalInstance.GetCurrentState(
                    @{
                        ApplicationId = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
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

Describe 'DatabricksServicePrincipal\Modify()' -Tag 'Modify' {
    Context 'When service principal exists and needs to be updated' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksServicePrincipalInstance = [DatabricksServicePrincipal] @{
                    WorkspaceUrl  = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    ApplicationId = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
                    DisplayName   = 'New Display Name'
                    Id            = 'sp-123'
                }

                $script:mockDatabricksServicePrincipalInstance._exist = $true

                Mock -CommandName Write-Verbose

                $script:mockDatabricksServicePrincipalInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param($Method, $Path, $Body)

                        $script:mockInvokeApiMethod = $Method
                        $script:mockInvokeApiPath = $Path
                        $script:mockInvokeApiBody = $Body
                    } -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'BuildServicePrincipalPatchPayload' -Value {
                        return @{
                            schemas = @('urn:ietf:params:scim:api:messages:2.0:PatchOp')
                            Operations = @()
                        }
                    }
            }
        }

        It 'Should call InvokeDatabricksApi with PATCH method' {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksServicePrincipalInstance.Modify(
                    @{
                        DisplayName = 'New Display Name'
                    }
                )

                $script:mockInvokeApiMethod | Should -Be 'PATCH'
                $script:mockInvokeApiPath | Should -Be '/api/2.0/preview/scim/v2/ServicePrincipals/sp-123'
                # PATCH uses SCIM PatchOp format
                $script:mockInvokeApiBody.schemas | Should -Contain 'urn:ietf:params:scim:api:messages:2.0:PatchOp'
            }
        }

        It 'Should write verbose messages' {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksServicePrincipalInstance.Modify(
                    @{
                        DisplayName = 'New Display Name'
                    }
                )

                Should -Invoke -CommandName Write-Verbose -Exactly -Times 2 -Scope It
            }
        }
    }

    Context 'When service principal does not exist and needs to be created' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksServicePrincipalInstance = [DatabricksServicePrincipal] @{
                    WorkspaceUrl  = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    ApplicationId = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
                    DisplayName   = 'New Service Principal'
                }

                $script:mockDatabricksServicePrincipalInstance._exist = $false

                Mock -CommandName Write-Verbose

                $script:mockDatabricksServicePrincipalInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param($Method, $Path, $Body)

                        $script:mockInvokeApiMethod = $Method
                        $script:mockInvokeApiPath = $Path
                        $script:mockInvokeApiBody = $Body
                    } -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'BuildServicePrincipalPayload' -Value {
                        return @{
                            displayName = $this.DisplayName
                        }
                    }
            }
        }

        It 'Should call InvokeDatabricksApi with POST method' {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksServicePrincipalInstance.Modify(
                    @{
                        _exist      = $true
                        DisplayName = 'New Service Principal'
                    }
                )

                $script:mockInvokeApiMethod | Should -Be 'POST'
                $script:mockInvokeApiPath | Should -Be '/api/2.0/preview/scim/v2/ServicePrincipals'
                $script:mockInvokeApiBody.displayName | Should -Be 'New Service Principal'
                $script:mockInvokeApiBody.applicationId | Should -Be 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
                $script:mockInvokeApiBody.schemas | Should -Contain 'urn:ietf:params:scim:schemas:core:2.0:ServicePrincipal'
            }
        }
    }

    Context 'When update fails' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksServicePrincipalInstance = [DatabricksServicePrincipal] @{
                    WorkspaceUrl  = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    ApplicationId = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
                    DisplayName   = 'New Display Name'
                    Id            = 'sp-123'
                }

                $script:mockDatabricksServicePrincipalInstance._exist = $true

                Mock -CommandName Write-Verbose

                $script:mockDatabricksServicePrincipalInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        throw 'Update failed'
                    } -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'BuildServicePrincipalPatchPayload' -Value {
                        return @{
                            schemas = @('urn:ietf:params:scim:api:messages:2.0:PatchOp')
                            Operations = @()
                        }
                    }
            }
        }

        It 'Should throw with localized error message' {
            InModuleScope -ScriptBlock {
                $errorMessage = $script:localizedData.FailedToUpdateServicePrincipal -f @(
                    'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
                    'Update failed'
                )

                {
                    $script:mockDatabricksServicePrincipalInstance.Modify(@{ DisplayName = 'New Display Name' })
                } | Should -Throw -ExpectedMessage "*$errorMessage*"
            }
        }
    }

    Context 'When create fails' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksServicePrincipalInstance = [DatabricksServicePrincipal] @{
                    WorkspaceUrl  = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    ApplicationId = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
                    DisplayName   = 'New Service Principal'
                }

                $script:mockDatabricksServicePrincipalInstance._exist = $false

                Mock -CommandName Write-Verbose

                $script:mockDatabricksServicePrincipalInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        throw 'Create failed'
                    } -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'BuildServicePrincipalPayload' -Value {
                        return @{
                            displayName = $this.DisplayName
                        }
                    }
            }
        }

        It 'Should throw with localized error message' {
            InModuleScope -ScriptBlock {
                $errorMessage = $script:localizedData.FailedToCreateServicePrincipal -f @(
                    'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
                    'Create failed'
                )

                {
                    $script:mockDatabricksServicePrincipalInstance.Modify(@{ _exist = $true; DisplayName = 'New Service Principal' })
                } | Should -Throw -ExpectedMessage "*$errorMessage*"
            }
        }
    }

    Context 'When service principal exists and should be removed' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksServicePrincipalInstance = [DatabricksServicePrincipal] @{
                    WorkspaceUrl  = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    ApplicationId = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
                    Id            = 'sp-123'
                }

                # Current state: service principal exists
                $script:mockDatabricksServicePrincipalInstance._exist = $true

                Mock -CommandName Write-Verbose

                $script:mockDatabricksServicePrincipalInstance |
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
                $script:mockDatabricksServicePrincipalInstance.Modify(@{ _exist = $false })

                $script:mockInvokeApiMethod | Should -Be 'DELETE'
                $script:mockInvokeApiPath | Should -Be '/api/2.0/preview/scim/v2/ServicePrincipals/sp-123'
                $script:mockInvokeApiBody | Should -BeNullOrEmpty
            }
        }

        It 'Should write verbose messages' {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksServicePrincipalInstance.Modify(@{ _exist = $false })

                Should -Invoke -CommandName Write-Verbose -Exactly -Times 2 -Scope It
            }
        }
    }

    Context 'When remove fails' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksServicePrincipalInstance = [DatabricksServicePrincipal] @{
                    WorkspaceUrl  = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    ApplicationId = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
                    Id            = 'sp-123'
                }

                # Current state: service principal exists
                $script:mockDatabricksServicePrincipalInstance._exist = $true

                Mock -CommandName Write-Verbose

                $script:mockDatabricksServicePrincipalInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        throw 'Remove failed'
                    }
            }
        }

        It 'Should throw with localized error message' {
            InModuleScope -ScriptBlock {
                $errorMessage = $script:localizedData.FailedToRemoveServicePrincipal -f @(
                    'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
                    'Remove failed'
                )

                {
                    $script:mockDatabricksServicePrincipalInstance.Modify(@{ _exist = $false })
                } | Should -Throw -ExpectedMessage "*$errorMessage*"
            }
        }
    }
}

Describe 'DatabricksServicePrincipal\BuildServicePrincipalPayload()' -Tag 'BuildServicePrincipalPayload' {
    BeforeAll {
        InModuleScope -ScriptBlock {
            $script:mockDatabricksServicePrincipalInstance = [DatabricksServicePrincipal] @{
                WorkspaceUrl  = 'https://adb-1234567890123456.12.azuredatabricks.net'
                AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                ApplicationId = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
            }
        }
    }

    Context 'When building payload with DisplayName' {
        It 'Should include displayName in payload' {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksServicePrincipalInstance.DisplayName = 'Test Service Principal'

                $payload = $script:mockDatabricksServicePrincipalInstance.BuildServicePrincipalPayload(@{ DisplayName = 'Test Service Principal' })

                $payload.displayName | Should -Be 'Test Service Principal'
            }
        }
    }

    Context 'When building payload with Active' {
        It 'Should include active in payload' {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksServicePrincipalInstance.Active = $false

                $payload = $script:mockDatabricksServicePrincipalInstance.BuildServicePrincipalPayload(@{ Active = $false })

                $payload.active | Should -BeFalse
            }
        }
    }

    Context 'When building payload with ExternalId' {
        It 'Should include externalId in payload' {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksServicePrincipalInstance.ExternalId = 'ext-123'

                $payload = $script:mockDatabricksServicePrincipalInstance.BuildServicePrincipalPayload(@{ ExternalId = 'ext-123' })

                $payload.externalId | Should -Be 'ext-123'
            }
        }
    }

    Context 'When building payload with Entitlements' {
        It 'Should include sorted entitlements in payload' {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksServicePrincipalInstance.Entitlements = @(
                    [UserEntitlement]@{ Value = 'databricks-sql-access' }
                    [UserEntitlement]@{ Value = 'allow-cluster-create' }
                )

                $payload = $script:mockDatabricksServicePrincipalInstance.BuildServicePrincipalPayload(@{ Entitlements = $script:mockDatabricksServicePrincipalInstance.Entitlements })

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
                $script:mockDatabricksServicePrincipalInstance.Roles = @(
                    [UserRole]@{ Value = 'user' }
                    [UserRole]@{ Value = 'admin' }
                )

                $payload = $script:mockDatabricksServicePrincipalInstance.BuildServicePrincipalPayload(@{ Roles = $script:mockDatabricksServicePrincipalInstance.Roles })

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
                $script:mockDatabricksServicePrincipalInstance.DisplayName = 'Test Service Principal'
                $script:mockDatabricksServicePrincipalInstance.Active = $true
                $script:mockDatabricksServicePrincipalInstance.ExternalId = 'ext-123'

                $payload = $script:mockDatabricksServicePrincipalInstance.BuildServicePrincipalPayload(@{
                        DisplayName = 'Test Service Principal'
                        Active      = $true
                        ExternalId  = 'ext-123'
                    })

                $payload.displayName | Should -Be 'Test Service Principal'
                $payload.active | Should -BeTrue
                $payload.externalId | Should -Be 'ext-123'
            }
        }
    }
}

Describe 'DatabricksServicePrincipal\BuildServicePrincipalPatchPayload()' -Tag 'BuildServicePrincipalPatchPayload' {
    BeforeAll {
        InModuleScope -ScriptBlock {
            $script:mockDatabricksServicePrincipalInstance = [DatabricksServicePrincipal] @{
                WorkspaceUrl  = 'https://adb-1234567890123456.12.azuredatabricks.net'
                AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                ApplicationId = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
            }
        }
    }

    Context 'When building PATCH payload with Entitlements' {
        It 'Should include sorted entitlements in SCIM PatchOp format' {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksServicePrincipalInstance.Entitlements = @(
                    [UserEntitlement]@{ Value = 'databricks-sql-access' }
                    [UserEntitlement]@{ Value = 'allow-cluster-create' }
                )

                $payload = $script:mockDatabricksServicePrincipalInstance.BuildServicePrincipalPatchPayload(@{ Entitlements = $script:mockDatabricksServicePrincipalInstance.Entitlements })

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
                $payload = $script:mockDatabricksServicePrincipalInstance.BuildServicePrincipalPatchPayload(@{ DisplayName = 'Test' })

                $payload.schemas | Should -Contain 'urn:ietf:params:scim:api:messages:2.0:PatchOp'
                $payload.Operations | Should -HaveCount 0
            }
        }
    }
}

Describe 'DatabricksServicePrincipal\AssertProperties()' -Tag 'AssertProperties' {
    BeforeAll {
        InModuleScope -ScriptBlock {
            $script:mockDatabricksServicePrincipalInstance = [DatabricksServicePrincipal] @{
                WorkspaceUrl  = 'https://adb-1234567890123456.12.azuredatabricks.net'
                AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                ApplicationId = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
            }
        }
    }

    Context 'When WorkspaceUrl is valid' {
        It 'Should not throw an exception' {
            InModuleScope -ScriptBlock {
                {
                    $script:mockDatabricksServicePrincipalInstance.AssertProperties(@{
                            WorkspaceUrl  = 'https://adb-1234567890123456.12.azuredatabricks.net'
                            ApplicationId = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
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
                    $script:mockDatabricksServicePrincipalInstance.AssertProperties(@{
                            WorkspaceUrl  = 'http://invalid.com'
                            ApplicationId = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
                        })
                } | Should -Throw -ExpectedMessage "*$errorMessage*"
            }
        }
    }

    Context 'When ApplicationId is valid GUID' {
        It 'Should not throw an exception' {
            InModuleScope -ScriptBlock {
                {
                    $script:mockDatabricksServicePrincipalInstance.AssertProperties(@{
                            WorkspaceUrl  = 'https://adb-1234567890123456.12.azuredatabricks.net'
                            ApplicationId = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
                        })
                } | Should -Not -Throw
            }
        }
    }

    Context 'When ApplicationId is invalid' {
        It 'Should throw an exception for non-GUID format' {
            InModuleScope -ScriptBlock {
                $errorMessage = $script:localizedData.InvalidApplicationId -f 'not-a-guid'

                {
                    $script:mockDatabricksServicePrincipalInstance.AssertProperties(@{
                            WorkspaceUrl  = 'https://adb-1234567890123456.12.azuredatabricks.net'
                            ApplicationId = 'not-a-guid'
                        })
                } | Should -Throw -ExpectedMessage "*$errorMessage*"
            }
        }

        It 'Should throw an exception for empty string' {
            InModuleScope -ScriptBlock {
                $errorMessage = $script:localizedData.InvalidApplicationId -f ''

                {
                    $script:mockDatabricksServicePrincipalInstance.AssertProperties(@{
                            WorkspaceUrl  = 'https://adb-1234567890123456.12.azuredatabricks.net'
                            ApplicationId = ''
                        })
                } | Should -Throw -ExpectedMessage "*$errorMessage*"
            }
        }
    }
}
