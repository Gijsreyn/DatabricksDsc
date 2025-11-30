#Requires -Module DatabricksDsc

BeforeDiscovery {
    try
    {
        if (-not (Get-Module -Name 'DscResource.Test'))
        {
            # Assumes dependencies has been resolved, so if this module is not available, run 'noop' task.
            if (-not (Get-Module -Name 'DscResource.Test' -ListAvailable))
            {
                # Redirect all streams to $null, except the error stream (stream 2)
                & "$PSScriptRoot/../../../build.ps1" -Tasks 'noop' 2>&1 4>&1 5>&1 6>&1 > $null
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

Describe 'DatabricksSecret' -Tag 'DatabricksSecret' {
    Context 'When instantiating the class' {
        It 'Should not throw an exception' {
            InModuleScope -ScriptBlock {
                { [DatabricksSecret]::new() } | Should -Not -Throw
            }
        }

        It 'Should have a default _exist value of $true' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksSecret]::new()
                $instance._exist | Should -Be $true
            }
        }

        It 'Should be of the correct type' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksSecret]::new()
                $instance.GetType().Name | Should -Be 'DatabricksSecret'
            }
        }
    }

    Context 'When validating SecretKey with invalid pattern' {
        It 'Should throw when SecretKey contains invalid characters' {
            InModuleScope -ScriptBlock {
                {
                    $instance = [DatabricksSecret]::new()
                    $instance.SecretKey = 'invalid@key!'
                } | Should -Throw
            }
        }

        It 'Should throw when SecretKey exceeds 128 characters' {
            InModuleScope -ScriptBlock {
                {
                    $instance = [DatabricksSecret]::new()
                    $instance.SecretKey = 'a' * 129
                } | Should -Throw
            }
        }

        It 'Should not throw when SecretKey is valid' {
            InModuleScope -ScriptBlock {
                {
                    $instance = [DatabricksSecret]::new()
                    $instance.SecretKey = 'valid-key_123.test'
                } | Should -Not -Throw
            }
        }
    }

    Context 'When AssertProperties is called' {
        BeforeAll {
            Mock -CommandName New-InvalidOperationException -MockWith { throw 'Invalid operation' }
            Mock -CommandName New-InvalidArgumentException -MockWith { throw 'Invalid argument' }
            Mock -CommandName New-ArgumentException -MockWith { throw 'Argument exception' }
        }

        It 'Should throw when both StringValue and BytesValue are specified' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksSecret]::new()
                $instance.WorkspaceUrl = 'https://test.azuredatabricks.net'
                $instance.ScopeName = 'test-scope'
                $instance.SecretKey = 'test-key'
                $instance.StringValue = 'string-value'
                $instance.BytesValue = 'bytes-value'
                $instance._exist = $true

                { $instance.AssertProperties(@{ _exist = $true }) } | Should -Throw
            }

            Should -Invoke -CommandName New-InvalidOperationException -Times 1 -Exactly
        }

        It 'Should not throw when only StringValue is specified' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksSecret]::new()
                $instance.WorkspaceUrl = 'https://test.azuredatabricks.net'
                $instance.ScopeName = 'test-scope'
                $instance.SecretKey = 'test-key'
                $instance.StringValue = 'string-value'
                $instance._exist = $true

                { $instance.AssertProperties(@{ StringValue = 'string-value' }) } | Should -Not -Throw
            }
        }

        It 'Should not throw when only BytesValue is specified' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksSecret]::new()
                $instance.WorkspaceUrl = 'https://test.azuredatabricks.net'
                $instance.ScopeName = 'test-scope'
                $instance.SecretKey = 'test-key'
                $instance.BytesValue = 'bytes-value'
                $instance._exist = $true

                { $instance.AssertProperties(@{ BytesValue = 'bytes-value' }) } | Should -Not -Throw
            }
        }

        It 'Should not throw when _exist is false' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksSecret]::new()
                $instance.WorkspaceUrl = 'https://test.azuredatabricks.net'
                $instance.ScopeName = 'test-scope'
                $instance.SecretKey = 'test-key'
                $instance._exist = $false

                { $instance.AssertProperties(@{}) } | Should -Not -Throw
            }
        }
    }

    Context 'When GetCurrentState is called' {
        BeforeAll {
            Mock -CommandName Get-DatabricksSecret
        }

        Context 'When the secret exists' {
            BeforeAll {
                Mock -CommandName Get-DatabricksSecret -MockWith {
                    return @{
                        key = 'test-key'
                    }
                }
            }

            It 'Should return a hashtable with _exist set to true' {
                InModuleScope -ScriptBlock {
                    $instance = [DatabricksSecret]::new()
                    $instance.WorkspaceUrl = 'https://test.azuredatabricks.net'
                    $instance.AccessToken = (ConvertTo-SecureString -String 'test-token' -AsPlainText -Force)
                    $instance.ScopeName = 'test-scope'
                    $instance.SecretKey = 'test-key'

                    $currentState = $instance.GetCurrentState(@{
                        ScopeName = 'test-scope'
                        SecretKey = 'test-key'
                    })

                    $currentState._exist | Should -Be $true
                    $currentState.ScopeName | Should -Be 'test-scope'
                    $currentState.SecretKey | Should -Be 'test-key'
                }

                Should -Invoke -CommandName Get-DatabricksSecret -Times 1 -Exactly
            }
        }

        Context 'When the secret does not exist' {
            BeforeAll {
                Mock -CommandName Get-DatabricksSecret -MockWith {
                    return $null
                }
            }

            It 'Should return a hashtable with _exist set to false' {
                InModuleScope -ScriptBlock {
                    $instance = [DatabricksSecret]::new()
                    $instance.WorkspaceUrl = 'https://test.azuredatabricks.net'
                    $instance.AccessToken = (ConvertTo-SecureString -String 'test-token' -AsPlainText -Force)
                    $instance.ScopeName = 'test-scope'
                    $instance.SecretKey = 'test-key'

                    $currentState = $instance.GetCurrentState(@{
                        ScopeName = 'test-scope'
                        SecretKey = 'test-key'
                    })

                    $currentState._exist | Should -Be $false
                }

                Should -Invoke -CommandName Get-DatabricksSecret -Times 1 -Exactly
            }
        }

        Context 'When Get-DatabricksSecret throws an error' {
            BeforeAll {
                Mock -CommandName Get-DatabricksSecret -MockWith {
                    throw 'API Error'
                }
            }

            It 'Should return a hashtable with _exist set to false' {
                InModuleScope -ScriptBlock {
                    $instance = [DatabricksSecret]::new()
                    $instance.WorkspaceUrl = 'https://test.azuredatabricks.net'
                    $instance.AccessToken = (ConvertTo-SecureString -String 'test-token' -AsPlainText -Force)
                    $instance.ScopeName = 'test-scope'
                    $instance.SecretKey = 'test-key'

                    $currentState = $instance.GetCurrentState(@{
                        ScopeName = 'test-scope'
                        SecretKey = 'test-key'
                    })

                    $currentState._exist | Should -Be $false
                }

                Should -Invoke -CommandName Get-DatabricksSecret -Times 1 -Exactly
            }
        }
    }

    Context 'When Get() is called' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksSecret] @{
                    WorkspaceUrl = 'https://test.azuredatabricks.net'
                    AccessToken  = (ConvertTo-SecureString -String 'test-token' -AsPlainText -Force)
                    ScopeName    = 'test-scope'
                    SecretKey    = 'test-key'
                }

                <#
                    This mocks the method GetCurrentState().

                    Method Get() will call the base method Get() which will
                    call back to the derived class method GetCurrentState()
                    to get the current state.
                #>
                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                        return @{
                            WorkspaceUrl = 'https://test.azuredatabricks.net'
                            AccessToken  = (ConvertTo-SecureString -String 'test-token' -AsPlainText -Force)
                            ScopeName    = 'test-scope'
                            SecretKey    = 'test-key'
                            _exist       = $true
                        }
                    } -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'AssertProperties' -Value {
                        return
                    }
            }
        }

        It 'Should return the current state' {
            InModuleScope -ScriptBlock {
                $result = $script:mockInstance.Get()

                $result.WorkspaceUrl | Should -Be 'https://test.azuredatabricks.net'
                $result.ScopeName | Should -Be 'test-scope'
                $result.SecretKey | Should -Be 'test-key'
                $result._exist | Should -Be $true
            }
        }
    }

    Context 'When Test() is called' {
        Context 'When the secret should be present' {
            Context 'When the secret exists' {
                BeforeAll {
                    Mock -CommandName Get-DatabricksSecret -MockWith {
                        return @{
                            key = 'test-key'
                        }
                    }
                }

                It 'Should return $true' {
                    InModuleScope -ScriptBlock {
                        $instance = [DatabricksSecret]::new()
                        $instance.WorkspaceUrl = 'https://test.azuredatabricks.net'
                        $instance.AccessToken = (ConvertTo-SecureString -String 'test-token' -AsPlainText -Force)
                        $instance.ScopeName = 'test-scope'
                        $instance.SecretKey = 'test-key'
                        $instance._exist = $true

                        $result = $instance.Test()

                        $result | Should -Be $true
                    }

                    Should -Invoke -CommandName Get-DatabricksSecret -Times 1 -Exactly
                }
            }

            Context 'When the secret does not exist' {
                BeforeAll {
                    Mock -CommandName Get-DatabricksSecret -MockWith {
                        return $null
                    }
                }

                It 'Should return $false' {
                    InModuleScope -ScriptBlock {
                        $instance = [DatabricksSecret]::new()
                        $instance.WorkspaceUrl = 'https://test.azuredatabricks.net'
                        $instance.AccessToken = (ConvertTo-SecureString -String 'test-token' -AsPlainText -Force)
                        $instance.ScopeName = 'test-scope'
                        $instance.SecretKey = 'test-key'
                        $instance._exist = $true

                        $result = $instance.Test()

                        $result | Should -Be $false
                    }

                    Should -Invoke -CommandName Get-DatabricksSecret -Times 1 -Exactly
                }
            }
        }

        Context 'When the secret should be absent' {
            Context 'When the secret exists' {
                BeforeAll {
                    Mock -CommandName Get-DatabricksSecret -MockWith {
                        return @{
                            key = 'test-key'
                        }
                    }
                }

                It 'Should return $false' {
                    InModuleScope -ScriptBlock {
                        $instance = [DatabricksSecret]::new()
                        $instance.WorkspaceUrl = 'https://test.azuredatabricks.net'
                        $instance.AccessToken = (ConvertTo-SecureString -String 'test-token' -AsPlainText -Force)
                        $instance.ScopeName = 'test-scope'
                        $instance.SecretKey = 'test-key'
                        $instance._exist = $false

                        $result = $instance.Test()

                        $result | Should -Be $false
                    }

                    Should -Invoke -CommandName Get-DatabricksSecret -Times 1 -Exactly
                }
            }

            Context 'When the secret does not exist' {
                BeforeAll {
                    Mock -CommandName Get-DatabricksSecret -MockWith {
                        return $null
                    }
                }

                It 'Should return $true' {
                    InModuleScope -ScriptBlock {
                        $instance = [DatabricksSecret]::new()
                        $instance.WorkspaceUrl = 'https://test.azuredatabricks.net'
                        $instance.AccessToken = (ConvertTo-SecureString -String 'test-token' -AsPlainText -Force)
                        $instance.ScopeName = 'test-scope'
                        $instance.SecretKey = 'test-key'
                        $instance._exist = $false

                        $result = $instance.Test()

                        $result | Should -Be $true
                    }

                    Should -Invoke -CommandName Get-DatabricksSecret -Times 1 -Exactly
                }
            }
        }
    }

    Context 'When Modify() is called' {
        BeforeAll {
            Mock -CommandName New-DatabricksSecret
            Mock -CommandName Remove-DatabricksSecret
        }

        Context 'When creating a secret' {
            It 'Should call New-DatabricksSecret with StringValue' {
                InModuleScope -ScriptBlock {
                    $instance = [DatabricksSecret]::new()
                    $instance.WorkspaceUrl = 'https://test.azuredatabricks.net'
                    $instance.AccessToken = (ConvertTo-SecureString -String 'test-token' -AsPlainText -Force)
                    $instance.ScopeName = 'test-scope'
                    $instance.SecretKey = 'test-key'
                    $instance.StringValue = 'test-value'

                    $instance.Modify(@{ _exist = $true })
                }

                Should -Invoke -CommandName New-DatabricksSecret -Times 1 -Exactly -ParameterFilter {
                    $ScopeName -eq 'test-scope' -and
                    $SecretKey -eq 'test-key' -and
                    $StringValue -eq 'test-value'
                }
            }

            It 'Should call New-DatabricksSecret with BytesValue' {
                InModuleScope -ScriptBlock {
                    $instance = [DatabricksSecret]::new()
                    $instance.WorkspaceUrl = 'https://test.azuredatabricks.net'
                    $instance.AccessToken = (ConvertTo-SecureString -String 'test-token' -AsPlainText -Force)
                    $instance.ScopeName = 'test-scope'
                    $instance.SecretKey = 'test-key'
                    $instance.BytesValue = 'dGVzdC1ieXRlcw=='

                    $instance.Modify(@{ _exist = $true })
                }

                Should -Invoke -CommandName New-DatabricksSecret -Times 1 -Exactly -ParameterFilter {
                    $ScopeName -eq 'test-scope' -and
                    $SecretKey -eq 'test-key' -and
                    $BytesValue -eq 'dGVzdC1ieXRlcw=='
                }
            }
        }

        Context 'When removing a secret' {
            It 'Should call Remove-DatabricksSecret' {
                InModuleScope -ScriptBlock {
                    $instance = [DatabricksSecret]::new()
                    $instance.WorkspaceUrl = 'https://test.azuredatabricks.net'
                    $instance.AccessToken = (ConvertTo-SecureString -String 'test-token' -AsPlainText -Force)
                    $instance.ScopeName = 'test-scope'
                    $instance.SecretKey = 'test-key'

                    $instance.Modify(@{ _exist = $false })
                }

                Should -Invoke -CommandName Remove-DatabricksSecret -Times 1 -Exactly -ParameterFilter {
                    $ScopeName -eq 'test-scope' -and
                    $SecretKey -eq 'test-key'
                }
            }
        }
    }

    Context 'When Set() is called' {
        BeforeAll {
            Mock -CommandName New-DatabricksSecret
            Mock -CommandName Remove-DatabricksSecret
            Mock -CommandName Get-DatabricksSecret
        }

        Context 'When creating a new secret' {
            BeforeAll {
                Mock -CommandName Get-DatabricksSecret -MockWith {
                    return $null
                }
            }

            It 'Should call New-DatabricksSecret' {
                InModuleScope -ScriptBlock {
                    $instance = [DatabricksSecret]::new()
                    $instance.WorkspaceUrl = 'https://test.azuredatabricks.net'
                    $instance.AccessToken = (ConvertTo-SecureString -String 'test-token' -AsPlainText -Force)
                    $instance.ScopeName = 'test-scope'
                    $instance.SecretKey = 'test-key'
                    $instance.StringValue = 'test-value'
                    $instance._exist = $true

                    $instance.Set()
                }

                Should -Invoke -CommandName New-DatabricksSecret -Times 1 -Exactly
                Should -Invoke -CommandName Remove-DatabricksSecret -Times 0 -Exactly
            }
        }

        Context 'When updating an existing secret' {
            BeforeAll {
                Mock -CommandName Get-DatabricksSecret -MockWith {
                    return @{
                        key = 'test-key'
                    }
                }
            }

            It 'Should remove and recreate the secret' {
                InModuleScope -ScriptBlock {
                    $instance = [DatabricksSecret]::new()
                    $instance.WorkspaceUrl = 'https://test.azuredatabricks.net'
                    $instance.AccessToken = (ConvertTo-SecureString -String 'test-token' -AsPlainText -Force)
                    $instance.ScopeName = 'test-scope'
                    $instance.SecretKey = 'test-key'
                    $instance.StringValue = 'new-value'
                    $instance._exist = $true

                    $instance.Set()
                }

                Should -Invoke -CommandName Remove-DatabricksSecret -Times 1 -Exactly
                Should -Invoke -CommandName New-DatabricksSecret -Times 1 -Exactly
            }
        }

        Context 'When removing a secret' {
            BeforeAll {
                Mock -CommandName Get-DatabricksSecret -MockWith {
                    return @{
                        key = 'test-key'
                    }
                }
            }

            It 'Should call Remove-DatabricksSecret' {
                InModuleScope -ScriptBlock {
                    $instance = [DatabricksSecret]::new()
                    $instance.WorkspaceUrl = 'https://test.azuredatabricks.net'
                    $instance.AccessToken = (ConvertTo-SecureString -String 'test-token' -AsPlainText -Force)
                    $instance.ScopeName = 'test-scope'
                    $instance.SecretKey = 'test-key'
                    $instance._exist = $false

                    $instance.Set()
                }

                Should -Invoke -CommandName Remove-DatabricksSecret -Times 1 -Exactly
                Should -Invoke -CommandName New-DatabricksSecret -Times 0 -Exactly
            }
        }

        Context 'When the secret should be absent and does not exist' {
            BeforeAll {
                Mock -CommandName Get-DatabricksSecret -MockWith {
                    return $null
                }
            }

            It 'Should not call any modification functions' {
                InModuleScope -ScriptBlock {
                    $instance = [DatabricksSecret]::new()
                    $instance.WorkspaceUrl = 'https://test.azuredatabricks.net'
                    $instance.AccessToken = (ConvertTo-SecureString -String 'test-token' -AsPlainText -Force)
                    $instance.ScopeName = 'test-scope'
                    $instance.SecretKey = 'test-key'
                    $instance._exist = $false

                    $instance.Set()
                }

                Should -Invoke -CommandName Remove-DatabricksSecret -Times 0 -Exactly
                Should -Invoke -CommandName New-DatabricksSecret -Times 0 -Exactly
            }
        }
    }

    Context 'When Export() is called' {
        BeforeAll {
            Mock -CommandName Get-DatabricksSecretScope
            Mock -CommandName Get-DatabricksSecret
        }

        Context 'When exporting all secrets from all scopes' {
            BeforeAll {
                Mock -CommandName Get-DatabricksSecretScope -MockWith {
                    return @{
                        scopes = @(
                            @{ name = 'scope1' }
                            @{ name = 'scope2' }
                        )
                    }
                }

                Mock -CommandName Get-DatabricksSecret -MockWith {
                    param($ScopeName)

                    if ($ScopeName -eq 'scope1')
                    {
                        return @{
                            secrets = @(
                                @{ key = 'key1' }
                                @{ key = 'key2' }
                            )
                        }
                    }
                    elseif ($ScopeName -eq 'scope2')
                    {
                        return @{
                            secrets = @(
                                @{ key = 'key3' }
                            )
                        }
                    }
                }
            }

            It 'Should return all secrets from all scopes' {
                InModuleScope -ScriptBlock {
                    $filteringInstance = [DatabricksSecret]::new()
                    $filteringInstance.WorkspaceUrl = 'https://test.azuredatabricks.net'
                    $filteringInstance.AccessToken = (ConvertTo-SecureString -String 'test-token' -AsPlainText -Force)

                    $result = [DatabricksSecret]::Export($filteringInstance)

                    $result.Count | Should -Be 3
                    $result[0].ScopeName | Should -Be 'scope1'
                    $result[0].SecretKey | Should -Be 'key1'
                    $result[1].ScopeName | Should -Be 'scope1'
                    $result[1].SecretKey | Should -Be 'key2'
                    $result[2].ScopeName | Should -Be 'scope2'
                    $result[2].SecretKey | Should -Be 'key3'
                }

                Should -Invoke -CommandName Get-DatabricksSecretScope -Times 1 -Exactly
                Should -Invoke -CommandName Get-DatabricksSecret -Times 2 -Exactly
            }
        }

        Context 'When exporting secrets from a specific scope' {
            BeforeAll {
                Mock -CommandName Get-DatabricksSecretScope -MockWith {
                    return @{
                        name = 'scope1'
                    }
                }

                Mock -CommandName Get-DatabricksSecret -MockWith {
                    return @{
                        secrets = @(
                            @{ key = 'key1' }
                            @{ key = 'key2' }
                        )
                    }
                }
            }

            It 'Should return secrets only from the specified scope' {
                InModuleScope -ScriptBlock {
                    $filteringInstance = [DatabricksSecret]::new()
                    $filteringInstance.WorkspaceUrl = 'https://test.azuredatabricks.net'
                    $filteringInstance.AccessToken = (ConvertTo-SecureString -String 'test-token' -AsPlainText -Force)
                    $filteringInstance.ScopeName = 'scope1'

                    $result = [DatabricksSecret]::Export($filteringInstance)

                    $result.Count | Should -Be 2
                    $result[0].ScopeName | Should -Be 'scope1'
                    $result[0].SecretKey | Should -Be 'key1'
                    $result[1].ScopeName | Should -Be 'scope1'
                    $result[1].SecretKey | Should -Be 'key2'
                }

                Should -Invoke -CommandName Get-DatabricksSecretScope -Times 1 -Exactly -ParameterFilter {
                    $ScopeName -eq 'scope1'
                }
                Should -Invoke -CommandName Get-DatabricksSecret -Times 1 -Exactly
            }
        }

        Context 'When a scope has no secrets' {
            BeforeAll {
                Mock -CommandName Get-DatabricksSecretScope -MockWith {
                    return @{
                        scopes = @(
                            @{ name = 'scope1' }
                        )
                    }
                }

                Mock -CommandName Get-DatabricksSecret -MockWith {
                    return @{
                        secrets = @()
                    }
                }
            }

            It 'Should return an empty array' {
                InModuleScope -ScriptBlock {
                    $filteringInstance = [DatabricksSecret]::new()
                    $filteringInstance.WorkspaceUrl = 'https://test.azuredatabricks.net'
                    $filteringInstance.AccessToken = (ConvertTo-SecureString -String 'test-token' -AsPlainText -Force)

                    $result = [DatabricksSecret]::Export($filteringInstance)

                    $result.Count | Should -Be 0
                }

                Should -Invoke -CommandName Get-DatabricksSecretScope -Times 1 -Exactly
                Should -Invoke -CommandName Get-DatabricksSecret -Times 1 -Exactly
            }
        }

        Context 'When Get-DatabricksSecret throws an error' {
            BeforeAll {
                Mock -CommandName Get-DatabricksSecretScope -MockWith {
                    return @{
                        scopes = @(
                            @{ name = 'scope1' }
                        )
                    }
                }

                Mock -CommandName Get-DatabricksSecret -MockWith {
                    throw 'API Error'
                }
            }

            It 'Should handle the error gracefully and continue' {
                InModuleScope -ScriptBlock {
                    $filteringInstance = [DatabricksSecret]::new()
                    $filteringInstance.WorkspaceUrl = 'https://test.azuredatabricks.net'
                    $filteringInstance.AccessToken = (ConvertTo-SecureString -String 'test-token' -AsPlainText -Force)

                    $result = [DatabricksSecret]::Export($filteringInstance)

                    $result.Count | Should -Be 0
                }

                Should -Invoke -CommandName Get-DatabricksSecretScope -Times 1 -Exactly
                Should -Invoke -CommandName Get-DatabricksSecret -Times 1 -Exactly
            }
        }
    }
}
