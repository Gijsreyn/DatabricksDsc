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

Describe 'Get-DatabricksSecret' -Tag 'Get-DatabricksSecret' {
    BeforeAll {
        Mock -CommandName ConvertTo-DatabricksAuthHeader -MockWith {
            return 'Bearer test-token'
        }

        Mock -CommandName Invoke-RestMethod
    }

    Context 'When getting all secrets from a scope' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod -MockWith {
                return @{
                    secrets = @(
                        @{ key = 'key1' }
                        @{ key = 'key2' }
                    )
                }
            }
        }

        It 'Should call the API and return all secrets' {
            InModuleScope -ScriptBlock {
                $params = @{
                    WorkspaceUrl = 'https://test.azuredatabricks.net'
                    AccessToken  = (ConvertTo-SecureString -String 'test-token' -AsPlainText -Force)
                    ScopeName    = 'test-scope'
                }

                $result = Get-DatabricksSecret @params

                $result | Should -Not -BeNullOrEmpty
                $result.secrets.Count | Should -Be 2
                $result.secrets[0].key | Should -Be 'key1'
                $result.secrets[1].key | Should -Be 'key2'
            }

            Should -Invoke -CommandName Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
                $Uri -eq 'https://test.azuredatabricks.net/api/2.0/secrets/list' -and
                $Method -eq 'GET' -and
                $Body.scope -eq 'test-scope'
            }
        }
    }

    Context 'When getting a specific secret by key' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod -MockWith {
                return @{
                    secrets = @(
                        @{ key = 'key1' }
                        @{ key = 'key2' }
                    )
                }
            }
        }

        It 'Should call the API and return only the matching secret' {
            InModuleScope -ScriptBlock {
                $params = @{
                    WorkspaceUrl = 'https://test.azuredatabricks.net'
                    AccessToken  = (ConvertTo-SecureString -String 'test-token' -AsPlainText -Force)
                    ScopeName    = 'test-scope'
                    SecretKey    = 'key1'
                }

                $result = Get-DatabricksSecret @params

                $result | Should -Not -BeNullOrEmpty
                $result.key | Should -Be 'key1'
            }

            Should -Invoke -CommandName Invoke-RestMethod -Times 1 -Exactly
        }
    }

    Context 'When the API call fails' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod -MockWith {
                throw 'API Error: Resource not found'
            }

            Mock -CommandName Write-Error
        }

        It 'Should throw an error' {
            InModuleScope -ScriptBlock {
                $params = @{
                    WorkspaceUrl = 'https://test.azuredatabricks.net'
                    AccessToken  = (ConvertTo-SecureString -String 'test-token' -AsPlainText -Force)
                    ScopeName    = 'test-scope'
                }

                { Get-DatabricksSecret @params } | Should -Throw
            }

            Should -Invoke -CommandName Write-Error -Times 1 -Exactly
        }
    }

    Context 'When WorkspaceUrl has a trailing slash' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod -MockWith {
                return @{
                    secrets = @()
                }
            }
        }

        It 'Should trim the trailing slash from the URI' {
            InModuleScope -ScriptBlock {
                $params = @{
                    WorkspaceUrl = 'https://test.azuredatabricks.net/'
                    AccessToken  = (ConvertTo-SecureString -String 'test-token' -AsPlainText -Force)
                    ScopeName    = 'test-scope'
                }

                Get-DatabricksSecret @params
            }

            Should -Invoke -CommandName Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
                $Uri -eq 'https://test.azuredatabricks.net/api/2.0/secrets/list'
            }
        }
    }

    Context 'When validating parameters' {
        It 'Should have WorkspaceUrl as a mandatory parameter' {
            InModuleScope -ScriptBlock {
                $command = Get-Command -Name Get-DatabricksSecret
                $parameter = $command.Parameters['WorkspaceUrl']

                $parameter.Attributes.Mandatory | Should -Contain $true
            }
        }

        It 'Should have AccessToken as a mandatory parameter' {
            InModuleScope -ScriptBlock {
                $command = Get-Command -Name Get-DatabricksSecret
                $parameter = $command.Parameters['AccessToken']

                $parameter.Attributes.Mandatory | Should -Contain $true
            }
        }

        It 'Should have ScopeName as a mandatory parameter' {
            InModuleScope -ScriptBlock {
                $command = Get-Command -Name Get-DatabricksSecret
                $parameter = $command.Parameters['ScopeName']

                $parameter.Attributes.Mandatory | Should -Contain $true
            }
        }

        It 'Should have SecretKey as an optional parameter' {
            InModuleScope -ScriptBlock {
                $command = Get-Command -Name Get-DatabricksSecret
                $parameter = $command.Parameters['SecretKey']

                $parameter.Attributes.Mandatory | Should -Not -Contain $true
            }
        }
    }
}
