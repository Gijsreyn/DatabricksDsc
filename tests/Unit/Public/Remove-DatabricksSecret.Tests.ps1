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

Describe 'Remove-DatabricksSecret' -Tag 'Remove-DatabricksSecret' {
    BeforeAll {
        Mock -CommandName ConvertTo-DatabricksAuthHeader -MockWith {
            return 'Bearer test-token'
        }

        Mock -CommandName Invoke-RestMethod
    }

    Context 'When removing a secret' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod -MockWith {
                return @{}
            }
        }

        It 'Should call the API with correct parameters' {
            InModuleScope -ScriptBlock {
                $params = @{
                    WorkspaceUrl = 'https://test.azuredatabricks.net'
                    AccessToken  = (ConvertTo-SecureString -String 'test-token' -AsPlainText -Force)
                    ScopeName    = 'test-scope'
                    SecretKey    = 'test-key'
                }

                Remove-DatabricksSecret @params
            }

            Should -Invoke -CommandName Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
                $Uri -eq 'https://test.azuredatabricks.net/api/2.0/secrets/delete' -and
                $Method -eq 'POST' -and
                $Body -match '"scope":"test-scope"' -and
                $Body -match '"key":"test-key"'
            }
        }

        It 'Should return an empty hashtable' {
            InModuleScope -ScriptBlock {
                $params = @{
                    WorkspaceUrl = 'https://test.azuredatabricks.net'
                    AccessToken  = (ConvertTo-SecureString -String 'test-token' -AsPlainText -Force)
                    ScopeName    = 'test-scope'
                    SecretKey    = 'test-key'
                }

                $result = Remove-DatabricksSecret @params

                $result | Should -BeOfType [hashtable]
                $result.Count | Should -Be 0
            }
        }
    }

    Context 'When the API call fails' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod -MockWith {
                throw 'API Error: Secret not found'
            }

            Mock -CommandName Write-Error
        }

        It 'Should throw an error' {
            InModuleScope -ScriptBlock {
                $params = @{
                    WorkspaceUrl = 'https://test.azuredatabricks.net'
                    AccessToken  = (ConvertTo-SecureString -String 'test-token' -AsPlainText -Force)
                    ScopeName    = 'test-scope'
                    SecretKey    = 'test-key'
                }

                { Remove-DatabricksSecret @params } | Should -Throw
            }

            Should -Invoke -CommandName Write-Error -Times 1 -Exactly
        }
    }

    Context 'When WorkspaceUrl has a trailing slash' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod -MockWith {
                return @{}
            }
        }

        It 'Should trim the trailing slash from the URI' {
            InModuleScope -ScriptBlock {
                $params = @{
                    WorkspaceUrl = 'https://test.azuredatabricks.net/'
                    AccessToken  = (ConvertTo-SecureString -String 'test-token' -AsPlainText -Force)
                    ScopeName    = 'test-scope'
                    SecretKey    = 'test-key'
                }

                Remove-DatabricksSecret @params
            }

            Should -Invoke -CommandName Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
                $Uri -eq 'https://test.azuredatabricks.net/api/2.0/secrets/delete'
            }
        }
    }

    Context 'When validating parameters' {
        It 'Should have WorkspaceUrl as a mandatory parameter' {
            InModuleScope -ScriptBlock {
                $command = Get-Command -Name Remove-DatabricksSecret
                $parameter = $command.Parameters['WorkspaceUrl']

                $parameter.Attributes.Mandatory | Should -Contain $true
            }
        }

        It 'Should have AccessToken as a mandatory parameter' {
            InModuleScope -ScriptBlock {
                $command = Get-Command -Name Remove-DatabricksSecret
                $parameter = $command.Parameters['AccessToken']

                $parameter.Attributes.Mandatory | Should -Contain $true
            }
        }

        It 'Should have ScopeName as a mandatory parameter' {
            InModuleScope -ScriptBlock {
                $command = Get-Command -Name Remove-DatabricksSecret
                $parameter = $command.Parameters['ScopeName']

                $parameter.Attributes.Mandatory | Should -Contain $true
            }
        }

        It 'Should have SecretKey as a mandatory parameter' {
            InModuleScope -ScriptBlock {
                $command = Get-Command -Name Remove-DatabricksSecret
                $parameter = $command.Parameters['SecretKey']

                $parameter.Attributes.Mandatory | Should -Contain $true
            }
        }
    }
}
