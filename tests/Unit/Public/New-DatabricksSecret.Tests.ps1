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

Describe 'New-DatabricksSecret' -Tag 'New-DatabricksSecret' {
    BeforeAll {
        Mock -CommandName ConvertTo-DatabricksAuthHeader -MockWith {
            return 'Bearer test-token'
        }

        Mock -CommandName Invoke-RestMethod
        Mock -CommandName New-ArgumentException -MockWith {
            throw 'Either StringValue or BytesValue must be specified'
        }
    }

    Context 'When creating a secret with StringValue' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod -MockWith {
                return @{}
            }
        }

        It 'Should call the API with StringValue' {
            InModuleScope -ScriptBlock {
                $params = @{
                    WorkspaceUrl = 'https://test.azuredatabricks.net'
                    AccessToken  = (ConvertTo-SecureString -String 'test-token' -AsPlainText -Force)
                    ScopeName    = 'test-scope'
                    SecretKey    = 'test-key'
                    StringValue  = 'test-value'
                }

                New-DatabricksSecret @params
            }

            Should -Invoke -CommandName Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
                $Uri -eq 'https://test.azuredatabricks.net/api/2.0/secrets/put' -and
                $Method -eq 'POST' -and
                $Body -match '"scope":"test-scope"' -and
                $Body -match '"key":"test-key"' -and
                $Body -match '"string_value":"test-value"'
            }
        }
    }

    Context 'When creating a secret with BytesValue' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod -MockWith {
                return @{}
            }
        }

        It 'Should call the API with BytesValue' {
            InModuleScope -ScriptBlock {
                $params = @{
                    WorkspaceUrl = 'https://test.azuredatabricks.net'
                    AccessToken  = (ConvertTo-SecureString -String 'test-token' -AsPlainText -Force)
                    ScopeName    = 'test-scope'
                    SecretKey    = 'test-key'
                    BytesValue   = 'dGVzdC1ieXRlcw=='
                }

                New-DatabricksSecret @params
            }

            Should -Invoke -CommandName Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
                $Uri -eq 'https://test.azuredatabricks.net/api/2.0/secrets/put' -and
                $Method -eq 'POST' -and
                $Body -match '"scope":"test-scope"' -and
                $Body -match '"key":"test-key"' -and
                $Body -match '"bytes_value":"dGVzdC1ieXRlcw=="'
            }
        }
    }

    Context 'When the API call fails' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod -MockWith {
                throw 'API Error: Unauthorized'
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
                    StringValue  = 'test-value'
                }

                { New-DatabricksSecret @params } | Should -Throw
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
                    StringValue  = 'test-value'
                }

                New-DatabricksSecret @params
            }

            Should -Invoke -CommandName Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
                $Uri -eq 'https://test.azuredatabricks.net/api/2.0/secrets/put'
            }
        }
    }

    Context 'When validating parameters' {
        It 'Should have WorkspaceUrl as a mandatory parameter' {
            InModuleScope -ScriptBlock {
                $command = Get-Command -Name New-DatabricksSecret
                $parameter = $command.Parameters['WorkspaceUrl']

                $parameter.Attributes.Mandatory | Should -Contain $true
            }
        }

        It 'Should have AccessToken as a mandatory parameter' {
            InModuleScope -ScriptBlock {
                $command = Get-Command -Name New-DatabricksSecret
                $parameter = $command.Parameters['AccessToken']

                $parameter.Attributes.Mandatory | Should -Contain $true
            }
        }

        It 'Should have ScopeName as a mandatory parameter' {
            InModuleScope -ScriptBlock {
                $command = Get-Command -Name New-DatabricksSecret
                $parameter = $command.Parameters['ScopeName']

                $parameter.Attributes.Mandatory | Should -Contain $true
            }
        }

        It 'Should have SecretKey as a mandatory parameter' {
            InModuleScope -ScriptBlock {
                $command = Get-Command -Name New-DatabricksSecret
                $parameter = $command.Parameters['SecretKey']

                $parameter.Attributes.Mandatory | Should -Contain $true
            }
        }

        It 'Should have StringValue in the String parameter set' {
            InModuleScope -ScriptBlock {
                $command = Get-Command -Name New-DatabricksSecret
                $parameter = $command.Parameters['StringValue']

                $parameter.ParameterSets['String'].IsMandatory | Should -Be $false
            }
        }

        It 'Should have BytesValue in the Bytes parameter set' {
            InModuleScope -ScriptBlock {
                $command = Get-Command -Name New-DatabricksSecret
                $parameter = $command.Parameters['BytesValue']

                $parameter.ParameterSets['Bytes'].IsMandatory | Should -Be $false
            }
        }
    }
}
