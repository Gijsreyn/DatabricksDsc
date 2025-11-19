<#
    .SYNOPSIS
        Unit test for DatabricksResourceBase class.
#>

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

Describe 'DatabricksResourceBase' {
    Context 'When class is instantiated' {
        It 'Should not throw an exception' {
            InModuleScope -ScriptBlock {
                { [DatabricksResourceBase]::new() } | Should -Not -Throw
            }
        }

        It 'Should have a default constructor' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksResourceBase]::new()
                $instance | Should -Not -BeNullOrEmpty
                $instance.WorkspaceUrl | Should -BeNullOrEmpty
                $instance.AccessToken | Should -BeNullOrEmpty
            }
        }

        It 'Should be the correct type' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksResourceBase]::new()
                $instance.GetType().Name | Should -Be 'DatabricksResourceBase'
            }
        }
    }
}

Describe 'DatabricksResourceBase\InvokeDatabricksApi()' -Tag 'InvokeDatabricksApi' {
    Context 'When making a GET request' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksResourceBaseInstance = [DatabricksResourceBase]::new()
                $script:mockDatabricksResourceBaseInstance.WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                $script:mockDatabricksResourceBaseInstance.AccessToken = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force

                Mock -CommandName Write-Verbose

                Mock -CommandName ConvertTo-DatabricksAuthHeader -MockWith {
                    return 'Bearer dapi1234567890abcdef'
                }

                Mock -CommandName Invoke-RestMethod -MockWith {
                    return @{
                        id       = 'user-123'
                        userName = 'testuser@example.com'
                    }
                }
            }
        }

        It 'Should call the method without throwing and call ConvertTo-DatabricksAuthHeader' {
            InModuleScope -ScriptBlock {
                {
                    $script:mockDatabricksResourceBaseInstance.InvokeDatabricksApi('GET', '/api/2.0/preview/scim/v2/Users/user-123', $null)
                } | Should -Not -Throw

                Should -Invoke -CommandName ConvertTo-DatabricksAuthHeader -Exactly -Times 1 -Scope It
            }
        }
    }

    Context 'When making a POST request with a body' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksResourceBaseInstance = [DatabricksResourceBase]::new()
                $script:mockDatabricksResourceBaseInstance.WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net/'
                $script:mockDatabricksResourceBaseInstance.AccessToken = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force

                Mock -CommandName Write-Verbose

                Mock -CommandName ConvertTo-DatabricksAuthHeader -MockWith {
                    return 'Bearer dapi1234567890abcdef'
                }

                Mock -CommandName Invoke-RestMethod -MockWith {
                    return @{
                        id       = 'user-456'
                        userName = 'newuser@example.com'
                    }
                }
            }
        }

        It 'Should call the method with body parameter without throwing' {
            $testBody = @{
                userName = 'newuser@example.com'
                active   = $true
            }

            InModuleScope -Parameters @{ testBody = $testBody } -ScriptBlock {
                {
                    $script:mockDatabricksResourceBaseInstance.InvokeDatabricksApi('POST', '/api/2.0/preview/scim/v2/Users', $testBody)
                } | Should -Not -Throw

                Should -Invoke -CommandName ConvertTo-DatabricksAuthHeader -Exactly -Times 1 -Scope It
            }
        }
    }

    Context 'When WorkspaceUrl has a trailing slash' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksResourceBaseInstance = [DatabricksResourceBase]::new()
                $script:mockDatabricksResourceBaseInstance.WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net/'
                $script:mockDatabricksResourceBaseInstance.AccessToken = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
            }

            Mock -CommandName Write-Verbose

            Mock -CommandName ConvertTo-DatabricksAuthHeader -MockWith {
                return 'Bearer dapi1234567890abcdef'
            }

            Mock -CommandName Invoke-RestMethod -MockWith {
                return @{ success = $true }
            }
        }

        It 'Should correctly handle the trailing slash in URL construction' {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksResourceBaseInstance.InvokeDatabricksApi('GET', '/api/2.0/preview/scim/v2/Users', $null)
            }

            Should -Invoke -CommandName Invoke-RestMethod -ParameterFilter {
                $Uri -eq 'https://adb-1234567890123456.12.azuredatabricks.net/api/2.0/preview/scim/v2/Users'
            } -Exactly -Times 1 -Scope It
        }
    }

    Context 'When API call fails' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksResourceBaseInstance = [DatabricksResourceBase]::new()
                $script:mockDatabricksResourceBaseInstance.WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                $script:mockDatabricksResourceBaseInstance.AccessToken = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
            }

            Mock -CommandName Write-Verbose

            Mock -CommandName ConvertTo-DatabricksAuthHeader -MockWith {
                return 'Bearer dapi1234567890abcdef'
            }

            Mock -CommandName Invoke-RestMethod -MockWith {
                throw 'Unauthorized: Invalid access token'
            }
        }

        It 'Should throw a terminating error with localized message' {
            InModuleScope -ScriptBlock {
                $errorMessage = $script:localizedData.FailedToInvokeDatabricksApi -f @(
                    'GET',
                    '/api/2.0/preview/scim/v2/Users',
                    'Unauthorized: Invalid access token'
                )

                {
                    $script:mockDatabricksResourceBaseInstance.InvokeDatabricksApi('GET', '/api/2.0/preview/scim/v2/Users', $null)
                } | Should -Throw -ExpectedMessage "*$errorMessage*"
            }

            Should -Invoke -CommandName Invoke-RestMethod -Exactly -Times 1 -Scope It
        }
    }

    Context 'When making a PATCH request' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksResourceBaseInstance = [DatabricksResourceBase]::new()
                $script:mockDatabricksResourceBaseInstance.WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                $script:mockDatabricksResourceBaseInstance.AccessToken = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
            }

            Mock -CommandName Write-Verbose

            Mock -CommandName ConvertTo-DatabricksAuthHeader -MockWith {
                return 'Bearer dapi1234567890abcdef'
            }

            Mock -CommandName Invoke-RestMethod -MockWith {
                return @{
                    id     = 'user-789'
                    active = $false
                }
            }
        }

        It 'Should call the correct mocks for PATCH method' {
            $testBody = @{
                active = $false
            }

            $result = InModuleScope -Parameters @{ testBody = $testBody } -ScriptBlock {
                $script:mockDatabricksResourceBaseInstance.InvokeDatabricksApi('PATCH', '/api/2.0/preview/scim/v2/Users/user-789', $testBody)
            }

            $result.id | Should -Be 'user-789'
            $result.active | Should -BeFalse

            Should -Invoke -CommandName Invoke-RestMethod -ParameterFilter {
                $Method -eq 'PATCH' -and
                $Uri -eq 'https://adb-1234567890123456.12.azuredatabricks.net/api/2.0/preview/scim/v2/Users/user-789'
            } -Exactly -Times 1 -Scope It
        }
    }

    Context 'When making a DELETE request' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksResourceBaseInstance = [DatabricksResourceBase]::new()
                $script:mockDatabricksResourceBaseInstance.WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                $script:mockDatabricksResourceBaseInstance.AccessToken = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
            }

            Mock -CommandName Write-Verbose

            Mock -CommandName ConvertTo-DatabricksAuthHeader -MockWith {
                return 'Bearer dapi1234567890abcdef'
            }

            Mock -CommandName Invoke-RestMethod -MockWith {
                return $null
            }
        }

        It 'Should call the correct mocks for DELETE method' {
            InModuleScope -ScriptBlock {
                $script:mockDatabricksResourceBaseInstance.InvokeDatabricksApi('DELETE', '/api/2.0/preview/scim/v2/Users/user-999', $null)
            }

            Should -Invoke -CommandName Invoke-RestMethod -ParameterFilter {
                $Method -eq 'DELETE' -and
                $Uri -eq 'https://adb-1234567890123456.12.azuredatabricks.net/api/2.0/preview/scim/v2/Users/user-999'
            } -Exactly -Times 1 -Scope It
        }
    }
}
