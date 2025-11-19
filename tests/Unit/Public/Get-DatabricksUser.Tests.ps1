[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Justification = 'because ConvertTo-SecureString is used to simplify the tests.')]
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

    $env:DatabricksDscCI = $true

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

    Remove-Item -Path 'env:DatabricksDscCI'
}

Describe 'Get-DatabricksUser' -Tag 'Public' {
    BeforeAll {
        $mockWorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
        $mockAccessToken = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force

        $mockDefaultParameters = @{
            WorkspaceUrl = $mockWorkspaceUrl
            AccessToken  = $mockAccessToken
        }
    }

    It 'Should have the correct parameters in parameter set <MockParameterSetName>' -ForEach @(
        @{
            MockParameterSetName   = 'All'
            MockExpectedParameters = '-WorkspaceUrl <string> -AccessToken <securestring> [<CommonParameters>]'
        }
        @{
            MockParameterSetName   = 'ByUserName'
            MockExpectedParameters = '-WorkspaceUrl <string> -AccessToken <securestring> [-UserName <string>] [<CommonParameters>]'
        }
        @{
            MockParameterSetName   = 'ById'
            MockExpectedParameters = '-WorkspaceUrl <string> -AccessToken <securestring> [-Id <string>] [<CommonParameters>]'
        }
    ) {
        $result = (Get-Command -Name 'Get-DatabricksUser').ParameterSets |
            Where-Object -FilterScript {
                $_.Name -eq $mockParameterSetName
            } |
            Select-Object -Property @(
                @{
                    Name       = 'ParameterSetName'
                    Expression = { $_.Name }
                },
                @{
                    Name       = 'ParameterListAsString'
                    Expression = { $_.ToString() }
                }
            )

        $result.ParameterSetName | Should -Be $MockParameterSetName
        $result.ParameterListAsString | Should -Be $MockExpectedParameters
    }

    Context 'When getting all users' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod -MockWith {
                return @{
                    Resources = @(
                        @{
                            id       = '1234567890'
                            userName = 'user1@example.com'
                            active   = $true
                        }
                        @{
                            id       = '0987654321'
                            userName = 'user2@example.com'
                            active   = $true
                        }
                    )
                }
            }
        }

        It 'Should return all users' {
            $result = Get-DatabricksUser @mockDefaultParameters

            $result | Should -HaveCount 2
            $result[0].userName | Should -Be 'user1@example.com'
            $result[1].userName | Should -Be 'user2@example.com'
        }

        It 'Should call Invoke-RestMethod with the correct parameters' {
            Get-DatabricksUser @mockDefaultParameters

            Should -Invoke -CommandName Invoke-RestMethod -Exactly -Times 1 -Scope It -ParameterFilter {
                $Uri -eq "$mockWorkspaceUrl/api/2.0/preview/scim/v2/Users" -and
                $Method -eq 'Get' -and
                $Headers.Authorization -match '^Bearer ' -and
                $Headers.'Content-Type' -eq 'application/json'
            }
        }
    }

    Context 'When getting a user by username' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod -MockWith {
                return @{
                    Resources = @(
                        @{
                            id       = '1234567890'
                            userName = 'user1@example.com'
                            active   = $true
                        }
                        @{
                            id       = '0987654321'
                            userName = 'user2@example.com'
                            active   = $true
                        }
                    )
                }
            }
        }

        It 'Should return the specific user' {
            $result = Get-DatabricksUser @mockDefaultParameters -UserName 'user1@example.com'

            $result.userName | Should -Be 'user1@example.com'
            $result.id | Should -Be '1234567890'
        }

        It 'Should return null when user is not found' {
            $result = Get-DatabricksUser @mockDefaultParameters -UserName 'nonexistent@example.com'

            $result | Should -BeNullOrEmpty
        }
    }

    Context 'When getting a user by ID' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod -MockWith {
                return @{
                    id       = '1234567890'
                    userName = 'user1@example.com'
                    active   = $true
                }
            }
        }

        It 'Should return the specific user' {
            $result = Get-DatabricksUser @mockDefaultParameters -Id '1234567890'

            $result.userName | Should -Be 'user1@example.com'
            $result.id | Should -Be '1234567890'
        }

        It 'Should call Invoke-RestMethod with the correct URI' {
            Get-DatabricksUser @mockDefaultParameters -Id '1234567890'

            Should -Invoke -CommandName Invoke-RestMethod -Exactly -Times 1 -Scope It -ParameterFilter {
                $Uri -eq "$mockWorkspaceUrl/api/2.0/preview/scim/v2/Users/1234567890" -and
                $Method -eq 'Get'
            }
        }
    }

    Context 'When an error occurs' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod -MockWith {
                throw 'API Error: Unauthorized'
            }

            Mock -CommandName Write-Error
        }

        It 'Should write an error message' {
            Get-DatabricksUser @mockDefaultParameters -ErrorAction SilentlyContinue

            Should -Invoke -CommandName Write-Error -Exactly -Times 1 -Scope It
        }
    }

    Context 'When WorkspaceUrl has trailing slash' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod -MockWith {
                return @{
                    Resources = @()
                }
            }

            $mockParametersWithTrailingSlash = @{
                WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net/'
                AccessToken  = $mockAccessToken
            }
        }

        It 'Should trim the trailing slash from WorkspaceUrl' {
            Get-DatabricksUser @mockParametersWithTrailingSlash

            Should -Invoke -CommandName Invoke-RestMethod -Exactly -Times 1 -Scope It -ParameterFilter {
                $Uri -eq "$mockWorkspaceUrl/api/2.0/preview/scim/v2/Users"
            }
        }
    }
}
