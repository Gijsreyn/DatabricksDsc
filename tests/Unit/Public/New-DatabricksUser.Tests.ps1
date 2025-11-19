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

Describe 'New-DatabricksUser' -Tag 'Public' {
    BeforeAll {
        $mockWorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
        $mockAccessToken = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force

        $mockDefaultParameters = @{
            WorkspaceUrl = $mockWorkspaceUrl
            AccessToken  = $mockAccessToken
            UserName     = 'user@example.com'
        }
    }

    It 'Should have the correct parameters in parameter set <MockParameterSetName>' -ForEach @(
        @{
            MockParameterSetName   = '__AllParameterSets'
            MockExpectedParameters = '[-WorkspaceUrl] <string> [-AccessToken] <securestring> [-UserName] <string> [[-DisplayName] <string>] [[-Active] <bool>] [[-GivenName] <string>] [[-FamilyName] <string>] [[-Entitlements] <string[]>] [-WhatIf] [-Confirm] [<CommonParameters>]'
        }
    ) {
        $result = (Get-Command -Name 'New-DatabricksUser').ParameterSets |
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

    Context 'When creating a user with minimal parameters' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod -MockWith {
                return @{
                    id       = '1234567890'
                    userName = 'user@example.com'
                    active   = $true
                }
            }
        }

        It 'Should create the user' {
            $result = New-DatabricksUser @mockDefaultParameters

            $result.userName | Should -Be 'user@example.com'
            $result.id | Should -Be '1234567890'
        }

        It 'Should call Invoke-RestMethod with the correct parameters' {
            New-DatabricksUser @mockDefaultParameters

            Should -Invoke -CommandName Invoke-RestMethod -Exactly -Times 1 -Scope It -ParameterFilter {
                $Uri -eq "$mockWorkspaceUrl/api/2.0/preview/scim/v2/Users" -and
                $Method -eq 'Post' -and
                $Headers.Authorization -match '^Bearer ' -and
                $Headers.'Content-Type' -eq 'application/json' -and
                $Body -match '"userName":"user@example.com"' -and
                $Body -match '"active":true'
            }
        }
    }

    Context 'When creating a user with all parameters' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod -MockWith {
                return @{
                    id          = '1234567890'
                    userName    = 'user@example.com'
                    displayName = 'John Doe'
                    active      = $true
                    name        = @{
                        givenName  = 'John'
                        familyName = 'Doe'
                    }
                    entitlements = @(
                        @{ value = 'workspace-access' }
                    )
                }
            }

            $mockCompleteParameters = @{
                WorkspaceUrl = $mockWorkspaceUrl
                AccessToken  = $mockAccessToken
                UserName     = 'user@example.com'
                DisplayName  = 'John Doe'
                Active       = $true
                GivenName    = 'John'
                FamilyName   = 'Doe'
                Entitlements = @('workspace-access')
            }
        }

        It 'Should create the user with all properties' {
            $result = New-DatabricksUser @mockCompleteParameters

            $result.userName | Should -Be 'user@example.com'
            $result.displayName | Should -Be 'John Doe'
            $result.name.givenName | Should -Be 'John'
            $result.name.familyName | Should -Be 'Doe'
            $result.entitlements[0].value | Should -Be 'workspace-access'
        }

        It 'Should call Invoke-RestMethod with the body containing all properties' {
            New-DatabricksUser @mockCompleteParameters

            Should -Invoke -CommandName Invoke-RestMethod -Exactly -Times 1 -Scope It -ParameterFilter {
                $Body -match '"displayName":"John Doe"' -and
                $Body -match '"givenName":"John"' -and
                $Body -match '"familyName":"Doe"' -and
                $Body -match '"entitlements"'
            }
        }
    }

    Context 'When creating an inactive user' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod -MockWith {
                return @{
                    id       = '1234567890'
                    userName = 'user@example.com'
                    active   = $false
                }
            }

            $mockInactiveParameters = @{
                WorkspaceUrl = $mockWorkspaceUrl
                AccessToken  = $mockAccessToken
                UserName     = 'user@example.com'
                Active       = $false
            }
        }

        It 'Should create an inactive user' {
            $result = New-DatabricksUser @mockInactiveParameters

            $result.active | Should -Be $false
        }
    }

    Context 'When using WhatIf' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod
        }

        It 'Should not call Invoke-RestMethod' {
            New-DatabricksUser @mockDefaultParameters -WhatIf

            Should -Invoke -CommandName Invoke-RestMethod -Exactly -Times 0 -Scope It
        }
    }

    Context 'When an error occurs' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod -MockWith {
                throw 'API Error: User already exists'
            }

            Mock -CommandName Write-Error
        }

        It 'Should write an error message' {
            New-DatabricksUser @mockDefaultParameters -ErrorAction SilentlyContinue

            Should -Invoke -CommandName Write-Error -Exactly -Times 1 -Scope It
        }
    }

    Context 'When WorkspaceUrl has trailing slash' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod -MockWith {
                return @{
                    id       = '1234567890'
                    userName = 'user@example.com'
                }
            }

            $mockParametersWithTrailingSlash = @{
                WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net/'
                AccessToken  = $mockAccessToken
                UserName     = 'user@example.com'
            }
        }

        It 'Should trim the trailing slash from WorkspaceUrl' {
            New-DatabricksUser @mockParametersWithTrailingSlash

            Should -Invoke -CommandName Invoke-RestMethod -Exactly -Times 1 -Scope It -ParameterFilter {
                $Uri -eq "$mockWorkspaceUrl/api/2.0/preview/scim/v2/Users"
            }
        }
    }
}
