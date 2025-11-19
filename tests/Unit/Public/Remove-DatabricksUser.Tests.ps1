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

Describe 'Remove-DatabricksUser' -Tag 'Public' {
    BeforeAll {
        $mockWorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
        $mockAccessToken = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force

        $mockDefaultParameters = @{
            WorkspaceUrl = $mockWorkspaceUrl
            AccessToken  = $mockAccessToken
            Id           = '1234567890'
        }
    }

    It 'Should have the correct parameters in parameter set <MockParameterSetName>' -ForEach @(
        @{
            MockParameterSetName   = '__AllParameterSets'
            MockExpectedParameters = '[-WorkspaceUrl] <string> [-AccessToken] <securestring> [-Id] <string> [-Force] [-WhatIf] [-Confirm] [<CommonParameters>]'
        }
    ) {
        $result = (Get-Command -Name 'Remove-DatabricksUser').ParameterSets |
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

    Context 'When removing a user with Force parameter' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod
        }

        It 'Should remove the user' {
            { Remove-DatabricksUser @mockDefaultParameters -Force } | Should -Not -Throw
        }

        It 'Should call Invoke-RestMethod with the correct parameters' {
            Remove-DatabricksUser @mockDefaultParameters -Force

            Should -Invoke -CommandName Invoke-RestMethod -Exactly -Times 1 -Scope It -ParameterFilter {
                $Uri -eq "$mockWorkspaceUrl/api/2.0/preview/scim/v2/Users/1234567890" -and
                $Method -eq 'Delete' -and
                $Headers.Authorization -match '^Bearer ' -and
                $Headers.'Content-Type' -eq 'application/json'
            }
        }
    }

    Context 'When removing a user with Confirm' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod
        }

        It 'Should remove the user when confirmed' {
            Remove-DatabricksUser @mockDefaultParameters -Confirm:$false

            Should -Invoke -CommandName Invoke-RestMethod -Exactly -Times 1 -Scope It
        }
    }

    Context 'When using WhatIf' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod
        }

        It 'Should not call Invoke-RestMethod' {
            Remove-DatabricksUser @mockDefaultParameters -WhatIf

            Should -Invoke -CommandName Invoke-RestMethod -Exactly -Times 0 -Scope It
        }
    }

    Context 'When an error occurs' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod -MockWith {
                throw 'API Error: User not found'
            }

            Mock -CommandName Write-Error
        }

        It 'Should write an error message' {
            Remove-DatabricksUser @mockDefaultParameters -Force -ErrorAction SilentlyContinue

            Should -Invoke -CommandName Write-Error -Exactly -Times 1 -Scope It
        }
    }

    Context 'When WorkspaceUrl has trailing slash' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod

            $mockParametersWithTrailingSlash = @{
                WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net/'
                AccessToken  = $mockAccessToken
                Id           = '1234567890'
            }
        }

        It 'Should trim the trailing slash from WorkspaceUrl' {
            Remove-DatabricksUser @mockParametersWithTrailingSlash -Force

            Should -Invoke -CommandName Invoke-RestMethod -Exactly -Times 1 -Scope It -ParameterFilter {
                $Uri -eq "$mockWorkspaceUrl/api/2.0/preview/scim/v2/Users/1234567890"
            }
        }
    }

    Context 'When command is called successfully' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod
        }

        It 'Should not return any output' {
            $result = Remove-DatabricksUser @mockDefaultParameters -Force

            $result | Should -BeNullOrEmpty
        }
    }
}
