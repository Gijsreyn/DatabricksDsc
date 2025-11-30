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

Describe 'Remove-DatabricksSecretScope' -Tag 'Public' {
    BeforeAll {
        $mockWorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
        $mockAccessToken = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force

        $mockDefaultParameters = @{
            WorkspaceUrl = $mockWorkspaceUrl
            AccessToken  = $mockAccessToken
            ScopeName    = 'test-scope'
        }
    }

    It 'Should have the correct parameters in parameter set <MockParameterSetName>' -ForEach @(
        @{
            MockParameterSetName   = '__AllParameterSets'
            MockExpectedParameters = '[-WorkspaceUrl] <string> [-AccessToken] <securestring> [-ScopeName] <string> [<CommonParameters>]'
        }
    ) {
        $result = (Get-Command -Name 'Remove-DatabricksSecretScope').ParameterSets |
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

    Context 'When removing a secret scope' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod -MockWith {
                return @{}
            }

            Mock -CommandName ConvertTo-DatabricksAuthHeader -MockWith {
                return 'Bearer dapi1234567890abcdef'
            }
        }

        It 'Should remove the secret scope successfully' {
            InModuleScope -Parameters @{
                mockDefaultParameters = $mockDefaultParameters
            } -ScriptBlock {
                { Remove-DatabricksSecretScope @mockDefaultParameters } | Should -Not -Throw
            }

            Should -Invoke -CommandName Invoke-RestMethod -Exactly -Times 1 -Scope It
        }

        It 'Should call Invoke-RestMethod with correct parameters' {
            InModuleScope -Parameters @{
                mockDefaultParameters = $mockDefaultParameters
                mockWorkspaceUrl      = $mockWorkspaceUrl
            } -ScriptBlock {
                Remove-DatabricksSecretScope @mockDefaultParameters

                Should -Invoke -CommandName Invoke-RestMethod -ParameterFilter {
                    $Uri -eq "$mockWorkspaceUrl/api/2.0/secrets/scopes/delete" -and
                    $Method -eq 'POST' -and
                    $Headers['Authorization'] -eq 'Bearer dapi1234567890abcdef' -and
                    $Headers['Content-Type'] -eq 'application/json'
                } -Exactly -Times 1 -Scope It
            }
        }

        It 'Should send correct body with scope name' {
            InModuleScope -Parameters @{
                mockDefaultParameters = $mockDefaultParameters
            } -ScriptBlock {
                Remove-DatabricksSecretScope @mockDefaultParameters

                Should -Invoke -CommandName Invoke-RestMethod -ParameterFilter {
                    $bodyObject = $Body | ConvertFrom-Json
                    $bodyObject.scope -eq 'test-scope'
                } -Exactly -Times 1 -Scope It
            }
        }
    }

    Context 'When API call fails' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod -MockWith {
                throw 'API Error: Scope not found'
            }

            Mock -CommandName ConvertTo-DatabricksAuthHeader -MockWith {
                return 'Bearer dapi1234567890abcdef'
            }
        }

        It 'Should throw an error' {
            InModuleScope -Parameters @{
                mockDefaultParameters = $mockDefaultParameters
            } -ScriptBlock {
                { Remove-DatabricksSecretScope @mockDefaultParameters } | Should -Throw
            }

            Should -Invoke -CommandName Invoke-RestMethod -Exactly -Times 1 -Scope It
        }
    }

    Context 'When WorkspaceUrl has trailing slash' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod -MockWith {
                return @{}
            }

            Mock -CommandName ConvertTo-DatabricksAuthHeader -MockWith {
                return 'Bearer dapi1234567890abcdef'
            }
        }

        It 'Should trim trailing slash from WorkspaceUrl' {
            InModuleScope -Parameters @{
                mockAccessToken = $mockAccessToken
            } -ScriptBlock {
                $params = @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net/'
                    AccessToken  = $mockAccessToken
                    ScopeName    = 'test-scope'
                }

                Remove-DatabricksSecretScope @params

                Should -Invoke -CommandName Invoke-RestMethod -ParameterFilter {
                    $Uri -eq 'https://adb-1234567890123456.12.azuredatabricks.net/api/2.0/secrets/scopes/delete'
                } -Exactly -Times 1 -Scope It
            }
        }
    }

    Context 'When removing different scope names' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod -MockWith {
                return @{}
            }

            Mock -CommandName ConvertTo-DatabricksAuthHeader -MockWith {
                return 'Bearer dapi1234567890abcdef'
            }
        }

        It 'Should handle scope name: <ScopeName>' -ForEach @(
            @{ ScopeName = 'simple-scope' }
            @{ ScopeName = 'scope_with_underscores' }
            @{ ScopeName = 'scope.with.dots' }
            @{ ScopeName = 'scope-123' }
        ) {
            InModuleScope -Parameters @{
                mockWorkspaceUrl = $mockWorkspaceUrl
                mockAccessToken  = $mockAccessToken
                scopeName        = $ScopeName
            } -ScriptBlock {
                $params = @{
                    WorkspaceUrl = $mockWorkspaceUrl
                    AccessToken  = $mockAccessToken
                    ScopeName    = $scopeName
                }

                { Remove-DatabricksSecretScope @params } | Should -Not -Throw

                Should -Invoke -CommandName Invoke-RestMethod -ParameterFilter {
                    $bodyObject = $Body | ConvertFrom-Json
                    $bodyObject.scope -eq $scopeName
                } -Exactly -Times 1 -Scope It
            }
        }
    }
}
