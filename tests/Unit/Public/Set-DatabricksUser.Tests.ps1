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

Describe 'Set-DatabricksUser' -Tag 'Public' {
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
            MockExpectedParameters = '[-WorkspaceUrl] <string> [-AccessToken] <securestring> [-Id] <string> [[-DisplayName] <string>] [[-Active] <bool>] [[-GivenName] <string>] [[-FamilyName] <string>] [[-Entitlements] <string[]>] [-WhatIf] [-Confirm] [<CommonParameters>]'
        }
    ) {
        $result = (Get-Command -Name 'Set-DatabricksUser').ParameterSets |
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

    Context 'When updating a user display name' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod -MockWith {
                return @{
                    id          = '1234567890'
                    displayName = 'Jane Doe'
                }
            }
        }

        It 'Should update the user' {
            $result = Set-DatabricksUser @mockDefaultParameters -DisplayName 'Jane Doe'

            $result.displayName | Should -Be 'Jane Doe'
        }

        It 'Should call Invoke-RestMethod with the correct parameters' {
            Set-DatabricksUser @mockDefaultParameters -DisplayName 'Jane Doe'

            Should -Invoke -CommandName Invoke-RestMethod -Exactly -Times 1 -Scope It -ParameterFilter {
                $Uri -eq "$mockWorkspaceUrl/api/2.0/preview/scim/v2/Users/1234567890" -and
                $Method -eq 'Patch' -and
                $Headers.Authorization -match '^Bearer ' -and
                $Body -match '"displayName"' -and
                $Body -match 'Jane Doe'
            }
        }
    }

    Context 'When updating user active status' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod -MockWith {
                return @{
                    id     = '1234567890'
                    active = $false
                }
            }
        }

        It 'Should update the active status' {
            $result = Set-DatabricksUser @mockDefaultParameters -Active $false

            $result.active | Should -Be $false
        }

        It 'Should call Invoke-RestMethod with active in the body' {
            Set-DatabricksUser @mockDefaultParameters -Active $false

            Should -Invoke -CommandName Invoke-RestMethod -Exactly -Times 1 -Scope It -ParameterFilter {
                $Body -match '"active"' -and
                $Body -match 'false'
            }
        }
    }

    Context 'When updating user name' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod -MockWith {
                return @{
                    id   = '1234567890'
                    name = @{
                        givenName  = 'Jane'
                        familyName = 'Smith'
                    }
                }
            }
        }

        It 'Should update both given and family name' {
            $result = Set-DatabricksUser @mockDefaultParameters -GivenName 'Jane' -FamilyName 'Smith'

            $result.name.givenName | Should -Be 'Jane'
            $result.name.familyName | Should -Be 'Smith'
        }

        It 'Should call Invoke-RestMethod with name in the body' {
            Set-DatabricksUser @mockDefaultParameters -GivenName 'Jane' -FamilyName 'Smith'

            Should -Invoke -CommandName Invoke-RestMethod -Exactly -Times 1 -Scope It -ParameterFilter {
                $Body -match '"givenName"' -and
                $Body -match 'Jane' -and
                $Body -match '"familyName"' -and
                $Body -match 'Smith'
            }
        }
    }

    Context 'When updating user entitlements' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod -MockWith {
                return @{
                    id           = '1234567890'
                    entitlements = @(
                        @{ value = 'workspace-access' }
                        @{ value = 'allow-cluster-create' }
                    )
                }
            }
        }

        It 'Should update the entitlements' {
            $result = Set-DatabricksUser @mockDefaultParameters -Entitlements @('workspace-access', 'allow-cluster-create')

            $result.entitlements | Should -HaveCount 2
        }

        It 'Should call Invoke-RestMethod with entitlements in the body' {
            Set-DatabricksUser @mockDefaultParameters -Entitlements @('workspace-access', 'allow-cluster-create')

            Should -Invoke -CommandName Invoke-RestMethod -Exactly -Times 1 -Scope It -ParameterFilter {
                $Body -match '"entitlements"' -and
                $Body -match 'workspace-access' -and
                $Body -match 'allow-cluster-create'
            }
        }
    }

    Context 'When updating multiple properties' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod -MockWith {
                return @{
                    id          = '1234567890'
                    displayName = 'Jane Smith'
                    active      = $false
                }
            }
        }

        It 'Should update all specified properties' {
            $result = Set-DatabricksUser @mockDefaultParameters -DisplayName 'Jane Smith' -Active $false

            $result.displayName | Should -Be 'Jane Smith'
            $result.active | Should -Be $false
        }
    }

    Context 'When using WhatIf' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod
        }

        It 'Should not call Invoke-RestMethod' {
            Set-DatabricksUser @mockDefaultParameters -DisplayName 'Jane Doe' -WhatIf

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
            Set-DatabricksUser @mockDefaultParameters -DisplayName 'Jane Doe' -ErrorAction SilentlyContinue

            Should -Invoke -CommandName Write-Error -Exactly -Times 1 -Scope It
        }
    }

    Context 'When WorkspaceUrl has trailing slash' {
        BeforeAll {
            Mock -CommandName Invoke-RestMethod -MockWith {
                return @{
                    id = '1234567890'
                }
            }

            $mockParametersWithTrailingSlash = @{
                WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net/'
                AccessToken  = $mockAccessToken
                Id           = '1234567890'
            }
        }

        It 'Should trim the trailing slash from WorkspaceUrl' {
            Set-DatabricksUser @mockParametersWithTrailingSlash -DisplayName 'Test'

            Should -Invoke -CommandName Invoke-RestMethod -Exactly -Times 1 -Scope It -ParameterFilter {
                $Uri -eq "$mockWorkspaceUrl/api/2.0/preview/scim/v2/Users/1234567890"
            }
        }
    }
}
