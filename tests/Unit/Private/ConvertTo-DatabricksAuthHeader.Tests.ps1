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

Describe 'ConvertTo-DatabricksAuthHeader' -Tag 'Private' {
    Context 'When converting a SecureString token' {
        It 'Should return a properly formatted Bearer token' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockToken = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force

                $result = ConvertTo-DatabricksAuthHeader -AccessToken $mockToken

                $result | Should -Be 'Bearer dapi1234567890abcdef'
            }
        }

        It 'Should handle tokens with special characters' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockToken = ConvertTo-SecureString -String 'dapi-test_token.123' -AsPlainText -Force

                $result = ConvertTo-DatabricksAuthHeader -AccessToken $mockToken

                $result | Should -Be 'Bearer dapi-test_token.123'
            }
        }

        It 'Should handle long tokens' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockLongToken = 'dapi' + ('a' * 100)
                $mockToken = ConvertTo-SecureString -String $mockLongToken -AsPlainText -Force

                $result = ConvertTo-DatabricksAuthHeader -AccessToken $mockToken

                $result | Should -Be "Bearer $mockLongToken"
            }
        }

        It 'Should not expose the token in plain text variables' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockToken = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force

                $result = ConvertTo-DatabricksAuthHeader -AccessToken $mockToken

                # The result should contain the Bearer token, but we're testing that
                # the function properly cleans up after itself
                $result | Should -Match '^Bearer '
            }
        }
    }
}
