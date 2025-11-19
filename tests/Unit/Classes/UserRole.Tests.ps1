<#
    .SYNOPSIS
        Unit test for UserRole class.
#>

[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
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

Describe 'UserRole' -Tag 'UserRole' {
    Context 'When instantiating the class' {
        It 'Should not throw an error' {
            $script:mockUserRoleInstance = InModuleScope -ScriptBlock {
                [UserRole] @{
                    Value = 'account_admin'
                }
            }
        }

        It 'Should be of the correct type' {
            $mockUserRoleInstance | Should -Not -BeNullOrEmpty
            $mockUserRoleInstance.GetType().Name | Should -Be 'UserRole'
        }
    }

    Context 'When setting and reading values' {
        It 'Should be able to set value in instance' {
            $script:mockUserRoleInstance = InModuleScope -ScriptBlock {
                $userRoleInstance = [UserRole]::new()
                $userRoleInstance.Value = 'account_admin'

                return $userRoleInstance
            }
        }

        It 'Should be able to read the values from instance' {
            $mockUserRoleInstance.Value | Should -Be 'account_admin'
        }
    }

    Context 'When comparing two objects using method Equals()' {
        Context 'When both objects are equal' {
            It 'Should return $true' {
                InModuleScope -ScriptBlock {
                    $userRoleInstance1 = [UserRole]::new()
                    $userRoleInstance1.Value = 'account_admin'

                    $userRoleInstance2 = [UserRole]::new()
                    $userRoleInstance2.Value = 'account_admin'

                    $userRoleInstance1 -eq $userRoleInstance2 | Should -BeTrue
                }
            }
        }

        Context 'When objects have different values' {
            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    $userRoleInstance1 = [UserRole]::new()
                    $userRoleInstance1.Value = 'account_admin'

                    $userRoleInstance2 = [UserRole]::new()
                    $userRoleInstance2.Value = 'workspace_admin'

                    $userRoleInstance1 -eq $userRoleInstance2 | Should -BeFalse
                }
            }
        }
    }

    Context 'When comparing two objects using method CompareTo()' {
        Context 'When the instance is compared against an invalid object' {
            It 'Should throw the correct error' {
                $mockUserRoleInstance1 = InModuleScope -ScriptBlock {
                    [UserRole] @{
                        Value = 'account_admin'
                    }
                }

                $mockErrorMessage = InModuleScope -ScriptBlock {
                    $script:localizedData.InvalidTypeForCompare
                }

                $mockErrorMessage = $mockErrorMessage -f @(
                    $mockUserRoleInstance1.GetType().FullName
                    'System.String'
                )

                # Escape the brackets so Pester can evaluate the string correctly.
                $mockErrorMessage = $mockErrorMessage -replace '\[', '`['
                $mockErrorMessage = $mockErrorMessage -replace '\]', '`]'

                # The expected message should match the localized error message and contain 'Object'
                { $mockUserRoleInstance1.CompareTo('AnyValue') } | Should -Throw -ExpectedMessage "*$mockErrorMessage*Object*"
            }
        }

        Context 'When the instance precedes the object being compared' {
            It 'Should return a value less than zero' {
                $mockUserRoleInstance1 = InModuleScope -ScriptBlock {
                    [UserRole] @{
                        Value = 'account_admin'
                    }
                }

                $mockUserRoleInstance2 = InModuleScope -ScriptBlock {
                    [UserRole] @{
                        Value = 'workspace_admin'
                    }
                }

                $mockUserRoleInstance1.CompareTo($mockUserRoleInstance2) | Should -BeLessThan 0
            }
        }

        Context 'When the instance follows the object being compared' {
            It 'Should return a value greater than zero' {
                $mockUserRoleInstance1 = InModuleScope -ScriptBlock {
                    [UserRole] @{
                        Value = 'workspace_admin'
                    }
                }

                $mockUserRoleInstance2 = InModuleScope -ScriptBlock {
                    [UserRole] @{
                        Value = 'account_admin'
                    }
                }

                $mockUserRoleInstance1.CompareTo($mockUserRoleInstance2) | Should -BeGreaterThan 0
            }

            Context 'When the instance is compared against an object that is $null' {
                It 'Should return a value greater than zero' {
                    $mockUserRoleInstance1 = InModuleScope -ScriptBlock {
                        [UserRole] @{
                            Value = 'account_admin'
                        }
                    }

                    $mockUserRoleInstance1.CompareTo($null) | Should -BeGreaterThan 0
                }
            }
        }

        Context 'When the instance is in the same position as the object being compared' {
            It 'Should return zero' {
                $mockUserRoleInstance1 = InModuleScope -ScriptBlock {
                    [UserRole] @{
                        Value = 'account_admin'
                    }
                }

                $mockUserRoleInstance2 = InModuleScope -ScriptBlock {
                    [UserRole] @{
                        Value = 'account_admin'
                    }
                }

                $mockUserRoleInstance1.CompareTo($mockUserRoleInstance2) | Should -Be 0
            }
        }

        Context 'When sorting the instances' {
            It 'Should always sort alphabetically' {
                $mockUserRoleArray = @(
                    InModuleScope -ScriptBlock {
                        [UserRole] @{ Value = 'workspace_admin' }
                        [UserRole] @{ Value = 'account_admin' }
                        [UserRole] @{ Value = 'user' }
                    }
                )

                $mockSortedArray = $mockUserRoleArray | Sort-Object

                $mockSortedArray[0].Value | Should -Be 'account_admin'
                $mockSortedArray[1].Value | Should -Be 'user'
                $mockSortedArray[2].Value | Should -Be 'workspace_admin'
            }
        }
    }

    Context 'When calling method ToString()' {
        It 'Should return the correct string representation' {
            $mockUserRoleInstance = InModuleScope -ScriptBlock {
                [UserRole] @{
                    Value = 'account_admin'
                }
            }

            $mockUserRoleInstance.ToString() | Should -Be 'account_admin'
        }
    }
}
