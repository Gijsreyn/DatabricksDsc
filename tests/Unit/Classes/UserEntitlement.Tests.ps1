<#
    .SYNOPSIS
        Unit test for UserEntitlement class.
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

Describe 'UserEntitlement' -Tag 'UserEntitlement' {
    Context 'When instantiating the class' {
        It 'Should not throw an error' {
            $script:mockUserEntitlementInstance = InModuleScope -ScriptBlock {
                [UserEntitlement] @{
                    Value = 'workspace-access'
                }
            }
        }

        It 'Should be of the correct type' {
            $mockUserEntitlementInstance | Should -Not -BeNullOrEmpty
            $mockUserEntitlementInstance.GetType().Name | Should -Be 'UserEntitlement'
        }
    }

    Context 'When setting and reading values' {
        It 'Should be able to set value in instance' {
            $script:mockUserEntitlementInstance = InModuleScope -ScriptBlock {
                $userEntitlementInstance = [UserEntitlement]::new()
                $userEntitlementInstance.Value = 'allow-cluster-create'

                return $userEntitlementInstance
            }
        }

        It 'Should be able to read the values from instance' {
            $mockUserEntitlementInstance.Value | Should -Be 'allow-cluster-create'
        }

        It 'Should validate against the ValidateSet' {
            InModuleScope -ScriptBlock {
                $userEntitlementInstance = [UserEntitlement]::new()

                { $userEntitlementInstance.Value = 'invalid-entitlement' } | Should -Throw
            }
        }
    }

    Context 'When comparing two objects using method Equals()' {
        Context 'When both objects are equal' {
            It 'Should return $true' {
                InModuleScope -ScriptBlock {
                    $userEntitlementInstance1 = [UserEntitlement]::new()
                    $userEntitlementInstance1.Value = 'workspace-access'

                    $userEntitlementInstance2 = [UserEntitlement]::new()
                    $userEntitlementInstance2.Value = 'workspace-access'

                    $userEntitlementInstance1 -eq $userEntitlementInstance2 | Should -BeTrue
                }
            }
        }

        Context 'When objects have different values' {
            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    $userEntitlementInstance1 = [UserEntitlement]::new()
                    $userEntitlementInstance1.Value = 'allow-cluster-create'

                    $userEntitlementInstance2 = [UserEntitlement]::new()
                    $userEntitlementInstance2.Value = 'workspace-access'

                    $userEntitlementInstance1 -eq $userEntitlementInstance2 | Should -BeFalse
                }
            }
        }
    }

    Context 'When comparing two objects using method CompareTo()' {
        Context 'When the instance is compared against an invalid object' {
            It 'Should throw the correct error' {
                $mockUserEntitlementInstance1 = InModuleScope -ScriptBlock {
                    [UserEntitlement] @{
                        Value = 'workspace-access'
                    }
                }

                $mockErrorMessage = InModuleScope -ScriptBlock {
                    $script:localizedData.InvalidTypeForCompare
                }

                $mockErrorMessage = $mockErrorMessage -f @(
                    $mockUserEntitlementInstance1.GetType().FullName
                    'System.String'
                )

                # Escape the brackets so Pester can evaluate the string correctly.
                $mockErrorMessage = $mockErrorMessage -replace '\[', '`['
                $mockErrorMessage = $mockErrorMessage -replace '\]', '`]'

                # The expected message should match the localized error message and contain 'Object'
                { $mockUserEntitlementInstance1.CompareTo('AnyValue') } | Should -Throw -ExpectedMessage "*$mockErrorMessage*Object*"
            }
        }

        Context 'When the instance precedes the object being compared' {
            It 'Should return a value less than zero' {
                $mockUserEntitlementInstance1 = InModuleScope -ScriptBlock {
                    [UserEntitlement] @{
                        Value = 'allow-cluster-create'
                    }
                }

                $mockUserEntitlementInstance2 = InModuleScope -ScriptBlock {
                    [UserEntitlement] @{
                        Value = 'workspace-access'
                    }
                }

                $mockUserEntitlementInstance1.CompareTo($mockUserEntitlementInstance2) | Should -BeLessThan 0
            }
        }

        Context 'When the instance follows the object being compared' {
            It 'Should return a value greater than zero' {
                $mockUserEntitlementInstance1 = InModuleScope -ScriptBlock {
                    [UserEntitlement] @{
                        Value = 'workspace-access'
                    }
                }

                $mockUserEntitlementInstance2 = InModuleScope -ScriptBlock {
                    [UserEntitlement] @{
                        Value = 'allow-cluster-create'
                    }
                }

                $mockUserEntitlementInstance1.CompareTo($mockUserEntitlementInstance2) | Should -BeGreaterThan 0
            }

            Context 'When the instance is compared against an object that is $null' {
                It 'Should return a value greater than zero' {
                    $mockUserEntitlementInstance1 = InModuleScope -ScriptBlock {
                        [UserEntitlement] @{
                            Value = 'workspace-access'
                        }
                    }

                    $mockUserEntitlementInstance1.CompareTo($null) | Should -BeGreaterThan 0
                }
            }
        }

        Context 'When the instance is in the same position as the object being compared' {
            It 'Should return zero' {
                $mockUserEntitlementInstance1 = InModuleScope -ScriptBlock {
                    [UserEntitlement] @{
                        Value = 'workspace-access'
                    }
                }

                $mockUserEntitlementInstance2 = InModuleScope -ScriptBlock {
                    [UserEntitlement] @{
                        Value = 'workspace-access'
                    }
                }

                $mockUserEntitlementInstance1.CompareTo($mockUserEntitlementInstance2) | Should -Be 0
            }
        }

        Context 'When sorting the instances' {
            It 'Should always sort alphabetically' {
                $mockUserEntitlementArray = @(
                    InModuleScope -ScriptBlock {
                        [UserEntitlement] @{ Value = 'workspace-access' }
                        [UserEntitlement] @{ Value = 'allow-cluster-create' }
                        [UserEntitlement] @{ Value = 'databricks-sql-access' }
                    }
                )

                $mockSortedArray = $mockUserEntitlementArray | Sort-Object

                $mockSortedArray[0].Value | Should -Be 'allow-cluster-create'
                $mockSortedArray[1].Value | Should -Be 'databricks-sql-access'
                $mockSortedArray[2].Value | Should -Be 'workspace-access'
            }
        }
    }

    Context 'When calling method ToString()' {
        It 'Should return the correct string representation' {
            $mockUserEntitlementInstance = InModuleScope -ScriptBlock {
                [UserEntitlement] @{
                    Value = 'workspace-access'
                }
            }

            $mockUserEntitlementInstance.ToString() | Should -Be 'workspace-access'
        }
    }
}
