<#
    .SYNOPSIS
        Unit test for UserName class.
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

Describe 'UserName' -Tag 'UserName' {
    Context 'When instantiating the class' {
        It 'Should not throw an error' {
            $script:mockUserNameInstance = InModuleScope -ScriptBlock {
                [UserName]::new()
            }
        }

        It 'Should be of the correct type' {
            $mockUserNameInstance | Should -Not -BeNullOrEmpty
            $mockUserNameInstance.GetType().Name | Should -Be 'UserName'
        }
    }

    Context 'When setting and reading values' {
        It 'Should be able to set value in instance' {
            $script:mockUserNameInstance = InModuleScope -ScriptBlock {
                $userNameInstance = [UserName]::new()

                $userNameInstance.GivenName = 'John'
                $userNameInstance.FamilyName = 'Doe'

                return $userNameInstance
            }
        }

        It 'Should be able to read the values from instance' {
            $mockUserNameInstance.GivenName | Should -Be 'John'
            $mockUserNameInstance.FamilyName | Should -Be 'Doe'
        }
    }

    Context 'When comparing two objects using method Equals()' {
        Context 'When both objects are equal' {
            It 'Should return $true' {
                InModuleScope -ScriptBlock {
                    $userNameInstance1 = [UserName]::new()
                    $userNameInstance1.GivenName = 'John'
                    $userNameInstance1.FamilyName = 'Doe'

                    $userNameInstance2 = [UserName]::new()
                    $userNameInstance2.GivenName = 'John'
                    $userNameInstance2.FamilyName = 'Doe'

                    $userNameInstance1 -eq $userNameInstance2 | Should -BeTrue
                }
            }
        }

        Context 'When object has different value for property GivenName' {
            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    $userNameInstance1 = [UserName]::new()
                    $userNameInstance1.GivenName = 'John'
                    $userNameInstance1.FamilyName = 'Doe'

                    $userNameInstance2 = [UserName]::new()
                    $userNameInstance2.GivenName = 'Jane'
                    $userNameInstance2.FamilyName = 'Doe'

                    $userNameInstance1 -eq $userNameInstance2 | Should -BeFalse
                }
            }
        }

        Context 'When object has different value for property FamilyName' {
            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    $userNameInstance1 = [UserName]::new()
                    $userNameInstance1.GivenName = 'John'
                    $userNameInstance1.FamilyName = 'Doe'

                    $userNameInstance2 = [UserName]::new()
                    $userNameInstance2.GivenName = 'John'
                    $userNameInstance2.FamilyName = 'Smith'

                    $userNameInstance1 -eq $userNameInstance2 | Should -BeFalse
                }
            }
        }
    }

    Context 'When comparing two objects using method CompareTo()' {
        Context 'When the instance is compared against an invalid object' {
            It 'Should throw the correct error' {
                $mockUserNameInstance1 = InModuleScope -ScriptBlock {
                    [UserName] @{
                        GivenName  = 'John'
                        FamilyName = 'Doe'
                    }
                }

                $mockErrorMessage = InModuleScope -ScriptBlock {
                    $script:localizedData.InvalidTypeForCompare
                }

                $mockErrorMessage = $mockErrorMessage -f @(
                    $mockUserNameInstance1.GetType().FullName
                    'System.String'
                )

                # Escape the brackets so Pester can evaluate the string correctly.
                $mockErrorMessage = $mockErrorMessage -replace '\[', '`['
                $mockErrorMessage = $mockErrorMessage -replace '\]', '`]'

                # The expected message should match the localized error message and contain 'Object'
                { $mockUserNameInstance1.CompareTo('AnyValue') } | Should -Throw -ExpectedMessage "*$mockErrorMessage*Object*"
            }
        }

        Context 'When the instance precedes the object being compared' {
            Context 'When FamilyName is alphabetically first' {
                It 'Should return a value less than zero' {
                    $mockUserNameInstance1 = InModuleScope -ScriptBlock {
                        [UserName] @{
                            GivenName  = 'John'
                            FamilyName = 'Anderson'
                        }
                    }

                    $mockUserNameInstance2 = InModuleScope -ScriptBlock {
                        [UserName] @{
                            GivenName  = 'John'
                            FamilyName = 'Zimmerman'
                        }
                    }

                    $mockUserNameInstance1.CompareTo($mockUserNameInstance2) | Should -BeLessThan 0
                }
            }

            Context 'When FamilyName is same and GivenName is alphabetically first' {
                It 'Should return a value less than zero' {
                    $mockUserNameInstance1 = InModuleScope -ScriptBlock {
                        [UserName] @{
                            GivenName  = 'Alice'
                            FamilyName = 'Smith'
                        }
                    }

                    $mockUserNameInstance2 = InModuleScope -ScriptBlock {
                        [UserName] @{
                            GivenName  = 'Zoe'
                            FamilyName = 'Smith'
                        }
                    }

                    $mockUserNameInstance1.CompareTo($mockUserNameInstance2) | Should -BeLessThan 0
                }
            }
        }

        Context 'When the instance follows the object being compared' {
            Context 'When FamilyName is alphabetically last' {
                It 'Should return a value greater than zero' {
                    $mockUserNameInstance1 = InModuleScope -ScriptBlock {
                        [UserName] @{
                            GivenName  = 'John'
                            FamilyName = 'Zimmerman'
                        }
                    }

                    $mockUserNameInstance2 = InModuleScope -ScriptBlock {
                        [UserName] @{
                            GivenName  = 'John'
                            FamilyName = 'Anderson'
                        }
                    }

                    $mockUserNameInstance1.CompareTo($mockUserNameInstance2) | Should -BeGreaterThan 0
                }
            }

            Context 'When the instance is compared against an object that is $null' {
                It 'Should return a value greater than zero' {
                    $mockUserNameInstance1 = InModuleScope -ScriptBlock {
                        [UserName] @{
                            GivenName  = 'John'
                            FamilyName = 'Doe'
                        }
                    }

                    $mockUserNameInstance1.CompareTo($null) | Should -BeGreaterThan 0
                }
            }
        }

        Context 'When the instance is in the same position as the object being compared' {
            It 'Should return zero' {
                $mockUserNameInstance1 = InModuleScope -ScriptBlock {
                    [UserName] @{
                        GivenName  = 'John'
                        FamilyName = 'Doe'
                    }
                }

                $mockUserNameInstance2 = InModuleScope -ScriptBlock {
                    [UserName] @{
                        GivenName  = 'John'
                        FamilyName = 'Doe'
                    }
                }

                $mockUserNameInstance1.CompareTo($mockUserNameInstance2) | Should -Be 0
            }
        }

        Context 'When sorting the instances' {
            It 'Should always sort by FamilyName first, then GivenName' {
                $mockUserNameArray = @(
                    InModuleScope -ScriptBlock {
                        [UserName] @{
                            GivenName  = 'Zoe'
                            FamilyName = 'Smith'
                        }
                        [UserName] @{
                            GivenName  = 'Alice'
                            FamilyName = 'Smith'
                        }
                        [UserName] @{
                            GivenName  = 'John'
                            FamilyName = 'Anderson'
                        }
                    }
                )

                $mockSortedArray = $mockUserNameArray | Sort-Object

                $mockSortedArray[0].FamilyName | Should -Be 'Anderson'
                $mockSortedArray[0].GivenName | Should -Be 'John'
                $mockSortedArray[1].FamilyName | Should -Be 'Smith'
                $mockSortedArray[1].GivenName | Should -Be 'Alice'
                $mockSortedArray[2].FamilyName | Should -Be 'Smith'
                $mockSortedArray[2].GivenName | Should -Be 'Zoe'
            }
        }
    }

    Context 'When calling method ToString()' {
        It 'Should return the correct string representation' {
            $mockUserNameInstance = InModuleScope -ScriptBlock {
                [UserName] @{
                    GivenName  = 'John'
                    FamilyName = 'Doe'
                }
            }

            $mockUserNameInstance.ToString() | Should -Be 'Doe, John'
        }
    }
}
