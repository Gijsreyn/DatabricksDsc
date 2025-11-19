<#
    .SYNOPSIS
        Unit test for UserEmail class.
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

Describe 'UserEmail' -Tag 'UserEmail' {
    Context 'When instantiating the class' {
        It 'Should not throw an error' {
            $script:mockUserEmailInstance = InModuleScope -ScriptBlock {
                [UserEmail]::new()
            }
        }

        It 'Should be of the correct type' {
            $mockUserEmailInstance | Should -Not -BeNullOrEmpty
            $mockUserEmailInstance.GetType().Name | Should -Be 'UserEmail'
        }
    }

    Context 'When setting and reading values' {
        It 'Should be able to set value in instance' {
            $script:mockUserEmailInstance = InModuleScope -ScriptBlock {
                $userEmailInstance = [UserEmail]::new()

                $userEmailInstance.Value = 'user@example.com'
                $userEmailInstance.Type = 'work'
                $userEmailInstance.Primary = $true

                return $userEmailInstance
            }
        }

        It 'Should be able to read the values from instance' {
            $mockUserEmailInstance.Value | Should -Be 'user@example.com'
            $mockUserEmailInstance.Type | Should -Be 'work'
            $mockUserEmailInstance.Primary | Should -BeTrue
        }
    }

    Context 'When comparing two objects using method Equals()' {
        Context 'When both objects are equal' {
            It 'Should return $true' {
                InModuleScope -ScriptBlock {
                    $userEmailInstance1 = [UserEmail]::new()
                    $userEmailInstance1.Value = 'user@example.com'
                    $userEmailInstance1.Type = 'work'
                    $userEmailInstance1.Primary = $true

                    $userEmailInstance2 = [UserEmail]::new()
                    $userEmailInstance2.Value = 'user@example.com'
                    $userEmailInstance2.Type = 'work'
                    $userEmailInstance2.Primary = $true

                    $userEmailInstance1 -eq $userEmailInstance2 | Should -BeTrue
                }
            }
        }

        Context 'When object has different value for property Value' {
            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    $userEmailInstance1 = [UserEmail]::new()
                    $userEmailInstance1.Value = 'user1@example.com'
                    $userEmailInstance1.Type = 'work'
                    $userEmailInstance1.Primary = $true

                    $userEmailInstance2 = [UserEmail]::new()
                    $userEmailInstance2.Value = 'user2@example.com'
                    $userEmailInstance2.Type = 'work'
                    $userEmailInstance2.Primary = $true

                    $userEmailInstance1 -eq $userEmailInstance2 | Should -BeFalse
                }
            }
        }

        Context 'When object has different value for property Type' {
            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    $userEmailInstance1 = [UserEmail]::new()
                    $userEmailInstance1.Value = 'user@example.com'
                    $userEmailInstance1.Type = 'work'
                    $userEmailInstance1.Primary = $true

                    $userEmailInstance2 = [UserEmail]::new()
                    $userEmailInstance2.Value = 'user@example.com'
                    $userEmailInstance2.Type = 'home'
                    $userEmailInstance2.Primary = $true

                    $userEmailInstance1 -eq $userEmailInstance2 | Should -BeFalse
                }
            }
        }

        Context 'When object has different value for property Primary' {
            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    $userEmailInstance1 = [UserEmail]::new()
                    $userEmailInstance1.Value = 'user@example.com'
                    $userEmailInstance1.Type = 'work'
                    $userEmailInstance1.Primary = $true

                    $userEmailInstance2 = [UserEmail]::new()
                    $userEmailInstance2.Value = 'user@example.com'
                    $userEmailInstance2.Type = 'work'
                    $userEmailInstance2.Primary = $false

                    $userEmailInstance1 -eq $userEmailInstance2 | Should -BeFalse
                }
            }
        }
    }

    Context 'When comparing two objects using method CompareTo()' {
        Context 'When the instance is compared against an invalid object' {
            It 'Should throw the correct error' {
                $mockUserEmailInstance1 = InModuleScope -ScriptBlock {
                    [UserEmail] @{
                        Value   = 'user@example.com'
                        Type    = 'work'
                        Primary = $true
                    }
                }

                $mockErrorMessage = InModuleScope -ScriptBlock {
                    $script:localizedData.InvalidTypeForCompare
                }

                $mockErrorMessage = $mockErrorMessage -f @(
                    $mockUserEmailInstance1.GetType().FullName
                    'System.String'
                )

                # Escape the brackets so Pester can evaluate the string correctly.
                $mockErrorMessage = $mockErrorMessage -replace '\[', '`['
                $mockErrorMessage = $mockErrorMessage -replace '\]', '`]'

                # The expected message should match the localized error message and contain 'Object'
                { $mockUserEmailInstance1.CompareTo('AnyValue') } | Should -Throw -ExpectedMessage "*$mockErrorMessage*Object*"
            }
        }

        Context 'When the instance precedes the object being compared' {
            Context 'When the instance is primary and object is not primary' {
                It 'Should return a value less than zero' {
                    $mockUserEmailInstance1 = InModuleScope -ScriptBlock {
                        [UserEmail] @{
                            Value   = 'user@example.com'
                            Type    = 'work'
                            Primary = $true
                        }
                    }

                    $mockUserEmailInstance2 = InModuleScope -ScriptBlock {
                        [UserEmail] @{
                            Value   = 'user@example.com'
                            Type    = 'work'
                            Primary = $false
                        }
                    }

                    $mockUserEmailInstance1.CompareTo($mockUserEmailInstance2) | Should -BeLessThan 0
                }
            }

            Context 'When both have same Primary value and instance Value is alphabetically first' {
                It 'Should return a value less than zero' {
                    $mockUserEmailInstance1 = InModuleScope -ScriptBlock {
                        [UserEmail] @{
                            Value   = 'a@example.com'
                            Type    = 'work'
                            Primary = $true
                        }
                    }

                    $mockUserEmailInstance2 = InModuleScope -ScriptBlock {
                        [UserEmail] @{
                            Value   = 'z@example.com'
                            Type    = 'work'
                            Primary = $true
                        }
                    }

                    $mockUserEmailInstance1.CompareTo($mockUserEmailInstance2) | Should -BeLessThan 0
                }
            }
        }

        Context 'When the instance follows the object being compared' {
            Context 'When the instance is not primary and object is primary' {
                It 'Should return a value greater than zero' {
                    $mockUserEmailInstance1 = InModuleScope -ScriptBlock {
                        [UserEmail] @{
                            Value   = 'user@example.com'
                            Type    = 'work'
                            Primary = $false
                        }
                    }

                    $mockUserEmailInstance2 = InModuleScope -ScriptBlock {
                        [UserEmail] @{
                            Value   = 'user@example.com'
                            Type    = 'work'
                            Primary = $true
                        }
                    }

                    $mockUserEmailInstance1.CompareTo($mockUserEmailInstance2) | Should -BeGreaterThan 0
                }
            }

            Context 'When the instance is compared against an object that is $null' {
                It 'Should return a value greater than zero' {
                    $mockUserEmailInstance1 = InModuleScope -ScriptBlock {
                        [UserEmail] @{
                            Value   = 'user@example.com'
                            Type    = 'work'
                            Primary = $true
                        }
                    }

                    $mockUserEmailInstance1.CompareTo($null) | Should -BeGreaterThan 0
                }
            }
        }

        Context 'When the instance is in the same position as the object being compared' {
            It 'Should return zero' {
                $mockUserEmailInstance1 = InModuleScope -ScriptBlock {
                    [UserEmail] @{
                        Value   = 'user@example.com'
                        Type    = 'work'
                        Primary = $true
                    }
                }

                $mockUserEmailInstance2 = InModuleScope -ScriptBlock {
                    [UserEmail] @{
                        Value   = 'user@example.com'
                        Type    = 'work'
                        Primary = $true
                    }
                }

                $mockUserEmailInstance1.CompareTo($mockUserEmailInstance2) | Should -Be 0
            }
        }

        Context 'When sorting the instances' {
            It 'Should always sort primary emails first, then by value' {
                $mockUserEmailArray = @(
                    InModuleScope -ScriptBlock {
                        [UserEmail] @{
                            Value   = 'z@example.com'
                            Type    = 'work'
                            Primary = $false
                        }
                        [UserEmail] @{
                            Value   = 'a@example.com'
                            Type    = 'work'
                            Primary = $true
                        }
                        [UserEmail] @{
                            Value   = 'm@example.com'
                            Type    = 'work'
                            Primary = $false
                        }
                    }
                )

                $mockSortedArray = $mockUserEmailArray | Sort-Object

                $mockSortedArray[0].Value | Should -Be 'a@example.com'
                $mockSortedArray[0].Primary | Should -BeTrue
                $mockSortedArray[1].Value | Should -Be 'm@example.com'
                $mockSortedArray[2].Value | Should -Be 'z@example.com'
            }
        }
    }

    Context 'When calling method ToString()' {
        It 'Should return the correct string representation for primary email' {
            $mockUserEmailInstance = InModuleScope -ScriptBlock {
                [UserEmail] @{
                    Value   = 'user@example.com'
                    Type    = 'work'
                    Primary = $true
                }
            }

            $mockUserEmailInstance.ToString() | Should -Be 'user@example.com (work, Primary)'
        }

        It 'Should return the correct string representation for non-primary email' {
            $mockUserEmailInstance = InModuleScope -ScriptBlock {
                [UserEmail] @{
                    Value   = 'user@example.com'
                    Type    = 'work'
                    Primary = $false
                }
            }

            $mockUserEmailInstance.ToString() | Should -Be 'user@example.com (work)'
        }
    }
}
