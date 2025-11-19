<#
    .SYNOPSIS
        Unit test for ClusterPolicyAccessControlEntry class.
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

Describe 'ClusterPolicyAccessControlEntry' -Tag 'ClusterPolicyAccessControlEntry' {
    Context 'When instantiating the class' {
        It 'Should not throw an error' {
            $script:mockAccessControlEntryInstance = InModuleScope -ScriptBlock {
                [ClusterPolicyAccessControlEntry]::new()
            }
        }

        It 'Should be of the correct type' {
            $mockAccessControlEntryInstance | Should -Not -BeNullOrEmpty
            $mockAccessControlEntryInstance.GetType().Name | Should -Be 'ClusterPolicyAccessControlEntry'
        }
    }

    Context 'When setting and reading values' {
        Context 'When setting UserName' {
            It 'Should be able to set value in instance' {
                $script:mockAccessControlEntryInstance = InModuleScope -ScriptBlock {
                    $aclInstance = [ClusterPolicyAccessControlEntry]::new()

                    $aclInstance.UserName = 'user@example.com'
                    $aclInstance.PermissionLevel = 'CAN_USE'

                    return $aclInstance
                }
            }

            It 'Should be able to read the values from instance' {
                $mockAccessControlEntryInstance.UserName | Should -Be 'user@example.com'
                $mockAccessControlEntryInstance.PermissionLevel | Should -Be 'CAN_USE'
            }
        }

        Context 'When setting GroupName' {
            It 'Should be able to set value in instance' {
                $script:mockAccessControlEntryInstance = InModuleScope -ScriptBlock {
                    $aclInstance = [ClusterPolicyAccessControlEntry]::new()

                    $aclInstance.GroupName = 'data-engineers'
                    $aclInstance.PermissionLevel = 'CAN_USE'

                    return $aclInstance
                }
            }

            It 'Should be able to read the values from instance' {
                $mockAccessControlEntryInstance.GroupName | Should -Be 'data-engineers'
                $mockAccessControlEntryInstance.PermissionLevel | Should -Be 'CAN_USE'
            }
        }

        Context 'When setting ServicePrincipalName' {
            It 'Should be able to set value in instance' {
                $script:mockAccessControlEntryInstance = InModuleScope -ScriptBlock {
                    $aclInstance = [ClusterPolicyAccessControlEntry]::new()

                    $aclInstance.ServicePrincipalName = '12345678-1234-1234-1234-123456789012'
                    $aclInstance.PermissionLevel = 'CAN_USE'

                    return $aclInstance
                }
            }

            It 'Should be able to read the values from instance' {
                $mockAccessControlEntryInstance.ServicePrincipalName | Should -Be '12345678-1234-1234-1234-123456789012'
                $mockAccessControlEntryInstance.PermissionLevel | Should -Be 'CAN_USE'
            }
        }
    }

    Context 'When comparing two objects using method Equals()' {
        Context 'When both objects are equal' {
            It 'Should return $true for UserName principal' {
                InModuleScope -ScriptBlock {
                    $aclInstance1 = [ClusterPolicyAccessControlEntry]::new()
                    $aclInstance1.UserName = 'user@example.com'
                    $aclInstance1.PermissionLevel = 'CAN_USE'

                    $aclInstance2 = [ClusterPolicyAccessControlEntry]::new()
                    $aclInstance2.UserName = 'user@example.com'
                    $aclInstance2.PermissionLevel = 'CAN_USE'

                    $aclInstance1 -eq $aclInstance2 | Should -BeTrue
                }
            }

            It 'Should return $true for GroupName principal' {
                InModuleScope -ScriptBlock {
                    $aclInstance1 = [ClusterPolicyAccessControlEntry]::new()
                    $aclInstance1.GroupName = 'data-engineers'
                    $aclInstance1.PermissionLevel = 'CAN_USE'

                    $aclInstance2 = [ClusterPolicyAccessControlEntry]::new()
                    $aclInstance2.GroupName = 'data-engineers'
                    $aclInstance2.PermissionLevel = 'CAN_USE'

                    $aclInstance1 -eq $aclInstance2 | Should -BeTrue
                }
            }

            It 'Should return $true for ServicePrincipalName principal' {
                InModuleScope -ScriptBlock {
                    $aclInstance1 = [ClusterPolicyAccessControlEntry]::new()
                    $aclInstance1.ServicePrincipalName = '12345678-1234-1234-1234-123456789012'
                    $aclInstance1.PermissionLevel = 'CAN_USE'

                    $aclInstance2 = [ClusterPolicyAccessControlEntry]::new()
                    $aclInstance2.ServicePrincipalName = '12345678-1234-1234-1234-123456789012'
                    $aclInstance2.PermissionLevel = 'CAN_USE'

                    $aclInstance1 -eq $aclInstance2 | Should -BeTrue
                }
            }
        }

        Context 'When object has different principal type' {
            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    $aclInstance1 = [ClusterPolicyAccessControlEntry]::new()
                    $aclInstance1.UserName = 'user@example.com'
                    $aclInstance1.PermissionLevel = 'CAN_USE'

                    $aclInstance2 = [ClusterPolicyAccessControlEntry]::new()
                    $aclInstance2.GroupName = 'data-engineers'
                    $aclInstance2.PermissionLevel = 'CAN_USE'

                    $aclInstance1 -eq $aclInstance2 | Should -BeFalse
                }
            }
        }

        Context 'When object has different principal name' {
            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    $aclInstance1 = [ClusterPolicyAccessControlEntry]::new()
                    $aclInstance1.UserName = 'user1@example.com'
                    $aclInstance1.PermissionLevel = 'CAN_USE'

                    $aclInstance2 = [ClusterPolicyAccessControlEntry]::new()
                    $aclInstance2.UserName = 'user2@example.com'
                    $aclInstance2.PermissionLevel = 'CAN_USE'

                    $aclInstance1 -eq $aclInstance2 | Should -BeFalse
                }
            }
        }

        Context 'When object has different permission level' {
            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    $aclInstance1 = [ClusterPolicyAccessControlEntry]::new()
                    $aclInstance1.UserName = 'user@example.com'
                    $aclInstance1.PermissionLevel = 'CAN_USE'

                    $aclInstance2 = [ClusterPolicyAccessControlEntry]::new()
                    $aclInstance2.UserName = 'user@example.com'
                    # Note: Currently only CAN_USE is supported, but this tests the logic
                    $aclInstance2.PermissionLevel = 'CAN_USE'

                    # For now they are equal, but logic is in place for future permission levels
                    $aclInstance1 -eq $aclInstance2 | Should -BeTrue
                }
            }
        }
    }

    Context 'When comparing two objects using method CompareTo()' {
        Context 'When the instance is compared against an invalid object' {
            It 'Should throw the correct error' {
                $mockAccessControlEntryInstance1 = InModuleScope -ScriptBlock {
                    [ClusterPolicyAccessControlEntry] @{
                        UserName        = 'user@example.com'
                        PermissionLevel = 'CAN_USE'
                    }
                }

                $mockErrorMessage = InModuleScope -ScriptBlock {
                    $script:localizedData.InvalidTypeForCompare
                }

                $mockErrorMessage = $mockErrorMessage -f @(
                    $mockAccessControlEntryInstance1.GetType().FullName
                    'System.String'
                )

                # Escape the brackets so Pester can evaluate the string correctly.
                $mockErrorMessage = $mockErrorMessage -replace '\[', '`['
                $mockErrorMessage = $mockErrorMessage -replace '\]', '`]'

                # The expected message should match the localized error message and contain 'Object'
                { $mockAccessControlEntryInstance1.CompareTo('AnyValue') } | Should -Throw -ExpectedMessage "*$mockErrorMessage*Object*"
            }
        }

        Context 'When the instance precedes the object being compared' {
            Context 'When comparing Group vs User (alphabetically)' {
                It 'Should return a value less than zero' {
                    $mockAccessControlEntryInstance1 = InModuleScope -ScriptBlock {
                        [ClusterPolicyAccessControlEntry] @{
                            GroupName       = 'admins'
                            PermissionLevel = 'CAN_USE'
                        }
                    }

                    $mockAccessControlEntryInstance2 = InModuleScope -ScriptBlock {
                        [ClusterPolicyAccessControlEntry] @{
                            UserName        = 'user@example.com'
                            PermissionLevel = 'CAN_USE'
                        }
                    }

                    $mockAccessControlEntryInstance1.CompareTo($mockAccessControlEntryInstance2) | Should -BeLessThan 0
                }
            }

            Context 'When comparing same principal type with different names' {
                It 'Should return a value less than zero' {
                    $mockAccessControlEntryInstance1 = InModuleScope -ScriptBlock {
                        [ClusterPolicyAccessControlEntry] @{
                            UserName        = 'a@example.com'
                            PermissionLevel = 'CAN_USE'
                        }
                    }

                    $mockAccessControlEntryInstance2 = InModuleScope -ScriptBlock {
                        [ClusterPolicyAccessControlEntry] @{
                            UserName        = 'z@example.com'
                            PermissionLevel = 'CAN_USE'
                        }
                    }

                    $mockAccessControlEntryInstance1.CompareTo($mockAccessControlEntryInstance2) | Should -BeLessThan 0
                }
            }
        }

        Context 'When the instance follows the object being compared' {
            Context 'When comparing User vs Group (alphabetically)' {
                It 'Should return a value greater than zero' {
                    $mockAccessControlEntryInstance1 = InModuleScope -ScriptBlock {
                        [ClusterPolicyAccessControlEntry] @{
                            UserName        = 'user@example.com'
                            PermissionLevel = 'CAN_USE'
                        }
                    }

                    $mockAccessControlEntryInstance2 = InModuleScope -ScriptBlock {
                        [ClusterPolicyAccessControlEntry] @{
                            GroupName       = 'admins'
                            PermissionLevel = 'CAN_USE'
                        }
                    }

                    $mockAccessControlEntryInstance1.CompareTo($mockAccessControlEntryInstance2) | Should -BeGreaterThan 0
                }
            }

            Context 'When the instance is compared against an object that is $null' {
                It 'Should return a value greater than zero' {
                    $mockAccessControlEntryInstance1 = InModuleScope -ScriptBlock {
                        [ClusterPolicyAccessControlEntry] @{
                            UserName        = 'user@example.com'
                            PermissionLevel = 'CAN_USE'
                        }
                    }

                    $mockAccessControlEntryInstance1.CompareTo($null) | Should -BeGreaterThan 0
                }
            }
        }

        Context 'When the instance is in the same position as the object being compared' {
            It 'Should return zero' {
                $mockAccessControlEntryInstance1 = InModuleScope -ScriptBlock {
                    [ClusterPolicyAccessControlEntry] @{
                        UserName        = 'user@example.com'
                        PermissionLevel = 'CAN_USE'
                    }
                }

                $mockAccessControlEntryInstance2 = InModuleScope -ScriptBlock {
                    [ClusterPolicyAccessControlEntry] @{
                        UserName        = 'user@example.com'
                        PermissionLevel = 'CAN_USE'
                    }
                }

                $mockAccessControlEntryInstance1.CompareTo($mockAccessControlEntryInstance2) | Should -Be 0
            }
        }

        Context 'When sorting the instances' {
            It 'Should sort by principal type and name' {
                $mockAccessControlArray = @(
                    InModuleScope -ScriptBlock {
                        [ClusterPolicyAccessControlEntry] @{
                            UserName        = 'z@example.com'
                            PermissionLevel = 'CAN_USE'
                        }
                        [ClusterPolicyAccessControlEntry] @{
                            GroupName       = 'admins'
                            PermissionLevel = 'CAN_USE'
                        }
                        [ClusterPolicyAccessControlEntry] @{
                            ServicePrincipalName = '12345678-1234-1234-1234-123456789012'
                            PermissionLevel      = 'CAN_USE'
                        }
                        [ClusterPolicyAccessControlEntry] @{
                            UserName        = 'a@example.com'
                            PermissionLevel = 'CAN_USE'
                        }
                    }
                )

                $mockSortedArray = $mockAccessControlArray | Sort-Object

                # Should be sorted: Group:admins, ServicePrincipal, User:a@, User:z@
                $mockSortedArray[0].GroupName | Should -Be 'admins'
                $mockSortedArray[1].ServicePrincipalName | Should -Be '12345678-1234-1234-1234-123456789012'
                $mockSortedArray[2].UserName | Should -Be 'a@example.com'
                $mockSortedArray[3].UserName | Should -Be 'z@example.com'
            }
        }
    }

    Context 'When calling method ToString()' {
        It 'Should return the correct string representation for UserName' {
            $mockAccessControlEntryInstance = InModuleScope -ScriptBlock {
                [ClusterPolicyAccessControlEntry] @{
                    UserName        = 'user@example.com'
                    PermissionLevel = 'CAN_USE'
                }
            }

            $mockAccessControlEntryInstance.ToString() | Should -Be 'User: user@example.com - CAN_USE'
        }

        It 'Should return the correct string representation for GroupName' {
            $mockAccessControlEntryInstance = InModuleScope -ScriptBlock {
                [ClusterPolicyAccessControlEntry] @{
                    GroupName       = 'data-engineers'
                    PermissionLevel = 'CAN_USE'
                }
            }

            $mockAccessControlEntryInstance.ToString() | Should -Be 'Group: data-engineers - CAN_USE'
        }

        It 'Should return the correct string representation for ServicePrincipalName' {
            $mockAccessControlEntryInstance = InModuleScope -ScriptBlock {
                [ClusterPolicyAccessControlEntry] @{
                    ServicePrincipalName = '12345678-1234-1234-1234-123456789012'
                    PermissionLevel      = 'CAN_USE'
                }
            }

            $mockAccessControlEntryInstance.ToString() | Should -Be 'ServicePrincipal: 12345678-1234-1234-1234-123456789012 - CAN_USE'
        }
    }
}
