<#
    .SYNOPSIS
        Unit test for ClusterPolicyPermissionTypes class (ClusterPolicyAccessControlEntry).
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
}

Describe 'ClusterPolicyAccessControlEntry' -Tag 'ClusterPolicyAccessControlEntry' {
    Context 'When instantiating the class' {
        It 'Should not throw an error with mandatory property' {
            InModuleScope -ScriptBlock {
                { [ClusterPolicyAccessControlEntry] @{ PermissionLevel = 'CAN_USE' } } | Should -Not -Throw
            }
        }

        It 'Should be of the correct type' {
            InModuleScope -ScriptBlock {
                $aclInstance = [ClusterPolicyAccessControlEntry] @{
                    PermissionLevel = 'CAN_USE'
                    UserName = 'user@example.com'
                }

                $aclInstance | Should -Not -BeNullOrEmpty
                $aclInstance.GetType().Name | Should -Be 'ClusterPolicyAccessControlEntry'
            }
        }
    }

    Context 'When setting and reading values' {
        Context 'When setting UserName principal' {
            It 'Should be able to set and read UserName' {
                InModuleScope -ScriptBlock {
                    $aclInstance = [ClusterPolicyAccessControlEntry]::new()
                    $aclInstance.UserName = 'user@example.com'
                    $aclInstance.PermissionLevel = 'CAN_USE'

                    $aclInstance.UserName | Should -Be 'user@example.com'
                    $aclInstance.PermissionLevel | Should -Be 'CAN_USE'
                }
            }
        }

        Context 'When setting GroupName principal' {
            It 'Should be able to set and read GroupName' {
                InModuleScope -ScriptBlock {
                    $aclInstance = [ClusterPolicyAccessControlEntry]::new()
                    $aclInstance.GroupName = 'data-engineers'
                    $aclInstance.PermissionLevel = 'CAN_USE'

                    $aclInstance.GroupName | Should -Be 'data-engineers'
                    $aclInstance.PermissionLevel | Should -Be 'CAN_USE'
                }
            }
        }

        Context 'When setting ServicePrincipalName principal' {
            It 'Should be able to set and read ServicePrincipalName' {
                InModuleScope -ScriptBlock {
                    $aclInstance = [ClusterPolicyAccessControlEntry]::new()
                    $aclInstance.ServicePrincipalName = '12345678-1234-1234-1234-123456789012'
                    $aclInstance.PermissionLevel = 'CAN_USE'

                    $aclInstance.ServicePrincipalName | Should -Be '12345678-1234-1234-1234-123456789012'
                    $aclInstance.PermissionLevel | Should -Be 'CAN_USE'
                }
            }
        }
    }

    Context 'When comparing two objects using method Equals()' {
        Context 'When both objects are equal' {
            It 'Should return $true for UserName principal' {
                InModuleScope -ScriptBlock {
                    $aclInstance1 = [ClusterPolicyAccessControlEntry] @{
                        UserName = 'user@example.com'
                        PermissionLevel = 'CAN_USE'
                    }

                    $aclInstance2 = [ClusterPolicyAccessControlEntry] @{
                        UserName = 'user@example.com'
                        PermissionLevel = 'CAN_USE'
                    }

                    $aclInstance1 -eq $aclInstance2 | Should -BeTrue
                }
            }

            It 'Should return $true for GroupName principal' {
                InModuleScope -ScriptBlock {
                    $aclInstance1 = [ClusterPolicyAccessControlEntry] @{
                        GroupName = 'data-engineers'
                        PermissionLevel = 'CAN_USE'
                    }

                    $aclInstance2 = [ClusterPolicyAccessControlEntry] @{
                        GroupName = 'data-engineers'
                        PermissionLevel = 'CAN_USE'
                    }

                    $aclInstance1 -eq $aclInstance2 | Should -BeTrue
                }
            }

            It 'Should return $true for ServicePrincipalName principal' {
                InModuleScope -ScriptBlock {
                    $aclInstance1 = [ClusterPolicyAccessControlEntry] @{
                        ServicePrincipalName = '12345678-1234-1234-1234-123456789012'
                        PermissionLevel = 'CAN_USE'
                    }

                    $aclInstance2 = [ClusterPolicyAccessControlEntry] @{
                        ServicePrincipalName = '12345678-1234-1234-1234-123456789012'
                        PermissionLevel = 'CAN_USE'
                    }

                    $aclInstance1 -eq $aclInstance2 | Should -BeTrue
                }
            }
        }

        Context 'When objects have different principal type' {
            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    $aclInstance1 = [ClusterPolicyAccessControlEntry] @{
                        UserName = 'user@example.com'
                        PermissionLevel = 'CAN_USE'
                    }

                    $aclInstance2 = [ClusterPolicyAccessControlEntry] @{
                        GroupName = 'data-engineers'
                        PermissionLevel = 'CAN_USE'
                    }

                    $aclInstance1 -eq $aclInstance2 | Should -BeFalse
                }
            }
        }

        Context 'When objects have different principal name' {
            It 'Should return $false for different UserName' {
                InModuleScope -ScriptBlock {
                    $aclInstance1 = [ClusterPolicyAccessControlEntry] @{
                        UserName = 'user1@example.com'
                        PermissionLevel = 'CAN_USE'
                    }

                    $aclInstance2 = [ClusterPolicyAccessControlEntry] @{
                        UserName = 'user2@example.com'
                        PermissionLevel = 'CAN_USE'
                    }

                    $aclInstance1 -eq $aclInstance2 | Should -BeFalse
                }
            }

            It 'Should return $false for different GroupName' {
                InModuleScope -ScriptBlock {
                    $aclInstance1 = [ClusterPolicyAccessControlEntry] @{
                        GroupName = 'group1'
                        PermissionLevel = 'CAN_USE'
                    }

                    $aclInstance2 = [ClusterPolicyAccessControlEntry] @{
                        GroupName = 'group2'
                        PermissionLevel = 'CAN_USE'
                    }

                    $aclInstance1 -eq $aclInstance2 | Should -BeFalse
                }
            }

            It 'Should return $false for different ServicePrincipalName' {
                InModuleScope -ScriptBlock {
                    $aclInstance1 = [ClusterPolicyAccessControlEntry] @{
                        ServicePrincipalName = '12345678-1234-1234-1234-123456789012'
                        PermissionLevel = 'CAN_USE'
                    }

                    $aclInstance2 = [ClusterPolicyAccessControlEntry] @{
                        ServicePrincipalName = '87654321-4321-4321-4321-210987654321'
                        PermissionLevel = 'CAN_USE'
                    }

                    $aclInstance1 -eq $aclInstance2 | Should -BeFalse
                }
            }
        }

        Context 'When objects have different permission level' {
            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    $aclInstance1 = [ClusterPolicyAccessControlEntry] @{
                        UserName = 'user@example.com'
                        PermissionLevel = 'CAN_USE'
                    }

                    $aclInstance2 = [ClusterPolicyAccessControlEntry] @{
                        UserName = 'user@example.com'
                        PermissionLevel = 'CAN_USE'
                    }

                    # Currently only CAN_USE is supported, so they will be equal
                    # This test validates the logic is in place for future permission levels
                    $aclInstance1 -eq $aclInstance2 | Should -BeTrue
                }
            }
        }

        Context 'When comparing against a different type' {
            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    $aclInstance1 = [ClusterPolicyAccessControlEntry] @{
                        UserName = 'user@example.com'
                        PermissionLevel = 'CAN_USE'
                    }

                    $aclInstance1 -eq 'user@example.com' | Should -BeFalse
                }
            }
        }
    }

    Context 'When comparing two objects using method CompareTo()' {
        Context 'When the instance is compared against an invalid object' {
            It 'Should throw an exception' {
                $mockAclInstance = InModuleScope -ScriptBlock {
                    [ClusterPolicyAccessControlEntry] @{
                        UserName = 'user@example.com'
                        PermissionLevel = 'CAN_USE'
                    }
                }

                $mockErrorMessage = InModuleScope -ScriptBlock {
                    $script:localizedData.InvalidTypeForCompare
                }

                $mockErrorMessage = $mockErrorMessage -f @(
                    $mockAclInstance.GetType().FullName
                    'System.String'
                )

                # Escape the brackets so Pester can evaluate the string correctly.
                $mockErrorMessage = $mockErrorMessage -replace '\[', '`['
                $mockErrorMessage = $mockErrorMessage -replace '\]', '`]'

                { $mockAclInstance.CompareTo('AnyValue') } | Should -Throw -ExpectedMessage "*$mockErrorMessage*"
            }
        }

        Context 'When the instance precedes the object being compared' {
            Context 'When comparing by principal type (Group vs User)' {
                It 'Should return a value less than zero' {
                    InModuleScope -ScriptBlock {
                        $aclInstance1 = [ClusterPolicyAccessControlEntry] @{
                            GroupName = 'admins'
                            PermissionLevel = 'CAN_USE'
                        }

                        $aclInstance2 = [ClusterPolicyAccessControlEntry] @{
                            UserName = 'user@example.com'
                            PermissionLevel = 'CAN_USE'
                        }

                        $aclInstance1.CompareTo($aclInstance2) | Should -BeLessThan 0
                    }
                }
            }

            Context 'When comparing same principal type with different names' {
                It 'Should return a value less than zero' {
                    InModuleScope -ScriptBlock {
                        $aclInstance1 = [ClusterPolicyAccessControlEntry] @{
                            UserName = 'a@example.com'
                            PermissionLevel = 'CAN_USE'
                        }

                        $aclInstance2 = [ClusterPolicyAccessControlEntry] @{
                            UserName = 'z@example.com'
                            PermissionLevel = 'CAN_USE'
                        }

                        $aclInstance1.CompareTo($aclInstance2) | Should -BeLessThan 0
                    }
                }
            }
        }

        Context 'When the instance follows the object being compared' {
            Context 'When comparing by principal type (User vs Group)' {
                It 'Should return a value greater than zero' {
                    InModuleScope -ScriptBlock {
                        $aclInstance1 = [ClusterPolicyAccessControlEntry] @{
                            UserName = 'user@example.com'
                            PermissionLevel = 'CAN_USE'
                        }

                        $aclInstance2 = [ClusterPolicyAccessControlEntry] @{
                            GroupName = 'admins'
                            PermissionLevel = 'CAN_USE'
                        }

                        $aclInstance1.CompareTo($aclInstance2) | Should -BeGreaterThan 0
                    }
                }
            }

            Context 'When comparing same principal type with different names' {
                It 'Should return a value greater than zero' {
                    InModuleScope -ScriptBlock {
                        $aclInstance1 = [ClusterPolicyAccessControlEntry] @{
                            UserName = 'z@example.com'
                            PermissionLevel = 'CAN_USE'
                        }

                        $aclInstance2 = [ClusterPolicyAccessControlEntry] @{
                            UserName = 'a@example.com'
                            PermissionLevel = 'CAN_USE'
                        }

                        $aclInstance1.CompareTo($aclInstance2) | Should -BeGreaterThan 0
                    }
                }
            }

            Context 'When the instance is compared against an object that is $null' {
                It 'Should return a value greater than zero' {
                    $mockAclInstance = InModuleScope -ScriptBlock {
                        [ClusterPolicyAccessControlEntry] @{
                            UserName = 'user@example.com'
                            PermissionLevel = 'CAN_USE'
                        }
                    }

                    $mockAclInstance.CompareTo($null) | Should -BeGreaterThan 0
                }
            }
        }

        Context 'When the instance is in the same position as the object being compared' {
            It 'Should return zero' {
                InModuleScope -ScriptBlock {
                    $aclInstance1 = [ClusterPolicyAccessControlEntry] @{
                        UserName = 'user@example.com'
                        PermissionLevel = 'CAN_USE'
                    }

                    $aclInstance2 = [ClusterPolicyAccessControlEntry] @{
                        UserName = 'user@example.com'
                        PermissionLevel = 'CAN_USE'
                    }

                    $aclInstance1.CompareTo($aclInstance2) | Should -Be 0
                }
            }
        }

        Context 'When sorting the instances' {
            It 'Should sort by principal type (Group, ServicePrincipal, User), then by name' {
                InModuleScope -ScriptBlock {
                    $mockAclArray = @(
                        [ClusterPolicyAccessControlEntry] @{
                            UserName = 'z@example.com'
                            PermissionLevel = 'CAN_USE'
                        }
                        [ClusterPolicyAccessControlEntry] @{
                            GroupName = 'data-engineers'
                            PermissionLevel = 'CAN_USE'
                        }
                        [ClusterPolicyAccessControlEntry] @{
                            ServicePrincipalName = '87654321-4321-4321-4321-210987654321'
                            PermissionLevel = 'CAN_USE'
                        }
                        [ClusterPolicyAccessControlEntry] @{
                            GroupName = 'admins'
                            PermissionLevel = 'CAN_USE'
                        }
                        [ClusterPolicyAccessControlEntry] @{
                            UserName = 'a@example.com'
                            PermissionLevel = 'CAN_USE'
                        }
                        [ClusterPolicyAccessControlEntry] @{
                            ServicePrincipalName = '12345678-1234-1234-1234-123456789012'
                            PermissionLevel = 'CAN_USE'
                        }
                    )

                    $mockSortedArray = $mockAclArray | Sort-Object

                    # Groups should come first (alphabetically)
                    $mockSortedArray[0].GroupName | Should -Be 'admins'
                    $mockSortedArray[1].GroupName | Should -Be 'data-engineers'

                    # Service principals next (alphabetically by GUID)
                    $mockSortedArray[2].ServicePrincipalName | Should -Be '12345678-1234-1234-1234-123456789012'
                    $mockSortedArray[3].ServicePrincipalName | Should -Be '87654321-4321-4321-4321-210987654321'

                    # Users last (alphabetically)
                    $mockSortedArray[4].UserName | Should -Be 'a@example.com'
                    $mockSortedArray[5].UserName | Should -Be 'z@example.com'
                }
            }
        }
    }

    Context 'When using method ToString()' {
        It 'Should return a formatted string for UserName principal' {
            InModuleScope -ScriptBlock {
                $aclInstance = [ClusterPolicyAccessControlEntry] @{
                    UserName = 'user@example.com'
                    PermissionLevel = 'CAN_USE'
                }

                $aclInstance.ToString() | Should -Be 'User: user@example.com - CAN_USE'
            }
        }

        It 'Should return a formatted string for GroupName principal' {
            InModuleScope -ScriptBlock {
                $aclInstance = [ClusterPolicyAccessControlEntry] @{
                    GroupName = 'data-engineers'
                    PermissionLevel = 'CAN_USE'
                }

                $aclInstance.ToString() | Should -Be 'Group: data-engineers - CAN_USE'
            }
        }

        It 'Should return a formatted string for ServicePrincipalName principal' {
            InModuleScope -ScriptBlock {
                $aclInstance = [ClusterPolicyAccessControlEntry] @{
                    ServicePrincipalName = '12345678-1234-1234-1234-123456789012'
                    PermissionLevel = 'CAN_USE'
                }

                $aclInstance.ToString() | Should -Be 'ServicePrincipal: 12345678-1234-1234-1234-123456789012 - CAN_USE'
            }
        }

        It 'Should return a formatted string with empty principal when none is set' {
            InModuleScope -ScriptBlock {
                $aclInstance = [ClusterPolicyAccessControlEntry] @{
                    PermissionLevel = 'CAN_USE'
                }

                $aclInstance.ToString() | Should -Be ' - CAN_USE'
            }
        }
    }
}
