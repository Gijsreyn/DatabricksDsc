BeforeAll {
    $script:dscModuleName = 'DatabricksDsc'

    Import-Module -Name $script:dscModuleName

    $PSDefaultParameterValues['InModuleScope:ModuleName'] = $script:dscModuleName
    $PSDefaultParameterValues['Should:ModuleName'] = $script:dscModuleName
}

AfterAll {
    $PSDefaultParameterValues.Remove('InModuleScope:ModuleName')
    $PSDefaultParameterValues.Remove('Should:ModuleName')
}

Describe 'WorkspaceObjectPermissionLevel' -Tag 'Type', 'Unit' {
    Context 'When checking enum values' {
        It 'Should have CAN_MANAGE value' {
            InModuleScope -ScriptBlock {
                [WorkspaceObjectPermissionLevel]::CAN_MANAGE | Should -Be 'CAN_MANAGE'
            }
        }

        It 'Should have CAN_READ value' {
            InModuleScope -ScriptBlock {
                [WorkspaceObjectPermissionLevel]::CAN_READ | Should -Be 'CAN_READ'
            }
        }

        It 'Should have CAN_RUN value' {
            InModuleScope -ScriptBlock {
                [WorkspaceObjectPermissionLevel]::CAN_RUN | Should -Be 'CAN_RUN'
            }
        }

        It 'Should have CAN_EDIT value' {
            InModuleScope -ScriptBlock {
                [WorkspaceObjectPermissionLevel]::CAN_EDIT | Should -Be 'CAN_EDIT'
            }
        }
    }
}

Describe 'WorkspaceObjectAccessControlEntry' -Tag 'Type', 'Unit' {
    Context 'When creating an instance with all properties' {
        It 'Should create an instance with GroupName' {
            InModuleScope -ScriptBlock {
                $entry = [WorkspaceObjectAccessControlEntry] @{
                    GroupName       = 'test-group'
                    PermissionLevel = 'CAN_MANAGE'
                }

                $entry | Should -Not -BeNullOrEmpty
                $entry.GroupName | Should -Be 'test-group'
                $entry.PermissionLevel | Should -Be 'CAN_MANAGE'
            }
        }

        It 'Should create an instance with UserName' {
            InModuleScope -ScriptBlock {
                $entry = [WorkspaceObjectAccessControlEntry] @{
                    UserName        = 'user@company.com'
                    PermissionLevel = 'CAN_READ'
                }

                $entry | Should -Not -BeNullOrEmpty
                $entry.UserName | Should -Be 'user@company.com'
                $entry.PermissionLevel | Should -Be 'CAN_READ'
            }
        }

        It 'Should create an instance with ServicePrincipalName' {
            InModuleScope -ScriptBlock {
                $entry = [WorkspaceObjectAccessControlEntry] @{
                    ServicePrincipalName = '6c81d91b-397d-4f70-871a-d07e84689edc'
                    PermissionLevel      = 'CAN_EDIT'
                }

                $entry | Should -Not -BeNullOrEmpty
                $entry.ServicePrincipalName | Should -Be '6c81d91b-397d-4f70-871a-d07e84689edc'
                $entry.PermissionLevel | Should -Be 'CAN_EDIT'
            }
        }
    }

    Context 'When using CompareTo method' {
        It 'Should return 0 when comparing identical entries with GroupName' {
            InModuleScope -ScriptBlock {
                $entry1 = [WorkspaceObjectAccessControlEntry] @{
                    GroupName       = 'test-group'
                    PermissionLevel = 'CAN_MANAGE'
                }

                $entry2 = [WorkspaceObjectAccessControlEntry] @{
                    GroupName       = 'test-group'
                    PermissionLevel = 'CAN_MANAGE'
                }

                $entry1.CompareTo($entry2) | Should -Be 0
            }
        }

        It 'Should return positive when first entry is greater' {
            InModuleScope -ScriptBlock {
                $entry1 = [WorkspaceObjectAccessControlEntry] @{
                    GroupName       = 'z-group'
                    PermissionLevel = 'CAN_MANAGE'
                }

                $entry2 = [WorkspaceObjectAccessControlEntry] @{
                    GroupName       = 'a-group'
                    PermissionLevel = 'CAN_MANAGE'
                }

                $entry1.CompareTo($entry2) | Should -BeGreaterThan 0
            }
        }

        It 'Should return negative when first entry is less' {
            InModuleScope -ScriptBlock {
                $entry1 = [WorkspaceObjectAccessControlEntry] @{
                    GroupName       = 'a-group'
                    PermissionLevel = 'CAN_MANAGE'
                }

                $entry2 = [WorkspaceObjectAccessControlEntry] @{
                    GroupName       = 'z-group'
                    PermissionLevel = 'CAN_MANAGE'
                }

                $entry1.CompareTo($entry2) | Should -BeLessThan 0
            }
        }

        It 'Should return 1 when comparing with null' {
            InModuleScope -ScriptBlock {
                $entry = [WorkspaceObjectAccessControlEntry] @{
                    GroupName       = 'test-group'
                    PermissionLevel = 'CAN_MANAGE'
                }

                $entry.CompareTo($null) | Should -Be 1
            }
        }

        It 'Should throw when comparing with non-WorkspaceObjectAccessControlEntry' {
            InModuleScope -ScriptBlock {
                $entry = [WorkspaceObjectAccessControlEntry] @{
                    GroupName       = 'test-group'
                    PermissionLevel = 'CAN_MANAGE'
                }

                { $entry.CompareTo('not an entry') } | Should -Throw '*is not a WorkspaceObjectAccessControlEntry*'
            }
        }

        It 'Should compare by permission level when principals are equal' {
            InModuleScope -ScriptBlock {
                $entry1 = [WorkspaceObjectAccessControlEntry] @{
                    GroupName       = 'test-group'
                    PermissionLevel = 'CAN_EDIT'
                }

                $entry2 = [WorkspaceObjectAccessControlEntry] @{
                    GroupName       = 'test-group'
                    PermissionLevel = 'CAN_MANAGE'
                }

                # CAN_EDIT (3) > CAN_MANAGE (0) in enum order
                $entry1.CompareTo($entry2) | Should -BeGreaterThan 0
            }
        }
    }

    Context 'When using Equals method' {
        It 'Should return true when entries are identical' {
            InModuleScope -ScriptBlock {
                $entry1 = [WorkspaceObjectAccessControlEntry] @{
                    GroupName       = 'test-group'
                    PermissionLevel = 'CAN_MANAGE'
                }

                $entry2 = [WorkspaceObjectAccessControlEntry] @{
                    GroupName       = 'test-group'
                    PermissionLevel = 'CAN_MANAGE'
                }

                $entry1.Equals($entry2) | Should -BeTrue
            }
        }

        It 'Should return false when GroupName differs' {
            InModuleScope -ScriptBlock {
                $entry1 = [WorkspaceObjectAccessControlEntry] @{
                    GroupName       = 'group1'
                    PermissionLevel = 'CAN_MANAGE'
                }

                $entry2 = [WorkspaceObjectAccessControlEntry] @{
                    GroupName       = 'group2'
                    PermissionLevel = 'CAN_MANAGE'
                }

                $entry1.Equals($entry2) | Should -BeFalse
            }
        }

        It 'Should return false when PermissionLevel differs' {
            InModuleScope -ScriptBlock {
                $entry1 = [WorkspaceObjectAccessControlEntry] @{
                    GroupName       = 'test-group'
                    PermissionLevel = 'CAN_MANAGE'
                }

                $entry2 = [WorkspaceObjectAccessControlEntry] @{
                    GroupName       = 'test-group'
                    PermissionLevel = 'CAN_READ'
                }

                $entry1.Equals($entry2) | Should -BeFalse
            }
        }

        It 'Should return false when comparing with null' {
            InModuleScope -ScriptBlock {
                $entry = [WorkspaceObjectAccessControlEntry] @{
                    GroupName       = 'test-group'
                    PermissionLevel = 'CAN_MANAGE'
                }

                $entry.Equals($null) | Should -BeFalse
            }
        }

        It 'Should return false when comparing with non-WorkspaceObjectAccessControlEntry' {
            InModuleScope -ScriptBlock {
                $entry = [WorkspaceObjectAccessControlEntry] @{
                    GroupName       = 'test-group'
                    PermissionLevel = 'CAN_MANAGE'
                }

                $entry.Equals('not an entry') | Should -BeFalse
            }
        }
    }

    Context 'When using ToString method' {
        It 'Should return string with GroupName' {
            InModuleScope -ScriptBlock {
                $entry = [WorkspaceObjectAccessControlEntry] @{
                    GroupName       = 'test-group'
                    PermissionLevel = 'CAN_MANAGE'
                }

                $entry.ToString() | Should -Be 'Group:test-group - CAN_MANAGE'
            }
        }

        It 'Should return string with UserName' {
            InModuleScope -ScriptBlock {
                $entry = [WorkspaceObjectAccessControlEntry] @{
                    UserName        = 'user@company.com'
                    PermissionLevel = 'CAN_READ'
                }

                $entry.ToString() | Should -Be 'User:user@company.com - CAN_READ'
            }
        }

        It 'Should return string with ServicePrincipalName' {
            InModuleScope -ScriptBlock {
                $entry = [WorkspaceObjectAccessControlEntry] @{
                    ServicePrincipalName = '6c81d91b-397d-4f70-871a-d07e84689edc'
                    PermissionLevel      = 'CAN_EDIT'
                }

                $entry.ToString() | Should -Be 'ServicePrincipal:6c81d91b-397d-4f70-871a-d07e84689edc - CAN_EDIT'
            }
        }

        It 'Should return Unknown when no principal is set' {
            InModuleScope -ScriptBlock {
                $entry = [WorkspaceObjectAccessControlEntry] @{
                    PermissionLevel = 'CAN_RUN'
                }

                $entry.ToString() | Should -Be 'Unknown - CAN_RUN'
            }
        }
    }

    Context 'When sorting an array of entries' {
        It 'Should sort by principal name' {
            InModuleScope -ScriptBlock {
                $entries = @(
                    [WorkspaceObjectAccessControlEntry] @{
                        GroupName       = 'z-group'
                        PermissionLevel = 'CAN_MANAGE'
                    }
                    [WorkspaceObjectAccessControlEntry] @{
                        GroupName       = 'a-group'
                        PermissionLevel = 'CAN_MANAGE'
                    }
                    [WorkspaceObjectAccessControlEntry] @{
                        GroupName       = 'm-group'
                        PermissionLevel = 'CAN_MANAGE'
                    }
                )

                $sorted = $entries | Sort-Object

                $sorted[0].GroupName | Should -Be 'a-group'
                $sorted[1].GroupName | Should -Be 'm-group'
                $sorted[2].GroupName | Should -Be 'z-group'
            }
        }
    }
}
