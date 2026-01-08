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

Describe 'DatabricksWorkspaceObjectPermission' -Tag 'Class', 'Unit' {
    Context 'When instantiating the class' {
        It 'Should not throw an exception' {
            InModuleScope -ScriptBlock {
                { [DatabricksWorkspaceObjectPermission]::new() } | Should -Not -Throw
            }
        }

        It 'Should have ExcludeDscProperties set correctly' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksWorkspaceObjectPermission]::new()

                $instance.ExcludeDscProperties | Should -Contain 'WorkspaceUrl'
                $instance.ExcludeDscProperties | Should -Contain 'AccessToken'
                $instance.ExcludeDscProperties | Should -Contain 'WorkspacePath'
                $instance.ExcludeDscProperties | Should -Contain '_exist'
            }
        }

        It 'Should have _exist default to true' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksWorkspaceObjectPermission]::new()
                $instance._exist | Should -BeTrue
            }
        }
    }
}

Describe 'DatabricksWorkspaceObjectPermission\ResolveWorkspaceObject()' -Tag 'ResolveWorkspaceObject' {
    Context 'When resolving a notebook path' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksWorkspaceObjectPermission] @{
                    WorkspaceUrl  = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    WorkspacePath = '/Shared/my-notebook'
                }

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            object_id   = 12345
                            object_type = 'NOTEBOOK'
                            path        = '/Shared/my-notebook'
                        }
                    }
            }
        }

        It 'Should resolve notebook to correct permission type' {
            InModuleScope -ScriptBlock {
                $script:mockInstance.ResolveWorkspaceObject('/Shared/my-notebook')

                $script:mockInstance._objectId | Should -Be '12345'
                $script:mockInstance._objectType | Should -Be 'NOTEBOOK'
                $script:mockInstance._permissionObjectType | Should -Be 'notebooks'
            }
        }
    }

    Context 'When resolving a directory path' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksWorkspaceObjectPermission] @{
                    WorkspaceUrl  = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    WorkspacePath = '/Users'
                }

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            object_id   = 67890
                            object_type = 'DIRECTORY'
                            path        = '/Users'
                        }
                    }
            }
        }

        It 'Should resolve directory to correct permission type' {
            InModuleScope -ScriptBlock {
                $script:mockInstance.ResolveWorkspaceObject('/Users')

                $script:mockInstance._objectId | Should -Be '67890'
                $script:mockInstance._objectType | Should -Be 'DIRECTORY'
                $script:mockInstance._permissionObjectType | Should -Be 'directories'
            }
        }
    }

    Context 'When resolving a repo path' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksWorkspaceObjectPermission] @{
                    WorkspaceUrl  = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    WorkspacePath = '/Repos/my-repo'
                }

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            object_id   = 11111
                            object_type = 'REPO'
                            path        = '/Repos/my-repo'
                        }
                    }
            }
        }

        It 'Should resolve repo to correct permission type' {
            InModuleScope -ScriptBlock {
                $script:mockInstance.ResolveWorkspaceObject('/Repos/my-repo')

                $script:mockInstance._objectId | Should -Be '11111'
                $script:mockInstance._objectType | Should -Be 'REPO'
                $script:mockInstance._permissionObjectType | Should -Be 'repos'
            }
        }
    }

    Context 'When object is not found' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksWorkspaceObjectPermission] @{
                    WorkspaceUrl  = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    WorkspacePath = '/NonExistent'
                }

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            path = '/NonExistent'
                        }
                    }
            }
        }

        It 'Should throw error when object_id is missing' {
            InModuleScope -ScriptBlock {
                { $script:mockInstance.ResolveWorkspaceObject('/NonExistent') } | Should -Throw '*not found*'
            }
        }
    }

    Context 'When object type is unsupported' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksWorkspaceObjectPermission] @{
                    WorkspaceUrl  = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    WorkspacePath = '/SomeFile'
                }

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            object_id   = 99999
                            object_type = 'FILE'
                            path        = '/SomeFile'
                        }
                    }
            }
        }

        It 'Should throw error for unsupported type' {
            InModuleScope -ScriptBlock {
                { $script:mockInstance.ResolveWorkspaceObject('/SomeFile') } | Should -Throw '*Unsupported*'
            }
        }
    }
}

Describe 'DatabricksWorkspaceObjectPermission\GetCurrentState()' -Tag 'GetCurrentState' {
    Context 'When permissions exist' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksWorkspaceObjectPermission] @{
                    WorkspaceUrl  = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    WorkspacePath = '/Shared/my-notebook'
                }

                Mock -CommandName Write-Verbose

                $resolveCallCount = 0
                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'ResolveWorkspaceObject' -Value {
                        $script:resolveCallCount++
                        $this._objectId = '12345'
                        $this._objectType = 'NOTEBOOK'
                        $this._permissionObjectType = 'notebooks'
                    }

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            object_id           = '12345'
                            object_type         = 'notebook'
                            access_control_list = @(
                                @{
                                    group_name      = 'data-team'
                                    all_permissions = @(
                                        @{ permission_level = 'CAN_EDIT' }
                                    )
                                }
                                @{
                                    user_name       = 'user@company.com'
                                    all_permissions = @(
                                        @{ permission_level = 'CAN_READ' }
                                    )
                                }
                            )
                        }
                    }
            }
        }

        It 'Should return permissions' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockInstance.GetCurrentState(@{
                        WorkspacePath = '/Shared/my-notebook'
                    })

                $currentState._exist | Should -BeTrue
                $currentState.AccessControlList | Should -HaveCount 2

                $groupEntry = $currentState.AccessControlList | Where-Object { $_.GroupName -eq 'data-team' }
                $groupEntry | Should -Not -BeNullOrEmpty
                $groupEntry.PermissionLevel | Should -Be 'CAN_EDIT'

                $userEntry = $currentState.AccessControlList | Where-Object { $_.UserName -eq 'user@company.com' }
                $userEntry | Should -Not -BeNullOrEmpty
                $userEntry.PermissionLevel | Should -Be 'CAN_READ'
            }
        }

        It 'Should call ResolveWorkspaceObject' {
            InModuleScope -ScriptBlock {
                $script:resolveCallCount | Should -BeGreaterThan 0
            }
        }
    }

    Context 'When no permissions exist' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksWorkspaceObjectPermission] @{
                    WorkspaceUrl  = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    WorkspacePath = '/Shared/my-notebook'
                }

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'ResolveWorkspaceObject' -Value {
                        $this._objectId = '12345'
                        $this._objectType = 'NOTEBOOK'
                        $this._permissionObjectType = 'notebooks'
                    }

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            object_id           = '12345'
                            object_type         = 'notebook'
                            access_control_list = @()
                        }
                    }
            }
        }

        It 'Should return empty access control list' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockInstance.GetCurrentState(@{
                        WorkspacePath = '/Shared/my-notebook'
                    })

                $currentState._exist | Should -BeFalse
                $currentState.AccessControlList | Should -HaveCount 0
            }
        }
    }
}

Describe 'DatabricksWorkspaceObjectPermission\Modify()' -Tag 'Modify' {
    Context 'When updating permissions' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksWorkspaceObjectPermission] @{
                    WorkspaceUrl  = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    WorkspacePath = '/Shared/my-notebook'
                }

                $script:mockInstance._objectId = '12345'
                $script:mockInstance._objectType = 'NOTEBOOK'
                $script:mockInstance._permissionObjectType = 'notebooks'

                Mock -CommandName Write-Verbose

                $script:invokeApiParams = $null
                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param($method, $path, $body)
                        $script:invokeApiParams = @{
                            Method = $method
                            Path   = $path
                            Body   = $body
                        }
                        return @{}
                    }
            }
        }

        It 'Should call PATCH with correct payload' {
            InModuleScope -ScriptBlock {
                $properties = @{
                    AccessControlList = @(
                        [WorkspaceObjectAccessControlEntry] @{
                            GroupName       = 'data-team'
                            PermissionLevel = 'CAN_EDIT'
                        }
                    )
                    _exist            = $true
                }

                $script:mockInstance.Modify($properties)

                $script:invokeApiParams.Method | Should -Be 'PATCH'
                $script:invokeApiParams.Path | Should -Be '/api/2.0/permissions/notebooks/12345'
                $script:invokeApiParams.Body.access_control_list | Should -HaveCount 1
                $script:invokeApiParams.Body.access_control_list[0].group_name | Should -Be 'data-team'
                $script:invokeApiParams.Body.access_control_list[0].permission_level | Should -Be 'CAN_EDIT'
            }
        }
    }

    Context 'When removing all permissions' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksWorkspaceObjectPermission] @{
                    WorkspaceUrl  = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    WorkspacePath = '/Shared/my-notebook'
                }

                $script:mockInstance._objectId = '12345'
                $script:mockInstance._objectType = 'NOTEBOOK'
                $script:mockInstance._permissionObjectType = 'notebooks'

                Mock -CommandName Write-Verbose

                $script:invokeApiParams = $null
                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param($method, $path, $body)
                        $script:invokeApiParams = @{
                            Method = $method
                            Path   = $path
                            Body   = $body
                        }
                        return @{}
                    }
            }
        }

        It 'Should call PUT with empty access control list' {
            InModuleScope -ScriptBlock {
                $properties = @{
                    _exist = $false
                }

                $script:mockInstance.Modify($properties)

                $script:invokeApiParams.Method | Should -Be 'PUT'
                $script:invokeApiParams.Path | Should -Be '/api/2.0/permissions/notebooks/12345'
                $script:invokeApiParams.Body.access_control_list | Should -HaveCount 0
            }
        }
    }
}

Describe 'DatabricksWorkspaceObjectPermission\Get()' -Tag 'Get' {
    Context 'When calling Get method' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksWorkspaceObjectPermission] @{
                    WorkspaceUrl  = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken   = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    WorkspacePath = '/Shared/my-notebook'
                }

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'ResolveWorkspaceObject' -Value {
                        $this._objectId = '12345'
                        $this._objectType = 'NOTEBOOK'
                        $this._permissionObjectType = 'notebooks'
                    }

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            object_id           = '12345'
                            object_type         = 'notebook'
                            access_control_list = @(
                                @{
                                    group_name      = 'data-team'
                                    all_permissions = @(
                                        @{ permission_level = 'CAN_EDIT' }
                                    )
                                }
                            )
                        }
                    }
            }
        }

        It 'Should return instance with current state' {
            InModuleScope -ScriptBlock {
                $result = $script:mockInstance.Get()

                $result | Should -Not -BeNullOrEmpty
                $result.WorkspacePath | Should -Be '/Shared/my-notebook'
                $result.AccessControlList | Should -HaveCount 1
            }
        }
    }
}

Describe 'DatabricksWorkspaceObjectPermission\Test()' -Tag 'Test' {
    Context 'When in desired state' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksWorkspaceObjectPermission] @{
                    WorkspaceUrl      = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken       = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    WorkspacePath     = '/Shared/my-notebook'
                    AccessControlList = @(
                        [WorkspaceObjectAccessControlEntry] @{
                            GroupName       = 'data-team'
                            PermissionLevel = 'CAN_EDIT'
                        }
                    )
                }

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'ResolveWorkspaceObject' -Value {
                        $this._objectId = '12345'
                        $this._objectType = 'NOTEBOOK'
                        $this._permissionObjectType = 'notebooks'
                    }

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            object_id           = '12345'
                            object_type         = 'notebook'
                            access_control_list = @(
                                @{
                                    group_name      = 'data-team'
                                    all_permissions = @(
                                        @{ permission_level = 'CAN_EDIT' }
                                    )
                                }
                            )
                        }
                    }
            }
        }

        It 'Should return true' {
            InModuleScope -ScriptBlock {
                $script:mockInstance.Test() | Should -BeTrue
            }
        }
    }

    Context 'When not in desired state' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksWorkspaceObjectPermission] @{
                    WorkspaceUrl      = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken       = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    WorkspacePath     = '/Shared/my-notebook'
                    AccessControlList = @(
                        [WorkspaceObjectAccessControlEntry] @{
                            GroupName       = 'data-team'
                            PermissionLevel = 'CAN_MANAGE'
                        }
                    )
                }

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'ResolveWorkspaceObject' -Value {
                        $this._objectId = '12345'
                        $this._objectType = 'NOTEBOOK'
                        $this._permissionObjectType = 'notebooks'
                    }

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            object_id           = '12345'
                            object_type         = 'notebook'
                            access_control_list = @(
                                @{
                                    group_name      = 'data-team'
                                    all_permissions = @(
                                        @{ permission_level = 'CAN_EDIT' }
                                    )
                                }
                            )
                        }
                    }
            }
        }

        It 'Should return false' {
            InModuleScope -ScriptBlock {
                $script:mockInstance.Test() | Should -BeFalse
            }
        }
    }
}
