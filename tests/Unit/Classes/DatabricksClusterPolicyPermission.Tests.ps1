<#
    .SYNOPSIS
        Unit test for DatabricksClusterPolicyPermission DSC resource.
#>

# Suppressing this rule because Script Analyzer does not understand Pester's syntax.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
# Suppressing this rule because tests are mocking passwords in clear text.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
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

Describe 'DatabricksClusterPolicyPermission' {
    Context 'When class is instantiated' {
        It 'Should not throw an exception' {
            InModuleScope -ScriptBlock {
                { [DatabricksClusterPolicyPermission]::new() } | Should -Not -Throw
            }
        }

        It 'Should have a default or empty constructor' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksClusterPolicyPermission]::new()
                $instance | Should -Not -BeNullOrEmpty
            }
        }

        It 'Should be the correct type' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksClusterPolicyPermission]::new()
                $instance.GetType().Name | Should -Be 'DatabricksClusterPolicyPermission'
            }
        }

        It 'Should have ExcludeDscProperties set' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksClusterPolicyPermission]::new()
                $instance.ExcludeDscProperties | Should -Contain 'WorkspaceUrl'
                $instance.ExcludeDscProperties | Should -Contain 'ClusterPolicyId'
                $instance.ExcludeDscProperties | Should -Contain 'AccessToken'
            }
        }
    }
}

Describe 'DatabricksClusterPolicyPermission\Get()' -Tag 'Get' {
    Context 'When permissions exist with group principal' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksClusterPolicyPermission] @{
                    WorkspaceUrl    = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken     = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    ClusterPolicyId = 'test-policy-123'
                }

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                        return [System.Collections.Hashtable] @{
                            WorkspaceUrl        = 'https://adb-1234567890123456.12.azuredatabricks.net'
                            ClusterPolicyId     = 'test-policy-123'
                            AccessControlList   = @(
                                [ClusterPolicyAccessControlEntry]@{
                                    GroupName       = 'admins'
                                    PermissionLevel = 'CAN_USE'
                                }
                            )
                            _exist              = $true
                        }
                    } -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'AssertProperties' -Value {
                        return
                    }
            }
        }

        It 'Should return the correct values' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockInstance.Get()

                $currentState.ClusterPolicyId | Should -Be 'test-policy-123'
                $currentState.AccessControlList | Should -HaveCount 1
                $currentState.AccessControlList[0].GroupName | Should -Be 'admins'
                $currentState.Reasons | Should -BeNullOrEmpty
            }
        }
    }
}

Describe 'DatabricksClusterPolicyPermission\GetCurrentState()' -Tag 'GetCurrentState' {
    Context 'When permissions exist with all principal types' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksClusterPolicyPermission] @{
                    WorkspaceUrl    = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken     = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    ClusterPolicyId = 'test-policy-123'
                }

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            access_control_list = @(
                                @{
                                    group_name      = 'admins'
                                    all_permissions = @(
                                        @{ permission_level = 'CAN_USE' }
                                    )
                                }
                                @{
                                    user_name       = 'user@example.com'
                                    all_permissions = @(
                                        @{ permission_level = 'CAN_USE' }
                                    )
                                }
                                @{
                                    service_principal_name = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
                                    all_permissions        = @(
                                        @{ permission_level = 'CAN_USE' }
                                    )
                                }
                            )
                        }
                    }
            }
        }

        It 'Should return permissions for all principal types' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockInstance.GetCurrentState(
                    @{
                        ClusterPolicyId = 'test-policy-123'
                    }
                )

                $currentState.AccessControlList | Should -HaveCount 3
                # After sorting: Group, ServicePrincipal, User (alphabetical by type prefix)
                $currentState.AccessControlList[0].GroupName | Should -Be 'admins'
                $currentState.AccessControlList[1].ServicePrincipalName | Should -Be 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
                $currentState.AccessControlList[2].UserName | Should -Be 'user@example.com'
                $currentState._exist | Should -BeTrue
            }
        }
    }

    Context 'When desired principals exist in current state' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksClusterPolicyPermission] @{
                    WorkspaceUrl      = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken       = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    ClusterPolicyId   = 'test-policy-123'
                    AccessControlList = @(
                        [ClusterPolicyAccessControlEntry]@{
                            GroupName       = 'admins'
                            PermissionLevel = 'CAN_USE'
                        }
                    )
                }

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            access_control_list = @(
                                @{
                                    group_name      = 'admins'
                                    all_permissions = @(
                                        @{ permission_level = 'CAN_USE' }
                                    )
                                }
                                @{
                                    group_name      = 'users'
                                    all_permissions = @(
                                        @{ permission_level = 'CAN_USE' }
                                    )
                                }
                            )
                        }
                    }
            }
        }

        It 'Should set _exist to true when desired principals are found' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockInstance.GetCurrentState(
                    @{
                        ClusterPolicyId = 'test-policy-123'
                    }
                )

                $currentState._exist | Should -BeTrue
            }
        }
    }

    Context 'When desired principals do not exist in current state' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksClusterPolicyPermission] @{
                    WorkspaceUrl      = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken       = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    ClusterPolicyId   = 'test-policy-123'
                    AccessControlList = @(
                        [ClusterPolicyAccessControlEntry]@{
                            GroupName       = 'missing-group'
                            PermissionLevel = 'CAN_USE'
                        }
                    )
                }

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            access_control_list = @(
                                @{
                                    group_name      = 'admins'
                                    all_permissions = @(
                                        @{ permission_level = 'CAN_USE' }
                                    )
                                }
                            )
                        }
                    }
            }
        }

        It 'Should set _exist to false when desired principals are not found' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockInstance.GetCurrentState(
                    @{
                        ClusterPolicyId = 'test-policy-123'
                    }
                )

                $currentState._exist | Should -BeFalse
            }
        }
    }

    Context 'When permissions endpoint returns null AccessControlList' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksClusterPolicyPermission] @{
                    WorkspaceUrl    = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken     = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    ClusterPolicyId = 'test-policy-123'
                }

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            access_control_list = $null
                        }
                    }
            }
        }

        It 'Should return _exist as false with empty ACL' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockInstance.GetCurrentState(
                    @{
                        ClusterPolicyId = 'test-policy-123'
                    }
                )

                $currentState._exist | Should -BeFalse
                $currentState.AccessControlList | Should -HaveCount 0
            }
        }
    }

    Context 'When response is null' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksClusterPolicyPermission] @{
                    WorkspaceUrl    = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken     = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    ClusterPolicyId = 'test-policy-123'
                }

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return $null
                    }
            }
        }

        It 'Should return _exist as false when response is null' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockInstance.GetCurrentState(
                    @{
                        ClusterPolicyId = 'test-policy-123'
                    }
                )

                $currentState._exist | Should -BeFalse
                $currentState.AccessControlList | Should -BeNullOrEmpty
            }
        }
    }

    Context 'When API call fails' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksClusterPolicyPermission] @{
                    WorkspaceUrl    = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken     = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    ClusterPolicyId = 'test-policy-123'
                }

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        throw 'API Error'
                    }
            }
        }

        It 'Should handle error and return _exist as false' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockInstance.GetCurrentState(
                    @{
                        ClusterPolicyId = 'test-policy-123'
                    }
                )

                $currentState._exist | Should -BeFalse
                Should -Invoke -CommandName Write-Verbose -ParameterFilter {
                    $Message -like '*API Error*'
                } -Exactly -Times 1 -Scope It
            }
        }
    }
}

Describe 'DatabricksClusterPolicyPermission\Modify()' -Tag 'Modify' {
    Context 'When permissions should be removed' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksClusterPolicyPermission] @{
                    WorkspaceUrl    = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken     = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    ClusterPolicyId = 'test-policy-123'
                }

                $script:mockInstance._exist = $true

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param($Method, $Path, $Body)

                        $script:mockInvokeApiMethod = $Method
                        $script:mockInvokeApiPath = $Path
                        $script:mockInvokeApiBody = $Body
                    }
            }
        }

        It 'Should call API with empty access control list' {
            InModuleScope -ScriptBlock {
                $script:mockInstance.Modify(@{ _exist = $false })

                $script:mockInvokeApiMethod | Should -Be 'PUT'
                $script:mockInvokeApiPath | Should -Match '/permissions/cluster-policies/test-policy-123'
                $script:mockInvokeApiBody.access_control_list | Should -HaveCount 0
            }
        }
    }

    Context 'When permissions should be created' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksClusterPolicyPermission] @{
                    WorkspaceUrl      = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken       = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    ClusterPolicyId   = 'test-policy-123'
                    AccessControlList = @(
                        [ClusterPolicyAccessControlEntry]@{
                            GroupName       = 'admins'
                            PermissionLevel = 'CAN_USE'
                        }
                    )
                }

                $script:mockInstance._exist = $false

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param($Method, $Path, $Body)

                        $script:mockInvokeApiMethod = $Method
                        $script:mockInvokeApiPath = $Path
                        $script:mockInvokeApiBody = $Body
                    } -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                        return @{
                            _exist = $false
                        }
                    } -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'BuildPermissionPayload' -Value {
                        return @{
                            access_control_list = @(
                                @{
                                    group_name       = 'admins'
                                    permission_level = 'CAN_USE'
                                }
                            )
                        }
                    }
            }
        }

        It 'Should call API with PUT method to create permissions' {
            InModuleScope -ScriptBlock {
                $script:mockInstance.Modify(@{ _exist = $true })

                $script:mockInvokeApiMethod | Should -Be 'PUT'
                $script:mockInvokeApiPath | Should -Match '/permissions/cluster-policies/test-policy-123'
            }
        }
    }

    Context 'When permissions should be updated' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockInstance = [DatabricksClusterPolicyPermission] @{
                    WorkspaceUrl      = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken       = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    ClusterPolicyId   = 'test-policy-123'
                    AccessControlList = @(
                        [ClusterPolicyAccessControlEntry]@{
                            GroupName       = 'admins'
                            PermissionLevel = 'CAN_USE'
                        }
                    )
                }

                $script:mockInstance._exist = $true

                Mock -CommandName Write-Verbose

                $script:mockInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param($Method, $Path, $Body)

                        $script:mockInvokeApiMethod = $Method
                        $script:mockInvokeApiPath = $Path
                        $script:mockInvokeApiBody = $Body
                    } -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                        return @{
                            _exist              = $true
                            AccessControlList   = @(
                                [ClusterPolicyAccessControlEntry]@{
                                    GroupName       = 'users'
                                    PermissionLevel = 'CAN_USE'
                                }
                            )
                        }
                    } -PassThru |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'BuildPermissionPayload' -Value {
                        return @{
                            access_control_list = @(
                                @{
                                    group_name       = 'admins'
                                    permission_level = 'CAN_USE'
                                }
                            )
                        }
                    }
            }
        }

        It 'Should call API with PATCH method to update permissions' {
            InModuleScope -ScriptBlock {
                $script:mockInstance.Modify(@{ AccessControlList = $script:mockInstance.AccessControlList })

                $script:mockInvokeApiMethod | Should -Be 'PATCH'
                $script:mockInvokeApiPath | Should -Match '/permissions/cluster-policies/test-policy-123'
            }
        }
    }
}

Describe 'DatabricksClusterPolicyPermission\BuildPermissionPayload()' -Tag 'BuildPermissionPayload' {
    BeforeAll {
        InModuleScope -ScriptBlock {
            $script:mockInstance = [DatabricksClusterPolicyPermission] @{
                WorkspaceUrl    = 'https://adb-1234567890123456.12.azuredatabricks.net'
                AccessToken     = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                ClusterPolicyId = 'test-policy-123'
            }
        }
    }

    Context 'When building payload with group principal' {
        It 'Should include group_name in payload' {
            InModuleScope -ScriptBlock {
                $script:mockInstance.AccessControlList = @(
                    [ClusterPolicyAccessControlEntry]@{
                        GroupName       = 'admins'
                        PermissionLevel = 'CAN_USE'
                    }
                )

                $payload = $script:mockInstance.BuildPermissionPayload(@{ AccessControlList = $script:mockInstance.AccessControlList })

                $payload.access_control_list | Should -HaveCount 1
                $payload.access_control_list[0].group_name | Should -Be 'admins'
                $payload.access_control_list[0].permission_level | Should -Be 'CAN_USE'
            }
        }
    }

    Context 'When building payload with user principal' {
        It 'Should include user_name in payload' {
            InModuleScope -ScriptBlock {
                $script:mockInstance.AccessControlList = @(
                    [ClusterPolicyAccessControlEntry]@{
                        UserName        = 'user@example.com'
                        PermissionLevel = 'CAN_USE'
                    }
                )

                $payload = $script:mockInstance.BuildPermissionPayload(@{ AccessControlList = $script:mockInstance.AccessControlList })

                $payload.access_control_list | Should -HaveCount 1
                $payload.access_control_list[0].user_name | Should -Be 'user@example.com'
            }
        }
    }

    Context 'When building payload with service principal' {
        It 'Should include service_principal_name in payload' {
            InModuleScope -ScriptBlock {
                $script:mockInstance.AccessControlList = @(
                    [ClusterPolicyAccessControlEntry]@{
                        ServicePrincipalName = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
                        PermissionLevel      = 'CAN_USE'
                    }
                )

                $payload = $script:mockInstance.BuildPermissionPayload(@{ AccessControlList = $script:mockInstance.AccessControlList })

                $payload.access_control_list | Should -HaveCount 1
                $payload.access_control_list[0].service_principal_name | Should -Be 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
            }
        }
    }

    Context 'When UserName has invalid format' {
        It 'Should throw an exception' {
            InModuleScope -ScriptBlock {
                $script:mockInstance.AccessControlList = @(
                    [ClusterPolicyAccessControlEntry]@{
                        UserName        = 'invalid-email'
                        PermissionLevel = 'CAN_USE'
                    }
                )

                {
                    $script:mockInstance.BuildPermissionPayload(@{ AccessControlList = $script:mockInstance.AccessControlList })
                } | Should -Throw
            }
        }
    }

    Context 'When ServicePrincipalName has invalid GUID format' {
        It 'Should throw an exception' {
            InModuleScope -ScriptBlock {
                $script:mockInstance.AccessControlList = @(
                    [ClusterPolicyAccessControlEntry]@{
                        ServicePrincipalName = 'not-a-guid'
                        PermissionLevel      = 'CAN_USE'
                    }
                )

                {
                    $script:mockInstance.BuildPermissionPayload(@{ AccessControlList = $script:mockInstance.AccessControlList })
                } | Should -Throw
            }
        }
    }

    Context 'When no principal is specified' {
        It 'Should throw an exception' {
            InModuleScope -ScriptBlock {
                $script:mockInstance.AccessControlList = @(
                    [ClusterPolicyAccessControlEntry]@{
                        PermissionLevel = 'CAN_USE'
                    }
                )

                {
                    $script:mockInstance.BuildPermissionPayload(@{ AccessControlList = $script:mockInstance.AccessControlList })
                } | Should -Throw
            }
        }
    }
}

Describe 'DatabricksClusterPolicyPermission\AssertProperties()' -Tag 'AssertProperties' {
    Context 'When WorkspaceUrl is valid' {
        It 'Should not throw' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksClusterPolicyPermission] @{
                    WorkspaceUrl    = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken     = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    ClusterPolicyId = 'test-policy-123'
                }

                { $instance.AssertProperties(@{}) } | Should -Not -Throw
            }
        }
    }

    Context 'When WorkspaceUrl is invalid' {
        It 'Should throw' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksClusterPolicyPermission] @{
                    WorkspaceUrl    = 'http://invalid.com'
                    AccessToken     = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    ClusterPolicyId = 'test-policy-123'
                }

                { $instance.AssertProperties(@{}) } | Should -Throw -ExpectedMessage '*WorkspaceUrl*'
            }
        }
    }

    Context 'When ClusterPolicyId is empty' {
        It 'Should throw with ClusterPolicyIdRequired message' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksClusterPolicyPermission] @{
                    WorkspaceUrl    = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken     = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    ClusterPolicyId = ''
                }

                { $instance.AssertProperties(@{}) } | Should -Throw
            }
        }
    }

    Context 'When ClusterPolicyId is whitespace' {
        It 'Should throw with ClusterPolicyIdRequired message' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksClusterPolicyPermission] @{
                    WorkspaceUrl    = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken     = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    ClusterPolicyId = '   '
                }

                { $instance.AssertProperties(@{}) } | Should -Throw
            }
        }
    }

    Context 'When ACL entry has no principal' {
        It 'Should throw with NoPrincipalSpecified message' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksClusterPolicyPermission] @{
                    WorkspaceUrl      = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken       = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    ClusterPolicyId   = 'test-policy-123'
                    AccessControlList = @(
                        [ClusterPolicyAccessControlEntry]@{
                            PermissionLevel = 'CAN_USE'
                        }
                    )
                }

                { $instance.AssertProperties(@{}) } | Should -Throw
            }
        }
    }

    Context 'When ACL entry has only GroupName' {
        It 'Should not throw' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksClusterPolicyPermission] @{
                    WorkspaceUrl      = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken       = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    ClusterPolicyId   = 'test-policy-123'
                    AccessControlList = @(
                        [ClusterPolicyAccessControlEntry]@{
                            GroupName       = 'admins'
                            PermissionLevel = 'CAN_USE'
                        }
                    )
                }

                { $instance.AssertProperties(@{}) } | Should -Not -Throw
            }
        }
    }

    Context 'When ACL entry has only UserName' {
        It 'Should not throw' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksClusterPolicyPermission] @{
                    WorkspaceUrl      = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken       = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    ClusterPolicyId   = 'test-policy-123'
                    AccessControlList = @(
                        [ClusterPolicyAccessControlEntry]@{
                            UserName        = 'user@example.com'
                            PermissionLevel = 'CAN_USE'
                        }
                    )
                }

                { $instance.AssertProperties(@{}) } | Should -Not -Throw
            }
        }
    }

    Context 'When ACL entry has only ServicePrincipalName' {
        It 'Should not throw' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksClusterPolicyPermission] @{
                    WorkspaceUrl      = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken       = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    ClusterPolicyId   = 'test-policy-123'
                    AccessControlList = @(
                        [ClusterPolicyAccessControlEntry]@{
                            ServicePrincipalName = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
                            PermissionLevel      = 'CAN_USE'
                        }
                    )
                }

                { $instance.AssertProperties(@{}) } | Should -Not -Throw
            }
        }
    }

    Context 'When ACL entry has multiple principals (GroupName and UserName)' {
        It 'Should throw with MultiplePrincipalsSpecified message' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksClusterPolicyPermission] @{
                    WorkspaceUrl      = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken       = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    ClusterPolicyId   = 'test-policy-123'
                    AccessControlList = @(
                        [ClusterPolicyAccessControlEntry]@{
                            GroupName       = 'admins'
                            UserName        = 'user@example.com'
                            PermissionLevel = 'CAN_USE'
                        }
                    )
                }

                { $instance.AssertProperties(@{}) } | Should -Throw
            }
        }
    }

    Context 'When ACL entry has multiple principals (UserName and ServicePrincipalName)' {
        It 'Should throw with MultiplePrincipalsSpecified message' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksClusterPolicyPermission] @{
                    WorkspaceUrl      = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken       = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    ClusterPolicyId   = 'test-policy-123'
                    AccessControlList = @(
                        [ClusterPolicyAccessControlEntry]@{
                            UserName             = 'user@example.com'
                            ServicePrincipalName = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
                            PermissionLevel      = 'CAN_USE'
                        }
                    )
                }

                { $instance.AssertProperties(@{}) } | Should -Throw
            }
        }
    }

    Context 'When ACL entry has all three principals' {
        It 'Should throw with MultiplePrincipalsSpecified message' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksClusterPolicyPermission] @{
                    WorkspaceUrl      = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken       = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    ClusterPolicyId   = 'test-policy-123'
                    AccessControlList = @(
                        [ClusterPolicyAccessControlEntry]@{
                            GroupName            = 'admins'
                            UserName             = 'user@example.com'
                            ServicePrincipalName = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
                            PermissionLevel      = 'CAN_USE'
                        }
                    )
                }

                { $instance.AssertProperties(@{}) } | Should -Throw
            }
        }
    }
}
