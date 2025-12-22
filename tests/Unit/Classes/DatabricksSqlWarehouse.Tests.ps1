#Requires -Module DatabricksDsc

BeforeDiscovery {
    try
    {
        if (-not (Get-Module -Name DscResource.Test))
        {
            # Assumes dependencies has been resolved, so if this module is not available, run 'noop' task.
            if (-not (Get-Module -Name DscResource.Test -ListAvailable))
            {
                # Redirect all streams to $null, except the error stream (stream 2)
                & "$PSScriptRoot/../../build.ps1" -Tasks 'noop' 2>&1 4>&1 5>&1 6>&1 > $null
            }

            # If the dependencies has not been resolved, this will throw an error.
            Import-Module -Name DscResource.Test -Force -ErrorAction 'Stop'
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

    Remove-Module -Name DatabricksDsc -Force -ErrorAction SilentlyContinue
}

Describe 'DatabricksSqlWarehouse' -Tag 'DatabricksSqlWarehouse' {
    Context 'Class instantiation' {
        It 'Should instantiate without errors' {
            InModuleScope -ScriptBlock {
                { [DatabricksSqlWarehouse]::new() } | Should -Not -Throw
            }
        }

        It 'Should have default value for _exist property' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksSqlWarehouse]::new()
                $instance._exist | Should -BeTrue
            }
        }

        It 'Should set ExcludeDscProperties in constructor' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksSqlWarehouse]::new()
                $instance.ExcludeDscProperties | Should -Contain 'WorkspaceUrl'
                $instance.ExcludeDscProperties | Should -Contain 'Name'
                $instance.ExcludeDscProperties | Should -Contain 'AccessToken'
                $instance.ExcludeDscProperties | Should -Not -Contain '_exist'
            }
        }

        It 'Should allow setting properties via constructor hashtable' {
            InModuleScope -ScriptBlock {
                $token = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force

                $instance = [DatabricksSqlWarehouse] @{
                    WorkspaceUrl   = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken    = $token
                    Name           = 'Test Warehouse'
                    ClusterSize    = 'Small'
                    MinNumClusters = 1
                    MaxNumClusters = 2
                }

                $instance.WorkspaceUrl | Should -Be 'https://adb-1234567890123456.12.azuredatabricks.net'
                $instance.Name | Should -Be 'Test Warehouse'
                $instance.ClusterSize | Should -Be 'Small'
                $instance.MinNumClusters | Should -Be 1
                $instance.MaxNumClusters | Should -Be 2
            }
        }
    }
}

Describe 'DatabricksSqlWarehouse\Get()' -Tag 'Get' {
    Context 'When calling Get method' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockSqlWarehouseInstance = [DatabricksSqlWarehouse] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    Name         = 'Test Warehouse'
                }

                Mock -CommandName Write-Verbose
            }
        }

        It 'Should return instance of DatabricksSqlWarehouse' {
            InModuleScope -ScriptBlock {
                $script:mockSqlWarehouseInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            warehouses = @()
                        }
                    }

                $result = $script:mockSqlWarehouseInstance.Get()
                $result.GetType().Name | Should -Be 'DatabricksSqlWarehouse'
            }
        }

        It 'Should call GetCurrentState with key properties' {
            InModuleScope -ScriptBlock {
                $script:mockSqlWarehouseInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            warehouses = @()
                        }
                    }

                $script:mockSqlWarehouseInstance.Get()

                Should -Invoke -CommandName Write-Verbose -ParameterFilter {
                    $Message -match 'Evaluating SQL warehouse state'
                }
            }
        }
    }
}

Describe 'DatabricksSqlWarehouse\Set()' -Tag 'Set' {
    Context 'When calling Set method' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockSqlWarehouseInstance = [DatabricksSqlWarehouse] @{
                    WorkspaceUrl   = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken    = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    Name           = 'Test Warehouse'
                    ClusterSize    = 'Small'
                    MinNumClusters = 1
                }

                Mock -CommandName Write-Verbose
            }
        }

        It 'Should not throw when warehouse needs to be created' {
            InModuleScope -ScriptBlock {
                $script:mockSqlWarehouseInstance._exist = $true

                $script:mockSqlWarehouseInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            warehouses = @()
                        }
                    }

                { $script:mockSqlWarehouseInstance.Set() } | Should -Not -Throw
            }
        }
    }
}

Describe 'DatabricksSqlWarehouse\Test()' -Tag 'Test' {
    Context 'When calling Test method' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockSqlWarehouseInstance = [DatabricksSqlWarehouse] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    Name         = 'Test Warehouse'
                }

                Mock -CommandName Write-Verbose
            }
        }

        It 'Should return $true when warehouse is in desired state' {
            InModuleScope -ScriptBlock {
                $script:mockSqlWarehouseInstance._exist = $false

                $script:mockSqlWarehouseInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            warehouses = @()
                        }
                    }

                $script:mockSqlWarehouseInstance.Test() | Should -BeTrue
            }
        }

        It 'Should return $false when warehouse is not in desired state' {
            InModuleScope -ScriptBlock {
                $script:mockSqlWarehouseInstance._exist = $true

                $script:mockSqlWarehouseInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            warehouses = @()
                        }
                    }

                $script:mockSqlWarehouseInstance.Test() | Should -BeFalse
            }
        }
    }
}

Describe 'DatabricksSqlWarehouse\GetCurrentState()' -Tag 'GetCurrentState' {
    Context 'When warehouse does not exist' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockSqlWarehouseInstance = [DatabricksSqlWarehouse] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    Name         = 'Test Warehouse'
                }

                Mock -CommandName Write-Verbose

                $script:mockSqlWarehouseInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            warehouses = @()
                        }
                    }
            }
        }

        It 'Should return the correct values with _exist = $false' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockSqlWarehouseInstance.GetCurrentState(
                    @{
                        Name = 'Test Warehouse'
                    }
                )

                $currentState.WorkspaceUrl | Should -Be 'https://adb-1234567890123456.12.azuredatabricks.net'
                $currentState.Name | Should -Be 'Test Warehouse'
                $currentState._exist | Should -BeFalse
                # Instance property should remain at default value (desired state)
                $script:mockSqlWarehouseInstance._exist | Should -BeTrue
            }
        }
    }

    Context 'When warehouse exists with minimal properties' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockSqlWarehouseInstance = [DatabricksSqlWarehouse] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    Name         = 'Test Warehouse'
                }

                Mock -CommandName Write-Verbose

                $script:mockSqlWarehouseInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            warehouses = @(
                                @{
                                    id             = 'warehouse-123'
                                    name           = 'Test Warehouse'
                                    cluster_size   = 'Small'
                                    min_num_clusters = 1
                                }
                            )
                        }
                    }
            }
        }

        It 'Should return the correct values with _exist = $true' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockSqlWarehouseInstance.GetCurrentState(
                    @{
                        Name = 'Test Warehouse'
                    }
                )

                $currentState.WorkspaceUrl | Should -Be 'https://adb-1234567890123456.12.azuredatabricks.net'
                $currentState.Name | Should -Be 'Test Warehouse'
                $currentState.WarehouseId | Should -Be 'warehouse-123'
                $currentState.ClusterSize | Should -Be 'Small'
                $currentState.MinNumClusters | Should -Be 1
                $currentState._exist | Should -BeTrue
                $script:mockSqlWarehouseInstance._exist | Should -BeTrue
            }
        }
    }

    Context 'When warehouse exists with all properties' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockSqlWarehouseInstance = [DatabricksSqlWarehouse] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    Name         = 'Test Warehouse'
                }

                Mock -CommandName Write-Verbose

                $script:mockSqlWarehouseInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            warehouses = @(
                                @{
                                    id                        = 'warehouse-123'
                                    name                      = 'Test Warehouse'
                                    cluster_size              = 'Medium'
                                    auto_stop_mins            = 60
                                    enable_photon             = $true
                                    enable_serverless_compute = $false
                                    max_num_clusters          = 5
                                    min_num_clusters          = 2
                                    spot_instance_policy      = 'COST_OPTIMIZED'
                                    warehouse_type            = 'PRO'
                                    channel                   = @{
                                        name         = 'CHANNEL_NAME_CURRENT'
                                        dbsql_version = '2024.20'
                                    }
                                    tags                      = @{
                                        custom_tags = @(
                                            @{
                                                key   = 'Environment'
                                                value = 'Production'
                                            },
                                            @{
                                                key   = 'Team'
                                                value = 'Data'
                                            }
                                        )
                                    }
                                }
                            )
                        }
                    }
            }
        }

        It 'Should return all properties correctly' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockSqlWarehouseInstance.GetCurrentState(
                    @{
                        Name = 'Test Warehouse'
                    }
                )

                $currentState.WarehouseId | Should -Be 'warehouse-123'
                $currentState.ClusterSize | Should -Be 'Medium'
                $currentState.AutoStopMins | Should -Be 60
                $currentState.EnablePhoton | Should -BeTrue
                $currentState.EnableServerlessCompute | Should -BeFalse
                $currentState.MaxNumClusters | Should -Be 5
                $currentState.MinNumClusters | Should -Be 2
                $currentState.SpotInstancePolicy | Should -Be 'COST_OPTIMIZED'
                $currentState.WarehouseType | Should -Be 'PRO'
            }
        }

        It 'Should convert Channel correctly' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockSqlWarehouseInstance.GetCurrentState(@{ Name = 'Test Warehouse' })

                $currentState.Channel | Should -Not -BeNullOrEmpty
                $currentState.Channel.Name | Should -Be 'CHANNEL_NAME_CURRENT'
                $currentState.Channel.DbsqlVersion | Should -Be '2024.20'
            }
        }

        It 'Should convert Tags correctly' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockSqlWarehouseInstance.GetCurrentState(@{ Name = 'Test Warehouse' })

                $currentState.Tags | Should -Not -BeNullOrEmpty
                $currentState.Tags.CustomTags | Should -HaveCount 2

                $envTag = $currentState.Tags.CustomTags | Where-Object { $_.Key -eq 'Environment' }
                $envTag.Value | Should -Be 'Production'

                $teamTag = $currentState.Tags.CustomTags | Where-Object { $_.Key -eq 'Team' }
                $teamTag.Value | Should -Be 'Data'
            }
        }
    }
}

Describe 'DatabricksSqlWarehouse\Modify()' -Tag 'Modify' {
    Context 'When creating a new warehouse' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockSqlWarehouseInstance = [DatabricksSqlWarehouse] @{
                    WorkspaceUrl   = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken    = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    Name           = 'Test Warehouse'
                    ClusterSize    = 'Small'
                    MinNumClusters = 1
                }

                Mock -CommandName Write-Verbose
            }
        }

        It 'Should call POST API to create warehouse' {
            InModuleScope -ScriptBlock {
                $script:apiCallMethod = $null
                $script:apiCallPath = $null

                $script:mockSqlWarehouseInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param ($method, $path, $body)
                        $script:apiCallMethod = $method
                        $script:apiCallPath = $path
                        return @{ id = 'warehouse-123' }
                    }

                $script:mockSqlWarehouseInstance.Modify(@{
                    _exist = $true
                })

                $script:apiCallMethod | Should -Be 'POST'
                $script:apiCallPath | Should -Be '/api/2.0/sql/warehouses'
            }
        }
    }

    Context 'When removing an existing warehouse' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockSqlWarehouseInstance = [DatabricksSqlWarehouse] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    Name         = 'Test Warehouse'
                    WarehouseId  = 'warehouse-123'
                }

                $script:mockSqlWarehouseInstance._exist = $false

                Mock -CommandName Write-Verbose
            }
        }

        It 'Should call DELETE API to remove warehouse' {
            InModuleScope -ScriptBlock {
                $script:apiCallMethod = $null
                $script:apiCallPath = $null

                $script:mockSqlWarehouseInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param ($method, $path, $body)
                        $script:apiCallMethod = $method
                        $script:apiCallPath = $path
                        return @{}
                    }

                $script:mockSqlWarehouseInstance.Modify(@{
                    _exist = $false
                })

                $script:apiCallMethod | Should -Be 'DELETE'
                $script:apiCallPath | Should -Be '/api/2.0/sql/warehouses/warehouse-123'
            }
        }
    }

    Context 'When updating an existing warehouse' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockSqlWarehouseInstance = [DatabricksSqlWarehouse] @{
                    WorkspaceUrl   = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken    = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    Name           = 'Test Warehouse'
                    WarehouseId    = 'warehouse-123'
                    ClusterSize    = 'Medium'
                    MinNumClusters = 2
                }

                Mock -CommandName Write-Verbose
            }
        }

        It 'Should call POST API to edit warehouse' {
            InModuleScope -ScriptBlock {
                $script:apiCallMethod = $null
                $script:apiCallPath = $null
                $script:apiCallBody = $null

                $script:mockSqlWarehouseInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param ($method, $path, $body)
                        $script:apiCallMethod = $method
                        $script:apiCallPath = $path
                        $script:apiCallBody = $body
                        return @{}
                    }

                $script:mockSqlWarehouseInstance.Modify(@{
                    ClusterSize = 'Medium'
                })

                $script:apiCallMethod | Should -Be 'POST'
                $script:apiCallPath | Should -Be '/api/2.0/sql/warehouses/warehouse-123/edit'
            }
        }
    }
}

Describe 'DatabricksSqlWarehouse\BuildWarehousePayload()' -Tag 'BuildWarehousePayload' {
    Context 'When building payload with various properties' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockSqlWarehouseInstance = [DatabricksSqlWarehouse] @{
                    WorkspaceUrl            = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken             = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    Name                    = 'Test Warehouse'
                    ClusterSize             = 'Small'
                    AutoStopMins            = 60
                    EnablePhoton            = $true
                    EnableServerlessCompute = $false
                    MinNumClusters          = 1
                    MaxNumClusters          = 5
                    SpotInstancePolicy      = 'COST_OPTIMIZED'
                    WarehouseType           = 'PRO'
                }
            }
        }

        It 'Should include all instance properties in payload' {
            InModuleScope -ScriptBlock {
                $payload = $script:mockSqlWarehouseInstance.BuildWarehousePayload(@{})

                $payload.name | Should -Be 'Test Warehouse'
                $payload.cluster_size | Should -Be 'Small'
                $payload.auto_stop_mins | Should -Be 60
                $payload.enable_photon | Should -BeTrue
                $payload.enable_serverless_compute | Should -BeFalse
                $payload.min_num_clusters | Should -Be 1
                $payload.max_num_clusters | Should -Be 5
                $payload.spot_instance_policy | Should -Be 'COST_OPTIMIZED'
                $payload.warehouse_type | Should -Be 'PRO'
            }
        }

        It 'Should use properties from $properties when provided' {
            InModuleScope -ScriptBlock {
                $payload = $script:mockSqlWarehouseInstance.BuildWarehousePayload(@{
                    ClusterSize    = 'Medium'
                    MinNumClusters = 2
                })

                $payload.cluster_size | Should -Be 'Medium'
                $payload.min_num_clusters | Should -Be 2
                # Other properties should come from instance
                $payload.auto_stop_mins | Should -Be 60
            }
        }
    }

    Context 'When building payload with Channel' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockSqlWarehouseInstance = [DatabricksSqlWarehouse] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    Name         = 'Test Warehouse'
                    Channel      = [SqlWarehouseChannel] @{
                        Name         = 'CHANNEL_NAME_PREVIEW'
                        DbsqlVersion = '2024.20'
                    }
                }
            }
        }

        It 'Should convert Channel to API format' {
            InModuleScope -ScriptBlock {
                $payload = $script:mockSqlWarehouseInstance.BuildWarehousePayload(@{})

                $payload.channel | Should -Not -BeNullOrEmpty
                $payload.channel.name | Should -Be 'CHANNEL_NAME_PREVIEW'
                $payload.channel.dbsql_version | Should -Be '2024.20'
            }
        }
    }

    Context 'When building payload with Tags' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockSqlWarehouseInstance = [DatabricksSqlWarehouse] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    Name         = 'Test Warehouse'
                    Tags         = [SqlWarehouseTags] @{
                        CustomTags = @(
                            [SqlWarehouseTag] @{ Key = 'Environment'; Value = 'Production' }
                            [SqlWarehouseTag] @{ Key = 'Team'; Value = 'Data' }
                        )
                    }
                }
            }
        }

        It 'Should convert Tags to API format' {
            InModuleScope -ScriptBlock {
                $payload = $script:mockSqlWarehouseInstance.BuildWarehousePayload(@{})

                $payload.tags | Should -Not -BeNullOrEmpty
                $payload.tags.custom_tags | Should -HaveCount 2

                $envTag = $payload.tags.custom_tags | Where-Object { $_.key -eq 'Environment' }
                $envTag.value | Should -Be 'Production'
            }
        }
    }
}

Describe 'DatabricksSqlWarehouse\AssertProperties()' -Tag 'AssertProperties' {
    Context 'When WorkspaceUrl is invalid' {
        It 'Should throw when WorkspaceUrl does not start with https://' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksSqlWarehouse] @{
                    WorkspaceUrl = 'http://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    Name         = 'Test Warehouse'
                }

                { $instance.AssertProperties(@{}) } | Should -Throw -ExpectedMessage '*must start with*https://*'
            }
        }
    }

    Context 'When AutoStopMins is invalid' {
        It 'Should throw when AutoStopMins is between 1 and 9' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksSqlWarehouse] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    Name         = 'Test Warehouse'
                    AutoStopMins = 5
                }

                { $instance.AssertProperties(@{}) } | Should -Throw -ExpectedMessage '*must be 0*or >= 10*'
            }
        }

        It 'Should not throw when AutoStopMins is 0' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksSqlWarehouse] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    Name         = 'Test Warehouse'
                    AutoStopMins = 0
                }

                { $instance.AssertProperties(@{}) } | Should -Not -Throw
            }
        }

        It 'Should not throw when AutoStopMins is >= 10' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksSqlWarehouse] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    Name         = 'Test Warehouse'
                    AutoStopMins = 10
                }

                { $instance.AssertProperties(@{}) } | Should -Not -Throw
            }
        }
    }

    Context 'When cluster count validation fails' {
        It 'Should throw when MaxNumClusters is less than MinNumClusters' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksSqlWarehouse] @{
                    WorkspaceUrl   = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken    = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    Name           = 'Test Warehouse'
                    MinNumClusters = 5
                    MaxNumClusters = 2
                }

                { $instance.AssertProperties(@{}) } | Should -Throw -ExpectedMessage '*must be greater than or equal*'
            }
        }
    }

    Context 'When serverless compute validation fails' {
        It 'Should throw when EnableServerlessCompute is true but WarehouseType is CLASSIC' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksSqlWarehouse] @{
                    WorkspaceUrl            = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken             = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    Name                    = 'Test Warehouse'
                    EnableServerlessCompute = $true
                    WarehouseType           = 'CLASSIC'
                }

                { $instance.AssertProperties(@{}) } | Should -Throw -ExpectedMessage '*requires WarehouseType to be*PRO*'
            }
        }

        It 'Should not throw when EnableServerlessCompute is true and WarehouseType is PRO' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksSqlWarehouse] @{
                    WorkspaceUrl            = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken             = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    Name                    = 'Test Warehouse'
                    EnableServerlessCompute = $true
                    WarehouseType           = 'PRO'
                }

                { $instance.AssertProperties(@{}) } | Should -Not -Throw
            }
        }
    }

    Context 'When tags count validation fails' {
        It 'Should throw when Tags count is >= 45' {
            InModuleScope -ScriptBlock {
                $customTags = @()
                for ($i = 0; $i -lt 45; $i++)
                {
                    $customTags += [SqlWarehouseTag] @{ Key = "Key$i"; Value = "Value$i" }
                }

                $instance = [DatabricksSqlWarehouse] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    Name         = 'Test Warehouse'
                    Tags         = [SqlWarehouseTags] @{ CustomTags = $customTags }
                }

                { $instance.AssertProperties(@{}) } | Should -Throw -ExpectedMessage '*Too many tags*'
            }
        }
    }
}

Describe 'DatabricksSqlWarehouse\Export()' -Tag 'Export' {
    Context 'When exporting all SQL warehouses' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockAccessToken = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                $script:mockWorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
            }
        }

        It 'Should export all SQL warehouses successfully' {
            InModuleScope -ScriptBlock {
                $filteringInstance = [DatabricksSqlWarehouse]::new()
                $filteringInstance.WorkspaceUrl = $script:mockWorkspaceUrl
                $filteringInstance.AccessToken = $script:mockAccessToken

                $filteringInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            warehouses = @(
                                @{
                                    id               = 'warehouse-1'
                                    name             = 'Warehouse One'
                                    cluster_size     = 'Small'
                                    min_num_clusters = 1
                                    max_num_clusters = 2
                                    warehouse_type   = 'PRO'
                                }
                                @{
                                    id               = 'warehouse-2'
                                    name             = 'Warehouse Two'
                                    cluster_size     = 'Medium'
                                    min_num_clusters = 2
                                    max_num_clusters = 5
                                    warehouse_type   = 'CLASSIC'
                                }
                                @{
                                    id               = 'warehouse-3'
                                    name             = 'Warehouse Three'
                                    cluster_size     = 'Large'
                                    min_num_clusters = 1
                                    max_num_clusters = 10
                                    warehouse_type   = 'PRO'
                                }
                            )
                        }
                    }

                $result = [DatabricksSqlWarehouse]::Export($filteringInstance)

                $result | Should -Not -BeNullOrEmpty
                $result.Count | Should -Be 3
                $result[0].Name | Should -Be 'Warehouse One'
                $result[0].WarehouseId | Should -Be 'warehouse-1'
                $result[0].ClusterSize | Should -Be 'Small'
                $result[0]._exist | Should -BeTrue
                $result[1].Name | Should -Be 'Warehouse Two'
                $result[2].Name | Should -Be 'Warehouse Three'
            }
        }

        It 'Should return empty array when no warehouses exist' {
            InModuleScope -ScriptBlock {
                $filteringInstance = [DatabricksSqlWarehouse]::new()
                $filteringInstance.WorkspaceUrl = $script:mockWorkspaceUrl
                $filteringInstance.AccessToken = $script:mockAccessToken

                $filteringInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            warehouses = @()
                        }
                    }

                $result = [DatabricksSqlWarehouse]::Export($filteringInstance)

                $result | Should -BeNullOrEmpty
            }
        }

        It 'Should return empty array when API returns null' {
            InModuleScope -ScriptBlock {
                $filteringInstance = [DatabricksSqlWarehouse]::new()
                $filteringInstance.WorkspaceUrl = $script:mockWorkspaceUrl
                $filteringInstance.AccessToken = $script:mockAccessToken

                $filteringInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return $null
                    }

                $result = [DatabricksSqlWarehouse]::Export($filteringInstance)

                $result | Should -BeNullOrEmpty
            }
        }
    }

    Context 'When filtering exported warehouses by WarehouseType' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockAccessToken = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                $script:mockWorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
            }
        }

        It 'Should filter warehouses by WarehouseType PRO' {
            InModuleScope -ScriptBlock {
                $filteringInstance = [DatabricksSqlWarehouse]::new()
                $filteringInstance.WorkspaceUrl = $script:mockWorkspaceUrl
                $filteringInstance.AccessToken = $script:mockAccessToken
                $filteringInstance.WarehouseType = 'PRO'

                $filteringInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            warehouses = @(
                                @{
                                    id             = 'warehouse-1'
                                    name           = 'Warehouse One'
                                    cluster_size   = 'Small'
                                    warehouse_type = 'PRO'
                                }
                                @{
                                    id             = 'warehouse-2'
                                    name           = 'Warehouse Two'
                                    cluster_size   = 'Medium'
                                    warehouse_type = 'CLASSIC'
                                }
                                @{
                                    id             = 'warehouse-3'
                                    name           = 'Warehouse Three'
                                    cluster_size   = 'Large'
                                    warehouse_type = 'PRO'
                                }
                            )
                        }
                    }

                $result = [DatabricksSqlWarehouse]::Export($filteringInstance)

                $result | Should -Not -BeNullOrEmpty
                $result.Count | Should -Be 2
                $result[0].Name | Should -Be 'Warehouse One'
                $result[0].WarehouseType | Should -Be 'PRO'
                $result[1].Name | Should -Be 'Warehouse Three'
                $result[1].WarehouseType | Should -Be 'PRO'
            }
        }

        It 'Should filter warehouses by WarehouseType CLASSIC' {
            InModuleScope -ScriptBlock {
                $filteringInstance = [DatabricksSqlWarehouse]::new()
                $filteringInstance.WorkspaceUrl = $script:mockWorkspaceUrl
                $filteringInstance.AccessToken = $script:mockAccessToken
                $filteringInstance.WarehouseType = 'CLASSIC'

                $filteringInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            warehouses = @(
                                @{
                                    id             = 'warehouse-1'
                                    name           = 'Warehouse One'
                                    cluster_size   = 'Small'
                                    warehouse_type = 'PRO'
                                }
                                @{
                                    id             = 'warehouse-2'
                                    name           = 'Warehouse Two'
                                    cluster_size   = 'Medium'
                                    warehouse_type = 'CLASSIC'
                                }
                            )
                        }
                    }

                $result = [DatabricksSqlWarehouse]::Export($filteringInstance)

                $result | Should -Not -BeNullOrEmpty
                $result.Count | Should -Be 1
                $result[0].Name | Should -Be 'Warehouse Two'
                $result[0].WarehouseType | Should -Be 'CLASSIC'
            }
        }
    }

    Context 'When filtering exported warehouses by ClusterSize' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockAccessToken = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                $script:mockWorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
            }
        }

        It 'Should filter warehouses by ClusterSize' {
            InModuleScope -ScriptBlock {
                $filteringInstance = [DatabricksSqlWarehouse]::new()
                $filteringInstance.WorkspaceUrl = $script:mockWorkspaceUrl
                $filteringInstance.AccessToken = $script:mockAccessToken
                $filteringInstance.ClusterSize = 'Small'

                $filteringInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            warehouses = @(
                                @{
                                    id           = 'warehouse-1'
                                    name         = 'Warehouse One'
                                    cluster_size = 'Small'
                                }
                                @{
                                    id           = 'warehouse-2'
                                    name         = 'Warehouse Two'
                                    cluster_size = 'Medium'
                                }
                                @{
                                    id           = 'warehouse-3'
                                    name         = 'Warehouse Three'
                                    cluster_size = 'Small'
                                }
                            )
                        }
                    }

                $result = [DatabricksSqlWarehouse]::Export($filteringInstance)

                $result | Should -Not -BeNullOrEmpty
                $result.Count | Should -Be 2
                $result[0].Name | Should -Be 'Warehouse One'
                $result[0].ClusterSize | Should -Be 'Small'
                $result[1].Name | Should -Be 'Warehouse Three'
                $result[1].ClusterSize | Should -Be 'Small'
            }
        }
    }

    Context 'When filtering by EnablePhoton' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockAccessToken = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                $script:mockWorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
            }
        }

        It 'Should filter warehouses by EnablePhoton = $true' {
            InModuleScope -ScriptBlock {
                $filteringInstance = [DatabricksSqlWarehouse]::new()
                $filteringInstance.WorkspaceUrl = $script:mockWorkspaceUrl
                $filteringInstance.AccessToken = $script:mockAccessToken
                $filteringInstance.EnablePhoton = $true

                $filteringInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            warehouses = @(
                                @{
                                    id            = 'warehouse-1'
                                    name          = 'Warehouse One'
                                    cluster_size  = 'Small'
                                    enable_photon = $true
                                }
                                @{
                                    id            = 'warehouse-2'
                                    name          = 'Warehouse Two'
                                    cluster_size  = 'Medium'
                                    enable_photon = $false
                                }
                                @{
                                    id            = 'warehouse-3'
                                    name          = 'Warehouse Three'
                                    cluster_size  = 'Large'
                                    enable_photon = $true
                                }
                            )
                        }
                    }

                $result = [DatabricksSqlWarehouse]::Export($filteringInstance)

                $result | Should -Not -BeNullOrEmpty
                $result.Count | Should -Be 2
                $result[0].EnablePhoton | Should -BeTrue
                $result[1].EnablePhoton | Should -BeTrue
            }
        }
    }

    Context 'When exporting warehouses with all properties' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockAccessToken = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                $script:mockWorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
            }
        }

        It 'Should export warehouses with Channel property correctly' {
            InModuleScope -ScriptBlock {
                $filteringInstance = [DatabricksSqlWarehouse]::new()
                $filteringInstance.WorkspaceUrl = $script:mockWorkspaceUrl
                $filteringInstance.AccessToken = $script:mockAccessToken

                $filteringInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            warehouses = @(
                                @{
                                    id           = 'warehouse-1'
                                    name         = 'Warehouse One'
                                    cluster_size = 'Small'
                                    channel      = @{
                                        name          = 'CHANNEL_NAME_CURRENT'
                                        dbsql_version = '2024.20'
                                    }
                                }
                            )
                        }
                    }

                $result = [DatabricksSqlWarehouse]::Export($filteringInstance)

                $result | Should -Not -BeNullOrEmpty
                $result.Count | Should -Be 1
                $result[0].Channel | Should -Not -BeNullOrEmpty
                $result[0].Channel.Name | Should -Be 'CHANNEL_NAME_CURRENT'
                $result[0].Channel.DbsqlVersion | Should -Be '2024.20'
            }
        }

        It 'Should export warehouses with Tags property correctly' {
            InModuleScope -ScriptBlock {
                $filteringInstance = [DatabricksSqlWarehouse]::new()
                $filteringInstance.WorkspaceUrl = $script:mockWorkspaceUrl
                $filteringInstance.AccessToken = $script:mockAccessToken

                $filteringInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            warehouses = @(
                                @{
                                    id           = 'warehouse-1'
                                    name         = 'Warehouse One'
                                    cluster_size = 'Small'
                                    tags         = @{
                                        custom_tags = @(
                                            @{
                                                key   = 'Environment'
                                                value = 'Production'
                                            }
                                            @{
                                                key   = 'Team'
                                                value = 'Data'
                                            }
                                        )
                                    }
                                }
                            )
                        }
                    }

                $result = [DatabricksSqlWarehouse]::Export($filteringInstance)

                $result | Should -Not -BeNullOrEmpty
                $result.Count | Should -Be 1
                $result[0].Tags | Should -Not -BeNullOrEmpty
                $result[0].Tags.CustomTags | Should -HaveCount 2

                $envTag = $result[0].Tags.CustomTags | Where-Object { $_.Key -eq 'Environment' }
                $envTag.Value | Should -Be 'Production'

                $teamTag = $result[0].Tags.CustomTags | Where-Object { $_.Key -eq 'Team' }
                $teamTag.Value | Should -Be 'Data'
            }
        }
    }

    Context 'When export fails' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockAccessToken = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                $script:mockWorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
            }
        }

        It 'Should return empty array on exception' {
            InModuleScope -ScriptBlock {
                $filteringInstance = [DatabricksSqlWarehouse]::new()
                $filteringInstance.WorkspaceUrl = $script:mockWorkspaceUrl
                $filteringInstance.AccessToken = $script:mockAccessToken

                $filteringInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        throw 'API Error'
                    }

                { $result = [DatabricksSqlWarehouse]::Export($filteringInstance) } | Should -Not -Throw

                $result = [DatabricksSqlWarehouse]::Export($filteringInstance)
                $result | Should -BeNullOrEmpty
            }
        }
    }
}
