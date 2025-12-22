#Requires -Module DatabricksDsc

BeforeAll {
    $script:dscModuleName = 'DatabricksDsc'

    # Import the module
    $modulePath = Join-Path -Path $PSScriptRoot -ChildPath '../../../output/module/DatabricksDsc' -Resolve
    Import-Module -Name $modulePath -Force

    $PSDefaultParameterValues['InModuleScope:ModuleName'] = $script:dscModuleName
}

AfterAll {
    $PSDefaultParameterValues.Remove('InModuleScope:ModuleName')
    Remove-Module -Name $script:dscModuleName -Force -ErrorAction SilentlyContinue
}

Describe 'SqlWarehouseChannel' -Tag 'SqlWarehouseChannel' {
    Context 'Class instantiation' {
        It 'Should instantiate without errors' {
            InModuleScope -ScriptBlock {
                { [SqlWarehouseChannel]::new() } | Should -Not -Throw
            }
        }

        It 'Should allow setting Name property' {
            InModuleScope -ScriptBlock {
                $instance = [SqlWarehouseChannel] @{
                    Name = 'CHANNEL_NAME_CURRENT'
                }

                $instance.Name | Should -Be 'CHANNEL_NAME_CURRENT'
            }
        }

        It 'Should allow setting DbsqlVersion property' {
            InModuleScope -ScriptBlock {
                $instance = [SqlWarehouseChannel] @{
                    Name         = 'CHANNEL_NAME_PREVIEW'
                    DbsqlVersion = '2024.20'
                }

                $instance.DbsqlVersion | Should -Be '2024.20'
            }
        }
    }

    Context 'Equals() method' {
        It 'Should return $true when objects are equal' {
            InModuleScope -ScriptBlock {
                $instance1 = [SqlWarehouseChannel] @{
                    Name         = 'CHANNEL_NAME_CURRENT'
                    DbsqlVersion = '2024.20'
                }

                $instance2 = [SqlWarehouseChannel] @{
                    Name         = 'CHANNEL_NAME_CURRENT'
                    DbsqlVersion = '2024.20'
                }

                $instance1.Equals($instance2) | Should -BeTrue
            }
        }

        It 'Should return $false when Name is different' {
            InModuleScope -ScriptBlock {
                $instance1 = [SqlWarehouseChannel] @{
                    Name = 'CHANNEL_NAME_CURRENT'
                }

                $instance2 = [SqlWarehouseChannel] @{
                    Name = 'CHANNEL_NAME_PREVIEW'
                }

                $instance1.Equals($instance2) | Should -BeFalse
            }
        }

        It 'Should return $false when DbsqlVersion is different' {
            InModuleScope -ScriptBlock {
                $instance1 = [SqlWarehouseChannel] @{
                    Name         = 'CHANNEL_NAME_CURRENT'
                    DbsqlVersion = '2024.20'
                }

                $instance2 = [SqlWarehouseChannel] @{
                    Name         = 'CHANNEL_NAME_CURRENT'
                    DbsqlVersion = '2024.21'
                }

                $instance1.Equals($instance2) | Should -BeFalse
            }
        }

        It 'Should return $false when comparing with different type' {
            InModuleScope -ScriptBlock {
                $instance1 = [SqlWarehouseChannel] @{
                    Name = 'CHANNEL_NAME_CURRENT'
                }

                $instance1.Equals('not a SqlWarehouseChannel') | Should -BeFalse
            }
        }
    }

    Context 'ToString() method' {
        It 'Should return Name when DbsqlVersion is not specified' {
            InModuleScope -ScriptBlock {
                $instance = [SqlWarehouseChannel] @{
                    Name = 'CHANNEL_NAME_CURRENT'
                }

                $instance.ToString() | Should -Be 'CHANNEL_NAME_CURRENT'
            }
        }

        It 'Should return Name with DbsqlVersion when DbsqlVersion is specified' {
            InModuleScope -ScriptBlock {
                $instance = [SqlWarehouseChannel] @{
                    Name         = 'CHANNEL_NAME_CURRENT'
                    DbsqlVersion = '2024.20'
                }

                $instance.ToString() | Should -Be 'CHANNEL_NAME_CURRENT (2024.20)'
            }
        }
    }
}

Describe 'SqlWarehouseTag' -Tag 'SqlWarehouseTag' {
    Context 'Class instantiation' {
        It 'Should instantiate without errors' {
            InModuleScope -ScriptBlock {
                { [SqlWarehouseTag]::new() } | Should -Not -Throw
            }
        }

        It 'Should allow setting Key and Value properties' {
            InModuleScope -ScriptBlock {
                $instance = [SqlWarehouseTag] @{
                    Key   = 'Environment'
                    Value = 'Production'
                }

                $instance.Key | Should -Be 'Environment'
                $instance.Value | Should -Be 'Production'
            }
        }
    }

    Context 'Equals() method' {
        It 'Should return $true when objects are equal' {
            InModuleScope -ScriptBlock {
                $instance1 = [SqlWarehouseTag] @{
                    Key   = 'Environment'
                    Value = 'Production'
                }

                $instance2 = [SqlWarehouseTag] @{
                    Key   = 'Environment'
                    Value = 'Production'
                }

                $instance1.Equals($instance2) | Should -BeTrue
            }
        }

        It 'Should return $false when Key is different' {
            InModuleScope -ScriptBlock {
                $instance1 = [SqlWarehouseTag] @{
                    Key   = 'Environment'
                    Value = 'Production'
                }

                $instance2 = [SqlWarehouseTag] @{
                    Key   = 'Team'
                    Value = 'Production'
                }

                $instance1.Equals($instance2) | Should -BeFalse
            }
        }

        It 'Should return $false when Value is different' {
            InModuleScope -ScriptBlock {
                $instance1 = [SqlWarehouseTag] @{
                    Key   = 'Environment'
                    Value = 'Production'
                }

                $instance2 = [SqlWarehouseTag] @{
                    Key   = 'Environment'
                    Value = 'Development'
                }

                $instance1.Equals($instance2) | Should -BeFalse
            }
        }

        It 'Should return $false when comparing with different type' {
            InModuleScope -ScriptBlock {
                $instance1 = [SqlWarehouseTag] @{
                    Key   = 'Environment'
                    Value = 'Production'
                }

                $instance1.Equals('not a SqlWarehouseTag') | Should -BeFalse
            }
        }
    }

    Context 'ToString() method' {
        It 'Should return Key=Value format' {
            InModuleScope -ScriptBlock {
                $instance = [SqlWarehouseTag] @{
                    Key   = 'Environment'
                    Value = 'Production'
                }

                $instance.ToString() | Should -Be 'Environment=Production'
            }
        }
    }
}

Describe 'SqlWarehouseTags' -Tag 'SqlWarehouseTags' {
    Context 'Class instantiation' {
        It 'Should instantiate without errors' {
            InModuleScope -ScriptBlock {
                { [SqlWarehouseTags]::new() } | Should -Not -Throw
            }
        }

        It 'Should allow setting CustomTags property' {
            InModuleScope -ScriptBlock {
                $instance = [SqlWarehouseTags] @{
                    CustomTags = @(
                        [SqlWarehouseTag] @{ Key = 'Environment'; Value = 'Production' }
                        [SqlWarehouseTag] @{ Key = 'Team'; Value = 'Data' }
                    )
                }

                $instance.CustomTags | Should -HaveCount 2
            }
        }
    }

    Context 'Equals() method' {
        It 'Should return $true when both have null CustomTags' {
            InModuleScope -ScriptBlock {
                $instance1 = [SqlWarehouseTags]::new()
                $instance2 = [SqlWarehouseTags]::new()

                $instance1.Equals($instance2) | Should -BeTrue
            }
        }

        It 'Should return $true when CustomTags are equal' {
            InModuleScope -ScriptBlock {
                $instance1 = [SqlWarehouseTags] @{
                    CustomTags = @(
                        [SqlWarehouseTag] @{ Key = 'Environment'; Value = 'Production' }
                    )
                }

                $instance2 = [SqlWarehouseTags] @{
                    CustomTags = @(
                        [SqlWarehouseTag] @{ Key = 'Environment'; Value = 'Production' }
                    )
                }

                $instance1.Equals($instance2) | Should -BeTrue
            }
        }

        It 'Should return $false when CustomTags count is different' {
            InModuleScope -ScriptBlock {
                $instance1 = [SqlWarehouseTags] @{
                    CustomTags = @(
                        [SqlWarehouseTag] @{ Key = 'Environment'; Value = 'Production' }
                    )
                }

                $instance2 = [SqlWarehouseTags] @{
                    CustomTags = @(
                        [SqlWarehouseTag] @{ Key = 'Environment'; Value = 'Production' }
                        [SqlWarehouseTag] @{ Key = 'Team'; Value = 'Data' }
                    )
                }

                $instance1.Equals($instance2) | Should -BeFalse
            }
        }

        It 'Should return $false when CustomTags values differ' {
            InModuleScope -ScriptBlock {
                $instance1 = [SqlWarehouseTags] @{
                    CustomTags = @(
                        [SqlWarehouseTag] @{ Key = 'Environment'; Value = 'Production' }
                    )
                }

                $instance2 = [SqlWarehouseTags] @{
                    CustomTags = @(
                        [SqlWarehouseTag] @{ Key = 'Environment'; Value = 'Development' }
                    )
                }

                $instance1.Equals($instance2) | Should -BeFalse
            }
        }

        It 'Should return $false when comparing with different type' {
            InModuleScope -ScriptBlock {
                $instance1 = [SqlWarehouseTags] @{
                    CustomTags = @(
                        [SqlWarehouseTag] @{ Key = 'Environment'; Value = 'Production' }
                    )
                }

                $instance1.Equals('not a SqlWarehouseTags') | Should -BeFalse
            }
        }
    }

    Context 'ToString() method' {
        It 'Should return empty string when CustomTags is null' {
            InModuleScope -ScriptBlock {
                $instance = [SqlWarehouseTags]::new()

                $instance.ToString() | Should -Be ''
            }
        }

        It 'Should return comma-separated list of tags' {
            InModuleScope -ScriptBlock {
                $instance = [SqlWarehouseTags] @{
                    CustomTags = @(
                        [SqlWarehouseTag] @{ Key = 'Environment'; Value = 'Production' }
                        [SqlWarehouseTag] @{ Key = 'Team'; Value = 'Data' }
                    )
                }

                $instance.ToString() | Should -Be 'Environment=Production, Team=Data'
            }
        }
    }
}
