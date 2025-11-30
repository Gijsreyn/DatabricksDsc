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

Describe 'DatabricksSecretScope' -Tag 'DatabricksSecretScope' {
    Context 'Class instantiation' {
        It 'Should instantiate without errors' {
            InModuleScope -ScriptBlock {
                { [DatabricksSecretScope]::new() } | Should -Not -Throw
            }
        }

        It 'Should have default value for _exist property' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksSecretScope]::new()
                $instance._exist | Should -BeTrue
            }
        }

        It 'Should set ExcludeDscProperties in constructor' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksSecretScope]::new()
                $instance.ExcludeDscProperties | Should -Contain 'WorkspaceUrl'
                $instance.ExcludeDscProperties | Should -Contain 'ScopeName'
                $instance.ExcludeDscProperties | Should -Contain 'AccessToken'
                $instance.ExcludeDscProperties | Should -Not -Contain '_exist'
            }
        }

        It 'Should allow setting properties via constructor hashtable' {
            InModuleScope -ScriptBlock {
                $token = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force

                $instance = [DatabricksSecretScope] @{
                    WorkspaceUrl     = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken      = $token
                    ScopeName        = 'test-scope'
                    ScopeBackendType = 'DATABRICKS'
                }

                $instance.WorkspaceUrl | Should -Be 'https://adb-1234567890123456.12.azuredatabricks.net'
                $instance.ScopeName | Should -Be 'test-scope'
                $instance.ScopeBackendType | Should -Be 'DATABRICKS'
            }
        }

        It 'Should validate ScopeName pattern' {
            InModuleScope -ScriptBlock {
                $token = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force

                # Valid scope names
                { [DatabricksSecretScope] @{
                    WorkspaceUrl     = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken      = $token
                    ScopeName        = 'valid-scope_name.123'
                    ScopeBackendType = 'DATABRICKS'
                }} | Should -Not -Throw

                # Invalid scope name (contains space)
                { [DatabricksSecretScope] @{
                    WorkspaceUrl     = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken      = $token
                    ScopeName        = 'invalid scope'
                    ScopeBackendType = 'DATABRICKS'
                }} | Should -Throw
            }
        }
    }
}

Describe 'DatabricksSecretScope\Get()' -Tag 'Get' {
    Context 'When calling Get method' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockSecretScopeInstance = [DatabricksSecretScope] @{
                    WorkspaceUrl     = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken      = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    ScopeName        = 'test-scope'
                    ScopeBackendType = 'DATABRICKS'
                }
            }
        }

        It 'Should return current state when scope exists' {
            InModuleScope -ScriptBlock {
                Mock -CommandName Get-DatabricksSecretScope -MockWith {
                    return [PSCustomObject] @{
                        name         = 'test-scope'
                        backend_type = 'DATABRICKS'
                    }
                }

                $result = $script:mockSecretScopeInstance.Get()

                $result | Should -Not -BeNullOrEmpty
                $result._exist | Should -BeTrue
                $result.ScopeName | Should -Be 'test-scope'
                $result.ScopeBackendType | Should -Be 'DATABRICKS'

                Should -Invoke -CommandName Get-DatabricksSecretScope -Exactly -Times 1
            }
        }

        It 'Should return _exist as false when scope does not exist' {
            InModuleScope -ScriptBlock {
                Mock -CommandName Get-DatabricksSecretScope -MockWith {
                    return $null
                }

                $result = $script:mockSecretScopeInstance.Get()

                $result | Should -Not -BeNullOrEmpty
                $result._exist | Should -BeFalse
                $result.ScopeName | Should -Be 'test-scope'

                Should -Invoke -CommandName Get-DatabricksSecretScope -Exactly -Times 1
            }
        }

        It 'Should return Azure Key Vault backend details when scope is AKV-backed' {
            InModuleScope -ScriptBlock {
                Mock -CommandName Get-DatabricksSecretScope -MockWith {
                    return [PSCustomObject] @{
                        name              = 'test-akv-scope'
                        backend_type      = 'AZURE_KEYVAULT'
                        keyvault_metadata = @{
                            resource_id = '/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault'
                            dns_name    = 'https://vault.vault.azure.net/'
                        }
                    }
                }

                $akvInstance = [DatabricksSecretScope] @{
                    WorkspaceUrl     = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken      = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    ScopeName        = 'test-akv-scope'
                    ScopeBackendType = 'AZURE_KEYVAULT'
                    BackendAzureKeyVault = [AzureKeyVaultBackend] @{
                        DnsName    = 'https://vault.vault.azure.net/'
                        ResourceId = '/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault'
                    }
                }

                $result = $akvInstance.Get()

                $result | Should -Not -BeNullOrEmpty
                $result._exist | Should -BeTrue
                $result.ScopeBackendType | Should -Be 'AZURE_KEYVAULT'
                $result.BackendAzureKeyVault | Should -Not -BeNullOrEmpty
                $result.BackendAzureKeyVault.DnsName | Should -Be 'https://vault.vault.azure.net/'
                $result.BackendAzureKeyVault.ResourceId | Should -Be '/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault'
            }
        }
    }
}

Describe 'DatabricksSecretScope\Test()' -Tag 'Test' {
    Context 'When testing desired state' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockSecretScopeInstance = [DatabricksSecretScope] @{
                    WorkspaceUrl     = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken      = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    ScopeName        = 'test-scope'
                    ScopeBackendType = 'DATABRICKS'
                }
            }
        }

        It 'Should return true when scope exists and properties match' {
            InModuleScope -ScriptBlock {
                Mock -CommandName Get-DatabricksSecretScope -MockWith {
                    return [PSCustomObject] @{
                        name         = 'test-scope'
                        backend_type = 'DATABRICKS'
                    }
                }

                $result = $script:mockSecretScopeInstance.Test()

                $result | Should -BeTrue

                Should -Invoke -CommandName Get-DatabricksSecretScope -Exactly -Times 1
            }
        }

        It 'Should return false when scope does not exist but should' {
            InModuleScope -ScriptBlock {
                Mock -CommandName Get-DatabricksSecretScope -MockWith {
                    return $null
                }

                $result = $script:mockSecretScopeInstance.Test()

                $result | Should -BeFalse

                Should -Invoke -CommandName Get-DatabricksSecretScope -Exactly -Times 1
            }
        }

        It 'Should return false when scope exists but should not' {
            InModuleScope -ScriptBlock {
                Mock -CommandName Get-DatabricksSecretScope -MockWith {
                    return [PSCustomObject] @{
                        name         = 'test-scope'
                        backend_type = 'DATABRICKS'
                    }
                }

                $script:mockSecretScopeInstance._exist = $false

                $result = $script:mockSecretScopeInstance.Test()

                $result | Should -BeFalse

                # Reset for other tests
                $script:mockSecretScopeInstance._exist = $true

                Should -Invoke -CommandName Get-DatabricksSecretScope -Exactly -Times 1
            }
        }

        It 'Should return false when backend type differs' {
            InModuleScope -ScriptBlock {
                Mock -CommandName Get-DatabricksSecretScope -MockWith {
                    return [PSCustomObject] @{
                        name         = 'test-scope'
                        backend_type = 'AZURE_KEYVAULT'
                        keyvault_metadata = @{
                            resource_id = '/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault'
                            dns_name    = 'https://vault.vault.azure.net/'
                        }
                    }
                }

                # Instance expects DATABRICKS but API returns AZURE_KEYVAULT
                $result = $script:mockSecretScopeInstance.Test()

                $result | Should -BeFalse

                Should -Invoke -CommandName Get-DatabricksSecretScope -Exactly -Times 1
            }
        }
    }
}

Describe 'DatabricksSecretScope\Set()' -Tag 'Set' {
    Context 'When enforcing desired state' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockSecretScopeInstance = [DatabricksSecretScope] @{
                    WorkspaceUrl     = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken      = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    ScopeName        = 'test-scope'
                    ScopeBackendType = 'DATABRICKS'
                }
            }
        }

        It 'Should create scope when it does not exist' {
            InModuleScope -ScriptBlock {
                Mock -CommandName Get-DatabricksSecretScope -MockWith {
                    return $null
                }

                Mock -CommandName New-DatabricksSecretScope -MockWith {
                    return @{}
                }

                { $script:mockSecretScopeInstance.Set() } | Should -Not -Throw

                Should -Invoke -CommandName Get-DatabricksSecretScope -Exactly -Times 1
                Should -Invoke -CommandName New-DatabricksSecretScope -Exactly -Times 1
            }
        }

        It 'Should remove scope when it exists but should not' {
            InModuleScope -ScriptBlock {
                Mock -CommandName Get-DatabricksSecretScope -MockWith {
                    return [PSCustomObject] @{
                        name         = 'test-scope'
                        backend_type = 'DATABRICKS'
                    }
                }

                Mock -CommandName Remove-DatabricksSecretScope -MockWith {
                    return @{}
                }

                $script:mockSecretScopeInstance._exist = $false

                { $script:mockSecretScopeInstance.Set() } | Should -Not -Throw

                # Reset for other tests
                $script:mockSecretScopeInstance._exist = $true

                Should -Invoke -CommandName Get-DatabricksSecretScope -Exactly -Times 1
                Should -Invoke -CommandName Remove-DatabricksSecretScope -Exactly -Times 1
            }
        }

        It 'Should recreate scope when properties differ' {
            InModuleScope -ScriptBlock {
                Mock -CommandName Get-DatabricksSecretScope -MockWith {
                    return [PSCustomObject] @{
                        name         = 'test-scope'
                        backend_type = 'AZURE_KEYVAULT'
                        keyvault_metadata = @{
                            resource_id = '/subscriptions/old/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault'
                            dns_name    = 'https://oldvault.vault.azure.net/'
                        }
                    }
                }

                Mock -CommandName Remove-DatabricksSecretScope -MockWith {
                    return @{}
                }

                Mock -CommandName New-DatabricksSecretScope -MockWith {
                    return @{}
                }

                # Instance wants DATABRICKS but current is AZURE_KEYVAULT
                { $script:mockSecretScopeInstance.Set() } | Should -Not -Throw

                Should -Invoke -CommandName Get-DatabricksSecretScope -Exactly -Times 1
                Should -Invoke -CommandName Remove-DatabricksSecretScope -Exactly -Times 1
                Should -Invoke -CommandName New-DatabricksSecretScope -Exactly -Times 1
            }
        }

        It 'Should create Azure Key Vault-backed scope with correct parameters' {
            InModuleScope -ScriptBlock {
                Mock -CommandName Get-DatabricksSecretScope -MockWith {
                    return $null
                }

                Mock -CommandName New-DatabricksSecretScope -MockWith {
                    return @{}
                }

                $akvInstance = [DatabricksSecretScope] @{
                    WorkspaceUrl              = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken               = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    ScopeName                 = 'test-akv-scope'
                    ScopeBackendType          = 'AZURE_KEYVAULT'
                    InitialManagePrincipal    = 'users'
                    BackendAzureKeyVault      = [AzureKeyVaultBackend] @{
                        DnsName    = 'https://myvault.vault.azure.net/'
                        ResourceId = '/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault'
                    }
                }

                { $akvInstance.Set() } | Should -Not -Throw

                Should -Invoke -CommandName Get-DatabricksSecretScope -Exactly -Times 1
                Should -Invoke -CommandName New-DatabricksSecretScope -Exactly -Times 1 -ParameterFilter {
                    $ScopeName -eq 'test-akv-scope' -and
                    $ScopeBackendType -eq 'AZURE_KEYVAULT' -and
                    $InitialManagePrincipal -eq 'users' -and
                    $BackendAzureKeyVault.ResourceId -eq '/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault' -and
                    $BackendAzureKeyVault.DnsName -eq 'https://myvault.vault.azure.net/'
                }
            }
        }

        It 'Should not call any API when scope is in desired state' {
            InModuleScope -ScriptBlock {
                Mock -CommandName Get-DatabricksSecretScope -MockWith {
                    return [PSCustomObject] @{
                        name         = 'test-scope'
                        backend_type = 'DATABRICKS'
                    }
                }

                Mock -CommandName New-DatabricksSecretScope -MockWith {
                    return @{}
                }

                Mock -CommandName Remove-DatabricksSecretScope -MockWith {
                    return @{}
                }

                { $script:mockSecretScopeInstance.Set() } | Should -Not -Throw

                Should -Invoke -CommandName Get-DatabricksSecretScope -Exactly -Times 1
                Should -Invoke -CommandName New-DatabricksSecretScope -Exactly -Times 0
                Should -Invoke -CommandName Remove-DatabricksSecretScope -Exactly -Times 0
            }
        }
    }
}

Describe 'DatabricksSecretScope\AssertProperties()' -Tag 'AssertProperties' {
    Context 'When validating properties' {
        It 'Should throw when WorkspaceUrl does not start with https://' {
            InModuleScope -ScriptBlock {
                $token = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force

                $instance = [DatabricksSecretScope] @{
                    WorkspaceUrl     = 'http://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken      = $token
                    ScopeName        = 'test-scope'
                    ScopeBackendType = 'DATABRICKS'
                }

                { $instance.Test() } | Should -Throw
            }
        }

        It 'Should throw when BackendAzureKeyVault is missing for AZURE_KEYVAULT type' {
            InModuleScope -ScriptBlock {
                $token = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force

                $instance = [DatabricksSecretScope] @{
                    WorkspaceUrl     = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken      = $token
                    ScopeName        = 'test-akv-scope'
                    ScopeBackendType = 'AZURE_KEYVAULT'
                }

                { $instance.Test() } | Should -Throw
            }
        }

        It 'Should throw when ScopeName contains invalid characters' {
            InModuleScope -ScriptBlock {
                $token = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force

                {
                    [DatabricksSecretScope] @{
                        WorkspaceUrl     = 'https://adb-1234567890123456.12.azuredatabricks.net'
                        AccessToken      = $token
                        ScopeName        = 'invalid@scope#name'
                        ScopeBackendType = 'DATABRICKS'
                    }
                } | Should -Throw
            }
        }

        It 'Should not throw when all properties are valid' {
            InModuleScope -ScriptBlock {
                Mock -CommandName Get-DatabricksSecretScope -MockWith {
                    return [PSCustomObject] @{
                        name         = 'valid-scope_name.123'
                        backend_type = 'DATABRICKS'
                    }
                }

                $token = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force

                $instance = [DatabricksSecretScope] @{
                    WorkspaceUrl     = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken      = $token
                    ScopeName        = 'valid-scope_name.123'
                    ScopeBackendType = 'DATABRICKS'
                }

                { $instance.Test() } | Should -Not -Throw
            }
        }
    }
}

Describe 'AzureKeyVaultBackend' -Tag 'AzureKeyVaultBackend', 'Types' {
    Context 'Class instantiation and comparison' {
        It 'Should instantiate without errors' {
            InModuleScope -ScriptBlock {
                { [AzureKeyVaultBackend]::new() } | Should -Not -Throw
            }
        }

        It 'Should allow setting properties via constructor hashtable' {
            InModuleScope -ScriptBlock {
                $backend = [AzureKeyVaultBackend] @{
                    DnsName    = 'https://myvault.vault.azure.net/'
                    ResourceId = '/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault'
                }

                $backend.DnsName | Should -Be 'https://myvault.vault.azure.net/'
                $backend.ResourceId | Should -Be '/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault'
            }
        }

        It 'Should return true when comparing equal objects' {
            InModuleScope -ScriptBlock {
                $backend1 = [AzureKeyVaultBackend] @{
                    DnsName    = 'https://myvault.vault.azure.net/'
                    ResourceId = '/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault'
                }

                $backend2 = [AzureKeyVaultBackend] @{
                    DnsName    = 'https://myvault.vault.azure.net/'
                    ResourceId = '/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault'
                }

                $backend1.Equals($backend2) | Should -BeTrue
            }
        }

        It 'Should return false when comparing different objects' {
            InModuleScope -ScriptBlock {
                $backend1 = [AzureKeyVaultBackend] @{
                    DnsName    = 'https://myvault.vault.azure.net/'
                    ResourceId = '/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault'
                }

                $backend2 = [AzureKeyVaultBackend] @{
                    DnsName    = 'https://othervault.vault.azure.net/'
                    ResourceId = '/subscriptions/yyy/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault2'
                }

                $backend1.Equals($backend2) | Should -BeFalse
            }
        }

        It 'Should have correct ToString output' {
            InModuleScope -ScriptBlock {
                $backend = [AzureKeyVaultBackend] @{
                    DnsName    = 'https://myvault.vault.azure.net/'
                    ResourceId = '/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault'
                }

                $backend.ToString() | Should -Be 'https://myvault.vault.azure.net/ (/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault)'
            }
        }

        It 'Should compare correctly using CompareTo' {
            InModuleScope -ScriptBlock {
                $backend1 = [AzureKeyVaultBackend] @{
                    DnsName    = 'https://avault.vault.azure.net/'
                    ResourceId = '/subscriptions/aaa/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/avault'
                }

                $backend2 = [AzureKeyVaultBackend] @{
                    DnsName    = 'https://bvault.vault.azure.net/'
                    ResourceId = '/subscriptions/bbb/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/bvault'
                }

                $backend1.CompareTo($backend2) | Should -BeLessThan 0
                $backend2.CompareTo($backend1) | Should -BeGreaterThan 0
                $backend1.CompareTo($backend1) | Should -Be 0
            }
        }
    }
}

Describe 'DatabricksSecretScope\Export()' -Tag 'Export' {
    Context 'When exporting all secret scopes' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockAccessToken = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                $script:mockWorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
            }
        }

        It 'Should export all secret scopes successfully' {
            InModuleScope -ScriptBlock {
                Mock -CommandName Get-DatabricksSecretScope -MockWith {
                    return @{
                        scopes = @(
                            @{
                                name         = 'databricks-scope-1'
                                backend_type = 'DATABRICKS'
                            }
                            @{
                                name              = 'akv-scope-1'
                                backend_type      = 'AZURE_KEYVAULT'
                                keyvault_metadata = @{
                                    resource_id = '/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault1'
                                    dns_name    = 'https://vault1.vault.azure.net/'
                                }
                            }
                            @{
                                name         = 'databricks-scope-2'
                                backend_type = 'DATABRICKS'
                            }
                        )
                    }
                }

                $filteringInstance = [DatabricksSecretScope] @{
                    WorkspaceUrl     = $script:mockWorkspaceUrl
                    AccessToken      = $script:mockAccessToken
                    ScopeName        = 'dummy'
                    ScopeBackendType = 'DATABRICKS'
                }

                $result = [DatabricksSecretScope]::Export($filteringInstance)

                $result | Should -Not -BeNullOrEmpty
                # When ScopeBackendType is set to DATABRICKS, only DATABRICKS scopes are returned
                $result.Count | Should -Be 2
                $result[0].ScopeName | Should -Be 'databricks-scope-1'
                $result[0].ScopeBackendType | Should -Be 'DATABRICKS'
                $result[0]._exist | Should -BeTrue
                $result[1].ScopeName | Should -Be 'databricks-scope-2'
                $result[1].ScopeBackendType | Should -Be 'DATABRICKS'

                Should -Invoke -CommandName Get-DatabricksSecretScope -Exactly -Times 1
            }
        }

        It 'Should export all secret scopes when no meaningful filters are set' {
            InModuleScope -ScriptBlock {
                Mock -CommandName Get-DatabricksSecretScope -MockWith {
                    return @{
                        scopes = @(
                            @{
                                name         = 'databricks-scope-1'
                                backend_type = 'DATABRICKS'
                            }
                            @{
                                name              = 'akv-scope-1'
                                backend_type      = 'AZURE_KEYVAULT'
                                keyvault_metadata = @{
                                    resource_id = '/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault1'
                                    dns_name    = 'https://vault1.vault.azure.net/'
                                }
                            }
                            @{
                                name         = 'databricks-scope-2'
                                backend_type = 'DATABRICKS'
                            }
                        )
                    }
                }

                # Create instance with only required properties for authentication
                $filteringInstance = [DatabricksSecretScope]::new()
                $filteringInstance.WorkspaceUrl = $script:mockWorkspaceUrl
                $filteringInstance.AccessToken = $script:mockAccessToken

                $result = [DatabricksSecretScope]::Export($filteringInstance)

                $result | Should -Not -BeNullOrEmpty
                $result.Count | Should -Be 3
                $result[0].ScopeName | Should -Be 'databricks-scope-1'
                $result[1].ScopeName | Should -Be 'akv-scope-1'
                $result[1].BackendAzureKeyVault | Should -Not -BeNullOrEmpty
                $result[1].BackendAzureKeyVault.DnsName | Should -Be 'https://vault1.vault.azure.net/'
                $result[2].ScopeName | Should -Be 'databricks-scope-2'

                Should -Invoke -CommandName Get-DatabricksSecretScope -Exactly -Times 1
            }
        }

        It 'Should return empty array when no scopes exist' {
            InModuleScope -ScriptBlock {
                Mock -CommandName Get-DatabricksSecretScope -MockWith {
                    return @{
                        scopes = @()
                    }
                }

                $filteringInstance = [DatabricksSecretScope] @{
                    WorkspaceUrl     = $script:mockWorkspaceUrl
                    AccessToken      = $script:mockAccessToken
                    ScopeName        = 'dummy'
                    ScopeBackendType = 'DATABRICKS'
                }

                $result = [DatabricksSecretScope]::Export($filteringInstance)

                $result | Should -BeNullOrEmpty

                Should -Invoke -CommandName Get-DatabricksSecretScope -Exactly -Times 1
            }
        }

        It 'Should return empty array when API returns null' {
            InModuleScope -ScriptBlock {
                Mock -CommandName Get-DatabricksSecretScope -MockWith {
                    return $null
                }

                $filteringInstance = [DatabricksSecretScope] @{
                    WorkspaceUrl     = $script:mockWorkspaceUrl
                    AccessToken      = $script:mockAccessToken
                    ScopeName        = 'dummy'
                    ScopeBackendType = 'DATABRICKS'
                }

                $result = [DatabricksSecretScope]::Export($filteringInstance)

                $result | Should -BeNullOrEmpty

                Should -Invoke -CommandName Get-DatabricksSecretScope -Exactly -Times 1
            }
        }
    }

    Context 'When filtering exported scopes by ScopeBackendType' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                Mock -CommandName Get-DatabricksSecretScope -MockWith {
                    return @{
                        scopes = @(
                            @{
                                name         = 'databricks-scope-1'
                                backend_type = 'DATABRICKS'
                            }
                            @{
                                name              = 'akv-scope-1'
                                backend_type      = 'AZURE_KEYVAULT'
                                keyvault_metadata = @{
                                    resource_id = '/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault1'
                                    dns_name    = 'https://vault1.vault.azure.net/'
                                }
                            }
                            @{
                                name         = 'databricks-scope-2'
                                backend_type = 'DATABRICKS'
                            }
                        )
                    }
                }
            }
        }

        It 'Should filter scopes by ScopeBackendType = DATABRICKS' {
            InModuleScope -ScriptBlock {
                $filteringInstance = [DatabricksSecretScope] @{
                    WorkspaceUrl     = $script:mockWorkspaceUrl
                    AccessToken      = $script:mockAccessToken
                    ScopeName        = 'dummy'
                    ScopeBackendType = 'DATABRICKS'
                }

                $result = [DatabricksSecretScope]::Export($filteringInstance)

                $result | Should -Not -BeNullOrEmpty
                $result.Count | Should -Be 2
                $result[0].ScopeName | Should -Be 'databricks-scope-1'
                $result[0].ScopeBackendType | Should -Be 'DATABRICKS'
                $result[1].ScopeName | Should -Be 'databricks-scope-2'
                $result[1].ScopeBackendType | Should -Be 'DATABRICKS'

                Should -Invoke -CommandName Get-DatabricksSecretScope -Exactly -Times 1
            }
        }

        It 'Should filter scopes by ScopeBackendType = AZURE_KEYVAULT' {
            InModuleScope -ScriptBlock {
                $filteringInstance = [DatabricksSecretScope] @{
                    WorkspaceUrl     = $script:mockWorkspaceUrl
                    AccessToken      = $script:mockAccessToken
                    ScopeName        = 'dummy'
                    ScopeBackendType = 'AZURE_KEYVAULT'
                    BackendAzureKeyVault = [AzureKeyVaultBackend] @{
                        DnsName    = 'https://vault1.vault.azure.net/'
                        ResourceId = '/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault1'
                    }
                }

                $result = [DatabricksSecretScope]::Export($filteringInstance)

                $result | Should -Not -BeNullOrEmpty
                $result.Count | Should -Be 1
                $result[0].ScopeName | Should -Be 'akv-scope-1'
                $result[0].ScopeBackendType | Should -Be 'AZURE_KEYVAULT'
                $result[0].BackendAzureKeyVault.DnsName | Should -Be 'https://vault1.vault.azure.net/'

                Should -Invoke -CommandName Get-DatabricksSecretScope -Exactly -Times 1
            }
        }
    }

    Context 'When filtering exported scopes by BackendAzureKeyVault' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                Mock -CommandName Get-DatabricksSecretScope -MockWith {
                    return @{
                        scopes = @(
                            @{
                                name              = 'akv-scope-1'
                                backend_type      = 'AZURE_KEYVAULT'
                                keyvault_metadata = @{
                                    resource_id = '/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault1'
                                    dns_name    = 'https://vault1.vault.azure.net/'
                                }
                            }
                            @{
                                name              = 'akv-scope-2'
                                backend_type      = 'AZURE_KEYVAULT'
                                keyvault_metadata = @{
                                    resource_id = '/subscriptions/yyy/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault2'
                                    dns_name    = 'https://vault2.vault.azure.net/'
                                }
                            }
                        )
                    }
                }
            }
        }

        It 'Should filter scopes by specific BackendAzureKeyVault configuration' {
            InModuleScope -ScriptBlock {
                $filteringInstance = [DatabricksSecretScope] @{
                    WorkspaceUrl         = $script:mockWorkspaceUrl
                    AccessToken          = $script:mockAccessToken
                    ScopeName            = 'dummy'
                    ScopeBackendType     = 'AZURE_KEYVAULT'
                    BackendAzureKeyVault = [AzureKeyVaultBackend] @{
                        DnsName    = 'https://vault1.vault.azure.net/'
                        ResourceId = '/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault1'
                    }
                }

                $result = [DatabricksSecretScope]::Export($filteringInstance)

                $result | Should -Not -BeNullOrEmpty
                $result.Count | Should -Be 1
                $result[0].ScopeName | Should -Be 'akv-scope-1'
                $result[0].BackendAzureKeyVault.ResourceId | Should -Be '/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault1'

                Should -Invoke -CommandName Get-DatabricksSecretScope -Exactly -Times 1
            }
        }

        It 'Should return empty when BackendAzureKeyVault does not match' {
            InModuleScope -ScriptBlock {
                $filteringInstance = [DatabricksSecretScope] @{
                    WorkspaceUrl         = $script:mockWorkspaceUrl
                    AccessToken          = $script:mockAccessToken
                    ScopeName            = 'dummy'
                    ScopeBackendType     = 'AZURE_KEYVAULT'
                    BackendAzureKeyVault = [AzureKeyVaultBackend] @{
                        DnsName    = 'https://nonexistent.vault.azure.net/'
                        ResourceId = '/subscriptions/zzz/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/nonexistent'
                    }
                }

                $result = [DatabricksSecretScope]::Export($filteringInstance)

                $result | Should -BeNullOrEmpty

                Should -Invoke -CommandName Get-DatabricksSecretScope -Exactly -Times 1
            }
        }
    }

    Context 'When export fails' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                Mock -CommandName Get-DatabricksSecretScope -MockWith {
                    throw 'API Error: Unauthorized'
                }
            }
        }

        It 'Should return empty array and not throw' {
            InModuleScope -ScriptBlock {
                $filteringInstance = [DatabricksSecretScope] @{
                    WorkspaceUrl     = $script:mockWorkspaceUrl
                    AccessToken      = $script:mockAccessToken
                    ScopeName        = 'dummy'
                    ScopeBackendType = 'DATABRICKS'
                }

                { $result = [DatabricksSecretScope]::Export($filteringInstance) } | Should -Not -Throw

                $result = [DatabricksSecretScope]::Export($filteringInstance)
                $result | Should -BeNullOrEmpty

                Should -Invoke -CommandName Get-DatabricksSecretScope -Exactly -Times 2
            }
        }
    }

    Context 'When exporting scopes with various properties' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                Mock -CommandName Get-DatabricksSecretScope -MockWith {
                    return @{
                        scopes = @(
                            @{
                                name         = 'scope-1'
                                backend_type = 'DATABRICKS'
                            }
                            @{
                                name         = 'scope-2'
                                backend_type = 'DATABRICKS'
                            }
                        )
                    }
                }
            }
        }

        It 'Should set all exported instances with correct properties' {
            InModuleScope -ScriptBlock {
                $filteringInstance = [DatabricksSecretScope] @{
                    WorkspaceUrl     = $script:mockWorkspaceUrl
                    AccessToken      = $script:mockAccessToken
                    ScopeName        = 'dummy'
                    ScopeBackendType = 'DATABRICKS'
                }

                $result = [DatabricksSecretScope]::Export($filteringInstance)

                $result | Should -Not -BeNullOrEmpty
                foreach ($scope in $result)
                {
                    $scope.WorkspaceUrl | Should -Be $script:mockWorkspaceUrl
                    $scope.AccessToken | Should -Not -BeNullOrEmpty
                    $scope._exist | Should -BeTrue
                    $scope.ScopeName | Should -Not -BeNullOrEmpty
                    $scope.ScopeBackendType | Should -Not -BeNullOrEmpty
                }

                Should -Invoke -CommandName Get-DatabricksSecretScope -Exactly -Times 1
            }
        }
    }
}
