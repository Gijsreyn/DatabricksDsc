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

Describe 'DatabricksClusterPolicy' -Tag 'DatabricksClusterPolicy' {
    Context 'Class instantiation' {
        It 'Should instantiate without errors' {
            InModuleScope -ScriptBlock {
                { [DatabricksClusterPolicy]::new() } | Should -Not -Throw
            }
        }

        It 'Should have default value for _exist property' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksClusterPolicy]::new()
                $instance._exist | Should -BeTrue
            }
        }

        It 'Should set ExcludeDscProperties in constructor' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksClusterPolicy]::new()
                $instance.ExcludeDscProperties | Should -Contain 'WorkspaceUrl'
                $instance.ExcludeDscProperties | Should -Contain 'Name'
                $instance.ExcludeDscProperties | Should -Contain 'AccessToken'
                $instance.ExcludeDscProperties | Should -Not -Contain '_exist'
            }
        }

        It 'Should allow setting properties via constructor hashtable' {
            InModuleScope -ScriptBlock {
                $token = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                $definition = @{
                    'custom_tags.test_tag' = @{
                        type  = 'fixed'
                        value = 'test_value'
                    }
                }

                $instance = [DatabricksClusterPolicy] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = $token
                    Name         = 'Test Policy'
                    Definition   = $definition
                    Description  = 'Test description'
                }

                $instance.WorkspaceUrl | Should -Be 'https://adb-1234567890123456.12.azuredatabricks.net'
                $instance.Name | Should -Be 'Test Policy'
                $instance.Description | Should -Be 'Test description'
                $instance.Definition | Should -Not -BeNullOrEmpty
            }
        }
    }
}

Describe 'DatabricksClusterPolicy\Get()' -Tag 'Get' {
    Context 'When calling Get method' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockClusterPolicyInstance = [DatabricksClusterPolicy] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    Name         = 'Test Policy'
                }

                Mock -CommandName Write-Verbose
            }
        }

        It 'Should return instance of DatabricksClusterPolicy' {
            InModuleScope -ScriptBlock {
                $script:mockClusterPolicyInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            policies = @()
                        }
                    }

                $result = $script:mockClusterPolicyInstance.Get()
                $result.GetType().Name | Should -Be 'DatabricksClusterPolicy'
            }
        }

        It 'Should call GetCurrentState with key properties' {
            InModuleScope -ScriptBlock {
                $script:mockClusterPolicyInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            policies = @()
                        }
                    }

                $script:mockClusterPolicyInstance.Get()

                Should -Invoke -CommandName Write-Verbose -ParameterFilter {
                    $Message -match 'Evaluating cluster policy state'
                }
            }
        }
    }
}

Describe 'DatabricksClusterPolicy\Set()' -Tag 'Set' {
    Context 'When calling Set method' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockClusterPolicyInstance = [DatabricksClusterPolicy] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    Name         = 'Test Policy'
                    Definition   = @{
                        'custom_tags.test_tag' = @{
                            type  = 'fixed'
                            value = 'test_value'
                        }
                    }
                }

                Mock -CommandName Write-Verbose
            }
        }

        It 'Should not throw when policy needs to be created' {
            InModuleScope -ScriptBlock {
                $script:mockClusterPolicyInstance._exist = $true

                $script:mockClusterPolicyInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            policies = @()
                        }
                    }

                { $script:mockClusterPolicyInstance.Set() } | Should -Not -Throw
            }
        }
    }
}

Describe 'DatabricksClusterPolicy\Test()' -Tag 'Test' {
    Context 'When calling Test method' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockClusterPolicyInstance = [DatabricksClusterPolicy] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    Name         = 'Test Policy'
                }

                Mock -CommandName Write-Verbose
            }
        }

        It 'Should return $true when policy is in desired state' {
            InModuleScope -ScriptBlock {
                $script:mockClusterPolicyInstance._exist = $false

                $script:mockClusterPolicyInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            policies = @()
                        }
                    }

                $script:mockClusterPolicyInstance.Test() | Should -BeTrue
            }
        }

        It 'Should return $false when policy is not in desired state' {
            InModuleScope -ScriptBlock {
                $script:mockClusterPolicyInstance._exist = $true

                $script:mockClusterPolicyInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            policies = @()
                        }
                    }

                $script:mockClusterPolicyInstance.Test() | Should -BeFalse
            }
        }
    }
}

Describe 'DatabricksClusterPolicy\GetCurrentState()' -Tag 'GetCurrentState' {
    Context 'When policy does not exist' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockClusterPolicyInstance = [DatabricksClusterPolicy] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    Name         = 'Test Policy'
                }

                Mock -CommandName Write-Verbose

                $script:mockClusterPolicyInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            policies = @()
                        }
                    }
            }
        }

        It 'Should return the correct values with _exist = $false' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockClusterPolicyInstance.GetCurrentState(
                    @{
                        Name = 'Test Policy'
                    }
                )

                $currentState.WorkspaceUrl | Should -Be 'https://adb-1234567890123456.12.azuredatabricks.net'
                $currentState.Name | Should -Be 'Test Policy'
                $currentState._exist | Should -BeFalse
                # Instance property should remain at default value (desired state)
                $script:mockClusterPolicyInstance._exist | Should -BeTrue
            }
        }
    }

    Context 'When policy exists with minimal properties' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockClusterPolicyInstance = [DatabricksClusterPolicy] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    Name         = 'Test Policy'
                }

                Mock -CommandName Write-Verbose

                $script:mockClusterPolicyInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            policies = @(
                                @{
                                    policy_id   = 'policy-123'
                                    name        = 'Test Policy'
                                    definition  = '{"custom_tags.test_tag":{"type":"fixed","value":"test_value"}}'
                                    description = 'Test description'
                                }
                            )
                        }
                    }
            }
        }

        It 'Should return the correct values with _exist = $true' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockClusterPolicyInstance.GetCurrentState(
                    @{
                        Name = 'Test Policy'
                    }
                )

                $currentState.WorkspaceUrl | Should -Be 'https://adb-1234567890123456.12.azuredatabricks.net'
                $currentState.Name | Should -Be 'Test Policy'
                $currentState.PolicyId | Should -Be 'policy-123'
                $currentState.Description | Should -Be 'Test description'
                $currentState._exist | Should -BeTrue
                $script:mockClusterPolicyInstance._exist | Should -BeTrue
            }
        }
    }

    Context 'When policy exists with all properties' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockClusterPolicyInstance = [DatabricksClusterPolicy] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    Name         = 'Test Policy'
                }

                Mock -CommandName Write-Verbose

                $script:mockClusterPolicyInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        return @{
                            policies = @(
                                @{
                                    policy_id                            = 'policy-123'
                                    name                                 = 'Test Policy'
                                    definition                           = '{"custom_tags.test_tag":{"type":"fixed","value":"test_value"}}'
                                    description                          = 'Test description'
                                    max_clusters_per_user                = 5
                                    policy_family_id                     = 'family-123'
                                    policy_family_definition_overrides   = '{"custom_tags.override":{"type":"fixed","value":"override_value"}}'
                                    libraries                            = @(
                                        @{
                                            jar = '/Workspace/path/to/library.jar'
                                        },
                                        @{
                                            pypi = @{
                                                package = 'simplejson'
                                                repo    = 'https://pypi.org/simple'
                                            }
                                        },
                                        @{
                                            cran = @{
                                                package = 'ada'
                                                repo    = 'https://cran.us.r-project.org'
                                            }
                                        },
                                        @{
                                            maven = @{
                                                coordinates = 'org.jsoup:jsoup:1.7.2'
                                                repo        = 'https://maven.company.com'
                                                exclusions  = @('org.slf4j:slf4j-api')
                                            }
                                        },
                                        @{
                                            requirements = '/Workspace/path/to/requirements.txt'
                                        },
                                        @{
                                            whl = '/Workspace/path/to/library.whl'
                                        }
                                    )
                                }
                            )
                        }
                    }
            }
        }

        It 'Should return all properties correctly' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockClusterPolicyInstance.GetCurrentState(
                    @{
                        Name = 'Test Policy'
                    }
                )

                $currentState.PolicyId | Should -Be 'policy-123'
                $currentState.Description | Should -Be 'Test description'
                $currentState.MaxClustersPerUser | Should -Be 5
                $currentState.PolicyFamilyId | Should -Be 'family-123'
                $currentState.Definition | Should -Not -BeNullOrEmpty
                $currentState.PolicyFamilyDefinitionOverrides | Should -Not -BeNullOrEmpty
                $currentState.Libraries | Should -HaveCount 6
            }
        }

        It 'Should convert JAR library correctly' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockClusterPolicyInstance.GetCurrentState(@{ Name = 'Test Policy' })

                $jarLib = $currentState.Libraries | Where-Object { $null -ne $_.Jar } | Select-Object -First 1
                $jarLib | Should -Not -BeNullOrEmpty
                $jarLib.Jar | Should -Be '/Workspace/path/to/library.jar'
            }
        }

        It 'Should convert PyPI library correctly' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockClusterPolicyInstance.GetCurrentState(@{ Name = 'Test Policy' })

                $pypiLib = $currentState.Libraries | Where-Object { $null -ne $_.PyPi } | Select-Object -First 1
                $pypiLib | Should -Not -BeNullOrEmpty
                $pypiLib.PyPi.Package | Should -Be 'simplejson'
                $pypiLib.PyPi.Repo | Should -Be 'https://pypi.org/simple'
            }
        }

        It 'Should convert CRAN library correctly' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockClusterPolicyInstance.GetCurrentState(@{ Name = 'Test Policy' })

                $cranLib = $currentState.Libraries | Where-Object { $null -ne $_.Cran } | Select-Object -First 1
                $cranLib | Should -Not -BeNullOrEmpty
                $cranLib.Cran.Package | Should -Be 'ada'
                $cranLib.Cran.Repo | Should -Be 'https://cran.us.r-project.org'
            }
        }

        It 'Should convert Maven library correctly' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockClusterPolicyInstance.GetCurrentState(@{ Name = 'Test Policy' })

                $mavenLib = $currentState.Libraries | Where-Object { $null -ne $_.Maven } | Select-Object -First 1
                $mavenLib | Should -Not -BeNullOrEmpty
                $mavenLib.Maven.Coordinates | Should -Be 'org.jsoup:jsoup:1.7.2'
                $mavenLib.Maven.Repo | Should -Be 'https://maven.company.com'
                $mavenLib.Maven.Exclusions | Should -Contain 'org.slf4j:slf4j-api'
            }
        }

        It 'Should convert Requirements library correctly' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockClusterPolicyInstance.GetCurrentState(@{ Name = 'Test Policy' })

                $reqLib = $currentState.Libraries | Where-Object { $null -ne $_.Requirements } | Select-Object -First 1
                $reqLib | Should -Not -BeNullOrEmpty
                $reqLib.Requirements | Should -Be '/Workspace/path/to/requirements.txt'
            }
        }

        It 'Should convert Whl library correctly' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockClusterPolicyInstance.GetCurrentState(@{ Name = 'Test Policy' })

                $whlLib = $currentState.Libraries | Where-Object { $null -ne $_.Whl } | Select-Object -First 1
                $whlLib | Should -Not -BeNullOrEmpty
                $whlLib.Whl | Should -Be '/Workspace/path/to/library.whl'
            }
        }
    }

    Context 'When API call fails' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockClusterPolicyInstance = [DatabricksClusterPolicy] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    Name         = 'Test Policy'
                }

                Mock -CommandName Write-Verbose

                $script:mockClusterPolicyInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        throw 'API Error: Unauthorized'
                    }
            }
        }

        It 'Should handle error gracefully and return _exist = $false' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockClusterPolicyInstance.GetCurrentState(@{ Name = 'Test Policy' })

                $currentState._exist | Should -BeFalse
                $currentState.Name | Should -Be 'Test Policy'
            }
        }
    }
}

Describe 'DatabricksClusterPolicy\Modify()' -Tag 'Modify' {
    Context 'When creating a new policy' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockClusterPolicyInstance = [DatabricksClusterPolicy] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    Name         = 'Test Policy'
                    Definition   = @{
                        'custom_tags.test_tag' = @{
                            type  = 'fixed'
                            value = 'test_value'
                        }
                    }
                }

                Mock -CommandName Write-Verbose

                $script:mockInvokeParams = $null
                $script:mockClusterPolicyInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param($Method, $Path, $Body)
                        $script:mockInvokeParams = @{
                            Method = $Method
                            Path   = $Path
                            Body   = $Body
                        }
                        return @{ policy_id = 'policy-123' }
                    }
            }
        }

        It 'Should call InvokeDatabricksApi with POST to /create endpoint' {
            InModuleScope -ScriptBlock {
                $script:mockClusterPolicyInstance._exist = $false

                $script:mockClusterPolicyInstance.Modify(@{
                        _exist     = $true
                        Definition = @{
                            'custom_tags.test_tag' = @{
                                type  = 'fixed'
                                value = 'test_value'
                            }
                        }
                    })

                $script:mockInvokeParams.Method | Should -Be 'POST'
                $script:mockInvokeParams.Path | Should -Be '/api/2.0/policies/clusters/create'
                $script:mockInvokeParams.Body | Should -Not -BeNullOrEmpty
            }
        }

        It 'Should include name and definition in payload' {
            InModuleScope -ScriptBlock {
                $script:mockClusterPolicyInstance._exist = $false

                $script:mockClusterPolicyInstance.Modify(@{
                        _exist     = $true
                        Definition = @{
                            'custom_tags.test_tag' = @{
                                type  = 'fixed'
                                value = 'test_value'
                            }
                        }
                    })

                $body = $script:mockInvokeParams.Body
                $body.name | Should -Be 'Test Policy'
                $body.definition | Should -Not -BeNullOrEmpty
            }
        }
    }

    Context 'When deleting an existing policy' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockClusterPolicyInstance = [DatabricksClusterPolicy] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    Name         = 'Test Policy'
                    PolicyId     = 'policy-123'
                }

                Mock -CommandName Write-Verbose

                $script:mockInvokeParams = $null
                $script:mockClusterPolicyInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param($Method, $Path, $Body)
                        $script:mockInvokeParams = @{
                            Method = $Method
                            Path   = $Path
                            Body   = $Body
                        }
                        return $null
                    }
            }
        }

        It 'Should call InvokeDatabricksApi with POST to /delete endpoint' {
            InModuleScope -ScriptBlock {
                $script:mockClusterPolicyInstance._exist = $true

                $script:mockClusterPolicyInstance.Modify(@{
                        _exist = $false
                    })

                $script:mockInvokeParams.Method | Should -Be 'POST'
                $script:mockInvokeParams.Path | Should -Be '/api/2.0/policies/clusters/delete'
            }
        }

        It 'Should include policy_id in delete payload' {
            InModuleScope -ScriptBlock {
                $script:mockClusterPolicyInstance._exist = $true

                $script:mockClusterPolicyInstance.Modify(@{
                        _exist = $false
                    })

                $body = $script:mockInvokeParams.Body
                $body.policy_id | Should -Be 'policy-123'
            }
        }
    }

    Context 'When updating an existing policy' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockClusterPolicyInstance = [DatabricksClusterPolicy] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    Name         = 'Test Policy'
                    PolicyId     = 'policy-123'
                }

                Mock -CommandName Write-Verbose

                $script:mockInvokeParams = $null
                $script:mockClusterPolicyInstance |
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'InvokeDatabricksApi' -Value {
                        param($Method, $Path, $Body)
                        $script:mockInvokeParams = @{
                            Method = $Method
                            Path   = $Path
                            Body   = $Body
                        }
                        return $null
                    }
            }
        }

        It 'Should call InvokeDatabricksApi with POST to /edit endpoint' {
            InModuleScope -ScriptBlock {
                $script:mockClusterPolicyInstance._exist = $true

                $script:mockClusterPolicyInstance.Modify(@{
                        Description = 'Updated description'
                    })

                $script:mockInvokeParams.Method | Should -Be 'POST'
                $script:mockInvokeParams.Path | Should -Be '/api/2.0/policies/clusters/edit'
            }
        }

        It 'Should include policy_id in update payload' {
            InModuleScope -ScriptBlock {
                $script:mockClusterPolicyInstance._exist = $true

                $script:mockClusterPolicyInstance.Modify(@{
                        Description = 'Updated description'
                    })

                $body = $script:mockInvokeParams.Body
                $body.policy_id | Should -Be 'policy-123'
            }
        }

        It 'Should include updated properties in payload' {
            InModuleScope -ScriptBlock {
                $script:mockClusterPolicyInstance._exist = $true
                $script:mockClusterPolicyInstance.Description = 'Original description'

                $script:mockClusterPolicyInstance.Modify(@{
                        Description = 'Updated description'
                    })

                $body = $script:mockInvokeParams.Body
                $body.description | Should -Be 'Updated description'
                $body.name | Should -Be 'Test Policy'
            }
        }
    }
}

Describe 'DatabricksClusterPolicy\BuildPolicyPayload()' -Tag 'BuildPolicyPayload' {
    BeforeAll {
        InModuleScope -ScriptBlock {
            $script:mockClusterPolicyInstance = [DatabricksClusterPolicy] @{
                WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                Name         = 'Test Policy'
            }

            Mock -CommandName Write-Verbose
        }
    }

    It 'Should build payload with name and definition' {
        InModuleScope -ScriptBlock {
            $script:mockClusterPolicyInstance.Definition = @{
                'custom_tags.test_tag' = @{
                    type  = 'fixed'
                    value = 'test_value'
                }
            }

            $payload = $script:mockClusterPolicyInstance.BuildPolicyPayload(@{})

            $payload.name | Should -Be 'Test Policy'
            $payload.definition | Should -Not -BeNullOrEmpty
        }
    }

    It 'Should include description when provided' {
        InModuleScope -ScriptBlock {
            $script:mockClusterPolicyInstance.Description = 'Test description'

            $payload = $script:mockClusterPolicyInstance.BuildPolicyPayload(@{})

            $payload.description | Should -Be 'Test description'
        }
    }

    It 'Should include max_clusters_per_user when provided' {
        InModuleScope -ScriptBlock {
            $script:mockClusterPolicyInstance.MaxClustersPerUser = 10

            $payload = $script:mockClusterPolicyInstance.BuildPolicyPayload(@{})

            $payload.max_clusters_per_user | Should -Be 10
        }
    }

    It 'Should include policy_family_id when provided' {
        InModuleScope -ScriptBlock {
            $script:mockClusterPolicyInstance.PolicyFamilyId = 'family-123'

            $payload = $script:mockClusterPolicyInstance.BuildPolicyPayload(@{})

            $payload.policy_family_id | Should -Be 'family-123'
        }
    }

    It 'Should include libraries when provided' {
        InModuleScope -ScriptBlock {
            $script:mockClusterPolicyInstance.Libraries = @(
                [ClusterPolicyLibrary] @{
                    Jar = '/Workspace/path/to/library.jar'
                }
            )

            $payload = $script:mockClusterPolicyInstance.BuildPolicyPayload(@{})

            $payload.libraries | Should -HaveCount 1
            $payload.libraries[0].jar | Should -Be '/Workspace/path/to/library.jar'
        }
    }
}

Describe 'DatabricksClusterPolicy\ConvertLibrariesToApiFormat()' -Tag 'ConvertLibrariesToApiFormat' {
    BeforeAll {
        InModuleScope -ScriptBlock {
            $script:mockClusterPolicyInstance = [DatabricksClusterPolicy] @{
                WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                Name         = 'Test Policy'
            }

            Mock -CommandName Write-Verbose
        }
    }

    It 'Should convert JAR library correctly' {
        InModuleScope -ScriptBlock {
            $libraries = @(
                [ClusterPolicyLibrary] @{
                    Jar = '/Workspace/path/to/library.jar'
                }
            )

            $result = $script:mockClusterPolicyInstance.ConvertLibrariesToApiFormat($libraries)

            $result | Should -HaveCount 1
            $result[0].jar | Should -Be '/Workspace/path/to/library.jar'
        }
    }

    It 'Should convert PyPI library correctly' {
        InModuleScope -ScriptBlock {
            $libraries = @(
                [ClusterPolicyLibrary] @{
                    PyPi = [PyPiLibrary] @{
                        Package = 'simplejson==3.8.0'
                        Repo    = 'https://pypi.org/simple'
                    }
                }
            )

            $result = $script:mockClusterPolicyInstance.ConvertLibrariesToApiFormat($libraries)

            $result | Should -HaveCount 1
            $result[0].pypi.package | Should -Be 'simplejson==3.8.0'
            $result[0].pypi.repo | Should -Be 'https://pypi.org/simple'
        }
    }

    It 'Should convert Maven library correctly' {
        InModuleScope -ScriptBlock {
            $libraries = @(
                [ClusterPolicyLibrary] @{
                    Maven = [MavenLibrary] @{
                        Coordinates = 'org.jsoup:jsoup:1.7.2'
                        Exclusions  = @('slf4j:slf4j')
                        Repo        = 'https://repo1.maven.org/maven2'
                    }
                }
            )

            $result = $script:mockClusterPolicyInstance.ConvertLibrariesToApiFormat($libraries)

            $result | Should -HaveCount 1
            $result[0].maven.coordinates | Should -Be 'org.jsoup:jsoup:1.7.2'
            $result[0].maven.exclusions | Should -Contain 'slf4j:slf4j'
            $result[0].maven.repo | Should -Be 'https://repo1.maven.org/maven2'
        }
    }

    It 'Should convert CRAN library correctly' {
        InModuleScope -ScriptBlock {
            $libraries = @(
                [ClusterPolicyLibrary] @{
                    Cran = [CranLibrary] @{
                        Package = 'ggplot2'
                        Repo    = 'https://cran.r-project.org'
                    }
                }
            )

            $result = $script:mockClusterPolicyInstance.ConvertLibrariesToApiFormat($libraries)

            $result | Should -HaveCount 1
            $result[0].cran.package | Should -Be 'ggplot2'
            $result[0].cran.repo | Should -Be 'https://cran.r-project.org'
        }
    }

    It 'Should convert Wheel library correctly' {
        InModuleScope -ScriptBlock {
            $libraries = @(
                [ClusterPolicyLibrary] @{
                    Whl = '/Volumes/path/to/library.whl'
                }
            )

            $result = $script:mockClusterPolicyInstance.ConvertLibrariesToApiFormat($libraries)

            $result | Should -HaveCount 1
            $result[0].whl | Should -Be '/Volumes/path/to/library.whl'
        }
    }

    It 'Should convert Requirements library correctly' {
        InModuleScope -ScriptBlock {
            $libraries = @(
                [ClusterPolicyLibrary] @{
                    Requirements = '/Workspace/path/to/requirements.txt'
                }
            )

            $result = $script:mockClusterPolicyInstance.ConvertLibrariesToApiFormat($libraries)

            $result | Should -HaveCount 1
            $result[0].requirements | Should -Be '/Workspace/path/to/requirements.txt'
        }
    }

    It 'Should convert multiple libraries correctly' {
        InModuleScope -ScriptBlock {
            $libraries = @(
                [ClusterPolicyLibrary] @{
                    Jar = '/Workspace/path/to/library.jar'
                },
                [ClusterPolicyLibrary] @{
                    PyPi = [PyPiLibrary] @{
                        Package = 'simplejson'
                    }
                }
            )

            $result = $script:mockClusterPolicyInstance.ConvertLibrariesToApiFormat($libraries)

            $result | Should -HaveCount 2
            $result[0].jar | Should -Be '/Workspace/path/to/library.jar'
            $result[1].pypi.package | Should -Be 'simplejson'
        }
    }
}

Describe 'DatabricksClusterPolicy\AssertProperties()' -Tag 'AssertProperties' {
    Context 'When validating WorkspaceUrl' {
        It 'Should throw when WorkspaceUrl does not start with https://' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksClusterPolicy] @{
                    WorkspaceUrl = 'http://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    Name         = 'Test Policy'
                }

                { $instance.AssertProperties(@{}) } | Should -Throw -ExpectedMessage '*not valid*https*'
            }
        }

        It 'Should not throw when WorkspaceUrl starts with https://' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksClusterPolicy] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    Name         = 'Test Policy'
                }

                { $instance.AssertProperties(@{}) } | Should -Not -Throw
            }
        }
    }

    Context 'When validating Definition and PolicyFamilyId' {
        It 'Should throw when both Definition and PolicyFamilyId are specified' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksClusterPolicy] @{
                    WorkspaceUrl    = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken     = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    Name            = 'Test Policy'
                    Definition      = @{ test = 'value' }
                    PolicyFamilyId  = 'family-123'
                }

                { $instance.AssertProperties(@{}) } | Should -Throw -ExpectedMessage '*mutually exclusive*'
            }
        }

        It 'Should not throw when only Definition is specified' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksClusterPolicy] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    Name         = 'Test Policy'
                    Definition   = @{ test = 'value' }
                }

                { $instance.AssertProperties(@{}) } | Should -Not -Throw
            }
        }

        It 'Should not throw when only PolicyFamilyId is specified' {
            InModuleScope -ScriptBlock {
                $instance = [DatabricksClusterPolicy] @{
                    WorkspaceUrl   = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken    = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    Name           = 'Test Policy'
                    PolicyFamilyId = 'family-123'
                }

                { $instance.AssertProperties(@{}) } | Should -Not -Throw
            }
        }
    }

    Context 'When validating Libraries count' {
        It 'Should throw when more than 500 libraries are specified' {
            InModuleScope -ScriptBlock {
                $libraries = @()
                for ($i = 1; $i -le 501; $i++)
                {
                    $libraries += [ClusterPolicyLibrary] @{
                        Jar = "/Workspace/path/to/library$i.jar"
                    }
                }

                $instance = [DatabricksClusterPolicy] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    Name         = 'Test Policy'
                    Libraries    = $libraries
                }

                { $instance.AssertProperties(@{}) } | Should -Throw -ExpectedMessage '*500*'
            }
        }

        It 'Should not throw when 500 or fewer libraries are specified' {
            InModuleScope -ScriptBlock {
                $libraries = @()
                for ($i = 1; $i -le 500; $i++)
                {
                    $libraries += [ClusterPolicyLibrary] @{
                        Jar = "/Workspace/path/to/library$i.jar"
                    }
                }

                $instance = [DatabricksClusterPolicy] @{
                    WorkspaceUrl = 'https://adb-1234567890123456.12.azuredatabricks.net'
                    AccessToken  = ConvertTo-SecureString -String 'dapi1234567890abcdef' -AsPlainText -Force
                    Name         = 'Test Policy'
                    Libraries    = $libraries
                }

                { $instance.AssertProperties(@{}) } | Should -Not -Throw
            }
        }
    }
}
