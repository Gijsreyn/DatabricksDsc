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

Describe 'CranLibrary' -Tag 'CranLibrary' {
    Context 'Class instantiation' {
        It 'Should instantiate without errors' {
            InModuleScope -ScriptBlock {
                { [CranLibrary]::new() } | Should -Not -Throw
            }
        }

        It 'Should allow setting Package property' {
            InModuleScope -ScriptBlock {
                $instance = [CranLibrary] @{
                    Package = 'ggplot2'
                }

                $instance.Package | Should -Be 'ggplot2'
            }
        }

        It 'Should allow setting Repo property' {
            InModuleScope -ScriptBlock {
                $instance = [CranLibrary] @{
                    Package = 'ggplot2'
                    Repo    = 'https://cran.r-project.org'
                }

                $instance.Repo | Should -Be 'https://cran.r-project.org'
            }
        }
    }

    Context 'Equals() method' {
        It 'Should return $true when objects are equal' {
            InModuleScope -ScriptBlock {
                $instance1 = [CranLibrary] @{
                    Package = 'ggplot2'
                    Repo    = 'https://cran.r-project.org'
                }

                $instance2 = [CranLibrary] @{
                    Package = 'ggplot2'
                    Repo    = 'https://cran.r-project.org'
                }

                $instance1.Equals($instance2) | Should -BeTrue
            }
        }

        It 'Should return $false when Package is different' {
            InModuleScope -ScriptBlock {
                $instance1 = [CranLibrary] @{
                    Package = 'ggplot2'
                }

                $instance2 = [CranLibrary] @{
                    Package = 'dplyr'
                }

                $instance1.Equals($instance2) | Should -BeFalse
            }
        }

        It 'Should return $false when Repo is different' {
            InModuleScope -ScriptBlock {
                $instance1 = [CranLibrary] @{
                    Package = 'ggplot2'
                    Repo    = 'https://cran.r-project.org'
                }

                $instance2 = [CranLibrary] @{
                    Package = 'ggplot2'
                    Repo    = 'https://cran.rstudio.com'
                }

                $instance1.Equals($instance2) | Should -BeFalse
            }
        }

        It 'Should return $false when comparing with different type' {
            InModuleScope -ScriptBlock {
                $instance1 = [CranLibrary] @{
                    Package = 'ggplot2'
                }

                $instance1.Equals('not a CranLibrary') | Should -BeFalse
            }
        }
    }

    Context 'ToString() method' {
        It 'Should return Package name when Repo is not specified' {
            InModuleScope -ScriptBlock {
                $instance = [CranLibrary] @{
                    Package = 'ggplot2'
                }

                $instance.ToString() | Should -Be 'ggplot2'
            }
        }

        It 'Should return Package name with Repo when Repo is specified' {
            InModuleScope -ScriptBlock {
                $instance = [CranLibrary] @{
                    Package = 'ggplot2'
                    Repo    = 'https://cran.r-project.org'
                }

                $instance.ToString() | Should -Be 'ggplot2 (from https://cran.r-project.org)'
            }
        }
    }
}

Describe 'MavenLibrary' -Tag 'MavenLibrary' {
    Context 'Class instantiation' {
        It 'Should instantiate without errors' {
            InModuleScope -ScriptBlock {
                { [MavenLibrary]::new() } | Should -Not -Throw
            }
        }

        It 'Should allow setting Coordinates property' {
            InModuleScope -ScriptBlock {
                $instance = [MavenLibrary] @{
                    Coordinates = 'org.jsoup:jsoup:1.7.2'
                }

                $instance.Coordinates | Should -Be 'org.jsoup:jsoup:1.7.2'
            }
        }

        It 'Should allow setting Exclusions property' {
            InModuleScope -ScriptBlock {
                $instance = [MavenLibrary] @{
                    Coordinates = 'org.jsoup:jsoup:1.7.2'
                    Exclusions  = @('slf4j:slf4j', '*:hadoop-client')
                }

                $instance.Exclusions | Should -HaveCount 2
                $instance.Exclusions[0] | Should -Be 'slf4j:slf4j'
            }
        }

        It 'Should allow setting Repo property' {
            InModuleScope -ScriptBlock {
                $instance = [MavenLibrary] @{
                    Coordinates = 'org.jsoup:jsoup:1.7.2'
                    Repo        = 'https://repo1.maven.org/maven2'
                }

                $instance.Repo | Should -Be 'https://repo1.maven.org/maven2'
            }
        }
    }

    Context 'Equals() method' {
        It 'Should return $true when objects are equal' {
            InModuleScope -ScriptBlock {
                $instance1 = [MavenLibrary] @{
                    Coordinates = 'org.jsoup:jsoup:1.7.2'
                    Exclusions  = @('slf4j:slf4j')
                    Repo        = 'https://repo1.maven.org/maven2'
                }

                $instance2 = [MavenLibrary] @{
                    Coordinates = 'org.jsoup:jsoup:1.7.2'
                    Exclusions  = @('slf4j:slf4j')
                    Repo        = 'https://repo1.maven.org/maven2'
                }

                $instance1.Equals($instance2) | Should -BeTrue
            }
        }

        It 'Should return $false when Coordinates is different' {
            InModuleScope -ScriptBlock {
                $instance1 = [MavenLibrary] @{
                    Coordinates = 'org.jsoup:jsoup:1.7.2'
                }

                $instance2 = [MavenLibrary] @{
                    Coordinates = 'org.jsoup:jsoup:1.8.0'
                }

                $instance1.Equals($instance2) | Should -BeFalse
            }
        }

        It 'Should return $false when Repo is different' {
            InModuleScope -ScriptBlock {
                $instance1 = [MavenLibrary] @{
                    Coordinates = 'org.jsoup:jsoup:1.7.2'
                    Repo        = 'https://repo1.maven.org/maven2'
                }

                $instance2 = [MavenLibrary] @{
                    Coordinates = 'org.jsoup:jsoup:1.7.2'
                    Repo        = 'https://repo2.maven.org/maven2'
                }

                $instance1.Equals($instance2) | Should -BeFalse
            }
        }

        It 'Should return $false when Exclusions count is different' {
            InModuleScope -ScriptBlock {
                $instance1 = [MavenLibrary] @{
                    Coordinates = 'org.jsoup:jsoup:1.7.2'
                    Exclusions  = @('slf4j:slf4j')
                }

                $instance2 = [MavenLibrary] @{
                    Coordinates = 'org.jsoup:jsoup:1.7.2'
                    Exclusions  = @('slf4j:slf4j', '*:hadoop-client')
                }

                $instance1.Equals($instance2) | Should -BeFalse
            }
        }

        It 'Should return $false when Exclusions values are different' {
            InModuleScope -ScriptBlock {
                $instance1 = [MavenLibrary] @{
                    Coordinates = 'org.jsoup:jsoup:1.7.2'
                    Exclusions  = @('slf4j:slf4j')
                }

                $instance2 = [MavenLibrary] @{
                    Coordinates = 'org.jsoup:jsoup:1.7.2'
                    Exclusions  = @('*:hadoop-client')
                }

                $instance1.Equals($instance2) | Should -BeFalse
            }
        }

        It 'Should return $false when one has Exclusions and other does not' {
            InModuleScope -ScriptBlock {
                $instance1 = [MavenLibrary] @{
                    Coordinates = 'org.jsoup:jsoup:1.7.2'
                    Exclusions  = @('slf4j:slf4j')
                }

                $instance2 = [MavenLibrary] @{
                    Coordinates = 'org.jsoup:jsoup:1.7.2'
                }

                $instance1.Equals($instance2) | Should -BeFalse
            }
        }

        It 'Should return $true when both have null Exclusions' {
            InModuleScope -ScriptBlock {
                $instance1 = [MavenLibrary] @{
                    Coordinates = 'org.jsoup:jsoup:1.7.2'
                }

                $instance2 = [MavenLibrary] @{
                    Coordinates = 'org.jsoup:jsoup:1.7.2'
                }

                $instance1.Equals($instance2) | Should -BeTrue
            }
        }

        It 'Should return $false when comparing with different type' {
            InModuleScope -ScriptBlock {
                $instance1 = [MavenLibrary] @{
                    Coordinates = 'org.jsoup:jsoup:1.7.2'
                }

                $instance1.Equals('not a MavenLibrary') | Should -BeFalse
            }
        }
    }

    Context 'ToString() method' {
        It 'Should return Coordinates' {
            InModuleScope -ScriptBlock {
                $instance = [MavenLibrary] @{
                    Coordinates = 'org.jsoup:jsoup:1.7.2'
                    Exclusions  = @('slf4j:slf4j')
                    Repo        = 'https://repo1.maven.org/maven2'
                }

                $instance.ToString() | Should -Be 'org.jsoup:jsoup:1.7.2'
            }
        }
    }
}

Describe 'PyPiLibrary' -Tag 'PyPiLibrary' {
    Context 'Class instantiation' {
        It 'Should instantiate without errors' {
            InModuleScope -ScriptBlock {
                { [PyPiLibrary]::new() } | Should -Not -Throw
            }
        }

        It 'Should allow setting Package property' {
            InModuleScope -ScriptBlock {
                $instance = [PyPiLibrary] @{
                    Package = 'simplejson==3.8.0'
                }

                $instance.Package | Should -Be 'simplejson==3.8.0'
            }
        }

        It 'Should allow setting Repo property' {
            InModuleScope -ScriptBlock {
                $instance = [PyPiLibrary] @{
                    Package = 'simplejson'
                    Repo    = 'https://pypi.org/simple'
                }

                $instance.Repo | Should -Be 'https://pypi.org/simple'
            }
        }
    }

    Context 'Equals() method' {
        It 'Should return $true when objects are equal' {
            InModuleScope -ScriptBlock {
                $instance1 = [PyPiLibrary] @{
                    Package = 'simplejson==3.8.0'
                    Repo    = 'https://pypi.org/simple'
                }

                $instance2 = [PyPiLibrary] @{
                    Package = 'simplejson==3.8.0'
                    Repo    = 'https://pypi.org/simple'
                }

                $instance1.Equals($instance2) | Should -BeTrue
            }
        }

        It 'Should return $false when Package is different' {
            InModuleScope -ScriptBlock {
                $instance1 = [PyPiLibrary] @{
                    Package = 'simplejson==3.8.0'
                }

                $instance2 = [PyPiLibrary] @{
                    Package = 'simplejson==3.9.0'
                }

                $instance1.Equals($instance2) | Should -BeFalse
            }
        }

        It 'Should return $false when Repo is different' {
            InModuleScope -ScriptBlock {
                $instance1 = [PyPiLibrary] @{
                    Package = 'simplejson'
                    Repo    = 'https://pypi.org/simple'
                }

                $instance2 = [PyPiLibrary] @{
                    Package = 'simplejson'
                    Repo    = 'https://pypi.python.org/simple'
                }

                $instance1.Equals($instance2) | Should -BeFalse
            }
        }

        It 'Should return $false when comparing with different type' {
            InModuleScope -ScriptBlock {
                $instance1 = [PyPiLibrary] @{
                    Package = 'simplejson'
                }

                $instance1.Equals('not a PyPiLibrary') | Should -BeFalse
            }
        }
    }

    Context 'ToString() method' {
        It 'Should return Package name when Repo is not specified' {
            InModuleScope -ScriptBlock {
                $instance = [PyPiLibrary] @{
                    Package = 'simplejson==3.8.0'
                }

                $instance.ToString() | Should -Be 'simplejson==3.8.0'
            }
        }

        It 'Should return Package name with Repo when Repo is specified' {
            InModuleScope -ScriptBlock {
                $instance = [PyPiLibrary] @{
                    Package = 'simplejson'
                    Repo    = 'https://pypi.org/simple'
                }

                $instance.ToString() | Should -Be 'simplejson (from https://pypi.org/simple)'
            }
        }
    }
}

Describe 'ClusterPolicyLibrary' -Tag 'ClusterPolicyLibrary' {
    Context 'Class instantiation' {
        It 'Should instantiate without errors' {
            InModuleScope -ScriptBlock {
                { [ClusterPolicyLibrary]::new() } | Should -Not -Throw
            }
        }

        It 'Should allow setting Cran property' {
            InModuleScope -ScriptBlock {
                $instance = [ClusterPolicyLibrary] @{
                    Cran = [CranLibrary] @{
                        Package = 'ggplot2'
                    }
                }

                $instance.Cran.Package | Should -Be 'ggplot2'
            }
        }

        It 'Should allow setting Jar property' {
            InModuleScope -ScriptBlock {
                $instance = [ClusterPolicyLibrary] @{
                    Jar = '/Workspace/path/to/library.jar'
                }

                $instance.Jar | Should -Be '/Workspace/path/to/library.jar'
            }
        }

        It 'Should allow setting Maven property' {
            InModuleScope -ScriptBlock {
                $instance = [ClusterPolicyLibrary] @{
                    Maven = [MavenLibrary] @{
                        Coordinates = 'org.jsoup:jsoup:1.7.2'
                    }
                }

                $instance.Maven.Coordinates | Should -Be 'org.jsoup:jsoup:1.7.2'
            }
        }

        It 'Should allow setting PyPi property' {
            InModuleScope -ScriptBlock {
                $instance = [ClusterPolicyLibrary] @{
                    PyPi = [PyPiLibrary] @{
                        Package = 'simplejson'
                    }
                }

                $instance.PyPi.Package | Should -Be 'simplejson'
            }
        }

        It 'Should allow setting Requirements property' {
            InModuleScope -ScriptBlock {
                $instance = [ClusterPolicyLibrary] @{
                    Requirements = '/Workspace/path/to/requirements.txt'
                }

                $instance.Requirements | Should -Be '/Workspace/path/to/requirements.txt'
            }
        }

        It 'Should allow setting Whl property' {
            InModuleScope -ScriptBlock {
                $instance = [ClusterPolicyLibrary] @{
                    Whl = '/Volumes/path/to/library.whl'
                }

                $instance.Whl | Should -Be '/Volumes/path/to/library.whl'
            }
        }
    }

    Context 'Equals() method' {
        It 'Should return $true when Jar libraries are equal' {
            InModuleScope -ScriptBlock {
                $instance1 = [ClusterPolicyLibrary] @{
                    Jar = '/Workspace/path/to/library.jar'
                }

                $instance2 = [ClusterPolicyLibrary] @{
                    Jar = '/Workspace/path/to/library.jar'
                }

                $instance1.Equals($instance2) | Should -BeTrue
            }
        }

        It 'Should return $false when Jar libraries are different' {
            InModuleScope -ScriptBlock {
                $instance1 = [ClusterPolicyLibrary] @{
                    Jar = '/Workspace/path/to/library.jar'
                }

                $instance2 = [ClusterPolicyLibrary] @{
                    Jar = '/Workspace/path/to/other.jar'
                }

                $instance1.Equals($instance2) | Should -BeFalse
            }
        }

        It 'Should return $true when Cran libraries are equal' {
            InModuleScope -ScriptBlock {
                $instance1 = [ClusterPolicyLibrary] @{
                    Cran = [CranLibrary] @{
                        Package = 'ggplot2'
                        Repo    = 'https://cran.r-project.org'
                    }
                }

                $instance2 = [ClusterPolicyLibrary] @{
                    Cran = [CranLibrary] @{
                        Package = 'ggplot2'
                        Repo    = 'https://cran.r-project.org'
                    }
                }

                $instance1.Equals($instance2) | Should -BeTrue
            }
        }

        It 'Should return $false when Cran libraries are different' {
            InModuleScope -ScriptBlock {
                $instance1 = [ClusterPolicyLibrary] @{
                    Cran = [CranLibrary] @{
                        Package = 'ggplot2'
                    }
                }

                $instance2 = [ClusterPolicyLibrary] @{
                    Cran = [CranLibrary] @{
                        Package = 'dplyr'
                    }
                }

                $instance1.Equals($instance2) | Should -BeFalse
            }
        }

        It 'Should return $true when Maven libraries are equal' {
            InModuleScope -ScriptBlock {
                $instance1 = [ClusterPolicyLibrary] @{
                    Maven = [MavenLibrary] @{
                        Coordinates = 'org.jsoup:jsoup:1.7.2'
                    }
                }

                $instance2 = [ClusterPolicyLibrary] @{
                    Maven = [MavenLibrary] @{
                        Coordinates = 'org.jsoup:jsoup:1.7.2'
                    }
                }

                $instance1.Equals($instance2) | Should -BeTrue
            }
        }

        It 'Should return $false when Maven libraries are different' {
            InModuleScope -ScriptBlock {
                $instance1 = [ClusterPolicyLibrary] @{
                    Maven = [MavenLibrary] @{
                        Coordinates = 'org.jsoup:jsoup:1.7.2'
                    }
                }

                $instance2 = [ClusterPolicyLibrary] @{
                    Maven = [MavenLibrary] @{
                        Coordinates = 'org.jsoup:jsoup:1.8.0'
                    }
                }

                $instance1.Equals($instance2) | Should -BeFalse
            }
        }

        It 'Should return $true when PyPi libraries are equal' {
            InModuleScope -ScriptBlock {
                $instance1 = [ClusterPolicyLibrary] @{
                    PyPi = [PyPiLibrary] @{
                        Package = 'simplejson'
                    }
                }

                $instance2 = [ClusterPolicyLibrary] @{
                    PyPi = [PyPiLibrary] @{
                        Package = 'simplejson'
                    }
                }

                $instance1.Equals($instance2) | Should -BeTrue
            }
        }

        It 'Should return $false when PyPi libraries are different' {
            InModuleScope -ScriptBlock {
                $instance1 = [ClusterPolicyLibrary] @{
                    PyPi = [PyPiLibrary] @{
                        Package = 'simplejson'
                    }
                }

                $instance2 = [ClusterPolicyLibrary] @{
                    PyPi = [PyPiLibrary] @{
                        Package = 'requests'
                    }
                }

                $instance1.Equals($instance2) | Should -BeFalse
            }
        }

        It 'Should return $true when Requirements are equal' {
            InModuleScope -ScriptBlock {
                $instance1 = [ClusterPolicyLibrary] @{
                    Requirements = '/Workspace/path/to/requirements.txt'
                }

                $instance2 = [ClusterPolicyLibrary] @{
                    Requirements = '/Workspace/path/to/requirements.txt'
                }

                $instance1.Equals($instance2) | Should -BeTrue
            }
        }

        It 'Should return $false when Requirements are different' {
            InModuleScope -ScriptBlock {
                $instance1 = [ClusterPolicyLibrary] @{
                    Requirements = '/Workspace/path/to/requirements.txt'
                }

                $instance2 = [ClusterPolicyLibrary] @{
                    Requirements = '/Workspace/path/to/other.txt'
                }

                $instance1.Equals($instance2) | Should -BeFalse
            }
        }

        It 'Should return $true when Whl libraries are equal' {
            InModuleScope -ScriptBlock {
                $instance1 = [ClusterPolicyLibrary] @{
                    Whl = '/Volumes/path/to/library.whl'
                }

                $instance2 = [ClusterPolicyLibrary] @{
                    Whl = '/Volumes/path/to/library.whl'
                }

                $instance1.Equals($instance2) | Should -BeTrue
            }
        }

        It 'Should return $false when Whl libraries are different' {
            InModuleScope -ScriptBlock {
                $instance1 = [ClusterPolicyLibrary] @{
                    Whl = '/Volumes/path/to/library.whl'
                }

                $instance2 = [ClusterPolicyLibrary] @{
                    Whl = '/Volumes/path/to/other.whl'
                }

                $instance1.Equals($instance2) | Should -BeFalse
            }
        }

        It 'Should return $false when library types are different' {
            InModuleScope -ScriptBlock {
                $instance1 = [ClusterPolicyLibrary] @{
                    Jar = '/Workspace/path/to/library.jar'
                }

                $instance2 = [ClusterPolicyLibrary] @{
                    Whl = '/Volumes/path/to/library.whl'
                }

                $instance1.Equals($instance2) | Should -BeFalse
            }
        }

        It 'Should return $false when comparing with different type' {
            InModuleScope -ScriptBlock {
                $instance1 = [ClusterPolicyLibrary] @{
                    Jar = '/Workspace/path/to/library.jar'
                }

                $instance1.Equals('not a ClusterPolicyLibrary') | Should -BeFalse
            }
        }
    }

    Context 'ToString() method' {
        It 'Should return CRAN prefix for Cran library' {
            InModuleScope -ScriptBlock {
                $instance = [ClusterPolicyLibrary] @{
                    Cran = [CranLibrary] @{
                        Package = 'ggplot2'
                    }
                }

                $instance.ToString() | Should -Be 'CRAN: ggplot2'
            }
        }

        It 'Should return JAR prefix for Jar library' {
            InModuleScope -ScriptBlock {
                $instance = [ClusterPolicyLibrary] @{
                    Jar = '/Workspace/path/to/library.jar'
                }

                $instance.ToString() | Should -Be 'JAR: /Workspace/path/to/library.jar'
            }
        }

        It 'Should return Maven prefix for Maven library' {
            InModuleScope -ScriptBlock {
                $instance = [ClusterPolicyLibrary] @{
                    Maven = [MavenLibrary] @{
                        Coordinates = 'org.jsoup:jsoup:1.7.2'
                    }
                }

                $instance.ToString() | Should -Be 'Maven: org.jsoup:jsoup:1.7.2'
            }
        }

        It 'Should return PyPI prefix for PyPi library' {
            InModuleScope -ScriptBlock {
                $instance = [ClusterPolicyLibrary] @{
                    PyPi = [PyPiLibrary] @{
                        Package = 'simplejson'
                    }
                }

                $instance.ToString() | Should -Be 'PyPI: simplejson'
            }
        }

        It 'Should return Requirements prefix for Requirements library' {
            InModuleScope -ScriptBlock {
                $instance = [ClusterPolicyLibrary] @{
                    Requirements = '/Workspace/path/to/requirements.txt'
                }

                $instance.ToString() | Should -Be 'Requirements: /Workspace/path/to/requirements.txt'
            }
        }

        It 'Should return Wheel prefix for Whl library' {
            InModuleScope -ScriptBlock {
                $instance = [ClusterPolicyLibrary] @{
                    Whl = '/Volumes/path/to/library.whl'
                }

                $instance.ToString() | Should -Be 'Wheel: /Volumes/path/to/library.whl'
            }
        }

        It 'Should return Empty Library when no properties are set' {
            InModuleScope -ScriptBlock {
                $instance = [ClusterPolicyLibrary]::new()

                $instance.ToString() | Should -Be 'Empty Library'
            }
        }
    }
}
