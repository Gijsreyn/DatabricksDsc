<#
    .SYNOPSIS
        Unit test for UserTypes classes (UserEmail, UserName, UserEntitlement, UserRole).
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

Describe 'UserEmail' -Tag 'UserEmail' {
    Context 'When instantiating the class' {
        It 'Should not throw an error' {
            $script:mockUserEmailInstance = InModuleScope -ScriptBlock {
                [UserEmail]::new()
            }
        }

        It 'Should be of the correct type' {
            $mockUserEmailInstance | Should -Not -BeNullOrEmpty
            $mockUserEmailInstance.GetType().Name | Should -Be 'UserEmail'
        }
    }

    Context 'When setting and reading values' {
        It 'Should be able to set value in instance' {
            $script:mockUserEmailInstance = InModuleScope -ScriptBlock {
                $userEmailInstance = [UserEmail]::new()

                $userEmailInstance.Value = 'user@example.com'
                $userEmailInstance.Type = 'work'
                $userEmailInstance.Primary = $true

                return $userEmailInstance
            }
        }

        It 'Should be able to read the values from instance' {
            $mockUserEmailInstance.Value | Should -Be 'user@example.com'
            $mockUserEmailInstance.Type | Should -Be 'work'
            $mockUserEmailInstance.Primary | Should -BeTrue
        }
    }

    Context 'When comparing two objects using method Equals()' {
        Context 'When both objects are equal' {
            It 'Should return $true' {
                InModuleScope -ScriptBlock {
                    $userEmailInstance1 = [UserEmail]::new()
                    $userEmailInstance1.Value = 'user@example.com'
                    $userEmailInstance1.Type = 'work'
                    $userEmailInstance1.Primary = $true

                    $userEmailInstance2 = [UserEmail]::new()
                    $userEmailInstance2.Value = 'user@example.com'
                    $userEmailInstance2.Type = 'work'
                    $userEmailInstance2.Primary = $true

                    $userEmailInstance1 -eq $userEmailInstance2 | Should -BeTrue
                }
            }
        }

        Context 'When object has different value for property Value' {
            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    $userEmailInstance1 = [UserEmail]::new()
                    $userEmailInstance1.Value = 'user1@example.com'
                    $userEmailInstance1.Type = 'work'
                    $userEmailInstance1.Primary = $true

                    $userEmailInstance2 = [UserEmail]::new()
                    $userEmailInstance2.Value = 'user2@example.com'
                    $userEmailInstance2.Type = 'work'
                    $userEmailInstance2.Primary = $true

                    $userEmailInstance1 -eq $userEmailInstance2 | Should -BeFalse
                }
            }
        }

        Context 'When object has different value for property Type' {
            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    $userEmailInstance1 = [UserEmail]::new()
                    $userEmailInstance1.Value = 'user@example.com'
                    $userEmailInstance1.Type = 'work'
                    $userEmailInstance1.Primary = $true

                    $userEmailInstance2 = [UserEmail]::new()
                    $userEmailInstance2.Value = 'user@example.com'
                    $userEmailInstance2.Type = 'home'
                    $userEmailInstance2.Primary = $true

                    $userEmailInstance1 -eq $userEmailInstance2 | Should -BeFalse
                }
            }
        }

        Context 'When object has different value for property Primary' {
            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    $userEmailInstance1 = [UserEmail]::new()
                    $userEmailInstance1.Value = 'user@example.com'
                    $userEmailInstance1.Type = 'work'
                    $userEmailInstance1.Primary = $true

                    $userEmailInstance2 = [UserEmail]::new()
                    $userEmailInstance2.Value = 'user@example.com'
                    $userEmailInstance2.Type = 'work'
                    $userEmailInstance2.Primary = $false

                    $userEmailInstance1 -eq $userEmailInstance2 | Should -BeFalse
                }
            }
        }

        Context 'When comparing against a different type' {
            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    $userEmailInstance1 = [UserEmail]::new()
                    $userEmailInstance1.Value = 'user@example.com'

                    $userEmailInstance1 -eq 'user@example.com' | Should -BeFalse
                }
            }
        }
    }

    Context 'When comparing two objects using method CompareTo()' {
        Context 'When the instance is compared against an invalid object' {
            It 'Should throw an exception' {
                $mockUserEmailInstance1 = InModuleScope -ScriptBlock {
                    [UserEmail] @{
                        Value   = 'user@example.com'
                        Type    = 'work'
                        Primary = $true
                    }
                }

                $mockErrorMessage = InModuleScope -ScriptBlock {
                    $script:localizedData.InvalidTypeForCompare
                }

                $mockErrorMessage = $mockErrorMessage -f @(
                    $mockUserEmailInstance1.GetType().FullName
                    'System.String'
                )

                # Escape the brackets so Pester can evaluate the string correctly.
                $mockErrorMessage = $mockErrorMessage -replace '\[', '`['
                $mockErrorMessage = $mockErrorMessage -replace '\]', '`]'

                { $mockUserEmailInstance1.CompareTo('AnyValue') } | Should -Throw -ExpectedMessage "*$mockErrorMessage*"
            }
        }

        Context 'When the instance precedes the object being compared' {
            Context 'When comparing by Primary (primary comes first)' {
                It 'Should return a value less than zero' {
                    InModuleScope -ScriptBlock {
                        $userEmailInstance1 = [UserEmail] @{
                            Value   = 'user@example.com'
                            Type    = 'work'
                            Primary = $true
                        }

                        $userEmailInstance2 = [UserEmail] @{
                            Value   = 'user@example.com'
                            Type    = 'work'
                            Primary = $false
                        }

                        $userEmailInstance1.CompareTo($userEmailInstance2) | Should -BeLessThan 0
                    }
                }
            }

            Context 'When comparing by Value (both have same Primary status)' {
                It 'Should return a value less than zero' {
                    InModuleScope -ScriptBlock {
                        $userEmailInstance1 = [UserEmail] @{
                            Value   = 'aaa@example.com'
                            Type    = 'work'
                            Primary = $true
                        }

                        $userEmailInstance2 = [UserEmail] @{
                            Value   = 'zzz@example.com'
                            Type    = 'work'
                            Primary = $true
                        }

                        $userEmailInstance1.CompareTo($userEmailInstance2) | Should -BeLessThan 0
                    }
                }
            }
        }

        Context 'When the instance follows the object being compared' {
            Context 'When comparing by Primary (non-primary comes after)' {
                It 'Should return a value greater than zero' {
                    InModuleScope -ScriptBlock {
                        $userEmailInstance1 = [UserEmail] @{
                            Value   = 'user@example.com'
                            Type    = 'work'
                            Primary = $false
                        }

                        $userEmailInstance2 = [UserEmail] @{
                            Value   = 'user@example.com'
                            Type    = 'work'
                            Primary = $true
                        }

                        $userEmailInstance1.CompareTo($userEmailInstance2) | Should -BeGreaterThan 0
                    }
                }
            }

            Context 'When comparing by Value (both have same Primary status)' {
                It 'Should return a value greater than zero' {
                    InModuleScope -ScriptBlock {
                        $userEmailInstance1 = [UserEmail] @{
                            Value   = 'zzz@example.com'
                            Type    = 'work'
                            Primary = $false
                        }

                        $userEmailInstance2 = [UserEmail] @{
                            Value   = 'aaa@example.com'
                            Type    = 'work'
                            Primary = $false
                        }

                        $userEmailInstance1.CompareTo($userEmailInstance2) | Should -BeGreaterThan 0
                    }
                }
            }

            Context 'When the instance is compared against an object that is $null' {
                It 'Should return a value greater than zero' {
                    $mockUserEmailInstance1 = InModuleScope -ScriptBlock {
                        [UserEmail] @{
                            Value   = 'user@example.com'
                            Type    = 'work'
                            Primary = $true
                        }
                    }

                    $mockUserEmailInstance1.CompareTo($null) | Should -BeGreaterThan 0
                }
            }
        }

        Context 'When the instance is in the same position as the object being compared' {
            It 'Should return zero' {
                InModuleScope -ScriptBlock {
                    $userEmailInstance1 = [UserEmail] @{
                        Value   = 'user@example.com'
                        Type    = 'work'
                        Primary = $true
                    }

                    $userEmailInstance2 = [UserEmail] @{
                        Value   = 'user@example.com'
                        Type    = 'work'
                        Primary = $true
                    }

                    $userEmailInstance1.CompareTo($userEmailInstance2) | Should -Be 0
                }
            }
        }

        Context 'When sorting the instances' {
            It 'Should always sort with primary emails first, then by Value' {
                InModuleScope -ScriptBlock {
                    $mockUserEmailArray = @(
                        [UserEmail] @{
                            Value   = 'zzz@example.com'
                            Type    = 'work'
                            Primary = $false
                        }
                        [UserEmail] @{
                            Value   = 'bbb@example.com'
                            Type    = 'work'
                            Primary = $true
                        }
                        [UserEmail] @{
                            Value   = 'aaa@example.com'
                            Type    = 'work'
                            Primary = $false
                        }
                    )

                    $mockSortedArray = $mockUserEmailArray | Sort-Object

                    # Primary email should be first
                    $mockSortedArray[0].Primary | Should -BeTrue
                    $mockSortedArray[0].Value | Should -Be 'bbb@example.com'

                    # Non-primary emails sorted by Value
                    $mockSortedArray[1].Value | Should -Be 'aaa@example.com'
                    $mockSortedArray[2].Value | Should -Be 'zzz@example.com'
                }
            }
        }
    }

    Context 'When using method ToString()' {
        Context 'When Primary is $true' {
            It 'Should return a formatted string with Primary indicator' {
                InModuleScope -ScriptBlock {
                    $userEmailInstance = [UserEmail] @{
                        Value   = 'user@example.com'
                        Type    = 'work'
                        Primary = $true
                    }

                    $userEmailInstance.ToString() | Should -Be 'user@example.com (work, Primary)'
                }
            }
        }

        Context 'When Primary is $false' {
            It 'Should return a formatted string without Primary indicator' {
                InModuleScope -ScriptBlock {
                    $userEmailInstance = [UserEmail] @{
                        Value   = 'user@example.com'
                        Type    = 'work'
                        Primary = $false
                    }

                    $userEmailInstance.ToString() | Should -Be 'user@example.com (work)'
                }
            }
        }

        Context 'When Primary is $null' {
            It 'Should return a formatted string without Primary indicator' {
                InModuleScope -ScriptBlock {
                    $userEmailInstance = [UserEmail] @{
                        Value   = 'user@example.com'
                        Type    = 'work'
                    }

                    $userEmailInstance.ToString() | Should -Be 'user@example.com (work)'
                }
            }
        }
    }
}

Describe 'UserName' -Tag 'UserName' {
    Context 'When instantiating the class' {
        It 'Should not throw an error' {
            $script:mockUserNameInstance = InModuleScope -ScriptBlock {
                [UserName]::new()
            }
        }

        It 'Should be of the correct type' {
            $mockUserNameInstance | Should -Not -BeNullOrEmpty
            $mockUserNameInstance.GetType().Name | Should -Be 'UserName'
        }
    }

    Context 'When setting and reading values' {
        It 'Should be able to set value in instance' {
            $script:mockUserNameInstance = InModuleScope -ScriptBlock {
                $userNameInstance = [UserName]::new()

                $userNameInstance.GivenName = 'John'
                $userNameInstance.FamilyName = 'Doe'

                return $userNameInstance
            }
        }

        It 'Should be able to read the values from instance' {
            $mockUserNameInstance.GivenName | Should -Be 'John'
            $mockUserNameInstance.FamilyName | Should -Be 'Doe'
        }
    }

    Context 'When comparing two objects using method Equals()' {
        Context 'When both objects are equal' {
            It 'Should return $true' {
                InModuleScope -ScriptBlock {
                    $userNameInstance1 = [UserName]::new()
                    $userNameInstance1.GivenName = 'John'
                    $userNameInstance1.FamilyName = 'Doe'

                    $userNameInstance2 = [UserName]::new()
                    $userNameInstance2.GivenName = 'John'
                    $userNameInstance2.FamilyName = 'Doe'

                    $userNameInstance1 -eq $userNameInstance2 | Should -BeTrue
                }
            }
        }

        Context 'When object has different value for property FamilyName' {
            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    $userNameInstance1 = [UserName]::new()
                    $userNameInstance1.GivenName = 'John'
                    $userNameInstance1.FamilyName = 'Doe'

                    $userNameInstance2 = [UserName]::new()
                    $userNameInstance2.GivenName = 'John'
                    $userNameInstance2.FamilyName = 'Smith'

                    $userNameInstance1 -eq $userNameInstance2 | Should -BeFalse
                }
            }
        }

        Context 'When object has different value for property GivenName' {
            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    $userNameInstance1 = [UserName]::new()
                    $userNameInstance1.GivenName = 'John'
                    $userNameInstance1.FamilyName = 'Doe'

                    $userNameInstance2 = [UserName]::new()
                    $userNameInstance2.GivenName = 'Jane'
                    $userNameInstance2.FamilyName = 'Doe'

                    $userNameInstance1 -eq $userNameInstance2 | Should -BeFalse
                }
            }
        }

        Context 'When comparing against a different type' {
            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    $userNameInstance1 = [UserName]::new()
                    $userNameInstance1.GivenName = 'John'
                    $userNameInstance1.FamilyName = 'Doe'

                    $userNameInstance1 -eq 'John Doe' | Should -BeFalse
                }
            }
        }
    }

    Context 'When comparing two objects using method CompareTo()' {
        Context 'When the instance is compared against an invalid object' {
            It 'Should throw an exception' {
                $mockUserNameInstance1 = InModuleScope -ScriptBlock {
                    [UserName] @{
                        GivenName  = 'John'
                        FamilyName = 'Doe'
                    }
                }

                $mockErrorMessage = InModuleScope -ScriptBlock {
                    $script:localizedData.InvalidTypeForCompare
                }

                $mockErrorMessage = $mockErrorMessage -f @(
                    $mockUserNameInstance1.GetType().FullName
                    'System.String'
                )

                # Escape the brackets so Pester can evaluate the string correctly.
                $mockErrorMessage = $mockErrorMessage -replace '\[', '`['
                $mockErrorMessage = $mockErrorMessage -replace '\]', '`]'

                { $mockUserNameInstance1.CompareTo('AnyValue') } | Should -Throw -ExpectedMessage "*$mockErrorMessage*"
            }
        }

        Context 'When the instance precedes the object being compared' {
            Context 'When comparing by FamilyName' {
                It 'Should return a value less than zero' {
                    InModuleScope -ScriptBlock {
                        $userNameInstance1 = [UserName] @{
                            GivenName  = 'John'
                            FamilyName = 'Anderson'
                        }

                        $userNameInstance2 = [UserName] @{
                            GivenName  = 'John'
                            FamilyName = 'Zimmerman'
                        }

                        $userNameInstance1.CompareTo($userNameInstance2) | Should -BeLessThan 0
                    }
                }
            }

            Context 'When comparing by GivenName (FamilyName is equal)' {
                It 'Should return a value less than zero' {
                    InModuleScope -ScriptBlock {
                        $userNameInstance1 = [UserName] @{
                            GivenName  = 'Alice'
                            FamilyName = 'Doe'
                        }

                        $userNameInstance2 = [UserName] @{
                            GivenName  = 'Zachary'
                            FamilyName = 'Doe'
                        }

                        $userNameInstance1.CompareTo($userNameInstance2) | Should -BeLessThan 0
                    }
                }
            }
        }

        Context 'When the instance follows the object being compared' {
            Context 'When comparing by FamilyName' {
                It 'Should return a value greater than zero' {
                    InModuleScope -ScriptBlock {
                        $userNameInstance1 = [UserName] @{
                            GivenName  = 'John'
                            FamilyName = 'Zimmerman'
                        }

                        $userNameInstance2 = [UserName] @{
                            GivenName  = 'John'
                            FamilyName = 'Anderson'
                        }

                        $userNameInstance1.CompareTo($userNameInstance2) | Should -BeGreaterThan 0
                    }
                }
            }

            Context 'When comparing by GivenName (FamilyName is equal)' {
                It 'Should return a value greater than zero' {
                    InModuleScope -ScriptBlock {
                        $userNameInstance1 = [UserName] @{
                            GivenName  = 'Zachary'
                            FamilyName = 'Doe'
                        }

                        $userNameInstance2 = [UserName] @{
                            GivenName  = 'Alice'
                            FamilyName = 'Doe'
                        }

                        $userNameInstance1.CompareTo($userNameInstance2) | Should -BeGreaterThan 0
                    }
                }
            }

            Context 'When the instance is compared against an object that is $null' {
                It 'Should return a value greater than zero' {
                    $mockUserNameInstance1 = InModuleScope -ScriptBlock {
                        [UserName] @{
                            GivenName  = 'John'
                            FamilyName = 'Doe'
                        }
                    }

                    $mockUserNameInstance1.CompareTo($null) | Should -BeGreaterThan 0
                }
            }
        }

        Context 'When the instance is in the same position as the object being compared' {
            It 'Should return zero' {
                InModuleScope -ScriptBlock {
                    $userNameInstance1 = [UserName] @{
                        GivenName  = 'John'
                        FamilyName = 'Doe'
                    }

                    $userNameInstance2 = [UserName] @{
                        GivenName  = 'John'
                        FamilyName = 'Doe'
                    }

                    $userNameInstance1.CompareTo($userNameInstance2) | Should -Be 0
                }
            }
        }

        Context 'When sorting the instances' {
            It 'Should always sort by FamilyName first, then by GivenName' {
                InModuleScope -ScriptBlock {
                    $mockUserNameArray = @(
                        [UserName] @{
                            GivenName  = 'Zachary'
                            FamilyName = 'Smith'
                        }
                        [UserName] @{
                            GivenName  = 'Alice'
                            FamilyName = 'Doe'
                        }
                        [UserName] @{
                            GivenName  = 'John'
                            FamilyName = 'Doe'
                        }
                        [UserName] @{
                            GivenName  = 'Betty'
                            FamilyName = 'Anderson'
                        }
                    )

                    $mockSortedArray = $mockUserNameArray | Sort-Object

                    # Sorted by FamilyName first
                    $mockSortedArray[0].FamilyName | Should -Be 'Anderson'
                    $mockSortedArray[1].FamilyName | Should -Be 'Doe'
                    $mockSortedArray[2].FamilyName | Should -Be 'Doe'
                    $mockSortedArray[3].FamilyName | Should -Be 'Smith'

                    # Within same FamilyName, sorted by GivenName
                    $mockSortedArray[1].GivenName | Should -Be 'Alice'
                    $mockSortedArray[2].GivenName | Should -Be 'John'
                }
            }
        }
    }

    Context 'When using method ToString()' {
        It 'Should return a formatted string' {
            InModuleScope -ScriptBlock {
                $userNameInstance = [UserName] @{
                    GivenName  = 'John'
                    FamilyName = 'Doe'
                }

                $userNameInstance.ToString() | Should -Be 'Doe, John'
            }
        }
    }
}

Describe 'UserEntitlement' -Tag 'UserEntitlement' {
    Context 'When instantiating the class' {
        It 'Should not throw an error with mandatory property' {
            InModuleScope -ScriptBlock {
                { [UserEntitlement] @{ Value = 'allow-cluster-create' } } | Should -Not -Throw
            }
        }

        It 'Should be of the correct type' {
            InModuleScope -ScriptBlock {
                $userEntitlementInstance = [UserEntitlement] @{ Value = 'allow-cluster-create' }

                $userEntitlementInstance | Should -Not -BeNullOrEmpty
                $userEntitlementInstance.GetType().Name | Should -Be 'UserEntitlement'
            }
        }
    }

    Context 'When comparing two objects using method Equals()' {
        Context 'When both objects are equal' {
            It 'Should return $true' {
                InModuleScope -ScriptBlock {
                    $userEntitlementInstance1 = [UserEntitlement] @{
                        Value = 'allow-cluster-create'
                    }

                    $userEntitlementInstance2 = [UserEntitlement] @{
                        Value = 'allow-cluster-create'
                    }

                    $userEntitlementInstance1 -eq $userEntitlementInstance2 | Should -BeTrue
                }
            }
        }

        Context 'When objects have different values' {
            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    $userEntitlementInstance1 = [UserEntitlement] @{
                        Value = 'allow-cluster-create'
                    }

                    $userEntitlementInstance2 = [UserEntitlement] @{
                        Value = 'databricks-sql-access'
                    }

                    $userEntitlementInstance1 -eq $userEntitlementInstance2 | Should -BeFalse
                }
            }
        }
    }

    Context 'When comparing two objects using method CompareTo()' {
        Context 'When sorting the instances' {
            It 'Should sort alphabetically by Value' {
                InModuleScope -ScriptBlock {
                    $mockUserEntitlementArray = @(
                        [UserEntitlement] @{ Value = 'workspace-access' }
                        [UserEntitlement] @{ Value = 'allow-cluster-create' }
                        [UserEntitlement] @{ Value = 'databricks-sql-access' }
                    )

                    $mockSortedArray = $mockUserEntitlementArray | Sort-Object

                    $mockSortedArray[0].Value | Should -Be 'allow-cluster-create'
                    $mockSortedArray[1].Value | Should -Be 'databricks-sql-access'
                    $mockSortedArray[2].Value | Should -Be 'workspace-access'
                }
            }
        }
    }

    Context 'When using method ToString()' {
        It 'Should return the Value' {
            InModuleScope -ScriptBlock {
                $userEntitlementInstance = [UserEntitlement] @{
                    Value = 'allow-cluster-create'
                }

                $userEntitlementInstance.ToString() | Should -Be 'allow-cluster-create'
            }
        }
    }
}

Describe 'UserRole' -Tag 'UserRole' {
    Context 'When instantiating the class' {
        It 'Should not throw an error' {
            InModuleScope -ScriptBlock {
                { [UserRole] @{ Value = 'admin' } } | Should -Not -Throw
            }
        }

        It 'Should be of the correct type' {
            InModuleScope -ScriptBlock {
                $userRoleInstance = [UserRole] @{ Value = 'admin' }
                $userRoleInstance.GetType().Name | Should -Be 'UserRole'
                $userRoleInstance | Should -Not -BeNullOrEmpty
            }
        }
    }

    Context 'When comparing two objects using method Equals()' {
        Context 'When both objects are equal' {
            It 'Should return $true' {
                InModuleScope -ScriptBlock {
                    $userRoleInstance1 = [UserRole] @{
                        Value = 'admin'
                    }

                    $userRoleInstance2 = [UserRole] @{
                        Value = 'admin'
                    }

                    $userRoleInstance1 -eq $userRoleInstance2 | Should -BeTrue
                }
            }
        }

        Context 'When objects have different values' {
            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    $userRoleInstance1 = [UserRole] @{
                        Value = 'admin'
                    }

                    $userRoleInstance2 = [UserRole] @{
                        Value = 'user'
                    }

                    $userRoleInstance1 -eq $userRoleInstance2 | Should -BeFalse
                }
            }
        }
    }

    Context 'When comparing two objects using method CompareTo()' {
        Context 'When sorting the instances' {
            It 'Should sort alphabetically by Value' {
                InModuleScope -ScriptBlock {
                    $mockUserRoleArray = @(
                        [UserRole] @{ Value = 'user' }
                        [UserRole] @{ Value = 'admin' }
                        [UserRole] @{ Value = 'developer' }
                    )

                    $mockSortedArray = $mockUserRoleArray | Sort-Object

                    $mockSortedArray[0].Value | Should -Be 'admin'
                    $mockSortedArray[1].Value | Should -Be 'developer'
                    $mockSortedArray[2].Value | Should -Be 'user'
                }
            }
        }
    }

    Context 'When using method ToString()' {
        It 'Should return the Value' {
            InModuleScope -ScriptBlock {
                $userRoleInstance = [UserRole] @{
                    Value = 'admin'
                }

                $userRoleInstance.ToString() | Should -Be 'admin'
            }
        }
    }
}
