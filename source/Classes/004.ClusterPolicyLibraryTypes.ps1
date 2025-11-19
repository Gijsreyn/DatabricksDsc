<#
    .SYNOPSIS
        Represents a CRAN library specification for cluster policy.

    .PARAMETER Package
        The name of the CRAN package to install.

    .PARAMETER Repo
        The repository where the package can be found. If not specified, the default CRAN repo is used.

    .NOTES
        This class cannot inherit a parent class. If it would have, then the
        DSC resource (e.g. DatabricksClusterPolicy) that uses the complex type fail
        with the error:

            "The 'Libraries' property with type 'ClusterPolicyLibrary' of DSC resource
            class 'DatabricksClusterPolicy' is not supported."

        The method Equals() returns $false if type is not the same on both sides
        of the comparison.

    .EXAMPLE
        [CranLibrary] @{ Package = 'ggplot2' }

        Initializes a new instance of the CranLibrary class with property values.
#>
class CranLibrary : System.IEquatable[Object]
{
    [DscProperty(Mandatory)]
    [System.String]
    $Package

    [DscProperty()]
    [System.String]
    $Repo

    CranLibrary()
    {
    }

    [System.Boolean] Equals([System.Object] $object)
    {
        $isEqual = $false

        if ($object -is $this.GetType())
        {
            if ($this.Package -eq $object.Package)
            {
                if ($this.Repo -eq $object.Repo)
                {
                    $isEqual = $true
                }
            }
        }

        return $isEqual
    }

    [System.String] ToString()
    {
        if ($this.Repo)
        {
            return ('{0} (from {1})' -f $this.Package, $this.Repo)
        }
        else
        {
            return $this.Package
        }
    }
}

<#
    .SYNOPSIS
        Represents a Maven library specification for cluster policy.

    .PARAMETER Coordinates
        Gradle-style maven coordinates. For example: "org.jsoup:jsoup:1.7.2".

    .PARAMETER Exclusions
        List of dependencies to exclude. For example: ["slf4j:slf4j", "*:hadoop-client"].

    .PARAMETER Repo
        Maven repo to install the Maven package from. If omitted, both Maven Central Repository and Spark Packages are searched.

    .NOTES
        This class cannot inherit a parent class.

        The method Equals() returns $false if type is not the same on both sides
        of the comparison.

    .EXAMPLE
        [MavenLibrary] @{ Coordinates = 'org.jsoup:jsoup:1.7.2' }

        Initializes a new instance of the MavenLibrary class with property values.
#>
class MavenLibrary : System.IEquatable[Object]
{
    [DscProperty(Mandatory)]
    [System.String]
    $Coordinates

    [DscProperty()]
    [System.String[]]
    $Exclusions

    [DscProperty()]
    [System.String]
    $Repo

    MavenLibrary()
    {
    }

    [System.Boolean] Equals([System.Object] $object)
    {
        $isEqual = $false

        if ($object -is $this.GetType())
        {
            if ($this.Coordinates -eq $object.Coordinates)
            {
                if ($this.Repo -eq $object.Repo)
                {
                    # Compare exclusions arrays
                    $exclusionsEqual = $true
                    if (($null -eq $this.Exclusions -and $null -ne $object.Exclusions) -or
                        ($null -ne $this.Exclusions -and $null -eq $object.Exclusions))
                    {
                        $exclusionsEqual = $false
                    }
                    elseif ($null -ne $this.Exclusions -and $null -ne $object.Exclusions)
                    {
                        if ($this.Exclusions.Count -ne $object.Exclusions.Count)
                        {
                            $exclusionsEqual = $false
                        }
                        else
                        {
                            for ($i = 0; $i -lt $this.Exclusions.Count; $i++)
                            {
                                if ($this.Exclusions[$i] -ne $object.Exclusions[$i])
                                {
                                    $exclusionsEqual = $false
                                    break
                                }
                            }
                        }
                    }

                    if ($exclusionsEqual)
                    {
                        $isEqual = $true
                    }
                }
            }
        }

        return $isEqual
    }

    [System.String] ToString()
    {
        return $this.Coordinates
    }
}

<#
    .SYNOPSIS
        Represents a PyPI library specification for cluster policy.

    .PARAMETER Package
        The name of the pypi package to install. An optional exact version specification is also supported.
        Examples: "simplejson" and "simplejson==3.8.0".

    .PARAMETER Repo
        The repository where the package can be found. If not specified, the default pip index is used.

    .NOTES
        This class cannot inherit a parent class.

        The method Equals() returns $false if type is not the same on both sides
        of the comparison.

    .EXAMPLE
        [PyPiLibrary] @{ Package = 'simplejson==3.8.0' }

        Initializes a new instance of the PyPiLibrary class with property values.
#>
class PyPiLibrary : System.IEquatable[Object]
{
    [DscProperty(Mandatory)]
    [System.String]
    $Package

    [DscProperty()]
    [System.String]
    $Repo

    PyPiLibrary()
    {
    }

    [System.Boolean] Equals([System.Object] $object)
    {
        $isEqual = $false

        if ($object -is $this.GetType())
        {
            if ($this.Package -eq $object.Package)
            {
                if ($this.Repo -eq $object.Repo)
                {
                    $isEqual = $true
                }
            }
        }

        return $isEqual
    }

    [System.String] ToString()
    {
        if ($this.Repo)
        {
            return ('{0} (from {1})' -f $this.Package, $this.Repo)
        }
        else
        {
            return $this.Package
        }
    }
}

<#
    .SYNOPSIS
        Represents a library specification for cluster policy.

    .PARAMETER Cran
        Specification of a CRAN library to be installed.

    .PARAMETER Jar
        URI of the JAR library to install. Supports Workspace paths, Unity Catalog Volumes paths, and ADLS URIs.

    .PARAMETER Maven
        Specification of a maven library to be installed.

    .PARAMETER PyPi
        Specification of a PyPi library to be installed.

    .PARAMETER Requirements
        URI of the requirements.txt file to install. Only Workspace paths and Unity Catalog Volumes paths are supported.

    .PARAMETER Whl
        URI of the wheel library to install. Supports Workspace paths, Unity Catalog Volumes paths, and ADLS URIs.

    .NOTES
        This class cannot inherit a parent class.

        The method Equals() returns $false if type is not the same on both sides
        of the comparison.

    .EXAMPLE
        [ClusterPolicyLibrary] @{ Jar = '/Workspace/path/to/library.jar' }

        Initializes a new instance of the ClusterPolicyLibrary class with a JAR library.

    .EXAMPLE
        [ClusterPolicyLibrary] @{ PyPi = [PyPiLibrary] @{ Package = 'simplejson' } }

        Initializes a new instance of the ClusterPolicyLibrary class with a PyPI library.
#>
class ClusterPolicyLibrary : System.IEquatable[Object]
{
    [DscProperty()]
    [CranLibrary]
    $Cran

    [DscProperty()]
    [System.String]
    $Jar

    [DscProperty()]
    [MavenLibrary]
    $Maven

    [DscProperty()]
    [PyPiLibrary]
    $PyPi

    [DscProperty()]
    [System.String]
    $Requirements

    [DscProperty()]
    [System.String]
    $Whl

    ClusterPolicyLibrary()
    {
    }

    [System.Boolean] Equals([System.Object] $object)
    {
        $isEqual = $false

        if ($object -is $this.GetType())
        {
            # Check if all properties are equal
            $cranEqual = ($null -eq $this.Cran -and $null -eq $object.Cran) -or
                         ($null -ne $this.Cran -and $this.Cran.Equals($object.Cran))
            $jarEqual = $this.Jar -eq $object.Jar
            $mavenEqual = ($null -eq $this.Maven -and $null -eq $object.Maven) -or
                          ($null -ne $this.Maven -and $this.Maven.Equals($object.Maven))
            $pypiEqual = ($null -eq $this.PyPi -and $null -eq $object.PyPi) -or
                         ($null -ne $this.PyPi -and $this.PyPi.Equals($object.PyPi))
            $requirementsEqual = $this.Requirements -eq $object.Requirements
            $whlEqual = $this.Whl -eq $object.Whl

            if ($cranEqual -and $jarEqual -and $mavenEqual -and $pypiEqual -and $requirementsEqual -and $whlEqual)
            {
                $isEqual = $true
            }
        }

        return $isEqual
    }

    [System.String] ToString()
    {
        if ($this.Cran)
        {
            return ('CRAN: {0}' -f $this.Cran.ToString())
        }
        elseif ($this.Jar)
        {
            return ('JAR: {0}' -f $this.Jar)
        }
        elseif ($this.Maven)
        {
            return ('Maven: {0}' -f $this.Maven.ToString())
        }
        elseif ($this.PyPi)
        {
            return ('PyPI: {0}' -f $this.PyPi.ToString())
        }
        elseif ($this.Requirements)
        {
            return ('Requirements: {0}' -f $this.Requirements)
        }
        elseif ($this.Whl)
        {
            return ('Wheel: {0}' -f $this.Whl)
        }
        else
        {
            return 'Empty Library'
        }
    }
}
