<#
    .SYNOPSIS
        Represents the channel configuration for a SQL warehouse.

    .PARAMETER Name
        The name of the channel (e.g., CHANNEL_NAME_PREVIEW, CHANNEL_NAME_CURRENT).

    .PARAMETER DbsqlVersion
        The DBSQL version (optional, used for specific version pinning).

    .NOTES
        This class cannot inherit a parent class. If it would have, then the
        DSC resource (e.g. DatabricksSqlWarehouse) that uses the complex type fail
        with the error:

            "The 'Channel' property with type 'SqlWarehouseChannel' of DSC resource
            class 'DatabricksSqlWarehouse' is not supported."

        The method Equals() returns $false if type is not the same on both sides
        of the comparison.

    .EXAMPLE
        [SqlWarehouseChannel] @{ Name = 'CHANNEL_NAME_CURRENT' }

        Initializes a new instance of the SqlWarehouseChannel class with property values.
#>
class SqlWarehouseChannel : System.IEquatable[Object]
{
    [DscProperty()]
    [System.String]
    $Name

    [DscProperty()]
    [System.String]
    $DbsqlVersion

    SqlWarehouseChannel()
    {
    }

    [System.Boolean] Equals([System.Object] $object)
    {
        $isEqual = $false

        if ($object -is $this.GetType())
        {
            if ($this.Name -eq $object.Name -and $this.DbsqlVersion -eq $object.DbsqlVersion)
            {
                $isEqual = $true
            }
        }

        return $isEqual
    }

    [System.String] ToString()
    {
        if ($this.DbsqlVersion)
        {
            return ('{0} ({1})' -f $this.Name, $this.DbsqlVersion)
        }
        else
        {
            return $this.Name
        }
    }
}

<#
    .SYNOPSIS
        Represents a custom tag for a SQL warehouse.

    .PARAMETER Key
        The key of the custom tag.

    .PARAMETER Value
        The value of the custom tag.

    .NOTES
        This class cannot inherit a parent class.

        The method Equals() returns $false if type is not the same on both sides
        of the comparison.

    .EXAMPLE
        [SqlWarehouseTag] @{ Key = 'Environment'; Value = 'Production' }

        Initializes a new instance of the SqlWarehouseTag class with property values.
#>
class SqlWarehouseTag : System.IEquatable[Object]
{
    [DscProperty(Key)]
    [System.String]
    $Key

    [DscProperty()]
    [System.String]
    $Value

    SqlWarehouseTag()
    {
    }

    [System.Boolean] Equals([System.Object] $object)
    {
        $isEqual = $false

        if ($object -is $this.GetType())
        {
            if ($this.Key -eq $object.Key -and $this.Value -eq $object.Value)
            {
                $isEqual = $true
            }
        }

        return $isEqual
    }

    [System.String] ToString()
    {
        return ('{0}={1}' -f $this.Key, $this.Value)
    }
}

<#
    .SYNOPSIS
        Represents the tags configuration for a SQL warehouse.

    .PARAMETER CustomTags
        An array of custom tags to apply to the SQL warehouse resources.

    .NOTES
        This class cannot inherit a parent class.

        The method Equals() returns $false if type is not the same on both sides
        of the comparison.

    .EXAMPLE
        [SqlWarehouseTags] @{
            CustomTags = @(
                [SqlWarehouseTag] @{ Key = 'Environment'; Value = 'Production' }
            )
        }

        Initializes a new instance of the SqlWarehouseTags class with property values.
#>
class SqlWarehouseTags : System.IEquatable[Object]
{
    [DscProperty()]
    [SqlWarehouseTag[]]
    $CustomTags

    SqlWarehouseTags()
    {
    }

    [System.Boolean] Equals([System.Object] $object)
    {
        $isEqual = $false

        if ($object -is $this.GetType())
        {
            if ($null -eq $this.CustomTags -and $null -eq $object.CustomTags)
            {
                $isEqual = $true
            }
            elseif ($null -ne $this.CustomTags -and $null -ne $object.CustomTags)
            {
                if ($this.CustomTags.Count -eq $object.CustomTags.Count)
                {
                    $isEqual = $true

                    foreach ($tag in $this.CustomTags)
                    {
                        $matchingTag = $object.CustomTags | Where-Object -FilterScript {
                            $_.Key -eq $tag.Key -and $_.Value -eq $tag.Value
                        }

                        if (-not $matchingTag)
                        {
                            $isEqual = $false
                            break
                        }
                    }
                }
            }
        }

        return $isEqual
    }

    [System.String] ToString()
    {
        if ($this.CustomTags)
        {
            return ($this.CustomTags | ForEach-Object -Process { $_.ToString() }) -join ', '
        }
        else
        {
            return ''
        }
    }
}
