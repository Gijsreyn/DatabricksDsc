<#
    .SYNOPSIS
        Represents the Azure Key Vault backend configuration for a Databricks secret scope.

    .PARAMETER DnsName
        The DNS name of the Azure Key Vault.
        Example: 'https://myvault.vault.azure.net/'

    .PARAMETER ResourceId
        The Azure Resource Manager ID of the Azure Key Vault.
        Example: '/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/myRg/providers/Microsoft.KeyVault/vaults/myVault'

    .NOTES
        This class cannot inherit a parent class. If it would have, then the
        DSC resource (e.g. DatabricksSecretScope) that uses the complex type fail
        with the error:

            "The 'BackendAzureKeyVault' property with type 'AzureKeyVaultBackend' of DSC resource
            class 'DatabricksSecretScope' is not supported."

        The method Equals() returns $false if type is not the same on both sides
        of the comparison.

    .EXAMPLE
        [AzureKeyVaultBackend] @{}

        Initializes a new instance of the AzureKeyVaultBackend class without any
        property values.

    .EXAMPLE
        [AzureKeyVaultBackend] @{
            DnsName = 'https://myvault.vault.azure.net/'
            ResourceId = '/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/myRg/providers/Microsoft.KeyVault/vaults/myVault'
        }

        Initializes a new instance of the AzureKeyVaultBackend class with property values.
#>
class AzureKeyVaultBackend : IComparable, System.IEquatable[Object]
{
    [DscProperty(Mandatory)]
    [System.String]
    $DnsName

    [DscProperty(Mandatory)]
    [System.String]
    $ResourceId

    AzureKeyVaultBackend()
    {
    }

    [System.Boolean] Equals([System.Object] $object)
    {
        $isEqual = $false

        if ($object -is $this.GetType())
        {
            if ($this.DnsName -eq $object.DnsName)
            {
                if ($this.ResourceId -eq $object.ResourceId)
                {
                    $isEqual = $true
                }
            }
        }

        return $isEqual
    }

    [System.Int32] CompareTo([Object] $object)
    {
        [System.Int32] $returnValue = 0

        if ($null -eq $object)
        {
            return 1
        }

        if ($object -is $this.GetType())
        {
            # Compare by ResourceId first
            $returnValue = [System.String]::Compare($this.ResourceId, $object.ResourceId, [System.StringComparison]::OrdinalIgnoreCase)

            # If ResourceId is equal, compare by DnsName
            if ($returnValue -eq 0)
            {
                $returnValue = [System.String]::Compare($this.DnsName, $object.DnsName, [System.StringComparison]::OrdinalIgnoreCase)
            }
        }
        else
        {
            $errorMessage = $script:localizedData.InvalidTypeForCompare -f @(
                $this.GetType().FullName,
                $object.GetType().FullName
            )

            New-ArgumentException -ArgumentName 'Object' -Message $errorMessage
        }

        return $returnValue
    }

    [System.String] ToString()
    {
        return ('{0} ({1})' -f $this.DnsName, $this.ResourceId)
    }
}
