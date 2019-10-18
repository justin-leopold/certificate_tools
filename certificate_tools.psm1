#Requires -RunAsAdministrator
#Add above to manifest later
Function New-Csr {
    <#
.SYNOPSIS
Creates a certificate signing request (CSR) file, which can contain aliases (CNames).
.DESCRIPTION
- Creates a CSR file for a certificate authority, which includes aliases (CNames).
- Alias names need to be comma separated.
- Run the script on the server that hosts the web service (e.g., IIS), since it needs to access the private key storage.
 
- This uses certreq.exe to transform the input of this script into a well-formed request file.
- For easy usage, the script exposes only the required and a few popular certutil parameters.
.LINK
https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/ff625722(v=ws.10)
.EXAMPLE
Create-Csr -FQDN servername.dcomain.org -KeyLength 4096 -Exportable:$true -EncryptionAlgorithm 'Microsoft RSA SChannel Cryptographic Provider' `
-Aliases website.domain.org,website,10.10.10.10 -DestinationFilePath C:\temp

$certReqParams = @{
    FQDN                = servername01.nwtraders.msft
    Aliases             = servername01, devmachine, devmachine.nwtraders.msft, 192.168.0.1
    DestinationFilePath = C:\Temp
}
New-Csr @certReqParams
.PARAMETER FQDN
Requests a certificate for the FQDN for the system like a website or a server name
.PARAMETER KeyLength
Length of keys used for encryption. 4096 is the default value
.PARAMETER Exportable
Defines exportability of the private key included in the certificate; the default for security reasons is false
.PARAMETER EncryptionAlgorithm
Sets the algorithm used for encryption. The available choices are the most popular according to research
.PARAMETER Aliases
Comma-separated list of alias names (CNames) to include in the certificate;
all names in the list can access the target resource without name-mismatch errors
.PARAMETER DestinationFilePath
Specifies the name and path for the certificate signing request (CSR) file; the name of the CSR file will be FQDN.csr
.INPUTS
None--you cannot pipe objects in...yet
.OUTPUTS
PKCS10-formatted CSR file
.NOTES
        File Name   : New-Csr.ps1  
        Author      : Justin Leopold - 9/18/2019
        Written on  : Powershell 5.1
        Tested on   : Powershell 5.1
        #>
 
    param(
 
        [Parameter(Mandatory = $true)]
        [String]$FQDN,
 
        [Parameter(Mandatory = $false)]
        [ValidateSet(1024, 2048, 4096)]
        [int]$KeyLength = 2048,
 
        [Parameter(Mandatory = $false)]
        [ValidateSet('True', 'False')]
        [string]$Exportable = 'False',
 
        [Parameter(Mandatory = $false)]
        [ValidateSet('Microsoft RSA SChannel Cryptographic Provider', `
                'Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Provider')]
        [string]$EncryptionAlgorithm = 'Microsoft RSA SChannel Cryptographic Provider',
 
        [Parameter(Mandatory = $false)]
        [object]$Aliases,
 
        [Parameter(Mandatory = $true)]
        [string]$DestinationFilePath
 
    )
 
    #region checking_parameters
 
    #Check if the FQDN matches valid syntax
    if ($FQDN -notMatch '\w{1,}\.\w{1,}\.?[\w.]*') {
        Write-Warning -Message "The FQDN: $($FQDN) seems to be invalid.`n The expected syntax is host.domain.<optional>"
        exit
    }
 
    #Check if aliases match valid syntax
    if ($Aliases -notMatch '[\w\.\s,]{1,}') {
        Write-Warning -Message "Aliases: $($Aliases) don't seem to be valid. Use a comma ',' to separate multiple aliases."
        exit
    }
 
    #Check if the destination file path exists
    if (-not (Test-Path -Path $DestinationFilePath)) {
        Write-Warning -Message "Path: $($DestinationFilePath) does not exist. Please specify a valid path."
        exit
    }
 
    #Check if the specified file path has a training backslash; if not, add it.
    if ($DestinationFilePath.Substring($DestinationFilePath.Length - 1, 1) -eq '\') {
        $DestinationFilePath = $DestinationFilePath + $FQDN + '.csr'
    }
    else {
        $DestinationFilePath = $DestinationFilePath + '\' + $FQDN + '.csr'
    }
 
    #endregion checking_parameters
 
    #region program_main
 
    <#
    If a comma occurs in an aliases value, 'split' will convert the string
    to an array. Building a valid extensions section requires a loop.
    In case only one value is specified as an alias value, the script will embed it into the required information.
    [System.Environment]::NewLine ensures one alias per line.
#>
 
    if ($Aliases -match ',') {
        $tmpAliases = $Aliases -split ','
        foreach ($itmAlias in $tmpAliases) {
            $dnsAliases += '_continue_ = "DNS=' + $itmAlias + '&"' + [System.Environment]::NewLine
        }
    }
    else {
        $dnsAliases = '_continue_ = "DNS=' + $Aliases + '&"' + [System.Environment]::NewLine
    }
 
    $certificateINF = @"
[Version]
Signature= '`$Windows NT$'
 
[NewRequest]
Subject = "CN=${FQDN}"
KeySpec = 1
KeyLength = ${KeyLength}
Exportable = ${Exportable}
MachineKeySet = TRUE
ProviderName = ${EncryptionAlgorithm}
RequestType = PKCS10
KeyUsage = 0xa0
 
[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.1
 
[Extensions]
2.5.29.17 = "{text}"
_continue_ = "DNS=${FQDN}&"
${dnsAliases}
"@
 
    <#
[System.IO.Path]::GetTmpFileName() creates a temporary file to store the information of the
certificateINF variable. The operating system will automatically drop it.
#>
    $tmpFile = [System.IO.Path]::GetTempFileName()
    $certificateINF | Out-File $tmpFile
 
    & certreq.exe -new $tmpFile $DestinationFilePath
 
    #endregion program_main

}#function
