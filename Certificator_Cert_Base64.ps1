# Please create C:\Temp for the temp files.

#import module 
#Install-Module -Name PSPKI
Import-Module -name PSPKI

# Common Name:
$CertName = "*.prod.dataloss"
# Edit SANs (if no SANS needed, set to "")
#Don't use space after comma
$SAN = "lab2-ops-portal.prod.dataloss,lab2-ops-anal-probe.prod.dataloss"
# Edit Path for the location of the PFX
$Path = "c:\cert\"
# Set Password for the PfxCertificate
$mypwd = ConvertTo-SecureString -String "123456" -Force -AsPlainText

#################### Creating Certifictae ##########################
$FileName = $CertName -replace '\*', 'star'
$BaseFileName = $FileName
$FileName = $FileName + ".pfx"
$PFXPath = $Path + $FileName
$CSRPath = "$Path$($FileName)_.csr"
$INFPath = "c:\cert\$($FileName)_.inf"
$NEWCsr = "c:\cert\$($FileName).cer"
$PFX = "c:\cert\$($BaseFileName)" + ".pfx"
$PEM = "c:\cert\$($BaseFileName).pem"
$PKEY = "c:\cert\$($BaseFileName).key"
$Base64Cert = "c:\cert\$($BaseFileName).crt"

if (Test-Path $CSRPath)
{
	Remove-Item $CSRPath
}
if (Test-Path $INFPath)
{
	Remove-Item $INFPath
}
if (Test-Path $NEWCsr)
{
	Remove-Item $NEWCsr
}
Write-Host "Creating certificate - $CertName"
Write-Host "SAN: $SAN"
Write-Host "PFX Path: $PFXPath"
Write-Host "-------------------------------------------------------"

$Signature = '$Windows NT$'
$INF =
@"
[Version]
Signature= "$Signature" 
[NewRequest]
Subject = "CN=$CertName, OU=GD IL, O=LAB, L=Bil, S=Bal, C=IL"
KeySpec = 1
KeyLength = 2048
Exportable = TRUE
MachineKeySet = TRUE
SMIME = False
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10
KeyUsage = 0xa0
[RequestAttributes]
CertificateTemplate = "WebServer"
[EnhancedKeyUsageExtension]
OID = 1.3.6.1.5.5.7.3.1 
"@
$INF += @"
`n
[Extensions]
2.5.29.17  = "{text}"`n
"@
$INF += "_continue_ = `"dns=$($CertName)&`"`n"
$SAN = $SAN.split(",")
foreach ($s in $SAN)
{
	$INF += "_continue_ = `"dns=$($s)&`"`n"
}

$INF | out-file -filepath $INFPath -force
certreq -new $INFPath $CSRPath
if (Test-Path $CSRPath)
{
	$rootDSE = [System.DirectoryServices.DirectoryEntry]'LDAP://RootDSE'
	$searchBase = [System.DirectoryServices.DirectoryEntry]"LDAP://$($rootDSE.configurationNamingContext)"
	$CAs = [System.DirectoryServices.DirectorySearcher]::new($searchBase, 'objectClass=pKIEnrollmentService').FindAll()
	$CAName = "$($CAs[0].Properties.dnshostname)\$($CAs[0].Properties.cn)"
	certreq -Config $CAName -submit $CSRPath $NEWCsr
	if (Test-Path $NEWCsr)
	{
		certreq -accept $NEWCsr
		$Thumb = (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2((Get-Item $NEWCsr).FullName, "")).Thumbprint
		Get-ChildItem -Path cert:\localMachine\my\$Thumb | Export-PfxCertificate -FilePath $PFXPath -Password $mypwd
		Get-ChildItem -Path cert:\localMachine\my\$Thumb | Remove-Item
	} else {Write-Host "Unable to create certificate."}
}
else { Write-Host "CSR Was not created." }

# Extract private key from pfx file or certificate store 
Convert-PfxToPem -InputFile $PFX -Password $mypwd -OutputFile $PEM


(Get-Content $PEM -Raw) -match "(?ms)(\s*((?<privatekey>-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----)|(?<certificate>-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----))\s*){2}"

$Matches["privatekey"] | Set-Content $PKEY
$Matches["certificate"] | Set-Content $Base64Cert


Remove-Item $CSRPath -Force
Remove-Item $INFPath -Force
Remove-Item $NEWCsr -Force