Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName AzureStack.Lab -DomainNetbiosName AZURESTACK

$Domain = Get-ADDomain | Select -ExpandProperty Forest
Enable-ADOptionalFeature "Recycle Bin Feature" -Scope ForestOrConfigurationSet -Target $Domain -Confirm:$false
$Domainpiece = $Domain.Split(".")
$dc = ""
foreach ($piece in $Domainpiece)
{
    $dc += "DC=$piece,"
}
$dc = $dc.TrimEnd(",")
New-ADOrganizationalUnit "LAB" -Path "$dc"
$ADM = New-ADOrganizationalUnit "_ADM" -Path "$dc" -PassThru
$SRV = New-ADOrganizationalUnit "SRV" -Path "OU=LAB,$dc" -PassThru
$GRP = New-ADOrganizationalUnit "GRP" -Path "OU=LAB,$dc" -PassThru
$USR = New-ADOrganizationalUnit "USR" -Path "OU=LAB,$dc" -PassThru
$TECH = New-ADOrganizationalUnit "TECH" -Path "OU=LAB,$dc" -PassThru

New-ADUser admsql `
    -PasswordNeverExpires 1 `
    -cannotchangepassword 1 `
    -path $TECH `
    -enabled 1 `
    -AccountPassword (ConvertTo-SecureString -AsPlainText "<PASSWORD>" -Force) `
    -Description "SQL Service Account"

New-ADUser admad `
    -PasswordNeverExpires 1 `
    -cannotchangepassword 1 `
    -path $TECH `
    -enabled 1 `
    -AccountPassword (ConvertTo-SecureString -AsPlainText "<PASSWORD>" -Force) `
    -Description "SMA AD Admin(Delegated) Account"

New-ADUser maswds `
    -PasswordNeverExpires 1 `
    -cannotchangepassword 1 `
    -path $TECH `
    -enabled 1 `
    -AccountPassword (ConvertTo-SecureString -AsPlainText "<PASSWORD>" -Force) `
    -Description "WDS SMB Share account bootimage"

New-ADUser admsma `
    -PasswordNeverExpires 1 `
    -cannotchangepassword 1 `
    -path $TECH `
    -enabled 1 `
    -AccountPassword (ConvertTo-SecureString -AsPlainText "<PASSWORD>" -Force) `
    -Description "SMA Service Account"

New-ADGroup -Name "SMA_Admins" -GroupCategory Security -GroupScope DomainLocal -DisplayName "SMA_Admins" -Description "SMA Admins" -path $GRP
New-ADGroup -Name "SQL_Admins" -GroupCategory Security -GroupScope DomainLocal -DisplayName "SQL_Admins" -Description "SQL Admins" -path $GRP