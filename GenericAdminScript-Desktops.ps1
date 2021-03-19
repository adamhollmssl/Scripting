#Requires -RunAsAdministrator
# Post Deployment Script - Generic Admin Script, Run at First Login After Image
# Content Creator - Adam Hollingsworth

$bckgrnd = 'Black'
$Host.PrivateData.ConsolePaneForegroundColor = "Red"
$Host.PrivateData.ConsolePaneBackgroundColor= $bckgrnd
$Host.PrivateData.ConsolePaneTextBackgroundColor= $bckgrnd
Clear

Write-Host "Post Deployment Script - Generic Admin Script, Run at First Login After Image"
Write-Host "Content Creator - Adam Hollingsworth"
Write-Host " "

# Sets the Variables Required to Run This

$TempLocation = "C:\Temp"
$TempScriptsLocation = "$TempLocation\Scripts"
$TempMicroSipLocation = "$TempScriptsLocation\MicroSip"
$StartMenuLocation = "C:\MSSIT\DoNotDelete"
$DefaultUser = "C:\Users\Default"
$ODT = "C:\ODT"
$system32 = "c:\windows\system32"
$ProgressPreference = 'SilentlyContinue' # Removes Progress Bar for Invoke-WebRequest Command to make it faster

# Creates the Folders needed

New-Item -Path "$TempLocation" -Name "Scripts" -ItemType "directory" -erroraction 'silentlycontinue'
New-Item -Path "$TempScriptsLocation" -Name "MicroSip" -ItemType "directory" -erroraction 'silentlycontinue'
New-Item -Path "$TempScriptsLocation" -Name "MicroSip" -ItemType "directory" -erroraction 'silentlycontinue'
New-Item -Path "C:\" -Name "MSSIT" -ItemType "directory" -erroraction 'silentlycontinue'
New-Item -Path "C:\" -Name "ODT" -ItemType "directory" -erroraction 'silentlycontinue'
New-Item -Path "C:\MSSIT" -Name "DoNotDelete" -ItemType "directory" -erroraction 'silentlycontinue'
New-Item -Path "C:\MSSIT\DoNotDelete" -Name "Links" -ItemType "directory" -erroraction 'silentlycontinue'
New-Item -Path "C:\Users\Default\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch" -Name "User Pinned" -ItemType "directory" -erroraction 'silentlycontinue'
New-Item -Path "C:\Users\Default\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned" -Name "TaskBar" -ItemType "directory" -erroraction 'silentlycontinue'

# Downloads Required Scripts

# Invoke-WebRequest -Uri https://raw.githubusercontent.com/adamhollmssl/Scripting/master/Microsip.ps1 -OutFile "$TempMicroSipLocation\Microsip.ps1"

# Downloads Required Files & Names them accordingly

Write-Host "Post Deployment Script - Generic Admin Script, Run at First Login After Image"
Write-Host "Content Creator - Adam Hollingsworth"
Write-Host " "
Write-Host "Download in Progress - May take some time"
Invoke-RestMethod -ContentType "application/octet-stream" -Uri https://www.microsip.org/download/MicroSIP-3.19.31.exe  -OutFile $TempMicroSipLocation\Microsip.exe
Invoke-RestMethod -ContentType "application/octet-stream" -Uri https://raw.githubusercontent.com/adamhollmssl/Scripting/master/Taskbar.zip -OutFile "$StartMenuLocation\Links.zip"
Invoke-RestMethod -ContentType "application/octet-stream" -Uri https://raw.githubusercontent.com/adamhollmssl/Scripting/master/TaskBarReg.reg -OutFile "$StartMenuLocation\TaskBarReg.reg"
Invoke-RestMethod -ContentType "application/octet-stream" -Uri https://raw.githubusercontent.com/adamhollmssl/Scripting/master/DefaultApps.reg -OutFile "$TempLocation\DefaultApps.reg"
Invoke-RestMethod -ContentType "application/octet-stream" -Uri https://raw.githubusercontent.com/adamhollmssl/Scripting/master/DefaultApps.xml -OutFile "$system32\defaultassociations.xml"
Invoke-RestMethod -ContentType "application/octet-stream"  -Uri "https://dl.google.com/tag/s/appguid%253D%257B8A69D345-D564-463C-AFF1-A69D9E530F96%257D%2526iid%253D%257BBEF3DB5A-5C0B-4098-B932-87EC614379B7%257D%2526lang%253Den%2526browser%253D4%2526usagestats%253D1%2526appname%253DGoogle%252520Chrome%2526needsadmin%253Dtrue%2526ap%253Dx64-stable-statsdef_1%2526brand%253DGCEB/dl/chrome/install/GoogleChromeEnterpriseBundle64.zip?_ga%3D2.8891187.708273100.1528207374-1188218225.1527264447" -OutFile "$TempScriptsLocation\GoogleChrome.zip"
Invoke-RestMethod -ContentType "application/octet-stream"  -Uri "https://download.microsoft.com/download/2/7/A/27AF1BE6-DD20-4CB4-B154-EBAB8A7D4A7E/officedeploymenttool_13530-20376.exe" -OutFile "$ODT\ODTTool.exe"
Invoke-RestMethod -ContentType "application/octet-stream"  -Uri "https://raw.githubusercontent.com/adamhollmssl/Scripting/master/ConfigurationSDL.xml" -OutFile "$ODT\ConfigurationSDL.xml"
Invoke-RestMethod -ContentType "application/octet-stream"  -Uri "https://api-cloudstation-us-east-2.prod.hydra.sophos.com/api/download/11432f59a664f6a712048f077b36305b/SophosSetup.exe" -OutFile "$TempLocation\SophosSetup.exe"
#Invoke-RestMethod -ContentType "application/octet-stream"  -Uri "https://get.adobe.com/uk/reader/completion/?installer=Reader_DC_2020.013.20074_English_UK_for_Windows&stype=7467&direct=true&standalone=1" -OutFile "$TempLocation\AcroRdrDC2001320074_en_US.exe"

# Install Sophos

Write-Host "Installing Sophos"
Start-Process "$TempLocation\SophosSetup.exe" -Wait -ArgumentList "--products=antivirus,intercept --quiet"
Start-Sleep -Seconds 10

# Install Office365

Write-Host "Installing Office365"
Start-Process "$ODT\ODTTool.exe" -ArgumentList "/Extract:$ODT /quiet"
Start-Sleep -Seconds 10
Start-Process $ODT\setup.exe -wait -ArgumentList "/Configure $ODT\ConfigurationSDL.xml"
Start-Sleep -Seconds 10

# Install Google Chrome

Write-Host "Installing Google Chrome"
Expand-Archive -LiteralPath "$TempScriptsLocation\GoogleChrome.zip" -DestinationPath "$TempScriptsLocation\GoogleChrome" -Force
Start-Process MSIEXEC.exe -wait -ArgumentList "/I $TempScriptsLocation\GoogleChrome\Installers\GoogleChromeStandaloneEnterprise64.msi /quiet"
Start-Sleep -Seconds 5

# Install NetExtender

Write-Host "Installing NetExtender"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/adamhollmssl/Scripting/master/NetExtender-9.0.0.274 (1).MSI" -OutFile "$TempScriptsLocation\NetExtender.msi"
Start-Process MSIEXEC.exe -wait -ArgumentList "/I $TempScriptsLocation\NetExtender.msi /quiet /norestart"
Start-Sleep -Seconds 5

# Install Adobe DC

#Write-Host "Installing Adobe Reader"
#Start-Process msiexec.exe -Wait -ArgumentList "/i $TempLocation\Acrobat\acroread.msi INSTALLDIR="C:\Program Files (x86)\Adobe\Acrobat Reader DC\" /qn"
#Start-Sleep -Seconds 5

# Adds Office & Google Chrome Applications to TaskBar

Write-Host "Adding Office & Google Chrome to TaskBar"
expand-archive -LiteralPath "$StartMenuLocation\Links.zip" -DestinationPath "$StartMenuLocation\Links" -Force
reg load HKU\ntuser.dat "$DefaultUser\NTUSER.DAT"
reg import "$StartMenuLocation\TaskBarReg.reg"
reg unload HKU\ntuser.dat
copy "$StartMenuLocation\Links\*.lnk" "C:\users\default\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
Start-Sleep -Seconds 5

# Install Default Apps

Write-Host "Changing Default Apps"
$PathofRegFile="$TempLocation\DefaultApps.reg"
regedit /s $PathofRegFile
Start-Sleep -Seconds 5

# Enabling Bitlocker
Write-Host "Enabling Bitlocker"
Manage-bde C: -On -RecoveryPassword
Start-Sleep -Seconds 5

# Turn off Fast-Startup
Write-Host "Turning Off Fast-Startup"
powercfg -h off
Start-Sleep -Seconds 5

# Disable NetBios
Write-Host "Disable NetBios"
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey |foreach { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}

# NetCease
Write-Host "Disabling NetCease"
param([switch]$Revert)

function IsAdministrator
{
    param()
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($currentUser)).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)   
}

function BackupRegistryValue
{
    param([string]$key, [string]$name)
    $backup = $name+'Backup'
    
    #Backup original Key value if needed
    $regKey = Get-Item -Path $key 
    $backupValue = $regKey.GetValue($backup, $null)
    $originalValue = $regKey.GetValue($name, $null)
    
    if (($backupValue -eq $null) -and ($originalValue -ne $null))
    {
        Set-ItemProperty -Path $key -Name $backup -Value $originalValue
    }

    return $originalValue
}

function RevertChanges
{
    param([string]$key,[string]$name)
    $backup = $name+'Backup'
    $regKey = Get-Item -Path $key

    #Backup original Key value if needed
    $backupValue = $regKey.GetValue($backup, $null)
    
    Write-Host "Reverting changes..."
    if ($backupValue -eq $null)
    {
        #Delete the value when no backed up value is found
        Write-Host "Backup value is missing. cannot revert changes"
    }
    elseif ($backupValue -ne $null)
    {
        Write-Verbose "Backup value: $backupValue"
        Set-ItemProperty -Path $key -Name $name -Value $backupValue
        Remove-ItemProperty -Path $key -Name $backup
    } 
      
    Write-Host "Revert completed"
}

if (-not (IsAdministrator))
{
    Write-Host "This script requires administrative rights, please run as administrator."
    exit
}

#NetSessionEnum SecurityDescriptor Registry Key 
$key = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity"
$name = "SrvsvcSessionInfo"
$SRVSVC_SESSION_USER_INFO_GET = 0x00000001

Write-Host "NetCease 1.02 by Itai Grady (@ItaiGrady), Microsoft Advance Threat Analytics (ATA) Research Team, 2016"

if ($Revert)
{
    RevertChanges -key $key -name $name
    Write-Host "In order for the reverting to take effect, please restart the Server service"
    exit
}

#Backup original Key value if needed
$srvSvcSessionInfo = BackupRegistryValue -key $key -name $name

#Load the SecurityDescriptor
$csd = New-Object -TypeName System.Security.AccessControl.CommonSecurityDescriptor -ArgumentList $true,$false, $srvSvcSessionInfo,0

#Remove Authenticated Users Sid permission entry from its DiscretionaryAcl (DACL)
$authUsers = [System.Security.Principal.WellKnownSidType]::AuthenticatedUserSid
$authUsersSid = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $authUsers, $null
$csd.DiscretionaryAcl.RemoveAccessSpecific([System.Security.AccessControl.AccessControlType]::Allow, $authUsersSid,$SRVSVC_SESSION_USER_INFO_GET, 0,0) 

#Add Access Control Entry permission for Interactive Logon Sid
$wkt = [System.Security.Principal.WellKnownSidType]::InteractiveSid
$interactiveUsers = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $wkt, $null
$csd.DiscretionaryAcl.AddAccess([System.Security.AccessControl.AccessControlType]::Allow, $interactiveUsers, $SRVSVC_SESSION_USER_INFO_GET,0,0)

#Add Access Control Entry permission for Service Logon Sid
$wkt = [System.Security.Principal.WellKnownSidType]::ServiceSid
$serviceLogins = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $wkt, $null
$csd.DiscretionaryAcl.AddAccess([System.Security.AccessControl.AccessControlType]::Allow, $serviceLogins, $SRVSVC_SESSION_USER_INFO_GET,0,0)

#Add Access Control Entry permission for Batch Logon Sid
$wkt = [System.Security.Principal.WellKnownSidType]::BatchSid
$BatchLogins = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $wkt, $null
$csd.DiscretionaryAcl.AddAccess([System.Security.AccessControl.AccessControlType]::Allow, $BatchLogins, $SRVSVC_SESSION_USER_INFO_GET,0,0)

#Update the SecurityDescriptor in the Registry with the updated DACL
$data = New-Object -TypeName System.Byte[] -ArgumentList $csd.BinaryLength
$csd.GetBinaryForm($data,0)
Set-ItemProperty -Path $key -Name $name -Value $data
Write-Host "Permissions successfully updated"
Write-Host "In order for the hardening to take effect, please restart the Server service"

# Spacing for Taskbar Apps

# Cleanup Folder

Remove-Item -Path $TempScriptsLocation -Recurse
