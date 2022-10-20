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
Invoke-RestMethod -ContentType "application/octet-stream" -Uri https://www.microsip.org/download/MicroSIP-3.20.7.exe  -OutFile $TempMicroSipLocation\Microsip.exe
Invoke-RestMethod -ContentType "application/octet-stream" -Uri https://raw.githubusercontent.com/adamhollmssl/Scripting/master/Taskbar.zip -OutFile "$StartMenuLocation\Links.zip"
Invoke-RestMethod -ContentType "application/octet-stream" -Uri https://raw.githubusercontent.com/adamhollmssl/Scripting/master/TaskBarReg.reg -OutFile "$StartMenuLocation\TaskBarReg.reg"
Invoke-RestMethod -ContentType "application/octet-stream" -Uri https://raw.githubusercontent.com/adamhollmssl/Scripting/master/DefaultApps.reg -OutFile "$TempLocation\DefaultApps.reg"
Invoke-RestMethod -ContentType "application/octet-stream" -Uri https://raw.githubusercontent.com/adamhollmssl/Scripting/master/DefaultApps.xml -OutFile "$system32\defaultassociations.xml"
Invoke-RestMethod -ContentType "application/octet-stream"  -Uri "https://dl.google.com/tag/s/appguid%253D%257B8A69D345-D564-463C-AFF1-A69D9E530F96%257D%2526iid%253D%257BBEF3DB5A-5C0B-4098-B932-87EC614379B7%257D%2526lang%253Den%2526browser%253D4%2526usagestats%253D1%2526appname%253DGoogle%252520Chrome%2526needsadmin%253Dtrue%2526ap%253Dx64-stable-statsdef_1%2526brand%253DGCEB/dl/chrome/install/GoogleChromeEnterpriseBundle64.zip?_ga%3D2.8891187.708273100.1528207374-1188218225.1527264447" -OutFile "$TempScriptsLocation\GoogleChrome.zip"
Invoke-RestMethod -ContentType "application/octet-stream"  -Uri "https://download.microsoft.com/download/2/7/A/27AF1BE6-DD20-4CB4-B154-EBAB8A7D4A7E/officedeploymenttool_13530-20376.exe" -OutFile "$ODT\ODTTool.exe"
Invoke-RestMethod -ContentType "application/octet-stream"  -Uri "https://raw.githubusercontent.com/adamhollmssl/Scripting/master/ConfigurationSDL.xml" -OutFile "$ODT\ConfigurationSDL.xml"
Invoke-RestMethod -ContentType "application/octet-stream"  -Uri "https://api-cloudstation-us-east-2.prod.hydra.sophos.com/api/download/11432f59a664f6a712048f077b36305b/SophosSetup.exe" -OutFile "$TempLocation\SophosSetup.exe"
Invoke-RestMethod -ContentType "application/octet-stream"  -Uri "https://msspublicdocs.blob.core.windows.net/public/ADSelfServicePlusClientSoftware.msi" -OutFile "$TempLocation\ADSelfServicePlusClientSoftware.msi"
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
Invoke-WebRequest -Uri "https://github.com/adamhollmssl/Scripting/raw/master/NetExtender-x64-10.2.319.MSI" -OutFile "$TempScriptsLocation\NetExtender.msi"
Start-Process MSIEXEC.exe -wait -ArgumentList "/I $TempScriptsLocation\NetExtender.msi /quiet /norestart"
Start-Sleep -Seconds 5

# Install GINA Client

Write-Host "Installing GINA Client"
Start-Process MSIEXEC.exe -wait -ArgumentList "/I $TempScriptsLocation\ADSelfServicePlusClientSoftware.msi SERVERNAME=selfservice.mssl.co.uk PORTNO=443 BUTTONTEXT=""Reset Password"" /qn"
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

# Set Quest Edge Compat Policy

function Set-RegistryValueForAllUsers {
    <#
    .SYNOPSIS
        This function uses Active Setup to create a "seeder" key which creates or modifies a user-based registry value
        for all users on a computer. If the key path doesn't exist to the value, it will automatically create the key and add the value.
    .EXAMPLE
        PS> Set-RegistryValueForAllUsers -RegistryInstance @{'Name' = 'Setting'; 'Type' = 'String'; 'Value' = 'someval'; 'Path' = 'SOFTWARE\Microsoft\Windows\Something'}
        This example would modify the string registry value 'Type' in the path 'SOFTWARE\Microsoft\Windows\Something' to 'someval'
        for every user registry hive.
    .PARAMETER RegistryInstance
         A hash table containing key names of 'Name' designating the registry value name, 'Type' to designate the type
        of registry value which can be 'String,Binary,Dword,ExpandString or MultiString', 'Value' which is the value itself of the
        registry value and 'Path' designating the parent registry key the registry value is in.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable[]]$RegistryInstance
    )
    try {
        New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null

        ## Change the registry values for the currently logged on user. Each logged on user SID is under HKEY_USERS
        $LoggedOnSids = $(Get-ChildItem HKU: | Where-Object { $_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$' } | foreach-object { $_.Name })
        Write-Verbose "Found $($LoggedOnSids.Count) logged on user SIDs"
        foreach ($sid in $LoggedOnSids) {
            Write-Verbose -Message "Loading the user registry hive for the logged on SID $sid"
            foreach ($instance in $RegistryInstance) {
                ## Create the key path if it doesn't exist
                if (!(Test-Path "HKU:\$sid\$($instance.Path)")) {
                    New-Item -Path "HKU:\$sid\$($instance.Path | Split-Path -Parent)" -Name ($instance.Path | Split-Path -Leaf) -Force | Out-Null
                }
                ## Create (or modify) the value specified in the param
                Set-ItemProperty -Path "HKU:\$sid\$($instance.Path)" -Name $instance.Name -Value $instance.Value -Type $instance.Type -Force
            }
        }

        ## Create the Active Setup registry key so that the reg add cmd will get ran for each user
        ## logging into the machine.
        ## http://www.itninja.com/blog/view/an-active-setup-primer
        Write-Verbose "Setting Active Setup registry value to apply to all other users"
        foreach ($instance in $RegistryInstance) {
            ## Generate a unique value (usually a GUID) to use for Active Setup
            $Guid = [guid]::NewGuid().Guid
            $ActiveSetupRegParentPath = 'HKLM:\Software\Microsoft\Active Setup\Installed Components'
            ## Create the GUID registry key under the Active Setup key
            New-Item -Path $ActiveSetupRegParentPath -Name $Guid -Force | Out-Null
            $ActiveSetupRegPath = "HKLM:\Software\Microsoft\Active Setup\Installed Components\$Guid"
            Write-Verbose "Using registry path '$ActiveSetupRegPath'"

            ## Convert the registry value type to one that reg.exe can understand.  This will be the
            ## type of value that's created for the value we want to set for all users
            switch ($instance.Type) {
                'String' {
                    $RegValueType = 'REG_SZ'
                }
                'Dword' {
                    $RegValueType = 'REG_DWORD'
                }
                'Binary' {
                    $RegValueType = 'REG_BINARY'
                }
                'ExpandString' {
                    $RegValueType = 'REG_EXPAND_SZ'
                }
                'MultiString' {
                    $RegValueType = 'REG_MULTI_SZ'
                }
                default {
                    throw "Registry type '$($instance.Type)' not recognized"
                }
            }

            ## Build the registry value to use for Active Setup which is the command to create the registry value in all user hives
            $ActiveSetupValue = "reg add `"{0}`" /v {1} /t {2} /d {3} /f" -f "HKCU\$($instance.Path)", $instance.Name, $RegValueType, $instance.Value
            Write-Verbose -Message "Active setup value is '$ActiveSetupValue'"
            ## Create the necessary Active Setup registry values
            Set-ItemProperty -Path $ActiveSetupRegPath -Name '(Default)' -Value 'Active Setup Test' -Force
            Set-ItemProperty -Path $ActiveSetupRegPath -Name 'Version' -Value '1' -Force
            Set-ItemProperty -Path $ActiveSetupRegPath -Name 'StubPath' -Value $ActiveSetupValue -Force
        }
    }
    catch {
        Write-Warning -Message $_.Exception.Message
    }
}
Set-RegistryValueForAllUsers -RegistryInstance @{'Name' = 'InternetExplorerIntegrationSiteList'; 'Type' = 'String'; 'Value' = 'https://msspublicdocs.blob.core.windows.net/public/sites.emie'; 'Path' = 'Software\Policies\Microsoft\Edge'}
Set-RegistryValueForAllUsers -RegistryInstance @{'Name' = 'InternetExplorerIntegrationLevel'; 'Type' = 'DWORD'; 'Value' = '00000001'; 'Path' = 'Software\Policies\Microsoft\Edge'}

# Cleanup Folder

Remove-Item -Path $TempScriptsLocation -Recurse

# Deletes Registry Key associated with CVE-2022-30190

reg delete HKEY_CLASSES_ROOT\ms-msdt /f
