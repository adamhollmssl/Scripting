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
Invoke-RestMethod -ContentType "application/octet-stream" -Uri https://www.microsip.org/download/MicroSIP-3.19.31.exe -OutFile "$TempMicroSipLocation\Microsip.exe"
Invoke-RestMethod -ContentType "application/octet-stream" -Uri https://raw.githubusercontent.com/adamhollmssl/Scripting/master/Taskbar.zip -OutFile "$StartMenuLocation\Links.zip"
Invoke-RestMethod -ContentType "application/octet-stream" -Uri https://raw.githubusercontent.com/adamhollmssl/Scripting/master/TaskBarReg.reg -OutFile "$StartMenuLocation\TaskBarReg.reg"
Invoke-RestMethod -ContentType "application/octet-stream" -Uri https://raw.githubusercontent.com/adamhollmssl/Scripting/master/DefaultApps.reg -OutFile "$TempLocation\DefaultApps.reg"
Invoke-RestMethod -ContentType "application/octet-stream" -Uri https://raw.githubusercontent.com/adamhollmssl/Scripting/master/DefaultApps.xml -OutFile "$system32\defaultassociations.xml"
Invoke-RestMethod -ContentType "application/octet-stream"  -Uri "https://dl.google.com/tag/s/appguid%253D%257B8A69D345-D564-463C-AFF1-A69D9E530F96%257D%2526iid%253D%257BBEF3DB5A-5C0B-4098-B932-87EC614379B7%257D%2526lang%253Den%2526browser%253D4%2526usagestats%253D1%2526appname%253DGoogle%252520Chrome%2526needsadmin%253Dtrue%2526ap%253Dx64-stable-statsdef_1%2526brand%253DGCEB/dl/chrome/install/GoogleChromeEnterpriseBundle64.zip?_ga%3D2.8891187.708273100.1528207374-1188218225.1527264447" -OutFile "$TempScriptsLocation\GoogleChrome.zip"
Invoke-RestMethod -ContentType "application/octet-stream"  -Uri "https://download.microsoft.com/download/2/7/A/27AF1BE6-DD20-4CB4-B154-EBAB8A7D4A7E/officedeploymenttool_13530-20376.exe" -OutFile "$ODT\ODTTool.exe"
Invoke-RestMethod -ContentType "application/octet-stream"  -Uri "https://raw.githubusercontent.com/adamhollmssl/Scripting/master/ConfigurationSDL.xml" -OutFile "$ODT\ConfigurationSDL.xml"

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

Write-Host "Installing Adobe Reader"

Start-Sleep -Seconds 5

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

# Spacing for Taskbar Apps

# Cleanup Folder

Remove-Item -Path $TempScriptsLocation -Recurse
