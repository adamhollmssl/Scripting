powershell.exe set-executionpolicy Unrestricted
powershell -Command "Invoke-WebRequest https://raw.githubusercontent.com/adamhollmssl/Scripting/master/GenericAdminScript-Desktops.ps1 -OutFile C:\temp\GenericAdminScript-Desktops.ps1"
powershell.exe "C:\temp\GenericAdminScript-Desktops.ps1"
powershell.exe set-executionpolicy Restricted
