Start-Process -FilePath "C:\Temp\Microsip.exe" -ArgumentList "/S /D=C:\Microsip"

$TargetFile = "C:\Microsip\Microsip.exe"
$ShortcutFile = "$env:Public\Desktop\Microsip.lnk"
$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $TargetFile
$Shortcut.Save()