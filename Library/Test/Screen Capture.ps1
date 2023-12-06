$ScreenCapture = [PSCustomObject]@{
    'Vendor' = 'infoSpark'
    'Name' = 'Screen Capture'
    'Version' = '2022.04.1714'
    'Debug' = $true
}

#[Admin] Create a sceduled task for this.
#Start-Process -FilePath 'C:\Windows\system32\SCHTASKS.EXE' -ArgumentList '/CREATE /F /TN "FWL\ENGAGE-NAVI-UNICORN" /RU "SYSTEM" /RL HIGHEST /SC ONSTART /TR "C:\Users\Wraven\OneDrive\Navi.bat"' -Wait
#Start-Process -FilePath 'C:\Windows\system32\SCHTASKS.EXE' -ArgumentList '/CREATE /F /TN "FWL\ENGAGE-NAVI-UNICORN" /RU "Wraven" /RL HIGHEST /SC ONSTART /TR "C:\Users\Wraven\OneDrive\Navi.bat"' -Wait
#Start-Process -FilePath 'C:\Windows\system32\SCHTASKS.EXE' -ArgumentList '/DELETE /F /TN "FWL\ENGAGE-NAVI-UNICORN"' -Wait

#Start-Process -FilePath 'C:\Program Files\PowerShell\7\pwsh.exe' -ArgumentList '-ExecutionPolicy RemoteSigned -Command "& {Invoke-Expression $($(Invoke-WebRequest 'https://raw.githubusercontent.com/WravenDERF/Navi/main/NAVI.TEST.SCREENCAPURE.PS1' -UseBasicParsing).Content)}' -WindowStyle 'Hidden' -Wait


#This is the main 
[Reflection.Assembly]::LoadWithPartialName("System.Drawing") | Out-Null
FUNCTION Screenshot ([Drawing.Rectangle]$bounds, $path) {
    $bmp = New-Object Drawing.Bitmap $bounds.width, $bounds.height
    $graphics = [Drawing.Graphics]::FromImage($bmp)
    $graphics.CopyFromScreen($bounds.Location, [Drawing.Point]::Empty, $bounds.size)
    $bmp.Save($path)
    $graphics.Dispose()
    $bmp.Dispose()
}
    
DO {
    Add-Type -AssemblyName System.Windows.Forms
    $ScreenHeight = $($([System.Windows.Forms.Screen]::AllScreens).WorkingArea.Height | Measure-Object -Maximum).Maximum
    $ScreenWidth = $($([System.Windows.Forms.Screen]::AllScreens).WorkingArea.Width | Measure-Object -Sum).Sum

    $bounds = [Drawing.Rectangle]::FromLTRB(0, 0, $ScreenWidth, $ScreenHeight)
    #$bounds = [Drawing.Rectangle]::FromLTRB(0, 0, 3000, 1000)
    $TimeStamp = Get-Date -Format "yyyy.MM.dd.HH-mm-ss"
    screenshot $bounds "D:\Screenshot-$TimeStamp.png"
    Start-Sleep -Seconds 2
} UNTIL (1 -eq 0)
