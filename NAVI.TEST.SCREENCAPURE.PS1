$ScreenCapture = [PSCustomObject]@{
    'Vendor' = 'infoSpark'
    'Name' = 'Screen Capture'
    'Version' = '2022.04.1714'
    'Debug' = $true
}

BEGIN {
    #Strt-Process -FilePath 'C:\Windows\system32\SCHTASKS.EXE' -ArgumentList '/CREATE /F /TN "Piedmont\LOGOUT-FUJISYNAPSE" /RU "SYSTEM" /RL HIGHEST /SC ONSTART /TR "C:\INSTALLS\Fuji Synapse 5.7.220\Help\Files\Fuji-Synapse-XML.bat"' -Wait
}

PROCESS {
    #This is the main 
    [Reflection.Assembly]::LoadWithPartialName("System.Drawing")
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
        Start-Sleep -Seconds 30
    } UNTIL (1 -eq 0)
}

END {

}
