FUNCTION Get-LinuxComputerInfo {

    PARAM(
        [bool]$Debug = $False,
        [string]$Computer = $Null,
        [string]$Username = $Null,
        [string]$Password = $Null
    )

    $ExecutablePath = 'C:\Programs\ServerCheck\plink.exe'
    
    $Linux = [PSCustomObject]@{
        'Debug' = [bool]$False

        'Vendor' = [string]'infoSpark'
        'Name' = [string]'Get-LinuxComputerInfo'
        'Version' = [string]'2023.12.29'

        'LinuxName' = [string]$Null
        'LinuxVersion' = [string]$Null
        'LinuxPrettyName' = [string]$Null
        'LinuxImageTime' = [string]$Null
        'LinuxLastBoot' = [string]$Null
    }
    $Linux.Debug = $Debug

    IF ($($Linux.Debug) -eq $True) {

        Start-Process -FilePath $ExecutablePath -ArgumentList "$Computer -l $Username -pw $Password"
        #Get-Process | Format-Table Id, ProcessName, MainWindowTitle -AutoSize
        $WindowsShell = New-Object -ComObject 'wscript.shell'
        Start-Sleep -Seconds 2
        $WindowsShell.AppActivate('C:\Programs\ServerCheck\plink.exe')
        $WindowsShell.SendKeys('Y')
        $WindowsShell.SendKeys('~')
        #Stop-Process -Name 'plink'
    }

    $Command = "cat /etc/os-release"
    $ReturnCollection = Invoke-Expression -Command $("$ExecutablePath -ssh -batch $Computer -l $Username -pw $Password $Command")

    FOREACH ($Line in $ReturnCollection) {
        $DataPoint = $Line.Split('=')[0]

        SWITCH ($DataPoint){
            'NAME'{
                $Data = [string]$($Line.Split('=')[1])
                $Linux.LinuxName = $Data.Trim('"')
				; Break
            }
            'VERSION'{
                $Data = [string]$($Line.Split('=')[1])
                $Linux.LinuxVersion = $Data.Trim('"')
				; Break
            }
            'PRETTY_NAME'{
                $Data = [string]$($Line.Split('=')[1])
                $Linux.LinuxPrettyName = $Data.Trim('"')
				; Break
            }
		}
    }

    $Command = "who -b"
    $ReturnData = Invoke-Expression -Command $("$ExecutablePath -ssh -batch $Computer -l $Username -pw $Password $Command")
    $Linux.LinuxLastBoot = $ReturnData.Trim("system boot  ")

    $Command = "stat /"
    $ReturnCollection = Invoke-Expression -Command $("$ExecutablePath -ssh -batch $Computer -l $Username -pw $Password $Command")
    FOREACH ($Line in $ReturnCollection) {
        $DataPoint = $Line.Split(' ')[0]
        IF ($DataPoint -eq 'Birth:') {
            $Linux.LinuxImageTime = $Line.Split(' ')[1]
        }
    }

    RETURN $Linux
}

Get-LinuxComputerInfo -Computer 'radagc2tstdb01.cc.ad.cchs.net' -Username 'agfaservice' -Password 'Open,Ses*123'

#Get-LinuxComputerInfo -Computer 'radagc2tstws01.cc.ad.cchs.net' -Username 'agfaservice' -Password 'Open,Ses*123'

#Get-LinuxComputerInfo -Computer 'agfac1engap1.cc.ad.cchs.net' -Username 'agfaservice' -Password 'd@ys*d@ys@321PRD' -Debug $True

#Get-LinuxComputerInfo -Computer 'agfac1engap1.cc.ad.cchs.net' -Username 'agfaservice' -Password 'd@ys*d@ys@321PRD'

#Get-LinuxComputerInfo -Computer 'agfac1engdb1.cc.ad.cchs.net' -Username 'agfaservice' -Password 'd@ys*d@ys@321PRD' -Debug $True

#Get-LinuxComputerInfo -Computer 'agfac1engdb1.cc.ad.cchs.net' -Username 'agfaservice' -Password 'd@ys*d@ys@321PRD'

<#
$ExecutablePath = 'C:\Programs\ServerCheck\plink.exe'
$TargetFQDN = 'radagc2tstdb01.cc.ad.cchs.net'
$Username = 'agfaservice'
$Password = 'Open,Ses*123'
$Command = "uname -a"
$Command = "lsb_release"
$Command = "cat /etc/os-release"
$Command = "who -b"

#Invoke-Expression -Command 'C:\Programs\ServerCheck\plink.exe -ssh -batch radagc2tstdb01.cc.ad.cchs.net -l agfaservice -pw Open,Ses*123 uname -o'
Invoke-Expression -Command $("$ExecutablePath -ssh -batch $TargetFQDN -l $Username -pw $Password $Command")

#$FredTest = Invoke-Expression -Command $("$ExecutablePath -ssh -batch $TargetFQDN -l $Username -pw $Password $Command")

#>
