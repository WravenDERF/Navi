#[Admin] Sets Execution Policy
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Unrestricted

#Get the Powershell verison
    Write-Host -Object $PSversiontable.PSversion

#Download the latest version of Powershell
    Invoke-RestMethod -Uri "https://github.com/PowerShell/PowerShell/releases/download/v7.1.4/PowerShell-7.1.4-win-x64.msi" -OutFile 'D:\Installs\PowerShell7.msi'
    Invoke-Command -ScriptBlock {MSIEXEC -i 'D:\Installs\PowerShell7.msi' -qb-}

#[Admin] Download the AZ module
    Install-Module -Name AZ -AllowClobber -Repository PSGALLERY -Force
    Get-InstalledModule -Name Az -AllVersions | Select-Object -Property Name, Version

#[Admin] Download the SQLPS module
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Unrestricted
    Import-Module -Name sqlserver
    Install-Module -Name SQLPS -Force

#Connect to Azure and see subscriptions.
    Connect-AzAccount
    Get-AzSubscription
    Get-AzSubscription -subscriptionID bc940dc8-ae88-4579-9ff5-f4e9c953c3f0
    Set-AzContext

    <#
    Account                  SubscriptionName     TenantId                             Environment
    -------                  ----------------     --------                             -----------
    fred.linthicum@gmail.com Azure subscription 1 d68c1f99-925e-4e6b-8b86-eeb9fdb3c980 AzureCloud
    #>


#[Admin] Enable Remote Desktop & Firewall Rule
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"


#[Admin] Enable ICMP Firewall Rule
New-NetFirewallRule `
    -Name 'ICMPv4' `
    -DisplayName 'ICMPv4' `
    -Description 'Allow ICMPv4' `
    -Profile Any `
    -Direction Inbound `
    -Action Allow `
    -Protocol ICMPv4 `
    -Program Any `
    -LocalAddress Any `
    -RemoteAddress Any 


#Windows Update
    #https://petri.com/how-to-manage-windows-update-using-powershell

#Set power to high performance.
    Invoke-Command -ScriptBlock {POWERCFG /list}
    Invoke-Command -ScriptBlock {POWERCFG /setactive e9a42b02-d5df-448d-aa00-03f14749eb61} #Win10
    Invoke-Command -ScriptBlock {POWERCFG /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c} #Server


#Rename the PC

    Rename-Computer -NewName 'FWL-PIEDMONT' -Restart
    Rename-Computer -NewName 'FWL-SCCM01' -Restart
    Rename-Computer -NewName 'FWL-VM01' -Restart
    Rename-Computer -NewName 'FWL-VM02' -Restart
    Add-Computer -DomainName 'piedmonthospital.org' -Restart

#Add user as Administrator.
    Add-LocalGroupMember -Group 'Administrators' -Member 'piedmont_nt\171013'GP


#Copy the contents of D: Drives
    #Get-ChildItem -Path D:\ -Recurse | Measure-Object
    Invoke-Command -ScriptBlock {ROBOCOPY "\\FWL-Z640A\Data\BIOS" "D:\BIOS" /MIR}
    Invoke-Command -ScriptBlock {ROBOCOPY "\\FWL-Z640A\Data\Drivers" "D:\Drivers" /MIR}
    Invoke-Command -ScriptBlock {ROBOCOPY "\\FWL-Z640A\Data\Installs" "D:\Installs" /MIR}
    Invoke-Command -ScriptBlock {ROBOCOPY "\\FWL-Z640A\Data\ISO" "D:\ISO" /MIR}
    

#Packup Piedmont to B drive for backup.
    #Invoke-Command -ScriptBlock {SCHTASKS /CREATE /F /TN "Piedmont\NIGHTLY-BACKUP" /RL HIGHEST /SC DAILY /ST 04:00 /TR "ROBOCOPY "}


#Scan files and make sure they are correct.
    Invoke-Command -ScriptBlock {SCHTASKS /CREATE /F /TN "FWL\OS-REGENERATE" /RU "SYSTEM" /RL HIGHEST /SC DAILY /ST 03:00 /TR "DISM /Online /Cleanup-Image /RestoreHealth"}

    
$BuildTestEnvironment = {
#Build out SCCM Test Environment ==================================================================================
    #[Admin] Add Hyper-V to the computer.
        Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All

    #[Admin] Add VM to Hypervisor.
        #https://dev.to/joeneville_/automate-hyper-v-vm-creation-with-powershell-1fgc

        #FWL-DC01
            $VM = 'FWL-DC01'
            $RAM = 8GB
            $DriveSpace = 128
            New-VM -Name $VM -Path "D:\Hyper-V" -Generation 1 -MemoryStartupBytes $RAM -SwitchName 'Nexus' -NewVHDPath "D:\Hyper-V\$VM\Virtual Hard Disks\$VM.vhdx" -NewVHDSizeBytes $($DriveSpace * 1024 * 1024 * 1024)
            Set-VM -Name $VM -ProcessorCount 2 -DynamicMemory -MemoryMinimumBytes 128MB -MemoryMaximumBytes $RAM -AutomaticStopAction ShutDown
            Set-VMDvdDrive -VMName $VM -Path 'D:\ISO\WindowsServer2019.iso'
            Checkpoint-VM -Name $VM -SnapshotName 'BareMetal'
            Start-VM -Name $VM

        #FWL-SCCM01
            $VM = 'FWL-SCCM01'
            $RAM = 8GB
            $DriveSpace = 128
            New-VM -Name $VM -Path "D:\Hyper-V" -Generation 1 -MemoryStartupBytes $RAM -SwitchName 'Nexus' -NewVHDPath "D:\Hyper-V\$VM\Virtual Hard Disks\$VM.vhdx" -NewVHDSizeBytes $($DriveSpace * 1024 * 1024 * 1024)
            Set-VM -Name $VM -ProcessorCount 2 -DynamicMemory -MemoryMinimumBytes 128MB -MemoryMaximumBytes $RAM -AutomaticStopAction ShutDown
            Set-VMDvdDrive -VMName $VM -Path 'D:\ISO\WindowsServer2019.iso'
            Checkpoint-VM -Name $VM -SnapshotName 'BareMetal'
            Start-VM -Name $VM

        #FWL-VM01
            $VM = 'FWL-VM01'
            $RAM = 4GB
            $DriveSpace = 128
            New-VM -Name $VM -Path "D:\Hyper-V" -Generation 1 -MemoryStartupBytes $RAM -SwitchName 'Nexus' -NewVHDPath "D:\Hyper-V\$VM\Virtual Hard Disks\$VM.vhdx" -NewVHDSizeBytes $($DriveSpace * 1024 * 1024 * 1024)
            Set-VM -Name $VM -ProcessorCount 2 -DynamicMemory -MemoryMinimumBytes 128MB -MemoryMaximumBytes $RAM -AutomaticStopAction ShutDown
            Set-VMDvdDrive -VMName $VM -Path 'D:\iso\Win10-20H2-Enterprise.iso'
            Checkpoint-VM -Name $VM -SnapshotName 'BareMetal'
            Start-VM -Name $VM

        #FWL-VM02
            $VM = 'FWL-VM02'
            $RAM = 4GB
            $DriveSpace = 128
            New-VM -Name $VM -Path "D:\Hyper-V" -Generation 1 -MemoryStartupBytes $RAM -SwitchName 'Nexus' -NewVHDPath "D:\Hyper-V\$VM\Virtual Hard Disks\$VM.vhdx" -NewVHDSizeBytes $($DriveSpace * 1024 * 1024 * 1024)
            Set-VM -Name $VM -ProcessorCount 2 -DynamicMemory -MemoryMinimumBytes 128MB -MemoryMaximumBytes $RAM -AutomaticStopAction ShutDown
            Set-VMDvdDrive -VMName $VM -Path 'D:\iso\Win10-20H2-Enterprise.iso'
            Checkpoint-VM -Name $VM -SnapshotName 'BareMetal'
            Start-VM -Name $VM

        <# Other Powershell commands for Hyper-V
        Get-VMa
        Stop-VM -Name 'OISCV99X' –Force
        Stop-VM -Name 'OISCV99X' –TurnOff
        Save-VM -Name 'OISCV99X'
        Start-VM -Name 'OISCV99X'

        Checkpoint-VM -Name 'OISCV99X' -SnapshotName 'Update1'
        Get-VMSnapshot -VMName 'OISCV99X'
        Remove-VMSnapshot -Name 'OISCV99X'

        Test-VHD -Path 'C:\Testing.vhd'

        Enable-VMResourceMetering -VMName 'OISCV99X'
        Measure-VM -VMName 'OISCV99X'

        Get-VMNetworkAdapter –All

        Update-VMVersion -Name 'OISCV99X'
        #>
}


$BuildDomainController = {
#Set up Active Directory DC =============================================================================


    #Rename PC
        Rename-Computer -NewName 'FWL-DC01' -Restart


    #The command for server core interface.
        Invoke-Command -ScriptBlock {SCONFIG}
        Start-Process -FilePath 'PowerShell' -Verb 'runas'
    
    #[Admin] Add Active Directory and DHCP to the computer.
        Get-WindowsFeature
        Install-WindowsFeature 'AD-Domain-Services' -IncludeAllSubFeature -IncludeManagementTools -Restart
        #Install-WindowsFeature 'DHCP' -IncludeAllSubFeature -IncludeManagementTools -Restart

    #Can't get these to work for DNA
        $IP = '192.168.1.150'
        $DefaultGateway = '192.168.1.254'
        Disable-NetAdapterBinding -Name "*" -DisplayName 'Internet Protocol Version 6 (TCP/IPv6)'
        Get-NetIPConfiguration -InterfaceAlias 'Ethernet'
        New-NetIPAddress -InterfaceAlias 'Ethernet' -IPAddress $IP -PrefixLength 24 -DefaultGateway $DefaultGateway
        Set-DnsClientServerAddress -InterfaceAlias 'Ethernet' -ServerAddresses ($IP,'8.8.8.8')
        Invoke-Command -ScriptBlock {IPCONFIG /all}

        #Set-NetIPInterface -InterfaceAlias 'Ethernet' -DHCP 'Enabled'


    #Setup Active Directory
        Import-Module -Name 'ADDSDeployment'
        Install-ADDSForest -DomainName 'infoSpark.com' -InstallDns -Force

        #New-ADOrganizationalUnit -Name 'SCCMTest' -Path 'DC=RobinHoodDrive,DC=infoSpark,DC=com'
        #Remove-ADOrganizationalUnit -Identity 'OU=SCCMTest,DC=RobinHoodDrive,DC=infoSpark,DC=com' -Recursive -Force



    #Configure DHCP
        Invoke-Command -ScriptBlock {NETSH DHCP ADD securitygroups}
        Restart-Service -Name 'dhcpserver'
        Set-DhcpServerv4DnsSetting -DynamicUpdates "Always" -DeleteDnsRRonLeaseExpiry $True
        Add-DhcpServerv4Scope -Name "Workstations" -StartRange '192.168.100' -EndRange '192.168.200' -SubnetMask 255.255.255.0 -State Active
        #Add-DhcpServerv4ExclusionRange -ScopeID 10.0.0.0 -StartRange 10.0.0.1 -EndRange 10.0.0.15
        #Set-DhcpServerv4OptionValue -OptionID 3 -Value 10.0.0.1 -ScopeID 10.0.0.0 -ComputerName DHCP1.corp.contoso.com
        #Set-DhcpServerv4OptionValue -DnsDomain corp.contoso.com -DnsServer 10.0.0.2
        Invoke-Command -ScriptBlock {PING google.com} #Verify this is working.
        Checkpoint-VM -Name $VM -SnapshotName 'Fully Built'

}


$BuildSystemCenterManager = {
#Set up SCCM Server


    #Rename PC
        Rename-Computer -NewName 'FWL-SCCM01' -Restart


    #Add to a domain
        Add-Computer -DomainName 'infoSpark.com' -Restart

    #SCCM with EP
    #ADK
    #ADK PE Addons
    #SQL Server 2017
    #SQL Server Reporting Services
    #SQL Server Cumulative Update 2
    #SQL Server Managment Studio
        #unattended install I found.
        #start "" /w <path where SSMS-Setup-ENU.exe file is located> /Quiet SSMSInstallRoot=<path where you want to install SSMS>

    #MDT
}


#Initialize Module Assets
$MenuArray = New-Object System.Collections.ArrayList

#Used to change DOB Formatting on crosswalk tables.
#https://docs.microsoft.com/en-us/powershell/scripting/learn/deep-dives/everything-about-arrays?view=powershell-7.1
$FileContents = Get-Content -Path "B:\Backup\Crosswalks\Columbus_Crosswalk_06262019.txt"
FOREACH ($Line in $FileContents) {
    #Write-Host -Object $Line
    $Test = $Line.Split("|")
    #Write-Host -Object $Test[4]
    [datetime]$Date = Get-Date($Test[4])
    $NewLine = $Test[0] + [char]124 + $Test[1] + [char]124 + $Test[2] + [char]124 + $Test[3] + [char]124 + $Date.ToString("yyyyMMdd") + [char]124 + $Test[5] | Out-File -FilePath "D:\ColumbusCrosswalk-2021.02.18.txt" -Append
}
Invoke-Command -ComputerName HD1OF13Z -ScriptBlock {DISM /Online /Cleanup-Image /RestoreHealth}
Invoke-Command -ComputerName HD1OF13Z -ScriptBlock {$PSVersionTable.PSVersion}
Invoke-Command -ComputerName HD1OF13Z -ScriptBlock {SCHTASKS /CREATE /F /TN "Piedmont\NIGHTLY-REBOOT" /RU "SYSTEM" /RL HIGHEST /SC DAILY /ST 04:00 /TR "SHUTDOWN /r /f /t 00"}
Invoke-Command -ComputerName HD1OF13Z -ScriptBlock {SCHTASKS /CREATE /F /TN "Piedmont\SFC-SCANNOW" /RU "SYSTEM" /RL HIGHEST /SC DAILY /ST 03:00 /TR "SFC /scannow"}
Invoke-Command -ComputerName HD1OF13Z -ScriptBlock {SCHTASKS /CREATE /F /TN "Piedmont\WinSAT-Formal" /RU ".\wks_admin" /RL HIGHEST /SC DAILY /ST 03:30 /TR "WinSAT formal"}
Invoke-Command -ComputerName HD1OF13Z -ScriptBlock {WUSA "C:\INSTALLS\windows10.0-kb4056887-x64.msu" /quiet /norestart}

[string]$AppName = 'Nuance PowerScribe'
[string]$Directory = "C:\INSTALLS\$AppName"
Invoke-Command -ScriptBlock {SCHTASKS /CREATE /F /TN "Piedmont\PS360-PROD-INSTALL" /RU "SYSTEM" /RL HIGHEST /SC ONSTART /TR "$Directory\Automated\Automated.bat INSTALLPROD"}

Invoke-Command -ComputerName TXRMR01W-NEW -ScriptBlock {DISM /Online /Cleanup-Image /RestoreHealth}


$TargetPC = "HD1OF13Z"
$DotNetVersions = Invoke-Command -ComputerName $TargetPC {Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -recurse | Get-ItemProperty -name Version -EA 0 | Where { $_.PSChildName -match '^(?!S)\p{L}'} | Select Version} | Measure-Object -Property Version -Maximum
write-host $DotNetVersions.Maximum

<#Working with Scheduled task
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Maintenance\" | Start-ScheduledTask
New-ScheduledTaskAction 
#>


    $ComputerName = "NOSRM05R-1"
    Invoke-Command -ScriptBlock {ROBOCOPY "\\PHCMS01\Share_Data\PHC\Imaging\FredTest\infoSpark TrainTracks 2020.08.25" "\\$ComputerName\C$\INSTALLS\infoSpark TrainTracks 2020.08.25" /E}
    Invoke-Command -ComputerName $ComputerName -ScriptBlock {Get-ChildItem "C:\INSTALLS\infoSpark TrainTracks 2020.08.25\Drivers" -Recurse -Filter "*.inf" | ForEach-Object { PNPUtil.exe /add-driver $_.FullName /install }}


    [string]$PathList = 'H:\FredDelete2.txt'
    $FileContents = Get-Content -Path $PathList
    FOREACH ($ComputerName in $FileContents) {
        IF (Test-Connection -Computer $ComputerName -Count 1 -Quiet) {
            Invoke-Command -ScriptBlock {ROBOCOPY "\\PHCMS01\Share_Data\PHC\Imaging\FredTest\infoSpark TrainTracks 2020.08.25" "\\$ComputerName\C$\INSTALLS\infoSpark TrainTracks 2020.08.25" /E}
            Write-Host -Object $ComputerName
            Invoke-Command -ComputerName $ComputerName -ScriptBlock {Get-ChildItem "C:\INSTALLS\infoSpark TrainTracks 2020.08.25\Drivers" -Recurse -Filter "*.inf" | ForEach-Object { PNPUtil.exe /add-driver $_.FullName /install }}
        }
    }
    

    #TrainTracks -Drivers
    Invoke-Command -ScriptBlock {ROBOCOPY "\\PHCMS01\Share_Data\PHC\Imaging\FredTest\infoSpark TrainTracks 2020.08.25" "\\$TargetComputer\C$\INSTALLS\infoSpark TrainTracks 2020.08.25" /E}
    Invoke-Command -ComputerName $TargetComputer -ScriptBlock {Get-ChildItem "C:\INSTALLS\infoSpark TrainTracks 2020.08.25\Drivers" -Recurse -Filter "*.inf" | ForEach-Object { PNPUtil.exe /add-driver $_.FullName /install }}
    #Maybe this? Add-WindowsDriver

    #Disable AV on network adaptor
    Invoke-Command -ComputerName $TargetComputer -ScriptBlock {Disable-NetAdapterBinding -Name "*" -DisplayName "Trend Micro NDIS 6.0 Filter Driver"}
    Invoke-Command -ComputerName $TargetComputer -ScriptBlock {Disable-NetAdapterBinding -Name "*" -DisplayName "Trend Micro LightWeight Filter Driver"}

    #MakeWinSAT run at login.
    Invoke-Command -ComputerName $TargetComputer -ScriptBlock {$Command = 'WinSAT formal' | Out-File -encoding 'ASCII' -FilePath 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\WinSAT.bat'}

    #Web Relay
    #10.202.126.219

#BIOS Update
Invoke-Command -ComputerName $TargetComputer -ScriptBlock {Start-Process -FilePath 'C:\INSTALLS\infoSpark TrainTracks 2020.08.25\BIOS\HP ProDesk 600 G4 2.17\HpFirmwareUpdRec64.exe' -ArgumentList '-s'}
#"C:\INSTALLS\infoSpark TrainTracks 2020.08.25\BIOS\HP ProDesk 600 G4 2.17\HpFirmwareUpdRec64.exe" -s
#"C:\INSTALLS\infoSpark TrainTracks 2020.08.25\BIOS\HP Z2 G5 01.02.01.A\HpFirmwareUpdRec64.exe" -s
#"C:\INSTALLS\infoSpark TrainTracks 2020.08.25\BIOS\Dell Precision 5820 2.8.0\5820T_2.8.0.exe" /s /f /r /p=piedwst
#"C:\INSTALLS\infoSpark TrainTracks 2020.08.25\BIOS\Dell Precision 5810 A34\T5810A34.exe" /s /f /r /p=piedwst
#"C:\INSTALLS\infoSpark TrainTracks 2020.08.25\BIOS\Dell Precision 3610 A19\T3610A19.exe" /s /f /r /p=piedwst
$TargetComputer = "MININT-BHQXCV2"
#Invoke-Command -ComputerName $TargetComputer -ScriptBlock {'"C:\INSTALLS\infoSpark TrainTracks 2020.08.25\BIOS\Dell Precision 3610 A19\T3610A19.exe" /s /f /r /p=piedwst'}
Invoke-Command -ComputerName $TargetComputer -ScriptBlock {'"C:\INSTALLS\infoSpark TrainTracks 2020.08.25\BIOS\Dell Precision 5820 2.8.0\5820T_2.8.0.exe" /s /f /r /p=piedwst'}

$CheckIdAppsInstalled = {
#Check If Apps Installed
    $TargetComputer = "OISCV05Z"
    #Get-WmiObject -Class Win32_Product -ComputerName $TargetPC | sort Name, Version, IdentifyingNumber | Format-Table -AutoSize -Property Name, Version, IdentifyingNumber -Wrap
    #Get-WmiObject -Class Win32_Product -ComputerName $TargetComputer | Get-Member -MemberType property | Where { $_.IdentifyingNumber -match '{64D3590F-3BF8-4E61-994F-9AFB89EA6176}'}
    Get-WmiObject -Class Win32_Product -ComputerName $TargetComputer | Get-Member -MemberType property | Where { $_.IdentifyingNumber -match '{56839E35-532F-479D-8BB9-64D3546DF819}'}



    Get-WmiObject -Class Win32_BIOS -ComputerName $TargetComputer | Get-Member -MemberType property | Where { $_.name -match 'install'}

    get-wmiobject Win32_Product | Sort-Object -Property Name |Format-Table IdentifyingNumber, Name, LocalPackage -AutoSize

    $query = “SELECT * FROM Win32_Product"
    Get-WmiObject -Query $query -ComputerName $TargetComputer

    $Query = “SELECT * FROM Win32_Product WHERE IdentifyingNumber = '{E6EB995F-F572-4DB9-A61A-0C3E6D11F75F}'”
    $TargetComputer = "OISCV10Z"
    $Results = Get-WmiObject -Query $Query -ComputerName $TargetComputer
    IF ($($Results.Name -eq 'Synapse Workstation Ex') -AND $($Results.Version -eq '5.7.220')) {
        Write-Host -Object $('The app was installed.') -ForegroundColor Green
    } ELSE {
        Write-Host -Object $('The app in not present.') -ForegroundColor Red
    }
    $Results
}


#Test to get Invoke-Command to pass arguments
$TargetName = "PHC-Z2G5A"
$AppName = "FredTest"
$AppHive = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$AppName"

New-Item -Path $AppHive -Force
New-ItemProperty -Path $AppHive -Name "DisplayName" -Value $AppName -PropertyType String -Force
New-ItemProperty -Path "HKLM:\Software\MyCompany" -Name "NoOfEmployees" -Value 822

Invoke-Command -ComputerName $TargetName -ScriptBlock {New-ItemProperty -Path $args[0] -Name "DisplayName" -Value $args[1] -PropertyType String -Force} -ArgumentList $AppHive, $AppName

New-ItemProperty -Path $args[0] -Name "DisplayName" -Value $args[1] -PropertyType String -Force


#Test SendKeys for Epic SER Record. Execute at Chronicles Main Menu.
#https://stackoverflow.com/questions/17849522/how-to-perform-keystroke-inside-powershell
$Wshell = New-Object -ComObject wscript.shell;
$Wshell.AppActivate('PRD')
$Wshell.SendKeys('1')
$Wshell.SendKeys('{ENTER}')
Start-Sleep -s 1
$Wshell.AppActivate('PRD')
$Wshell.SendKeys('1')
$Wshell.SendKeys('{ENTER}')
Start-Sleep -s 1


#Test SendKeys for Epic SER Record. Execute within the record to navigate.
$Wshell = New-Object -ComObject wscript.shell;
$Wshell.AppActivate('PRD')
#$Wshell.SendKeys('{TAB}')
#$Wshell.SendKeys('{TAB}')
#$Wshell.SendKeys('{TAB}')
#$Wshell.SendKeys('{TAB}')
#$Wshell.SendKeys('{TAB}')
#$Wshell.SendKeys('{TAB}')
#$Wshell.SendKeys('{TAB}')
#$Wshell.SendKeys('{TAB}')
$Wshell.SendKeys('{PGDN}')
$Wshell.SendKeys('{PGDN}')
$Wshell.SendKeys('{PGDN}')
$Wshell.SendKeys('{PGDN}')
$Wshell.SendKeys('{PGDN}')
$Wshell.SendKeys('{PGDN}')
$Wshell.SendKeys('{PGDN}')
$Wshell.SendKeys('{PGDN}')
$Wshell.SendKeys('{PGDN}')
$Wshell.SendKeys('{PGDN}')
$Wshell.SendKeys('{PGDN}')
$Wshell.SendKeys('{PGDN}')
$Wshell.SendKeys('{PGDN}')


#Test Epic SER Build:1056597
[string]$Environment = 'POC'
[string]$ProviderName = 'PMH ODC ABI 1'
[string]$Abbrev = 'PMH ODC ABI1'
[string]$Modality = 'US'
[string]$Department = '10502045'
$Wshell = New-Object -ComObject wscript.shell;
#Provider Information
$Wshell.AppActivate("$Environment")
$Wshell.SendKeys("$ProviderName")
$Wshell.SendKeys('{TAB}')
$Wshell.SendKeys("$Abbrev")
$Wshell.SendKeys('{TAB}')
$Wshell.SendKeys("$ProviderName")
$Wshell.SendKeys('{TAB}')
#Page Down 13 times
$Wshell.AppActivate("$Environment")
$Wshell.SendKeys('{PGDN}')
$Wshell.SendKeys('{PGDN}')
$Wshell.SendKeys('{PGDN}')
$Wshell.SendKeys('{PGDN}')
$Wshell.SendKeys('{PGDN}')
$Wshell.SendKeys('{PGDN}')
$Wshell.SendKeys('{PGDN}')
$Wshell.SendKeys('{PGDN}')
$Wshell.SendKeys('{PGDN}')
$Wshell.SendKeys('{PGDN}')
$Wshell.SendKeys('{PGDN}')
$Wshell.SendKeys('{PGDN}')
$Wshell.SendKeys('{PGDN}')
#Provider/Resource Information
$Wshell.AppActivate("$Environment")
$Wshell.SendKeys('{TAB}')
$Wshell.SendKeys("$Modality")
$Wshell.SendKeys('{TAB}')
$Wshell.SendKeys("$ProviderName")
$Wshell.SendKeys('{TAB}')
$Wshell.SendKeys('{TAB}')
$Wshell.SendKeys('{TAB}')
$Wshell.SendKeys('{TAB}')
$Wshell.SendKeys('{TAB}')
$Wshell.SendKeys('{TAB}')
$Wshell.SendKeys('{TAB}')
$Wshell.SendKeys('{TAB}')
$Wshell.SendKeys("$Department")
$Wshell.SendKeys('{TAB}')
$Wshell.SendKeys('ACT')
$Wshell.SendKeys('{TAB}')
$Wshell.SendKeys('{PGDN}')
$Wshell.SendKeys('{ENTER}')
#This tested out to fully work


#JSON Object Creation
[string]$JSONtest = '
{
"ProviderName":"US1, PPG SURG SPEC MACON",
"Abbrev":"PPG SS MAC",
"Departments":"14779001"
}
'


<#Read an Excel Workbook
#https://www.c-sharpcorner.com/article/read-excel-file-using-psexcel-in-powershell2/
$ExcelFile = 'C:\Users\Wraven\Desktop\Agfa Migration\All EI Patients.csv'
$objExcel = New-Object -ComObject Excel.Application
$WorkBook = $objExcel.Workbooks.Open($ExcelFile)
#$WorkBook.sheets | Select-Object -Property Fred
$WorkSheet = $WorkBook.Sheets.Item(1)
$totalNoOfRecords = ($WorkSheet.UsedRange.Rows).count
Write-Host -Object $totalNoOfRecords

ForEach($Row in @($totalNoOfRecords = $Worksheet.Dimension.Rows)) { 

Write-Host -Object $Row
}
$objExcel.Workbooks.Close
#>


<#Worksheet Test 2
#https://social.technet.microsoft.com/Forums/ie/en-US/797665d6-e881-4f69-86c5-533941c72288/powershell-script-to-read-coulumn-2-data-from-xlsx-file?forum=winserverpowershell
$Excel = New-Object -Com Excel.Application

$WorkBook = $Excel.Workbooks.Open('C:\Users\Wraven\Desktop\Agfa Migration\All EI Patients.csv')

$WorkSheet = $WorkBook.Sheets.Item(1)

Write-Host -Object ($WorkSheet.UsedRange.Rows).count

Write-Host -Object ($WorkSheet.UsedRange.Columns).count

FOREACH ($Row in $Worksheet.Rows) {
    Write-Host -Object ($WorkSheet.Cells.Item
}

$excel.Workbooks.Close()
#>



Invoke-Command -ScriptBlock {
#Convert crosswalk to no leading zeros and proper date format.

    
    #Declare universal values
    [bool]$Debug = $false
    [datetime]$StartTime = Get-Date
    [int]$Index = 0
    [string]$CrossWalkPath = "C:\Users\Wraven\OneDrive\Backup\MaconSurgicalSpecialist-SciImage\Crosswalk.csv"
    [string]$NewCrosswalkPath = "C:\Users\Wraven\OneDrive\Backup\MaconSurgicalSpecialist-SciImage\CrosswalkOut.csv"
    $Table = New-Object System.Collections.ArrayList
    IF ($Debug) {Write-Host -Object $CrossWalkPath -ForegroundColor Cyan}
    IF ($Debug) {Write-Host -Object $NewCrosswalkPath -ForegroundColor Cyan}
    IF ($Debug) {PAUSE}
    
    
    #Read all entries and activate the progress bar.
    Write-Host -Object $('Reading the Crosswalk...') -ForegroundColor Cyan
    $WorkBook = Import-Csv -Path $CrossWalkPath -Delimiter ','
    $MaxCount = ($WorkBook.Count / 100)
    IF ($Debug) {Write-Host -Object $("MaxIndex:$($WorkBook.Count)") -ForegroundColor Cyan}
    IF ($Debug) {PAUSE}


    #Process each line.
    Clear-Host
    FOREACH ($Row in $Workbook) {


        #Progress bar keeps track of how long it takes.
        IF (-not $Debug) {
            $Index = $Index + 1
            $DifferenceTime = New-TimeSpan -Start $StartTime -End $(Get-Date)
            $Progress = [math]::Round(($Index / $MaxCount), 4)
            $Message = $DifferenceTime -replace ".{8}$"
            Write-Progress -Activity "Progress - $Message" -Status "$Progress% Complete" -PercentComplete $Progress
        }


        #Makes a new object based off the old data to translate.
        TRY {


            #This block adds the data to a Custom Object that refelexts teh old data.
            $OldRow = [PSCustomObject]@{
                OldMRN = [string]$($Row.OldMRN)
                NewMRN = [string]$($Row.NewMRN)
                DOB = [string]$($Row.DOB)
            }
            IF ($Debug) {Write-Host -Object $($OldRow | Format-List | Out-String)}
        } CATCH {


            #Show a bad result.
            Write-Host -Object $($OldRow| Format-List | Out-String) -ForegroundColor Red
            PAUSE
        }


        #This block adds the data to a Custom Object and adds it to a table to be exported to a CSV later.
        TRY {


            #This block adds the data to a Custom Object that refelexts teh old data.
            $NewRow = [PSCustomObject]@{
                OldMRN = [string]$($OldRow.OldMRN)
                NewMRN = [string]$($OldRow.NewMRN)
                DOB = [string]$($OldRow.DOB)
            }
            IF ($Debug) {Write-Host -Object $("$($NewRow.OldMRN), $($NewRow.NewMRN), $($NewRow.DOB)") -ForegroundColor Green}
        } CATCH {


            #Show a bad result.
            Write-Host -Object $($NewRow | Format-List | Out-String) -ForegroundColor Red
            PAUSE
        }


        #Trim the existing MRN
        TRY {
            $TrimmedMRN = $($OldRow.OldMRN).trimstart('0')
            $NewRow.OldMRN = [string]$TrimmedMRN
        } CATCH {

        }


        #Convert DOB
        TRY {
            $ConvertedDate = Get-Date -Date $($OldRow.DOB) -Format "yyyyMMdd"
            $NewRow.DOB = $ConvertedDate
        } CATCH {
            Write-Host -Object $("$($Row.OldMRN), $($Row.NewMRN), $($Row.DOB)") -ForegroundColor Red
        }


        #Add Array to ArrayList if the key data points are not null.
        IF ($Debug) {Write-Host -Object $("$($NewRow.OldMRN), $($NewRow.NewMRN), $($NewRow.DOB)") -ForegroundColor Magenta}
        IF (-not($($NewRow.OldMRN) -eq 'NULL' -or $($NewRow.NewMRN) -eq 'NULL' -or $($NewRow.DateOfBirth) -eq 'NULL')) {
            $Table.Add($NewRow) | Out-Null
        }

    }


    #Export table to CSV
    IF ($Debug) {$Table}
    $Table | Export-Csv -Path $NewCrosswalkPath -Encoding ASCII -NoTypeInformation
    $Message = "Total Run Time: $DifferenceTime"
    Write-Host -Object $Message -ForegroundColor Green


}

















$RunStudyListAgainstCrosswalk = {


    #Import tools needed.
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Unrestricted -Force
    #Install-Module -Name sqlserver -Force -AllowClobber
    Import-Module -Name sqlserver


    #Worksheet CSV read patient list and modify it with the crosswalk.
    [bool]$Debug = $False
    [datetime]$StartTime = Get-Date
    [int]$AccessionMigration = 3900001
    [int]$MRNMigration = 1200001
    [int]$Index = 0
    [string]$TableDB = 'OrthoAtlanta-Medstrat'
    [string]$OldWorkBookPath = "C:\Users\Wraven\OneDrive\Backup\OrthoAtlanta-Medstrat\FredTestIn.csv"
    [string]$NewWorkBookPath = "C:\Users\Wraven\OneDrive\Backup\OrthoAtlanta-Medstrat\FredTestOut.csv"
    $Table = New-Object System.Collections.ArrayList
    IF ($Debug) {Write-Host -Object $OldWorkBookPath -ForegroundColor Cyan}
    IF ($Debug) {Write-Host -Object $NewWorkBookPath -ForegroundColor Cyan}
    IF ($Debug) {PAUSE}

    
    #Set the process priority
    Write-Host -Object $('Setting Process Priority...') -ForegroundColor Cyan
    #Set Process Priority
        #Idle
        #BelowNormal
        #Normal
        #AboveNormal
        #High
        #RealTime
    $ProcessPriority = Get-Process -Name 'powershell_ise'
    $ProcessPriority.PriorityClass = 'High'

    
    #Read all entries and activate the progress bar.
    Write-Host -Object $('Reading the Study List...') -ForegroundColor Cyan
    $WorkBook = Import-Csv -Path $OldWorkBookPath -Delimiter '|'
    $MaxCount = ($WorkBook.Count / 100)
    IF ($Debug) {Write-Host -Object $("MaxIndex:$($WorkBook.Count)") -ForegroundColor Cyan}
    IF ($Debug) {PAUSE}



    #Process each line.
    Clear-Host
    FOREACH ($Row in $Workbook) {
        

        #Progress bar keeps track of how long it takes.
        IF (-not $Debug) {
            $Index = $Index + 1
            $DifferenceTime = New-TimeSpan -Start $StartTime -End $(Get-Date)
            $Progress = [math]::Round(($Index / $MaxCount), 4)
            $Message = $DifferenceTime -replace ".{8}$"
            Write-Progress -Activity "Progress - $Message" -Status "$Progress% Complete" -PercentComplete $Progress
        }


        #Makes a new object based off the old data to translate.
        TRY {


            #This block adds the data to a Custom Object that refelexts teh old data.
            $OldRow = [PSCustomObject]@{
                MRN = [string]$($Row.mrn).trimstart('0')
                PatientName = [string]$($Row.lastname) + [char]94 + $($Row.firstname) + [char]94 + $($Row.middlename) + [char]94 + [char]94
                DOB = [string]$($Row.date_of_birth)
                Sex = [string]$($Row.sex)

                Accession = [string]$($Row.accession_number)
                Modalities = [string]$($Row.modalities)
                StudyDescription = [string]$($Row.study_description)
                StudyDate = [string]$($Row.study_date)
                StudyUID = [string]$($Row.suid)
            }


            IF ($Debug) {Write-Host -Object $($OldRow | Sort-Object -Property 'Name' | Format-List | Out-String)}
        } CATCH {


            #Show a bad result.
            Write-Host -Object $($OldRow | Sort-Object -Property 'Name' | Format-List | Out-String) -ForegroundColor Red
            PAUSE
        }





        TRY {


            #This block adds the data to a Custom Object and adds it to a table to be exported to a CSV later.
            $NewRow = [PSCustomObject]@{
                OldMRN = [string]$($OldRow.MRN)
                NewMRN = $Null
                PatientName = [string]$($OldRow.PatientName)
                DOB = [string]$($OldRow.DOB)
                Sex = [string]$($OldRow.Sex)
                OldAccession = [string]$($OldRow.Accession)
                NewAccession = $Null
                Modalities = [string]$($OldRow.Modalities)
                StudyDescription = [string]$($OldRow.StudyDescription)
                StudyDate = [string]$($OldRow.StudyDate)
                StudyUID = [string]$($OldRow.StudyUID)
            }


            IF ($Debug) {Write-Host -Object $($NewRow | Sort-Object -Property 'Name' | Format-List | Out-String)}
        } CATCH {


            #Show a bad result.
            Write-Host -Object $($NewRow | Sort-Object -Property 'Name' | Format-List | Out-String) -ForegroundColor Red
            PAUSE
        }


        TRY {


            #This block will crosswalk the OldMRN and if it matches, verifies the DOB. If they both match, it saves the new MRN to a veriable and sets a flag to true. If the operator stays false, it assigns a new MRN.
            $QueryText = "SELECT * FROM [Crosswalks].[dbo].[$TableDB] WHERE [OldMRN] = '$($NewRow.OldMRN)' AND [DOB] = '$($NewRow.DOB)';"
            IF ($Debug) {Write-Host -Object $QueryText}
            $QueryResult = Invoke-Sqlcmd -ServerInstance "LOCALHOST" -Query $QueryText
            $NewRow.NewMRN = $($QueryResult.NewMRN)


            IF ($Debug) {Write-Host -Object $($NewRow | Sort-Object -Property 'Name' | Format-List | Out-String) -ForegroundColor Green}
        } CATCH {


            #Show a bad result.
            Write-Host -Object $($NewRow | Sort-Object -Property 'Name' | Format-List | Out-String) -ForegroundColor Red
        }


        TRY {


            #This block will put in an MRN if one was not filled in by the SQL query.
            IF ($NewRow.NewMRN -eq $null) {
                [string]$DisplayMRN = $MRNMigration
                $NewRow.NewMRN = 'MIG' + $DisplayMRN.PadLeft(9,'0')
                $MRNMigration = $MRNMigration + 1
            }

            IF ($Debug) {Write-Host -Object $($NewRow | Sort-Object -Property 'Name' | Format-List | Out-String) -ForegroundColor Orange}
        } CATCH {


            #Show a bad result.
            Write-Host -Object $('MRN did not process correctly.') -ForegroundColor Red
            Write-Host -Object $($NewRow | Sort-Object -Property 'Name' | Format-List | Out-String) -ForegroundColor Red
            PAUSE
        }
            

       TRY {


            #Generate Accession
            [string]$DisplayAccession = $AccessionMigration
            $NewRow.NewAccession = 'MIG' + $DisplayAccession.PadLeft(9,'0')
            $AccessionMigration = $AccessionMigration + 1


            IF ($Debug) {Write-Host -Object $($NewRow | Sort-Object -Property 'Name' | Format-List | Out-String) -ForegroundColor Green}
        } CATCH {


            #Show a bad result.
            Write-Host -Object $('Accession did not process correctly.') -ForegroundColor Red
            Write-Host -Object $($NewRow | Sort-Object -Property 'Name' | Format-List | Out-String) -ForegroundColor Red
            PAUSE
        }
    

        #Add New Row object to the table.
        $Table.Add($NewRow) | Out-Null
        IF ($Debug) {$NewRow}
    }


    #$Table
    $Table | Export-Csv -Path $NewWorkBookPath -Encoding ASCII -NoTypeInformation


    #Time Reporting
    $TotalTimeSpan = New-TimeSpan -Start $StartTime -End $(Get-Date)
    $Message = "Total Run Time: $TotalTimeSpan"
    Write-Host -Object $Message -ForegroundColor Green


}
Start-Process POWERSHELL $RunStudyListAgainstCrosswalk -Wait




#Trying to delete the profile from a windows 10 machine.
#Fuji Synapse Agent has an issue with user profiles.
#https://stackoverflow.com/questions/42963661/use-powershell-to-search-for-string-in-registry-keys-and-values
$FredTest = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
FOREACH ($Profile IN $FredTest) {
    $ChildPath = Get-ChildItem $Profile.PSPath
    FOREACH ($ProfilePath IN $ChildPath) {
        Write-Host -Object '=================================================='
        $ProfilePath.Property.ProfileImagePath
        #IF ($ProfilePath.)
    }
}







$DoDiscoveryForPACS = {
#PACS Discovery
#Done for Xcelera on 1/13/2022


    #Main System Variables
    [int]$DelayBetweenQueries = 3
    [bool]$Debug = $false
    [int]$Index = 0
    [string]$StudyBreak = 'I: # Dicom-Data-Set'
    $Table = New-Object System.Collections.ArrayList
    $StartTime = Get-Date


    #Designate data that I need in an object.
    $Query = [PSCustomObject]@{
        'SCPAET' = [string]"--call" + [char]32 + $($null)
        'SCUAET' = [string]"--aetitle" + [char]32 + $($null)
        'StudyDate' = [string]"-k 0008,0020=" + $($null)
        'Accession' = [string]"-k 0008,0050=" + $($null)
        'Level' = [string]"-k 0008,0052=" + $('STUDY')
        'Modality' = [string]"-k 0008,0060=" + $($null)
        'StudyDescription' = [string]"-k 0008,1030=" + $($null)
        'PatientName' = [string]"-k 0010,0010=" + $($null)
        'PatientMRN' = [string]"-k 0010,0020=" + $($null)
        'PatientDOB' = [string]"-k 0010,0030=" + $($null)
        'PatientSex' = [string]"-k 0010,0040=" + $($null)
        'StudyUID' = [string]"-k 0020,000D=" + $($null)
        'IP' = [string]$($null)
        'Port' = [string]$($null)
    }
    $Query.SCPAET = [string]"--call" + [char]32 + $('PHCCAR_SCP')
    $Query.SCUAET = [string]"--aetitle" + [char]32 + $('ADAM')
    $Query.IP = [string]$('10.22.24.58')
    $Query.Port = [string]$('7000')

    #$Query.SCPAET = [string]"--call" + [char]32 + $('FREDTEST')
    #$Query.SCUAET = [string]"--aetitle" + [char]32 + $('farmamb')
    #$Query.IP = [string]$('10.15.2.11')
    #$Query.Port = [string]$('105')

    #$Query.SCPAET = [string]"--call" + [char]32 + $('farmamb')
    #$Query.SCUAET = [string]"--aetitle" + [char]32 + $('AGFA')
    #$Query.IP = [string]$('10.25.222.203')
    #$Query.Port = [string]$('104')


    #Get the tools from the website if findscu does not exist.
    IF (-NOT $(Test-Path -Path "$Env:temp\dcmtk-3.6.6-win64-dynamic\bin\findscu.exe")) {
        Invoke-RestMethod -Uri "https://dicom.offis.de/download/dcmtk/dcmtk366/bin/dcmtk-3.6.6-win64-dynamic.zip" -OutFile "H:\Installs\DCMTK.zip"
        Expand-Archive -LiteralPath "H:\Installs\DCMTK.zip" -DestinationPath $Env:temp
    }
    [string]$CFIND = "$Env:temp\dcmtk-3.6.6-win64-dynamic\bin\findscu.exe -S -v"


    #Set the timepan on how far back Xcelera will go.
    [datetime]$StartDate = Get-Date("01/01/1900")
    [datetime]$EndDate = Get-Date
    [int]$TotalTime = (New-TimeSpan –Start $StartDate –End $EndDate).Days
    IF ($Debug) {Write-Host -Object $TotalTime -ForegroundColor Cyan}


    #Cycle through all dates and get a list of all studies.
    Clear-Host
    WHILE ($StartDate -le $EndDate){


        #Calculate the time for the progress bar.
        $DifferenceTime = New-TimeSpan -Start $StartTime -End $(Get-Date)
        $Timer = $DifferenceTime -replace ".{8}$"

        #Add the start date into the info object.
        $ConvertedDate = Get-Date -Date $StartDate -Format "yyyyMMdd"
        $Query.StudyDate = [string]"-k 0008,0020=" + $($ConvertedDate)


        #Progress bar keeps track of how long it takes.
        $Progress = [math]::Round(($Index / $TotalTime), 4)
        $ProgressPercent = $Progress * 100
        Write-Progress -Activity "Progress - $ConvertedDate - $Timer" -Status "$ProgressPercent% Complete" -PercentComplete $ProgressPercent

                
        #Create the string to find the data.
        $Command = -join @(
            $CFIND + [char]32
            $Query.SCPAET + [char]32
            $Query.SCUAET + [char]32
            $Query.StudyDate + [char]32
            $Query.Accession + [char]32
            $Query.Level + [char]32
            $Query.Modality + [char]32
            $Query.StudyDescription + [char]32
            $Query.PatientName + [char]32
            $Query.PatientMRN + [char]32
            $Query.PatientDOB + [char]32
            $Query.PatientSex + [char]32
            $Query.StudyUID + [char]32
            $Query.IP + [char]32
            $Query.Port
        )


        #Display command and add to it.
        IF ($Debug) {Write-Host -Object $Command -ForegroundColor Cyan}
        $DailyStudyList = Invoke-Expression -Command $Command
            
            
        #Parse the list of data returned. Add it to the Study Object.
        FOREACH ($Line in $DailyStudyList) {
            IF ($Debug) {Write-Host -Object $Line}
            IF ($Line -eq $StudyBreak) {

                #Create a study object wil all details to be filled in.
                $Study = [PSCustomObject]@{
                    'Date' = $null
                    'Accession' = $null
                    'Modality' = $null
                    'Description' = $null
                    'PatientName' = $null
                    'PatientMRN' = $null
                    'PatientDOB' = $null
                    'PatientSex' = $null
                    'UID' = $null
                }


            } ELSE {

                #Parse the info returned.
                $DataPoint = $Line.Split('()')[1]
                SWITCH ($DataPoint){
					"0008,0020"{
                        $Study.Date = [string]$($Line.Split('[]')[1])
						; Break
					}
					"0008,0050"{
                        $Study.Accession = [string]$($Line.Split('[]')[1])
						; Break
					}
					"0008,0060"{
                        $Study.Modality = [string]$($Line.Split('[]')[1])
						; Break
					}
					"0008,1030"{
                        $Study.Description = [string]$($Line.Split('[]')[1])
						; Break
					}
					"0010,0010"{
                        $Study.PatientName = [string]$($Line.Split('[]')[1])
						; Break
					}
					"0010,0020"{
                        $Study.PatientMRN = [string]$($Line.Split('[]')[1])
						; Break
					}
					"0010,0030"{
                        $Study.PatientDOB = [string]$($Line.Split('[]')[1])
						; Break
					}
					"0010,0040"{
                        $Study.PatientSex = [string]$($Line.Split('[]')[1])
						; Break
					}
					"0020,000D"{
                        $Study.UID = [string]$($Line.Split('[]')[1])

                        IF (-NOT ([string]::IsNullOrEmpty($Study.UID))) {
						    $Table.Add($Study) | Out-Null
                        }

					}
                    
                }


            }


        #Progress the metrics
        $StartDate = $Startdate.AddDays(1)
        $Index = $Index + 1


        }


    }


    #Add the Table collection to a spreadsheet.
    $PathToCSV = 'D:\FredTest.csv'
    $Table | Export-Csv -Path $PathToCSV -Encoding ASCII -NoTypeInformation
    Start-Sleep -Seconds $DelayBetweenQueries

    #Report the total time
    $TotalTimeSpan = New-TimeSpan -Start $StartTime -End $(Get-Date)
    $Message = "Total Run Time: $TotalTimeSpan"
    Write-Host -Object $Message -ForegroundColor Green


}











$CreateVMforWork = {
#This is use dto create VMs for use with Agfa and Piedmont.


    $VM = 'FWL-CLEVE01'
    $RAM = 8GB
    $DriveSpace = 128
    New-VM -Name $VM -Path "D:\Hyper-V" -Generation 1 -MemoryStartupBytes $RAM -SwitchName 'Nexus' -NewVHDPath "D:\Hyper-V\$VM\Virtual Hard Disks\$VM.vhdx" -NewVHDSizeBytes $($DriveSpace * 1024 * 1024 * 1024)
    Set-VM -Name $VM -ProcessorCount 4 -DynamicMemory -MemoryMinimumBytes 128MB -MemoryMaximumBytes $RAM -AutomaticStopAction ShutDown
    Set-VMDvdDrive -VMName $VM -Path 'D:\ISO\Win10-1511-Enterprise.ISO'
    Checkpoint-VM -Name $VM -SnapshotName 'BareMetal'
    Start-VM -Name $VM
    PAUSE
    $VM = 'FWL-CLEVE01'
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
    Set-Timezone -Name 'Eastern Standard Time'
    Rename-Computer -NewName $VM -Restart
    PAUSE
    $VM = 'FWL-CLEVE01'
    Checkpoint-VM -Name $VM -SnapshotName 'Win10-1511'
    PAUSE
    $VM = 'FWL-CLEVE01'
    Checkpoint-VM -Name $VM -SnapshotName 'Win10-21H1'
}







$DoVerificationForPACS = {
#PACS verification.
#Used to check what system is reporting back what data.


    #Main System Variables
    [bool]$Debug = $false
    [int]$Index = 0
    [string]$StudyBreak = 'I: # Dicom-Data-Set'
    [string]$OldWorkBookPath = "H:\Backup\Walton-Agfa-Migration\FredTestIn.csv"
    [string]$NewWorkBookPath = "H:\Backup\Walton-Agfa-Migration\FredTestOut.csv"
    $Table = New-Object System.Collections.ArrayList
    $StartTime = Get-Date
    Clear-Host


    #Change the process priority.
    Write-Host -Object $('Setting Process Priority...') -ForegroundColor Cyan
    #Set Process Priority
        #Idle
        #BelowNormal
        #Normal
        #AboveNormal
        #High
        #RealTime
    $ProcessPriority = Get-Process -Name 'powershell_ise'
    $ProcessPriority.PriorityClass = 'High'


    #Get the tools from the website if findscu does not exist.
    IF (-NOT $(Test-Path -Path "$Env:temp\dcmtk-3.6.6-win64-dynamic\bin\findscu.exe")) {
        Invoke-RestMethod -Uri "https://dicom.offis.de/download/dcmtk/dcmtk366/bin/dcmtk-3.6.6-win64-dynamic.zip" -OutFile "H:\Installs\DCMTK.zip"
        Expand-Archive -LiteralPath "H:\Installs\DCMTK.zip" -DestinationPath $Env:temp
    }
    [string]$CFIND = "$Env:temp\dcmtk-3.6.6-win64-dynamic\bin\findscu.exe -S -v"


    #Import in Study List
    Write-Host -Object $('Reading the Study List...') -ForegroundColor Cyan
    $WorkBook = Import-Csv -Path $OldWorkBookPath -Delimiter ','
    $MaxIndex = $WorkBook | Measure-Object
    $MaxCount = ($MaxIndex.Count / 100)
    $StatusMessage = 'Finished Importing Study List: ' + $MaxIndex.Count
    Write-Host -Object $StatusMessage -ForegroundColor Cyan
    

    #Designate data that I need in an object.
    $Query = [PSCustomObject]@{
        'SCPAET' = [string]"--call" + [char]32 + $($null)
        'SCUAET' = [string]"--aetitle" + [char]32 + $($null)
        'StudyDate' = [string]"-k 0008,0020=" + $($null)
        'Accession' = [string]"-k 0008,0050=" + $($null)
        'Level' = [string]"-k 0008,0052=" + $('STUDY')
        'Modality' = [string]"-k 0008,0060=" + $($null)
        'StudyDescription' = [string]"-k 0008,1030=" + $($null)
        'PatientName' = [string]"-k 0010,0010=" + $($null)
        'PatientMRN' = [string]"-k 0010,0020=" + $($null)
        'PatientDOB' = [string]"-k 0010,0030=" + $($null)
        'PatientSex' = [string]"-k 0010,0040=" + $($null)
        'StudyUID' = [string]"-k 0020,000D=" + $($null)
        'IP' = [string]$($null)
        'Port' = [string]$($null)
    }


    #Cycle through all dates and get a list of all studies.
    FOREACH ($StudyRow in $Workbook) {


        #Progress bar keeps track of how long it takes.
        $Index = $Index + 1
        $DifferenceTime = New-TimeSpan -Start $StartTime -End $(Get-Date)
        $Progress = [math]::Round(($Index / $MaxCount), 4)
        $Message = $DifferenceTime -replace ".{8}$"
        Write-Progress -Activity "Progress - $Message" -Status "$Progress% Complete" -PercentComplete $Progress


        TRY {


            #This block adds the data to a Custom Object and adds it to a table to be exported to a CSV later.
            $NewRow = [PSCustomObject]@{
                Status = $Null
                OldMRN = [string]$($StudyRow.OldMRN)
                NewMRN = [string]$($StudyRow.NewMRN)
                FujiMRN = $Null
                AcuoMRN = $Null
                PatientName = [string]$($StudyRow.PatientName)
                FujiPatientName = $Null
                AcuoPatientName = $Null
                DOB = [string]$($StudyRow.DOB)
                FujiDOB = $Null
                AcuoDOB = $Null
                OldAccession = [string]$($StudyRow.OldAccession)
                NewAccession = [string]$($StudyRow.NewAccession)
                FujiAccession = $Null
                AcuoAccession = $Null
                StudyDescription = [string]$($StudyRow.StudyDescription)
                FujiStudyDescription = $Null
                AcuoStudyDescription = $Null
                StudyDate = [string]$($StudyRow.StudyDate)
                FujiStudyDate = $Null
                AcuoStudyDate = $Null
                StudyUID = [string]$($StudyRow.StudyUID)
            }


            IF ($Debug) {Write-Host -Object $($NewRow | Sort-Object -Property 'Name' | Format-List | Out-String)}
        } CATCH {


            #Show a bad result.
            Write-Host -Object $($NewRow | Sort-Object -Property 'Name' | Format-List | Out-String) -ForegroundColor Red
            PAUSE
        }


        TRY {

            #Fuji


            #Use the new UID in th3 query.
            $Query.SCPAET = [string]"--call" + [char]32 + $('Farmcstor2SCP')
            $Query.SCUAET = [string]"--aetitle" + [char]32 + $('AGFA')
            $Query.IP = [string]$('10.15.2.6')
            $Query.Port = [string]$('104')
            $Query.StudyUID = [string]"-k 0020,000D=" + $($NewRow.StudyUID)


            #Create the string to find the data.
            $Command = -join @(
                $CFIND + [char]32
                $Query.SCPAET + [char]32
                $Query.SCUAET + [char]32
                $Query.StudyDate + [char]32
                $Query.Accession + [char]32
                $Query.Level + [char]32
                $Query.Modality + [char]32
                $Query.StudyDescription + [char]32
                $Query.PatientName + [char]32
                $Query.PatientMRN + [char]32
                $Query.PatientDOB + [char]32
                $Query.PatientSex + [char]32
                $Query.StudyUID + [char]32
                $Query.IP + [char]32
                $Query.Port
            )


            #Display command and add to it.
            IF ($Debug) {Write-Host -Object $Command -ForegroundColor Cyan}
            $ResultsFromPACS = Invoke-Expression -Command $Command


            #IF ($Debug) {Write-Host -Object $($ResultsFromPACS | Sort-Object -Property 'Name' | Format-List | Out-String)}
            IF ($Debug) {Write-Host -Object $($ResultsFromPACS | Out-String)}
        } CATCH {


            #Show a bad result.
            Write-Host -Object $($ResultsFromPACS | Out-String) -ForegroundColor Red
            PAUSE
        }

               
        TRY {

            
            #Fuji


            #Parse the list of data returned. Add it to the Study Object.
            FOREACH ($Line in $ResultsFromPACS) {
                IF ($Debug) {Write-Host -Object $Line}
                IF ($Line -eq $StudyBreak) {


                    #Create a study object wil all details to be filled in.
                    $Study = [PSCustomObject]@{
                        'Date' = $null
                        'Accession' = $null
                        'Modality' = $null
                        'Description' = $null
                        'PatientName' = $null
                        'PatientMRN' = $null
                        'PatientDOB' = $null
                        'PatientSex' = $null
                        'UID' = $null
                    }
                } ELSE {


                    #Parse the info returned.
                    $DataPoint = $Line.Split('()')[1]
                    SWITCH ($DataPoint){
					    "0008,0020"{
                            $Study.Date = [string]$($Line.Split('[]')[1])
						    ; Break
					    }
					    "0008,0050"{
                            $Study.Accession = [string]$($Line.Split('[]')[1])
						    ; Break
					    }
					    "0008,0060"{
                            $Study.Modality = [string]$($Line.Split('[]')[1])
						    ; Break
					    }
					    "0008,1030"{
                            $Study.Description = [string]$($Line.Split('[]')[1])
						    ; Break
					    }
					    "0010,0010"{
                            $Study.PatientName = [string]$($Line.Split('[]')[1])
						    ; Break
					    }
					    "0010,0020"{
                            $Study.PatientMRN = [string]$($Line.Split('[]')[1])
						    ; Break
					    }
					    "0010,0030"{
                            $Study.PatientDOB = [string]$($Line.Split('[]')[1])
						    ; Break
					    }
					    "0010,0040"{
                            $Study.PatientSex = [string]$($Line.Split('[]')[1])
						    ; Break
					    }
					    "0020,000D"{
                            $Study.UID = [string]$($Line.Split('[]')[1])
                            ; Break
					    }
                    }
                }


                $NewRow.FujiMRN = $Study.PatientMRN
                $NewRow.FujiPatientName = $Study.PatientName
                $NewRow.FujiDOB = $Study.PatientDOB
                $NewRow.FujiAccession = $Study.Accession
                $NewRow.FujiStudyDescription = $Study.Description
                $NewRow.FujiStudyDate = $Study.Date
            }
        } CATCH {


            #Show a bad result.
            Write-Host -Object $($ResultsFromPACS | Out-String) -ForegroundColor Red
        }


        TRY {

            #Acuo


            #Use the new UID in the query.
            $Query.SCPAET = [string]"--call" + [char]32 + $('WALTONFUJI')
            $Query.SCUAET = [string]"--aetitle" + [char]32 + $('AGFA')
            $Query.IP = [string]$('10.15.2.11')
            $Query.Port = [string]$('104')
            $Query.StudyUID = [string]"-k 0020,000D=" + $($NewRow.StudyUID)


            #Create the string to find the data.
            $Command = -join @(
                $CFIND + [char]32
                $Query.SCPAET + [char]32
                $Query.SCUAET + [char]32
                $Query.StudyDate + [char]32
                $Query.Accession + [char]32
                $Query.Level + [char]32
                $Query.Modality + [char]32
                $Query.StudyDescription + [char]32
                $Query.PatientName + [char]32
                $Query.PatientMRN + [char]32
                $Query.PatientDOB + [char]32
                $Query.PatientSex + [char]32
                $Query.StudyUID + [char]32
                $Query.IP + [char]32
                $Query.Port
            )


            #Display command and add to it.
            IF ($Debug) {Write-Host -Object $Command -ForegroundColor Cyan}
            $ResultsFromPACS = Invoke-Expression -Command $Command


            #IF ($Debug) {Write-Host -Object $($ResultsFromPACS | Sort-Object -Property 'Name' | Format-List | Out-String)}
            IF ($Debug) {Write-Host -Object $($ResultsFromPACS | Out-String)}
        } CATCH {


            #Show a bad result.
            Write-Host -Object $($ResultsFromPACS | Out-String) -ForegroundColor Red
        }

               
       TRY {

            
            #Acuo


            #Parse the list of data returned. Add it to the Study Object.
            FOREACH ($Line in $ResultsFromPACS) {
                IF ($Debug) {Write-Host -Object $Line}
                IF ($Line -eq $StudyBreak) {


                    #Create a study object wil all details to be filled in.
                    $Study = [PSCustomObject]@{
                        'Date' = $null
                        'Accession' = $null
                        'Modality' = $null
                        'Description' = $null
                        'PatientName' = $null
                        'PatientMRN' = $null
                        'PatientDOB' = $null
                        'PatientSex' = $null
                        'UID' = $null
                    }
                } ELSE {


                    #Parse the info returned.
                    $DataPoint = $Line.Split('()')[1]
                    SWITCH ($DataPoint){
					    "0008,0020"{
                            $Study.Date = [string]$($Line.Split('[]')[1])
						    ; Break
					    }
					    "0008,0050"{
                            $Study.Accession = [string]$($Line.Split('[]')[1])
						    ; Break
					    }
					    "0008,0060"{
                            $Study.Modality = [string]$($Line.Split('[]')[1])
						    ; Break
					    }
					    "0008,1030"{
                            $Study.Description = [string]$($Line.Split('[]')[1])
						    ; Break
					    }
					    "0010,0010"{
                            $Study.PatientName = [string]$($Line.Split('[]')[1])
						    ; Break
					    }
					    "0010,0020"{
                            $Study.PatientMRN = [string]$($Line.Split('[]')[1])
						    ; Break
					    }
					    "0010,0030"{
                            $Study.PatientDOB = [string]$($Line.Split('[]')[1])
						    ; Break
					    }
					    "0010,0040"{
                            $Study.PatientSex = [string]$($Line.Split('[]')[1])
						    ; Break
					    }
					    "0020,000D"{
                            $Study.UID = [string]$($Line.Split('[]')[1])
                            ; Break
					    }
                    }
                }


                $NewRow.AcuoMRN = $Study.PatientMRN
                $NewRow.AcuoPatientName = $Study.PatientName
                $NewRow.AcuoDOB = $Study.PatientDOB
                $NewRow.AcuoAccession = $Study.Accession
                $NewRow.AcuoStudyDescription = $Study.Description
                $NewRow.AcuoStudyDate = $Study.Date
            }


            IF (($($NewRow.FujiMRN) -eq '') -AND ($($NewRow.AcuoMRN) -eq '')) {
                $NewRow.Status = [String]'NotMigrated'
            } ELSE {
                $NewRow.Status = [String]'Migrated'
            }
            $Table.Add($NewRow) | Out-Null


            IF ($Debug) {Write-Host -Object $($NewRow | Sort-Object -Property 'Name' | Format-List | Out-String)}
            IF ($Debug) {PAUSE}
        } CATCH {


            #Show a bad result.
            Write-Host -Object $($NewRow | Sort-Object -Property 'Name' | Format-List | Out-String) -ForegroundColor Red
        }
    }

    #Add the Table collection to a spreadsheet.
    $Table | Export-Csv -Path $NewWorkBookPath -Encoding ASCII -NoTypeInformation


    #Report the total time
    $TotalTimeSpan = New-TimeSpan -Start $StartTime -End $(Get-Date)
    $Message = "Total Run Time: $TotalTimeSpan"
    Write-Host -Object $Message -ForegroundColor Green


}





$CleanupOfAcuoImageCache = {


    #$ListOfFiles = Get-ChildItem '\\phcnas01\Acuo\ImageCache\PHC_GLA_MIG1' -Recurse
    #$ListOfFiles = Get-ChildItem '\\phcnas01\Acuo\ImageCache\PHC_GLA_MIG' -Recurse
    $ListOfFiles = Get-ChildItem '\\phcnas01\Acuo\ImageCache\PHC_CAR_PRI' -Recurse -Force -Attributes 'D'

    [bool]$Debug = $false
    [datetime]$StartTime = Get-Date

    FOREACH ($File in $ListOfFiles) {


        #Progress bar keeps track of how long it takes.
        $Index = $Index + 1
        $DifferenceTime = New-TimeSpan -Start $StartTime -End $(Get-Date)
        $Progress = [math]::Round(($Index / $($ListOfFiles.Count)), 4)
        $Message = $DifferenceTime -replace ".{8}$"
        Write-Progress -Activity "Progress - $Message" -Status "$Progress% Complete" -PercentComplete $Progress



        Write-Host -Object $($File.FullName)
        Write-Host -Object $($File.LastWriteTime)

        $TimeSpan = $(Get-Date) - $File.LastWriteTime
        Write-Host -Object $($TimeSpan.Days)


        IF ($($Timespan.Days) -gt 365) {
            Write-Host -Object 'Yes'
            IF (-not ($Debug)){Remove-Item -Path $($File.FullName) -Force -Recurse}
        } ELSE {
            Write-Host -Object 'No'
        }
    }
}


$InstallApplication = {


    [string]$TargetComputer = 'OISCV05Z'
    #[string]$AppName = 'Nuance PowerScribe360 4.0 SP6.TEST'
    [string]$AppName = 'Nuance PowerScribe360 4.0'
    
    
    
    Invoke-Command -ScriptBlock {ROBOCOPY "\\PHCMS01\Share_Data\PHC\Imaging\FredTest\$AppName" "\\$TargetComputer\C$\INSTALLS\$AppName" /E}
    
    
    [string]$Directory = "C:\INSTALLS\$AppName"
    [string]$Command = [char]34 + [char]39 + "$Directory\Automated\Automated.bat" + [char]39 + 'INSTALLPROD' + [char]34
    Invoke-Command -ComputerName $TargetComputer -ScriptBlock {SCHTASKS /CREATE /F /TN "Piedmont\PS360-PROD-INSTALL" /RU "SYSTEM" /RL HIGHEST /SC ONSTART /TR $Using:Command}


    Invoke-Command -ComputerName $TargetComputer -ScriptBlock {SCHTASKS /DELETE /F /TN "Piedmont\PS360-PROD-INSTALL"}


}



$MassDriver = {





    #Set basic parameters
    $Output = [PSCustomObject]@{
        'Hostname' = [string]'Status'
    }

    [string]$AppName = 'infoSpark Train Tracks 2022.05.18'
    [string]$BatchFilePath = ''
    [string]$WorkstationPath = "H:\MassDriver-UpdateAMD.txt"

    [string]$AppName = 'Fuji Synapse 5.7.220'
    [string]$BatchFilePath = '\\PHCMS01\Share_Data\PHC\Imaging\FredTest\Fuji Synapse 5.7.220\Automated\Automated.bat'
    [string]$WorkstationPath = "H:\MassDriver-FujiWebIcon.txt"

    [string]$AppName = 'Siemens sD Workplace VA40'
    [string]$BatchFilePath = '\\PHCMS01\Share_Data\PHC\Imaging\FredTest\Siemens sD Workplace VA40\Automated\Automated.bat'
    [string]$WorkstationPath = "H:\MassDriver-SyngoDynamics.txt"

    [string]$AppName = 'Eizo RadiCS 4.6.7'
    [string]$BatchFilePath = '\\PHCMS01\Share_Data\PHC\Imaging\FredTest\Eizo RadiCS 4.6.7\Automated\Automated.bat'
    [string]$WorkstationPath = "H:\MassDriver-EizoRadics.txt"

    [string]$AppName = 'Philips DynaCAD 5.0'
    [string]$BatchFilePath = '\\PHCMS01\Share_Data\PHC\Imaging\FredTest\Philips DynaCAD 5.0\Automated\Automated.bat'
    [string]$WorkstationPath = "H:\MassDriver-DynaCAD.txt"

    #Read the file
    [string]$Directory = "C:\INSTALLS\$AppName"
    $FileContents = Get-Content -Path $WorkstationPath
    FOREACH ($ComputerName in $FileContents) {
        IF (Test-Connection -Computer $ComputerName -Count 1 -Quiet) {
            IF (Invoke-Command -ComputerName $ComputerName -ScriptBlock {Test-ComputerSecureChannel}) {

                <# Fuji Synapse Web
                $Application = Get-WmiObject -ComputerName $ComputerName -Class 'Win32_Product' | Where-Object {$_.IdentifyingNumber -Match '{E6EB995F-F572-4DB9-A61A-0C3E6D11F75F}'}
                IF ((Test-Path -Path "\\$ComputerName\c$\USERS\PUBLIC\DESKTOP\Synapse 5 Web.lnk") -OR ($Null -ne $Application)) {
                    IF (Test-Path -Path "\\$ComputerName\c$\USERS\PUBLIC\DESKTOP\Synapse 5 Web.lnk") {
                        Write-Host -Object $('Web Complete')
                        Add-Member -InputObject $Output -MemberType 'NoteProperty' -Name $ComputerName -Value 'Web Complete'
                        Invoke-Command -ScriptBlock {Start-Process -FilePath $BatchFilePath -ArgumentList "BATCH 5 $ComputerName" -Wait}
                    }
                    IF ($Null -ne $Application) {
                        Write-Host -Object $('Agent Complete')
                        Add-Member -InputObject $Output -MemberType 'NoteProperty' -Name $ComputerName -Value $("$Application.Name Complete")
                        Invoke-Command -ScriptBlock {Start-Process -FilePath $BatchFilePath -ArgumentList "BATCH 2 $ComputerName" -Wait}
                    }
                } ELSE {
                    Write-Host -Object $("$ComputerName - Failed")
                    Add-Member -InputObject $Output -MemberType 'NoteProperty' -Name $ComputerName -Value 'Failed'
                    Invoke-Command -ScriptBlock {Start-Process -FilePath $BatchFilePath -ArgumentList "BATCH 4 $ComputerName" -Wait}
                }
                #>

                <#Syngo Dynamics
                $Application = Get-WmiObject -ComputerName $ComputerName -Class 'Win32_Product' | Where-Object {$_.IdentifyingNumber -Match '{FD42DDCC-6250-4E0F-BC38-42F0F5F44FED}'}
                IF ($Null -ne $Application) {
                    Write-Host -Object $("$ComputerName - Complete")
                    Add-Member -InputObject $Output -MemberType 'NoteProperty' -Name $ComputerName -Value 'Complete'
                } ELSE {
                    Write-Host -Object $("$ComputerName - Failed")
                    Add-Member -InputObject $Output -MemberType 'NoteProperty' -Name $ComputerName -Value 'Failed'
                    Invoke-Command -ScriptBlock {Start-Process -FilePath $BatchFilePath -ArgumentList "BATCH 1 $ComputerName" -Wait}
                }
                #>
                
                <#Video Drivers
                $Application = Get-WmiObject -ComputerName $ComputerName -Class 'Win32_VideoController' | Where-Object {$_.Name -Match 'AMD Radeon Pro WX 3200 Series'}
                #$Application = Get-WmiObject -ComputerName $ComputerName -Class 'Win32_VideoController' | Where-Object {$_.Name -Match 'NVIDIA Quadro P2000'}
                IF ($Null -ne $Application) {
                    IF ($Application.DriverVersion -eq '30.0.14011.2006') {
                    #IF ($Application.DriverVersion -eq '27.21.14.5239') {
                        Write-Host -Object $("$ComputerName - Complete")
                        Add-Member -InputObject $Output -MemberType 'NoteProperty' -Name $ComputerName -Value 'Complete'
                    } ELSE {
                        Write-Host -Object $("$ComputerName - Failed")
                        Add-Member -InputObject $Output -MemberType 'NoteProperty' -Name $ComputerName -Value 'Failed'
                        $ComputerName = 'CARDGYRDRM001R'
                        Invoke-Command -ComputerName $ComputerName -ScriptBlock {IF (-Not (Test-Path -Path "C:\INSTALLS\Packages")) {New-Item -ItemType 'Directory' -Path "C:\INSTALLS\Packages" -Force}}
                        Start-BitsTransfer -Source '\\PHCMS01\Share_Data\PHC\Imaging\Applications\INFOSPARKTRAINTRACK20200825.ZIP' -Destination "\\$ComputerName\C$\Installs\Packages"
                        Invoke-Command -ComputerName $ComputerName -ScriptBlock {Expand-Archive -LiteralPath 'C:\Installs\Packages\INFOSPARKTRAINTRACK20200825.ZIP' -DestinationPath 'C:\Installs\infoSpark TrainTracks 2020.08.25' -Force}
                        $Counter = 0
                        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                            $DriverList = Get-ChildItem "C:\INSTALLS\infoSpark TrainTracks 2020.08.25\Drivers" -Recurse -Filter "*.inf"
                            FOREACH ($Driver IN $DriverList) {
                                $Counter = $Counter + 1
                                $Percent = [math]::Round($($Counter / $DriverList.Count), 4) * 100
                                Write-Progress -Activity "Installing Drivers" -Status "$Percent% Complete" -PercentComplete $Percent
                                Start-Process -FilePath 'C:\Windows\system32\PNPUtil.exe' -ArgumentList "/add-driver $Driver.FullName /install" -Wait
                            }
                        }
                    }
                } ELSE {
                    Write-Host -Object $("$ComputerName - Hardware Not Present")
                    Add-Member -InputObject $Output -MemberType 'NoteProperty' -Name $ComputerName -Value 'Hardware Not Present'
                }
                #>


                #Eizo RadiCS
                Invoke-Command -ScriptBlock {Start-Process -FilePath $BatchFilePath -ArgumentList "BATCH 1 $ComputerName" -Wait}
                Write-Host -Object $("$ComputerName - Complete")
                Add-Member -InputObject $Output -MemberType 'NoteProperty' -Name $ComputerName -Value 'Complete'
                #




            } ELSE {
                Write-Host -Object $("$ComputerName - Not trusted by domain")
                Add-Member -InputObject $Output -MemberType 'NoteProperty' -Name $ComputerName -Value 'Not trusted by domain'
            }
        } ELSE {
            Write-Host -Object $("$ComputerName - Could Not Ping")
            Add-Member -InputObject $Output -MemberType 'NoteProperty' -Name $ComputerName -Value 'Could Not Ping'
        }
    }



    #Write the CSV file at teh very end.
     $Output | Export-Csv -Path 'C:\INSTALLS\MassDriver.csv' -Encoding ASCII -NoTypeInformation -Append

     $Output | Get-Member -MemberType 'NoteProperty' | Select-Object -ExpandProperty 'Name' | Format-List
     $Output | Get-Member -MemberType 'NoteProperty' | Format-List
     $Output | Get-Member -MemberType 'NoteProperty' | Select-Object -Property 'Name', 'Definition' | Format-List -View 
     $Output | Get-Member -MemberType 'NoteProperty' | Format-List -Property 'Name', 'Definition'
     $Output | Get-Member -MemberType 'NoteProperty' | Select-Object -Property 'Name', 'Definition' | Format-Table | Export-Csv -Path 'C:\INSTALLS\MassDriver.csv' -Encoding ASCII -NoTypeInformation -Append
    


    


}


$FreedTest = {
#trying to remove drivers

Remove-WindowsDriver -Path 'C:' -Driver 'oem33.inf'

pnputil -f -d oem33.inf

pnputil -e

}