$Tools = [PSCustomObject]@{
    'Vendor' = 'infoSpark'
    'Name' = 'Tools'
    'Version' = '2022.04.14'
    'Notes1' = 'None at this time.'
    'ComputerList' = New-Object System.Collections.ArrayList
    'WorkstationInfoExport' = 'H:\WorkstationInfo.csv'
}


Add-Member -InputObject $Tools -MemberType 'ScriptMethod' -Name 'GetWorkstationInfo' -Force -Value {


    #A scriptblock that is run to collect Windows data.
    $GetWMI = {
        #Receive parameters
        PARAM (
            [Parameter(Mandatory)][string]$ComputerName
        )


        #Write Output for tracking.
        Write-Host -Object "$($Tools.ComputerList.Count) $($ComputerName)" -ForegroundColor Cyan
        #Create a blank object.
        $Computer = New-Object System.Object
        #This will ping the machine.
        IF (Test-Connection -Computer $ComputerName -Count 1 -Quiet) {
            #This tries to connect to the WMI.
            TRY {
                #Access the libraries
                $Win32_BIOS = Get-WmiObject Win32_BIOS -ComputerName $ComputerName
                $Win32_LogicalDisk = Get-WmiObject Win32_LogicalDisk -Filter "DriveType = '3'" -ComputerName $ComputerName
		        $Win32_ComputerSystem = Get-WmiObject Win32_ComputerSystem -ComputerName $ComputerName
		        $Win32_OperatingSystem = Get-WmiObject Win32_OperatingSystem -ComputerName $ComputerName
		        $Win32_NetworkAdapterConfiguration = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $ComputerName
		        $Win32_VideoController = Get-WmiObject Win32_VideoController  -ComputerName $ComputerName
                $Win32_DesktopMonitor = Get-WmiObject Win32_DesktopMonitor -ComputerName $ComputerName
                $Win32_WinSAT = Get-WmiObject -Class Win32_WinSAT -ComputerName $ComputerName


                #Add the properties.
                Add-Member -InputObject $Computer -MemberType 'NoteProperty' -Name 'General_Hostname' -Value $($Win32_ComputerSystem.Name)
                Add-Member -InputObject $Computer -MemberType 'NoteProperty' -Name 'General_Status' -Value 'Active'
                Add-Member -InputObject $Computer -MemberType 'NoteProperty' -Name 'General_DateQueried' -Value $(Get-Date -Format "MM-dd-yyyy")


                #Process the user into displayable format.
                IF ([string]::IsNullOrEmpty($($Win32_ComputerSystem.UserName))) {
                    Add-Member -InputObject $Computer -MemberType 'NoteProperty' -Name 'General_User' -Value 'Logged Out'
                } ELSE {
                    Add-Member -InputObject $Computer -MemberType 'NoteProperty' -Name 'General_User' -Value $($Win32_ComputerSystem.UserName)
                }


                #Add the properties.
                Add-Member -InputObject $Computer -MemberType 'NoteProperty' -Name 'Hardware_Model' -Value $($Win32_ComputerSystem.Model)
                Add-Member -InputObject $Computer -MemberType 'NoteProperty' -Name 'Hardware_BIOS' -Value $($Win32_BIOS.SMBIOSBIOSVersion)
                Add-Member -InputObject $Computer -MemberType 'NoteProperty' -Name 'Hardware_RAM' -Value $([math]::round($Win32_ComputerSystem.TotalPhysicalMemory/1024/1024/1024, 0))


                #Process the drive space into a usable format.
                $Index = 0
                FOREACH ($Drive in $Win32_LogicalDisk) {
                    Add-Member -InputObject $Computer -MemberType 'NoteProperty' -Name "Hardware_Disk$($Index)_Freespace" -Value $([math]::round($Drive.FreeSpace/1024/1024/1024, 0))
                    $Index = $Index + 1
		        }
                

                #Process the Video Adaptors into a usable format.
                $Index = 0
		        FOREACH ($GPU in $Win32_VideoController) {
                    Add-Member -InputObject $Computer -MemberType 'NoteProperty' -Name "Hardware_VideoAdaptor$Index" -Value "$($GPU.Description)"
                    $Index = $Index + 1
		        }


                #Process the Monitors into a usable format.
                $Index = 0
		        FOREACH ($Monitor in $Win32_DesktopMonitor) {
                    Add-Member -InputObject $Computer -MemberType 'NoteProperty' -Name "Hardware_Monitor$Index" -Value "$($Monitor.Name)"
                    $Index = $Index + 1
		        }


                #Add the properties.
                Add-Member -InputObject $Computer -MemberType 'NoteProperty' -Name 'OS_Name' -Value $($Win32_OperatingSystem.Caption)
                Add-Member -InputObject $Computer -MemberType 'NoteProperty' -Name 'OS_Build' -Value $($Win32_OperatingSystem.Version)
                Add-Member -InputObject $Computer -MemberType 'NoteProperty' -Name 'OS_Boot' -Value $([System.Management.ManagementDateTimeConverter]::ToDateTime($Win32_OperatingSystem.LastBootUpTime))
                Add-Member -InputObject $Computer -MemberType 'NoteProperty' -Name 'OS_Imaged' -Value $([System.Management.ManagementDateTimeConverter]::ToDateTime($Win32_OperatingSystem.InstallDate))
                Add-Member -InputObject $Computer -MemberType 'NoteProperty' -Name 'Net_IP' -Value $($Win32_NetworkAdapterConfiguration | WHERE {$_.IPEnabled -match 'True'}).IPAddress[0]
                Add-Member -InputObject $Computer -MemberType 'NoteProperty' -Name 'Net_MAC' -Value $($Win32_NetworkAdapterConfiguration | WHERE {$_.IPEnabled -match 'True'}).MACAddress


                #Speed Test                    
                TRY {
                    $Time = $(Measure-Command { Copy-Item -Path $Navi.FredTools -Destination "\\$TargetPC\c$\Installs" }).TotalSeconds
                    $Size = $(Get-ChildItem -File $Navi.FredTools).length / 1024 / 1024
                    Add-Member -InputObject $Computer -MemberType 'NoteProperty' -Name 'Net_Speed' -Value $($Size / $Time)
                } CATCH {
                    Add-Member -InputObject $Computer -MemberType 'NoteProperty' -Name 'Net_Speed' -Value $('Failed')
                }


                Add-Member -InputObject $Computer -MemberType 'NoteProperty' -Name 'WinSAT_Overall' -Value $($Win32_WinSAT.WinSPRLevel)
                Add-Member -InputObject $Computer -MemberType 'NoteProperty' -Name 'WinSAT_CPU' -Value $($Win32_WinSAT.CPUScore)
                Add-Member -InputObject $Computer -MemberType 'NoteProperty' -Name 'WinSAT_RAM' -Value $($Win32_WinSAT.MemoryScore)
                Add-Member -InputObject $Computer -MemberType 'NoteProperty' -Name 'WinSAT_Disk' -Value $($Win32_WinSAT.DiskScore)
                Add-Member -InputObject $Computer -MemberType 'NoteProperty' -Name 'WinSAT_Graphics' -Value $($Win32_WinSAT.GraphicsScore)
                Add-Member -InputObject $Computer -MemberType 'NoteProperty' -Name 'WinSAT_D3D' -Value $($Win32_WinSAT.D3DScore)
            } CATCH {


                #Pulling from WMI didn't work
                Write-Host -Object $('Could not connect!') -ForegroundColor Red
                Add-Member -InputObject $Computer -MemberType 'NoteProperty' -Name 'General_Hostname' -Value $($TargetPC)
                Add-Member -InputObject $Computer -MemberType 'NoteProperty' -Name 'General_Status' -Value $('Inaccessible')
	        }
        } ELSE {


            #Could not PING the machine.
            Write-Host -Object $('Could not ping!') -ForegroundColor Red
            Add-Member -InputObject $Computer -MemberType 'NoteProperty' -Name 'General_Hostname' -Value $($TargetPC)
            Add-Member -InputObject $Computer -MemberType 'NoteProperty' -Name 'General_Status' -Value $('Inactive')
        }

        
        #Add the computer object to the collection and display the computer object.
        $Tools.ComputerList.Add($Computer) | Out-Null
        Write-Host -Object $($Computer | Sort-Object -Property 'Name' | Format-List | Out-String)
    }


    #Clear the screen and display the menu. Write the main titlebar.
    Clear-Host
    Write-Host -Object $Navi.ReturnMenuBreak() -ForegroundColor Cyan
    Write-Host -Object $Navi.ReturnFormattedTitle('Navi - Tools - Query Clients') -ForegroundColor Cyan
    Write-Host -Object $Navi.ReturnMenuBreak() -ForegroundColor Cyan
    $TargetInput = Read-Host "Enter the PC or List to target"


    #Test to see if the input is a list or a single computer.
    IF (Test-Path -Path $TargetInput) {
        

        #Iterate through list and hit each name.
        IF ($Navi.Debug) {Write-Host -Object "TargetInput:$TargetInput - This is a list." -ForegroundColor Magenta}
        IF ($Navi.Debug) {PAUSE}
        $FileContents = Get-Content -Path $TargetInput
	    FOREACH ($TargetPC in $FileContents) {
            Invoke-Command -ScriptBlock $GetWMI -ArgumentList $TargetPC
        }
    } ELSE {


        #Just query the one name.
        IF ($Navi.Debug) {Write-Host -Object "TargetInput:$TargetInput - This is a single computer." -ForegroundColor Magenta}
        IF ($Navi.Debug) {PAUSE}
        Invoke-Command -ScriptBlock $GetWMI -ArgumentList $TargetInput
    }


    #Create CSV List
    $Tools.ComputerList | Export-Csv -Path $($Tools.WorkstationInfoExport) -Encoding ASCII -NoTypeInformation -Append
    Write-Host -Object "A list has been generated: $($Tools.WorkstationInfoExport)" -ForegroundColor Green
    PAUSE
}


Add-Member -InputObject $Tools -MemberType 'ScriptMethod' -Name 'SendMsgToTarget' -Force -Value {


    $SendMsg = {
        PARAM (
            [Parameter(Mandatory)][string]$TargetPC,
            [Parameter(Mandatory)][string]$Message
        )

        IF ($Debug) {Write-Host -Object "TargetPC:$TargetPC" -ForegroundColor Magenta}
        IF ($Debug) {Write-Host -Object "Message:$Message" -ForegroundColor Magenta}
        IF ($Debug) {PAUSE}

        [string]$Signature = '-Sent by Fred Linthicum from IS Imaging Team @ 941-681-0669'
	    IF (Test-Connection -Computer $TargetPC -Count 1 -Quiet) {
		    TRY {
				Invoke-WmiMethod -Path Win32_Process -Name Create -ArgumentList "msg /TIME:28800 * $Message $Signature" -ComputerName $TargetPC
			} CATCH {
				Write-Host "Could not send message." -ForegroundColor Red
			}
		} ELSE {
			Write-Host "No Ping!" -ForegroundColor Red
		}
    }


    #Clear the screen and display the menu. Write the main titlebar.
    Clear-Host
    Write-Host -Object $Navi.ReturnMenuBreak() -ForegroundColor Cyan
    Write-Host -Object $Navi.ReturnFormattedTitle('Navi - Tools - Send Message') -ForegroundColor Cyan
    Write-Host -Object $Navi.ReturnMenuBreak() -ForegroundColor Cyan
    $Messageg = Read-Host 'What is your Message:'
    $TargetInput = Read-Host 'Enter the PC or List to target:'


    IF (Test-Path -Path $TargetInput) {
        IF ($Debug) {Write-Host -Object "TargetInput:$TargetInput - This is a list." -ForegroundColor Magenta}
        IF ($Debug) {PAUSE}

        #Iterate through list and hit each name.
        $FileContents = Get-Content -Path $TargetInput
	    FOREACH ($TargetPC in $FileContents) {
            Invoke-Command -ScriptBlock $SendMsg -ArgumentList $TargetPC, $Message
        }
    } ELSE {
        IF ($Debug) {Write-Host -Object "TargetInput:$TargetInput - This is a single computer." -ForegroundColor Magenta}
        IF ($Debug) {PAUSE}
        Invoke-Command -ScriptBlock $SendMsg -ArgumentList $TargetInput, $Message
    }
}


Add-Member -InputObject $Tools -MemberType 'ScriptMethod' -Name 'GetAddRemovePrograms' -Force -Value {


    #Initialize Function Assets
    $GetInstalledApps = {


        PARAM (
            [Parameter(Mandatory)][string]$TargetPC
        )


	    IF (Test-Connection -Computer $TargetPC -Count 1 -Quiet) {
		    TRY {
                Write-Host -Object $Navi.ReturnFormattedTitle("$TargetPC Programs") -ForegroundColor Cyan
                $InstalledPrograms = Get-WmiObject -Class Win32_Product -ComputerName $TargetPC | sort Name, Version, IdentifyingNumber | Format-Table -AutoSize -Property Name, Version, IdentifyingNumber -Wrap
                Write-Host -Object $($InstalledPrograms | Format-List | Out-String)
                #Write-Host -Object $($Computer | Sort-Object -Property 'Name' | Format-List | Out-String)
                
			} CATCH {
				Write-Host "Could not retreive list." -ForegroundColor Red
			}
		} ELSE {
			Write-Host "No Ping!" -ForegroundColor Red
		}
    }


    #Clear the screen and display the menu.
    Clear-Host
    Write-Host -Object $Navi.ReturnMenuBreak() -ForegroundColor Cyan
    Write-Host -Object $Navi.ReturnFormattedTitle('Navi - Tools - Add/Remove Programs') -ForegroundColor Cyan
    Write-Host -Object $Navi.ReturnMenuBreak() -ForegroundColor Cyan
    $TargetInput = Read-Host ''Enter the PC or List to target''


    #Test to see if the input is a list or a single computer.
    IF (Test-Path -Path $TargetInput) {
        
        IF ($Debug) {Write-Host -Object "TargetInput:$TargetInput - This is a list." -ForegroundColor Magenta}
        IF ($Debug) {PAUSE}

        #Iterate through list and hit each name.
        $FileContents = Get-Content -Path $TargetInput
	    FOREACH ($TargetPC in $FileContents) {
            Invoke-Command -ScriptBlock $GetInstalledApps -ArgumentList $TargetPC
        }
    } ELSE {
        IF ($Debug) {Write-Host -Object "TargetInput:$TargetInput - This is a single computer." -ForegroundColor Magenta}
        IF ($Debug) {PAUSE}
        Invoke-Command -ScriptBlock $GetInstalledApps -ArgumentList $TargetInput
    }
    PAUSE
}


Add-Member -InputObject $Tools -MemberType 'ScriptMethod' -Name 'GetListFromAD' -Force -Value {


    PARAM (
        [Parameter()][string]$ListType
    )


    SWITCH ($ListType) {


        'Radiant' {


            #Query AD for all computers that end in R
            $ListAD = Get-ADComputer -Filter 'Name -like "*R" -and ObjectClass -like "computer"' -Properties LastLogonDate
    

            #Create CSV List
            $ListAD | Export-Csv -Path "H:\Radiant.csv" -Encoding ascii -NoTypeInformation
            Write-Host -Object "A list has been generated: H:\Radiant.csv" -ForegroundColor Green
            PAUSE
        }


        'Cupid' {


            #Query AD for all computers that end in Z
            $ListAD = Get-ADComputer -Filter 'Name -like "*Z" -and ObjectClass -like "computer"' -Properties LastLogonDate
    
            #Create CSV List
            $ListAD | Export-Csv -Path "H:\Cupid.csv" -Encoding ascii -NoTypeInformation
            Write-Host -Object "A list has been generated: H:\Cupid.csv" -ForegroundColor Green
            PAUSE
        }
    }
}


#Display the main menu.
Invoke-Command -ScriptBlock {
    DO {
        #Write the main titlebar.
        Clear-Host
        Write-Host -Object $Navi.ReturnMenuBreak() -ForegroundColor Cyan
        Write-Host -Object $Navi.ReturnFormattedTitle('Navi - Tools') -ForegroundColor Cyan
        Write-Host -Object $Navi.ReturnMenuBreak() -ForegroundColor Cyan
        Write-Host -Object "  0 : Return"
        Write-Host -Object $Navi.ReturnMenuBreak() -ForegroundColor Cyan
        Write-Host -Object "  1 : Query Clients"
        Write-Host -Object "  2 : Send Message to PCs"
        Write-Host -Object "  3 : Get Installed Programs"
        Write-Host -Object "  4 : Create List of Radiant Workstations from AD"
        Write-Host -Object "  5 : Create List of Cupid Workstations from AD"
        Write-Host -Object $Navi.ReturnMenuBreak() -ForegroundColor Cyan

        #Allows for entry of menu choice.
        $SelectionInput = Read-Host "Please make a selection"
        SWITCH ($SelectionInput) {
            '1' {$Tools.GetWorkstationInfo()}
            '2' {$Tools.SendMsgToTarget()}
            '3' {$Tools.GetAddRemovePrograms()}
            '4' {$Tools.GetListFromAD('Radiant')}
            '5' {$Tools.GetListFromAD('Cupid')}
            DEFAULT {RETURN}
        }
    } UNTIL ($SelectionInput -eq '0')
}
