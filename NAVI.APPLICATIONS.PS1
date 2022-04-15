$Applications = [PSCustomObject]@{
    'Vendor' = 'infoSpark'
    'Name' = 'Applications'
    'Version' = '2022.04.14'
    'Debug' = $true
}


Add-Member -InputObject $Applications -MemberType 'ScriptMethod' -Name 'DisplayMaunMenu' -Force -Value {
	#Display the main menu.
	DO {
			#Write the main titlebar.
			Clear-Host
			Write-Host -Object $Navi.ReturnMenuBreak() -ForegroundColor Cyan
			Write-Host -Object $Navi.ReturnFormattedTitle('Navi - Applications') -ForegroundColor Cyan
			Write-Host -Object $Navi.ReturnMenuBreak() -ForegroundColor Cyan
			Write-Host -Object "  0 : Quit"
			Write-Host -Object $Navi.ReturnMenuBreak() -ForegroundColor Cyan
			Write-Host -Object "  1 : Fuji Synapse 5.7.220(Piedmont)"
			Write-Host -Object $Navi.ReturnMenuBreak() -ForegroundColor Cyan
			$SelectionInput = Read-Host "Please make a selection"


			#Perform task based off of the selection.
			SWITCH ($SelectionInput) {
					'0' {RETURN}
					'1' {Invoke-Expression $(Invoke-WebRequest 'https://raw.githubusercontent.com/WravenDERF/Piedmont/main/Applications/FUJISYNAPSE57220.PS1').Content}
					DEFAULT {. .\POWERSHELL\INFOSPARK.NAVI.PS1}
			}
	} UNTIL ($SelectionInput -eq '0')
}
