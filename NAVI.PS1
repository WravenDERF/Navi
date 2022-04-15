$Navi = [PSCustomObject]@{
    'Vendor' = 'infoSpark'
    'Name' = 'Navi'
    'Version' = '2022.04.14'
    'Debug' = $true
    'MenuArray' = New-Object System.Collections.ArrayList
    'WindowWidth' = 150
    'WindowHeight' = 50
}


#Resize the window.
Invoke-Command -ScriptBlock {
    IF ($Navi.Debug) {Write-Host -Object $('Current Window Size...') -ForegroundColor Magenta}
    IF ($Navi.Debug) {$host.UI.RawUI.WindowSize.width}
    IF ($Navi.Debug) {$host.UI.RawUI.WindowSize.height}
    IF ($Navi.Debug) {PAUSE}
    
    IF ($Navi.Debug) {Write-Host -Object $('Resizing Window...') -ForegroundColor Magenta}
    $host.UI.RawUI.BufferSize = New-Object System.Management.Automation.Host.size($Navi.WindowWidth, 5000)
    $host.UI.RawUI.WindowSize = New-Object System.Management.Automation.Host.size($Navi.WindowWidth, $Navi.WindowHeight)
    IF ($Navi.Debug) {$host.UI.RawUI.WindowSize.width}
    IF ($Navi.Debug) {$host.UI.RawUI.WindowSize.height}
    IF ($Navi.Debug) {PAUSE}
}


#General Housekeeping items.
Invoke-Command -ScriptBlock {
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy 'Unrestricted' -Force
    #IF ($Navi.Debug) {Write-Host -Object $Navi.infoSparkRoot -ForegroundColor Magenta}
    #IF ($Navi.Debug) {Write-Host -Object $PSScriptRoot -ForegroundColor Magenta}
    #IF ($Navi.Debug) {Write-Host -Object $($Navi.FredTools) -ForegroundColor Magenta}
    #IF ($Navi.Debug) {PAUSE}
}


#Load Modules
Invoke-Command -ScriptBlock {
    IF ($Navi.Debug) {Write-Host -Object $('Starting the loading of other modules...') -ForegroundColor Cyan}
    Import-Module SQLPS
	Invoke-Expression $(Invoke-WebRequest 'https://raw.githubusercontent.com/WravenDERF/Navi/main/NAVI.APPLICATIONS.PS1').Content
    
	
    <#Load the XML
    IF (Test-Path -Path "$($Navi.infoSparkRoot)\XML\INFOSPARK.XML") {
        [xml]$RootXML = Get-Content -Path "$($Navi.infoSparkRoot)\XML\INFOSPARK.XML"
        IF ($Navi.Debug) {Write-Host -Object 'Loaded XML...' -ForegroundColor Green}
    } ELSE {
        Write-Host -Object "Could not fild XML File." -ForegroundColor Red
        Invoke-Command -ScriptBlock {PAUSE}
    }


	#Import tools module
	IF (Test-Path "$PSScriptRoot\INFOSPARK.TOOLS.PS1") {
			Import-Module -Name "$PSScriptRoot\INFOSPARK.TOOLS.PS1"
			IF ($Navi.Debug) {Write-Host -Object 'Loaded Tools...' -ForegroundColor Green}
	} ELSE {
			Write-Host -Object "Could not load module INFOSPARK.TOOLS.PS1" -ForegroundColor Red
			Invoke-Command -ScriptBlock {PAUSE}
	}


	#Import Application module
	IF (Test-Path "$PSScriptRoot\INFOSPARK.APPLICATIONS.PS1") {
		Import-Module -Name "$PSScriptRoot\INFOSPARK.APPLICATIONS.PS1"
		IF ($Navi.Debug) {Write-Host -Object 'Loaded Applications...' -ForegroundColor Green}
	} ELSE {
		Write-Host -Object "Could not load module INFOSPARK.APPLICATIONS.PS1" -ForegroundColor Red
		Invoke-Command -ScriptBlock {PAUSE}
	}


	#Import Acuo module
	IF (Test-Path "$PSScriptRoot\INFOSPARK.ACUO.PS1") {
		Import-Module -Name "$PSScriptRoot\INFOSPARK.ACUO.PS1"
		IF ($Navi.Debug) {Write-Host -Object 'Loaded Acuo...' -ForegroundColor Green}
	} ELSE {
		Write-Host -Object "Could not load module INFOSPARK.ACUO.PS1" -ForegroundColor Red
		Invoke-Command -ScriptBlock {PAUSE}
	}


	#Import SyngoDynamics module
	IF (Test-Path "$PSScriptRoot\INFOSPARK.SYNGODYNAMICS.PS1") {
		Import-Module -Name "$PSScriptRoot\INFOSPARK.SYNGODYNAMICS.PS1"
		IF ($Navi.Debug) {Write-Host -Object 'Loaded SyngoDynamics...' -ForegroundColor Green}
	} ELSE {
		Write-Host -Object "Could not load module INFOSPARK.SYNGODYNAMICS.PS1" -ForegroundColor Red
		Invoke-Command -ScriptBlock {PAUSE}
	}


	<#Import maintenance module
	IF (Test-Path "$PSScriptRoot\INFOSPARK.MAINTENANCE.PS1") {
		Import-Module -Name "$PSScriptRoot\INFOSPARK.MAINTENANCE.PS1"
		IF ($Navi.Debug) {Write-Host -Object 'Loaded Maintenance...' -ForegroundColor Green}
	} ELSE {
		Write-Host -Object "Could not load module INFOSPARK.MAINTENANCE.PS1" -ForegroundColor Red
		Invoke-Command -ScriptBlock {PAUSE}
	}


	<#Import maintenance module
	IF (Test-Path "$PSScriptRoot\INFOSPARK.APPLICATIONS.FUJI-SYNAPSE.PS1") {
		Import-Module -Name "$PSScriptRoot\INFOSPARK.APPLICATIONS.FUJI-SYNAPSE.PS1"
		IF ($Navi.Debug) {Write-Host -Object 'Loaded Maintenance...' -ForegroundColor Green}
	} ELSE {
		Write-Host -Object "Could not load module INFOSPARK.APPLICATIONS.FUJI-SYNAPSE.PS1" -ForegroundColor Red
		Invoke-Command -ScriptBlock {PAUSE}
	}
	#>
}


Add-Member -InputObject $Navi -MemberType 'ScriptMethod' -Name 'ReturnFormattedTitle' -Force -Value {
	PARAM (
        [Parameter()][string]$Text
    )
	
	#Return a formatted title.
    [string]$Title = "=" + [char]32 + $Text  + [char]32 + "=" * $Navi.WindowWidth
    RETURN $($Title.substring(0, [System.Math]::Min($Navi.WindowWidth, $Title.Length)))
}


Add-Member -InputObject $Navi -MemberType 'ScriptMethod' -Name 'ReturnMenuBreak' -Force -Value {
    #Return formatted menu breaks.
    [string]$Break = "=" * $Navi.WindowWidth
    RETURN $Break
}

#Display the main menu.
DO {
    #Write the main titlebar.
    Clear-Host
    Write-Host -Object $Navi.ReturnMenuBreak() -ForegroundColor Cyan
    Write-Host -Object $Navi.ReturnFormattedTitle('Navi - Main') -ForegroundColor Cyan
    Write-Host -Object $Navi.ReturnMenuBreak() -ForegroundColor Cyan
    Write-Host -Object "  0 : Quit"
    Write-Host -Object $Navi.ReturnMenuBreak() -ForegroundColor Cyan
    Write-Host -Object "  1 : Tools"
    Write-Host -Object "  2 : Applications"
    Write-Host -Object "  3 : Builds"
    Write-Host -Object "  4 : Maintenance"
    Write-Host -Object $Navi.ReturnMenuBreak() -ForegroundColor Cyan
    Write-Host -Object "  5 : Acuo"
    Write-Host -Object "  6 : Syngo Dynamics"
    Write-Host -Object $Navi.ReturnMenuBreak() -ForegroundColor Cyan
    $SelectionInput = Read-Host "Please make a selection"


    #Perform task based off of the selection.
    SWITCH ($SelectionInput) {
        '0' {RETURN}
        '1' {$Tools.DisplayMainMenu()}
        '2' {$Applications.DisplayMainMenu()}
        '3' {$Builds.DisplayMainMenu()}
        '4' {$Maintenance.DisplayMainMenu()}
        '5' {$Acuo.DisplayMainMenu()}
        '6' {$SyngoDynamics.DisplayMainMenu()}
        DEFAULT {. .\POWERSHELL\INFOSPARK.NAVI.PS1}
    }
} UNTIL ($SelectionInput -eq '0')
