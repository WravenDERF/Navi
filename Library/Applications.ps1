FUNCTION Install-QAWebEnterprise {

    #This is an attempt to Install software.

    PARAM(
        [string]$FQDN,
        [string]$AppVendor = 'Barco',
        [string]$AppName = 'QAWeb Enterprise',
        [string]$AppVersion = '2.12.1',
        [string]$AppSource = 'C:\Installs\qaweb-agent-installer.exe',
        [string]$PSEXEC = 'C:\Programs\Validation\Sysinternals\PsExec.exe'
    )

    IF ((Test-Path -Path "\\$FQDN\c$\Installs") -eq $False) {
        New-Item -Path "\\$FQDN\c$\Installs" -ItemType Directory | Out-Null
    }

    IF ((Test-Path -Path "\\$FQDN\c$\Logs") -eq $False) {
        New-Item -Path "\\$FQDN\c$\Logs" -ItemType Directory | Out-Null
    }
    
    Copy-Item -Path $AppSource -Destination "\\$FQDN\c$\Installs" -Force

     $Contents = @(
        'SET DIRECTORY=C:\INSTALLS',
        '%DIRECTORY%\qaweb-agent-installer.exe /S /ORG 11ea7385-3e05-bb3a-96ec-cb42c6e241f2 /REGKEY 11ea7385-3e09-3af8-88be-57ec9b5d473b'
    ) | Out-File -FilePath "\\$FQDN\c$\Installs\Install-QAWebEnterprise.bat" -Encoding ascii

    Start-Process -FilePath $PSEXEC -ArgumentList "\\$FQDN -accepteula -e -h ""C:\Installs\Install-QAWebEnterprise.bat"""

}

FUNCTION Uninstall-QAWebEnterprise {

    #This is an attempt to Install software.

    PARAM(
        [string]$FQDN,
        [string]$AppVendor = 'Barco',
        [string]$AppName = 'QAWeb Enterprise',
        [string]$AppVersion = '2.12.1',
        [string]$AppSource = 'C:\Installs\qaweb-agent-installer.exe',
        [string]$PSEXEC = 'C:\Programs\Validation\Sysinternals\PsExec.exe'
    )

    IF ((Test-Path -Path "\\$FQDN\c$\Installs") -eq $False) {
        New-Item -Path "\\$FQDN\c$\Installs" -ItemType Directory | Out-Null
    }

    IF ((Test-Path -Path "\\$FQDN\c$\Logs") -eq $False) {
        New-Item -Path "\\$FQDN\c$\Logs" -ItemType Directory | Out-Null
    }

     $Contents = @(
	      'IF EXIST "C:\Program Files\Barco\QAWeb\Uninstall.exe" ["C:\Program Files\Barco\QAWeb\Uninstall.exe" /S]'
    ) | Out-File -FilePath "\\$FQDN\c$\Installs\Uninstall-QAWebEnterprise.bat" -Encoding ascii

    Start-Process -FilePath $PSEXEC -ArgumentList "\\$FQDN -accepteula -e -h ""C:\Installs\Uninstall-QAWebEnterprise.bat"""

}
