Install-Module UMN-Google







# Set security protocol to TLS 1.2 to avoid TLS errors
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Google API Authozation
$scope = "https://www.googleapis.com/auth/spreadsheets https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/drive.file"

$certPath = 'C:\Programs\NaviTest\zombiekiller-20181018-2a7d6a20b529.p12'


$iss = 'navi-483@zombiekiller-20181018.iam.gserviceaccount.com'
$certPswd = 'notasecret'

try {
    Write-Host -Object $('This worked!') -ForegroundColor 'Green'
    $accessToken = Get-GOAuthTokenService -scope $scope -certPath $certPath -certPswd $certPswd -iss $iss
} catch {
    Write-Host -Object $('This did not work!') -ForegroundColor 'Red'
    $err = $_.Exception
    $err | Select-Object -Property *
    "Response: "
    $err.Response
}









# Create new spreadsheet
$Title = 'Patching Spreadsheet'
$SpreadsheetID = (New-GSheetSpreadSheet -accessToken $accessToken -title $Title).spreadsheetId
$SpreadsheetID


Write-Host -Object $("https://docs.google.com/spreadsheets/d/$SpreadsheetID")


# Create new sheet
$Sheet = 'Computers'
Add-GSheetSheet -accessToken $accessToken -sheetName $Sheet -spreadSheetID $SpreadsheetID


Set-GFilePermissions -accessToken $accessToken -fileID $SpreadsheetID -role writer -type user -emailAddress 'fred.linthicum@gmail.com'


$accessToken
