#$Response = Invoke-WebRequest -URI 'https://www.bing.com/search?q=how+many+feet+in+a+mile'
#$Response.StatusCode

Clear-Host

Get-Command -Name '*-Job'

$List = New-Object System.Collections.ArrayList

$CheckWebsites = {
    PARAM ($URL)

    Write-Host -Object $URL -ForegroundColor 'Cyan'

    Invoke-WebRequest -URI $URL
    
}

$List.Add($(Start-Job -Scriptblock $CheckWebsites -ArgumentList @('https://www.bing.com') | Wait-Job| Receive-Job).StatusCode) | Out-Null
Invoke-Command -Scriptblock $CheckWebsites -ArgumentList 'https://www.evernote.com'
Invoke-Command -Scriptblock $CheckWebsites -ArgumentList 'https://www.google.com'
Invoke-Command -Scriptblock $CheckWebsites -ArgumentList 'https://www.amazon.com'
Invoke-Command -Scriptblock $CheckWebsites -ArgumentList 'https://www.apple.com'
