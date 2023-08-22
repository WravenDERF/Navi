FUNCTION Convert-IPtoFQDN {

    PARAM(
        [string]$IP
    )

    RETURN [System.Net.Dns]::GetHostByAddress($IP).Hostname

}

FUNCTION Get-ConnectionPortCount {

    PARAM(
        [string]$FQDN,
        [string]$IP,
        [int]$Port
    )

    #Gets the Web Connections
    $TotalCount = '0'
    $Connections = Get-NetTCPConnection -LocalAddress $IP -LocalPort '443' -CimSession $FQDN -ErrorAction 'Ignore'
    $TotalCount = @($Connections |Group {$_.RemoteAddress}).Count
    RETURN $TotalCount

}

FUNCTION Get-ProcessorUtilizationPercentage {

    PARAM(
        [string]$FQDN
    )

    #Gets the Processor Utilization 
    RETURN "$([math]::round((Get-Counter -Computer $FQDN -Counter '\Processor(_Total)\% Processor Time').CounterSamples[0].CookedValue, 2))"

}

FUNCTION Get-RamUtilizationPercentage {

    PARAM(
        [string]$FQDN
    )

    #Gets the RAM Utilization
    $Win32_ComputerSystem = Get-WmiObject 'Win32_ComputerSystem' -ComputerName $FQDN
    $TotalMemory = $([math]::round($Win32_ComputerSystem.TotalPhysicalMemory/1GB, 0))
    $AvailibleMemory = $([math]::round((Get-Counter -Computer $FQDN -Counter '\Memory\Available MBytes').CounterSamples[0].CookedValue / 1KB, 0))
    $UsedMemory = $TotalMemory - $AvailibleMemory
    $UsedMemoryPercentage = $([math]::round($(100 * $UsedMemory / $TotalMemory), 2))
    RETURN "$UsedMemory/$TotalMemory GB ($UsedMemoryPercentage%)"

}

FUNCTION Resolve-WebLink {

    PARAM ([string]$WebAddress)

    $HTTP_Request = [System.Net.WebRequest]::Create($WebAddress)
    $HTTP_Response = $HTTP_Request.GetResponse()
    RETURN $HTTP_Response.StatusCode

}

FUNCTION Test-Ping {

    PARAM(
        [string]$IP
    )

    RETURN Test-Connection -Computer $IP -Count 1 -Quiet

}

FUNCTION Test-WebLink {

    PARAM(
        [string]$WebAddress,
        [int]$WorkerCount = 10,
        [int]$IterationCount = 20
    )
    
    FOR ($Worker = 1; $Worker -le $WorkerCount; $Worker = $Worker + 1) {
        FOR ($Iteration = 1; $Iteration -le $IterationCount; $Iteration = $Iteration + 1) {
            $Response = cURL $WebAddress
            $Status = $Response.StatusCode
            Write-Host -Object $("Worker $Worker : Iteration $Iteration : $Status")
            Start-Sleep -Milliseconds 5
        }
    }

}

FUNCTION Get-DCMTK {

    #Download and expand DCMTK.

    PARAM(
        [string]$WebAddress = 'https://dicom.offis.de/download/dcmtk/dcmtk366/bin/dcmtk-3.6.6-win64-dynamic.zip',
        [string]$OutFile = 'C:\Installs\DCMTK.zip',
        [string]$ExtractionFolder = 'C:\Programs\ModalityValidation'
    )
    
    Invoke-RestMethod -Uri $WebAddress -OutFile $OutFile
    Expand-Archive -LiteralPath $OutFile -DestinationPath $ExtractionFolder
    $CECHO = 'C:\Installs\dcmtk-3.6.6-win64-dynamic\bin\echoscu.exe -v'
}

Clear-Host
Write-Host -Object 'Hello World!'
