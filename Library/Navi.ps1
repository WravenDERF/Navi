FUNCTION Convert-IPtoFQDN {

    PARAM(
        [string]$IP
    )

    RETURN [System.Net.Dns]::GetHostByAddress($IP).Hostname

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

Function Resolve-WebLink {

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

Function Test-WebLink {

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

    #$WebAddress = 'www.google.com'
    #$HTTP_Request = [System.Net.WebRequest]::Create($WebAddress)
    #$HTTP_Response = $HTTP_Request.GetResponse()
    #$HTTP_Response

    #$WebAddress = 'https://iscv-pre.stanfordmed.org/iscv'
    #$Response = cURL $WebAddress
    #$Response

}


Clear-Host
Write-Host -Object 'Hello World!'
