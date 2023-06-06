Function Resolve-WebLink {

    PARAM ([string]$WebAddress)

    $HTTP_Request = [System.Net.WebRequest]::Create($WebAddress)
    $HTTP_Response = $HTTP_Request.GetResponse()
    RETURN $HTTP_Response.StatusCode

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
