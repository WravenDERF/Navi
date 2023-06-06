

Function Resolve-WebLink {

    PARAM ([string]$WebAddress)

    $HTTP_Request = [System.Net.WebRequest]::Create($WebAddress)
    $HTTP_Response = $HTTP_Request.GetResponse()
    RETURN = $HTTP_Response.StatusCode

}

Clear-Host
Write-Host -Object 'Hello World!'
