Function Resolve-WebLinkAlso {

  param(
    [string]$url,
    [int]$parallelCount = 10,
    [int]$iterations = 10
  )

  foreach -parallel ($x in 1..$parallelCount) {
    1..$iterations | %{ 
        $response = curl $url
        $status = $response.StatusCode
        "worker $x : iteration $_ : $status"
        [System.Threading.Thread]::Sleep(500)
    }
  }

} 

Function Resolve-WebLink {

    PARAM ([string]$WebAddress)

    $HTTP_Request = [System.Net.WebRequest]::Create($WebAddress)
    $HTTP_Response = $HTTP_Request.GetResponse()
    RETURN $HTTP_Response.StatusCode

}

Clear-Host
Write-Host -Object 'Hello World!'
