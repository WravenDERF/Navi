$DCMTK = [PSCustomObject]@{
    'Debug' = [bool]$False

    'Vendor' = [string]'infoSpark'
    'Name' = [string]'DCMTK'
    'Version' = [string]'2023.12.21.A'

    'CFIND' = [string]'C:\Programs\DCMTK\dcmtk-3.6.6-win64-dynamic\bin\findscu.exe'
    'CECHO' = [string]'C:\Programs\DCMTK\dcmtk-3.6.6-win64-dynamic\bin\echoscu.exe'
    'CMOVE' = [string]'C:\Programs\DCMTK\dcmtk-3.6.6-win64-dynamic\bin\movescu.exe'
    'CREAD' = [string]'C:\Programs\DCMTK\dcmtk-3.6.6-win64-dynamic\bin\dcmdump.exe'
    'CSTORE' = [string]'C:\Programs\DCMTK\dcmtk-3.6.6-win64-dynamic\bin\storescu.exe'
    'MODIFY' = [string]'C:\Programs\DCMTK\dcmtk-3.6.6-win64-dynamic\bin\dcmodify.exe'
}

FUNCTION Get-DCMTK {

    #Download and expand DCMTK.
    #Works with 3.6.6

    PARAM(
        [string]$WebAddress = 'https://dicom.offis.de/download/dcmtk/dcmtk366/bin/dcmtk-3.6.6-win64-dynamic.zip',
        [string]$OutFile = 'C:\Installs\DCMTK.zip',
        [string]$ExtractionFolder = 'C:\Programs\DCMTK'
    )

    IF (-NOT $(Test-Path -Path "$ExtractionFolder\dcmtk-3.6.6-win64-dynamic\bin\findscu.exe")) { 
        Invoke-RestMethod -Uri $WebAddress -OutFile $OutFile
        Expand-Archive -LiteralPath $OutFile -DestinationPath $ExtractionFolder
        $CECHO = 'C:\Installs\dcmtk-3.6.6-win64-dynamic\bin\echoscu.exe -v'
    }

    #$CECHO = 'C:\Programs\DCMTK\dcmtk-3.6.6-win64-dynamic\bin\echoscu.exe'
    #$CFIND = 'C:\Programs\DCMTK\dcmtk-3.6.6-win64-dynamic\bin\findscu.exe'
    #$CMOVE = 'C:\Programs\DCMTK\dcmtk-3.6.6-win64-dynamic\bin\movescu.exe'
}

FUNCTION Assemble-Command {

    #Assembles a line for DCMTK commands and returns a string.

    PARAM(
        [string]$SCPAET = $Null,
        [string]$SCUAET = $Null,
        [string]$Level = $Null,
        [string]$StudyUID = $Null,
        [string]$StudyDate = $Null,
        [string]$StudyAccession = $Null,
        [string]$SeriesModality = $Null,
        [string]$StudyModalities = $Null,
        [string]$StudyDescription = $Null,
        [string]$PatientName = $Null,
        [string]$PatientMRN = $Null,
        [string]$PatientDOB = $Null,
        [string]$PatientSex = $Null,
        [string]$SeriesUID = $Null,
        [string]$IP = $Null,
        [string]$Port = $Null
    )

    $DICOM = [PSCustomObject]@{
        'Verbosity' = [string]"--verbose"
        'QueryModel' = [string]"--study"
        'SCPAET' = [string]"--call " + $SCPAET
        'SCUAET' = [string]"--aetitle " + $SCUAET
        'StudyDate' = [string]"--key 0008,0020=" + $StudyDate
        'StudyAccession' = [string]"--key 0008,0050=" + $StudyAccession
        'Level' = [string]"--key 0008,0052=" + $Level
        'SeriesModality' = [string]"--key 0008,0060=" + $SeriesModality
        'StudyModalities' = [string]"--key 0008,0061=" + $StudyModalities
        'StudyDescription' = [string]"--key 0008,1030=" + $StudyDescription
        'PatientName' = [string]"--key 0010,0010=" + $PatientName
        'PatientMRN' = [string]"--key 0010,0020=" + $PatientMRN
        'PatientDOB' = [string]"--key 0010,0030=" + $PatientDOB
        'PatientSex' = [string]"--key 0010,0040=" + $PatientSex
        'StudyUID' = [string]"--key 0020,000D=" + $StudyUID
        'IP' = [string]$IP
        'Port' = [string]$Port
    }

    $CommandDICOM = -join @(  
        $DICOM.Verbosity + [char]32
        $DICOM.QueryModel + [char]32
        $DICOM.SCPAET + [char]32
        $DICOM.SCUAET + [char]32
        $DICOM.Level + [char]32
        $DICOM.StudyUID + [char]32
        $DICOM.StudyDate + [char]32
        $DICOM.StudyAccession + [char]32
        $DICOM.SeriesModality + [char]32
        $DICOM.StudyModalities + [char]32
        $DICOM.StudyDescription + [char]32
        $DICOM.PatientName + [char]32
        $DICOM.PatientMRN + [char]32
        $DICOM.PatientDOB + [char]32
        $DICOM.PatientSex + [char]32
        $DICOM.IP + [char]32
        $DICOM.Port
    )

    #IF ($Navi.Debug) {Write-Host -Object $CommandDICOM}
    
    RETURN $CommandDICOM
    
}

FUNCTION Execute-CMOVE {

    #Performs a CMOVE and returns and object.
    #W: Move response with warning status (Warning: SubOperationsCompleteOneOrMoreFailures)
    #W: Move response with error status (Failed: UnableToProcess)
    #W: Move response with error status (Failed: UnableToProcess)

    PARAM(
        [string]$SCPAET = $Null,
        [string]$SCUAET = $Null,
        [string]$Level = 'STUDY',
        [string]$StudyUID = $Null,
        [string]$StudyDate = $Null,
        [string]$StudyAccession = $Null,
        [string]$StudyModality = $Null,
        [string]$StudyDescription = $Null,
        [string]$PatientName = $Null,
        [string]$PatientMRN = $Null,
        [string]$PatientDOB = $Null,
        [string]$PatientSex = $Null,
        [string]$SeriesUID = $Null,
        [string]$SeriesInstances = $Null,
        [string]$IP = $Null,
        [string]$Port = $Null
    )

    $Results = [PSCustomObject]@{
        'Sender' = $SCPAET
        'Receiver' = $SCUAET
        'SeriesCount' = [int]0
        'Success' = [bool]$False
    }

    $ReturnCollection = Invoke-Expression -Command "$($Navi.CMOVE) $(Assemble-Command -SCPAET $SCPAET -SCUAET $SCUAET -Level $Level -StudyUID $StudyUID -StudyDate $StudyDate -StudyAccession $StudyAccession -StudyModality $StudyModality -StudyDescription $StudyDescription -PatientName $PatientName -PatientMRN $PatientMRN -PatientDOB $PatientDOB -PatientSex $PatientSex -IP $IP -Port $Port)"

    FOREACH ($Line in $ReturnCollection) {

        $DataPoint = $Line.Split(' ')[4]
        IF ($($($Line.Split(' ')[1]) -eq 'Received') -and $($($Line.Split(' ')[2]) -eq 'Move') -and $($($Line.Split(' ')[3]) -eq 'Response')) {

            $Results.SeriesCount = $DataPoint
        }

        $DataPoint = $Line.Split(' ')[0]
        IF ($DataPoint -eq 'W:') {
            IF ($($Line.Split('()')) -eq 'Success') {
                $Results.Success = $True
            }
        }

    }

    RETURN $Results
    
}
















FUNCTION Execute-CFIND {

    #Performs a CFIND and returns and object.
    PARAM(
        [string]$SCPAET = $Null,
        [string]$SCUAET = $Null,
        [string]$Level = 'STUDY',
        [string]$StudyUID = $Null,
        [string]$StudyDate = $Null,
        [string]$StudyAccession = $Null,
        [string]$StudyModality = $Null,
        [string]$StudyModalities = $Null,
        [string]$StudyDescription = $Null,
        [string]$PatientName = $Null,
        [string]$PatientMRN = $Null,
        [string]$PatientIssuer = $Null,
        [string]$PatientDOB = $Null,
        [string]$PatientSex = $Null,
        [string]$IP = $Null,
        [string]$Port = $Null
    )

    $FinalCollection = New-Object System.Collections.ArrayList

<#
#Testing on 2024.12.31
#Execute-CFIND -SCPAET '0175wfmpFIR' -IP '10.26.23.12' -Port 2104 -SCUAET 'POWERSHARE' -StudyDate $FormattedDate -SeriesModality 'MG'
#Execute-CFIND -SCPAET 'CAMCSYNPROD' -IP '10.9.60.41' -Port 104 -SCUAET 'POWERSHARE' -StudyAccession 'MG240011678'
#$SCPAET = '0175wfmpFIR'
$SCPAET = 'CAMCSYNPROD'
#$IP = '10.26.23.12'
$IP = '10.9.60.41'
#$Port = 2104
$Port = 104
$SCUAET = 'POWERSHARE'
$StudyAccession = 'MG240011678'
#$StudyAccession = $NULL

#$StudyDate = '20240605'
$StudyDate = $NULL
#$StudyModality = 'MG'
$StudyModality = $NULL
#$StudyModalities = 'MG'
$StudyModalities = $NULL
$StudyUID = $NULL
$Level = 'STUDY'
#>

#Testing for Beckley Oncology.
#$SCPAET = 'RDSCRWVANSTD1'
#$SCUAET = 'POWERSHARE'
#$SCUAET = 'CAMCSYNPROD'
#$IP = '10.9.60.86'
#$Port = 5000
#$Level = 'STUDY'
#$StudyDate = '20220114'
#$StudyDate = $NULL
#$StudyAccession = '1111344CLC'
#$StudyAccession = '1111344'
#$StudyAccession = $NULL
#Execute-CFIND -SCPAET 'RDSCRWVANSTD1' -IP '10.9.60.86' -Port 5000 -SCUAET 'CAMCSYNPROD' -StudyAccession '1111344CLC'

    $Command = "$($DCMTK.CFIND) --verbose --study --call $SCPAET --aetitle $SCUAET --key 0008,0052=$Level --key 0008,0020=$StudyDate --key 0008,0050=$StudyAccession --key 0008,0060= --key 0008,0061= --key 0008,1030= --key 0010,0010= --key 0010,0020= --key 0010,0030= --key 0010,0040= --key 0020,000D=$StudyUID $IP $Port"
    #$Command
    $ReturnCollection = Invoke-Expression -Command $Command
    #$ReturnCollection
    #$ReturnCollection.Count




    FOREACH ($Line in $ReturnCollection) {
        
        $StudyStart = [string]'I: # Dicom-Data-Set'
        $StudyEnd1 = [string]'I: ---------------------------'
        $StudyEnd2 = [string]'I: Received Final Find Response (Success)'
        #$StudyCount = $Line.Split(' ')
        $DataPoint = $Line.Split('()')[1]

        <#IF (($StudyCount[1] -eq 'Find') -and ($StudyCount[2] -eq 'Response:')) {
            $Study = [PSCustomObject]@{   
                'Command' = $Command
                'Date' = [string]$Null
                'Accession' = [string]$Null
                'StudyModality' = [string]$Null
                'StudyModalities' = [string]$Null
                'Description' = [string]$Null
                'PatientName' = [string]$Null
                'PatientMRN' = [string]$Null
                'PatientIssuer' = [string]$Null
                'PatientDOB' = [string]$Null
                'PatientSex' = [string]$Null
                'StudyUID' = [string]$Null
                'StudySeriesCount' = [int]$Null
            }
        }
        #>

        IF ($Line -eq $StudyStart) {
            $Study = [PSCustomObject]@{   
                'Command' = $Command
                'Date' = [string]$Null
                'Accession' = [string]$Null
                'StudyModality' = [string]$Null
                'StudyModalities' = [string]$Null
                'Description' = [string]$Null
                'PatientName' = [string]$Null
                'PatientMRN' = [string]$Null
                'PatientIssuer' = [string]$Null
                'PatientDOB' = [string]$Null
                'PatientSex' = [string]$Null
                'StudyUID' = [string]$Null
                'StudySeriesCount' = [int]$Null
            }
        }

        IF (($Line -eq $StudyEnd1) -or ($Line -eq $StudyEnd2)) {
            $FinalCollection.Add($Study) | Out-Null
        }

        #$FinalCollection.Count


        #Parse the info returned.
        SWITCH ($DataPoint){   
			'0008,0020'{   
                $Study.Date = [string]$($Line.Split('[]')[1])   
				BREAK 
			}   
			'0008,0050'{   
                $Study.Accession = [string]$($Line.Split('[]')[1])   
				BREAK 
			}   
			'0008,0060'{   
                $Study.StudyModality = [string]$($Line.Split('[]')[1])   
				BREAK
			}   
			'0008,0061'{   
                $Study.StudyModalities = [string]$($Line.Split('[]')[1])
				BREAK
			}
			'0008,1030'{   
                $Study.Description = [string]$($Line.Split('[]')[1])   
				BREAK
			}   
			'0010,0010'{   
                $Study.PatientName = [string]$($Line.Split('[]')[1])   
				BREAK
			}   
			'0010,0020'{   
                $Study.PatientMRN = [string]$($Line.Split('[]')[1])   
				BREAK
			}   
			'0010,0021'{   
                $Study.PatientIssuer = [string]$($Line.Split('[]')[1])   
				BREAK
			}   
			'0010,0030'{   
                $Study.PatientDOB = [string]$($Line.Split('[]')[1])   
				BREAK
			}   
			'0010,0040'{   
                $Study.PatientSex = [string]$($Line.Split('[]')[1])   
				BREAK
			}
			'0020,000D'{
                $Study.StudyUID = [string]$($Line.Split('[]')[1])
                BREAK
			}
			'0020,1206'{
                $Study.StudySeriesCount = [string]$($Line.Split('[]')[1])
                BREAK
			}
        }
    }
   
    RETURN $FinalCollection
    

}






FUNCTION Execute-CECHO {

    #Gets status of DICOM listener.

    PARAM(
        [string]$WebAddress = 'https://dl.interfaceware.com/iguana/windows/6_1_5/iguana_noinstaller_6_1_5_windows_x64.zip',
        [string]$OutFile = 'C:\Installs\Iguana.zip',
        [string]$ExtractionFolder = 'C:\Programs',
        [string]$SCPAET,
        [string]$SCUAET,
        [string]$IP,
        [string]$Port
    )

#Testing for Beckley Oncology.
$SCPAET = 'RDSCRWVANSTD1'
$SCUAET = 'POWERSHARE'
$IP = '10.9.60.86'
$Port = 5000

#Testing for PowerShare.
$SCPAET = 'POWERSHARE'
$SCUAET = 'RDSCRWVANSTD1'
$IP = '10.11.26.184'
$Port = 104

    $Command = "$($DCMTK.CECHO) --verbose --call $SCPAET --aetitle $SCUAET $IP $Port"
    $Command
    $Reply = Invoke-Expression -Command $Command
    $Reply

    $Output = [bool]$False
    FOREACH ($ReturnedLine in $Reply) {
        IF ($ReturnedLine -eq 'I: Received Echo Response (Success)') {
            $Output = [bool]$true
        }#End IF
    } #End FOREACH

    RETURN $Output
    
}


<#
$DCMTK | Add-Member 'ScriptMethod' -name 'Get-DCMTK' -Value ${function:Get-DCMTK}
$DCMTK | Add-Member 'ScriptMethod' -name 'Assemble-Command' -Value ${function:Assemble-Command}
$DCMTK | Add-Member 'ScriptMethod' -name 'Execute-CMOVE' -Value ${function:Execute-CMOVE}
$DCMTK | Add-Member 'ScriptMethod' -name 'Execute-CFIND' -Value ${function:Execute-CFIND}
$DCMTK | Add-Member 'ScriptMethod' -name 'Execute-CECHO' -Value ${function:Execute-CECHO}
#>















FUNCTION Execute-CREAD {

    #Performs a read and returns and object.
    PARAM(
        [string]$Path = [string]$NULL
    )


    $FinalCollection = New-Object System.Collections.ArrayList
    $FinalHash = @{}

#Testing on 2025.01.07
#"C:\Programs\DCMTK\dcmtk-3.6.6-win64-dynamic\bin\dcmdump.exe" --verbose +P 0020,000D +P 0010,0010 "D:\Export Report Patient List\Images\Greenbriar Exams\1.2.40.0.13.1.220569771118656375822267719947277761874\47765c3470c84a17a958c9def95de800\1ae6278177064b5ba96ecdefadc76442.dcm"




#$Path = [string]"D:\Export Report Patient List\Images\Greenbriar Exams\1.2.40.0.13.1.220569771118656375822267719947277761874\47765c3470c84a17a958c9def95de800\1ae6278177064b5ba96ecdefadc76442.dcm"
#$Path = [string]'C:\Programs\1ae6278177064b5ba96ecdefadc76442.dcm'

    #$Command = "$($DCMTK.CREAD) --verbose +P 0008,0020 +P 0008,0050 +P 0008,0060 +P 0008,0061 +P 0008,1030 +P 0010,0010 +P 0010,0020 +P 0010,0021 +P 0010,0030 +P 0010,0040 +P 0020,000d $([char]34)$Path$([char]34)"
    $Command = "$($DCMTK.CREAD) --print-short $([char]34)$Path$([char]34)"
    #$Command
    $ReturnCollection = Invoke-Expression -Command $Command
    #$ReturnCollection

    #Create an object to hold the data.
    $Study = [PSCustomObject]@{   
        #'Command' = $Command
        'StudyDate' = [string]$Null
        'StudyAccession' = [string]$Null
        'StudyModality' = [string]$Null
        'StudyModalities' = [string]$Null
        'Description' = [string]$Null
        'PatientName' = [string]$Null
        'PatientMRN' = [string]$Null
        'PatientIssuer' = [string]$Null
        'PatientDOB' = [string]$Null
        'PatientSex' = [string]$Null
        'StudyUID' = [string]$Null
    }


    FOREACH ($Line in $ReturnCollection) {

        #Define the datapoint to look at.
        $DataPoint = $Line.Split('()')[1]

        #Parse the info returned.
        SWITCH ($DataPoint){   
			'0008,0020'{   
                $Study.Date = [string]$($Line.Split('[]')[1])   
				BREAK
			}   
			'0008,0050'{   
                $Study.Accession = [string]$($Line.Split('[]')[1])   
				BREAK
			}   
			'0008,0060'{   
                $Study.StudyModality = [string]$($Line.Split('[]')[1])   
				BREAK
			}   
			'0008,0061'{   
                $Study.StudyModalities = [string]$($Line.Split('[]')[1])
				BREAK
			}
			'0008,1030'{   
                $Study.Description = [string]$($Line.Split('[]')[1])   
				BREAK
			}   
			'0010,0010'{   
                $Study.PatientName = [string]$($Line.Split('[]')[1])   
				BREAK
			}   
			'0010,0020'{   
                $Study.PatientMRN = [string]$($Line.Split('[]')[1])   
				BREAK
			}   
			'0010,0021'{   
                $Study.PatientIssuer = [string]$($Line.Split('[]')[1])   
				BREAK
			}   
			'0010,0030'{   
                $Study.PatientDOB = [string]$($Line.Split('[]')[1])   
				BREAK
			}   
			'0010,0040'{   
                $Study.PatientSex = [string]$($Line.Split('[]')[1])   
				BREAK
			}
			'0020,000d'{
                $Study.StudyUID = [string]$($Line.Split('[]')[1])
                BREAK
			}
        }
    }


    #$Study

    RETURN $Study
    
}
















FUNCTION Execute-CSTORE {

    #Performs a read and returns and object.
    PARAM(
        [string]$SCPAET = $Null,
        #[string]$SCUAET = $Null,
        [string]$IP = $Null,
        [string]$Port = $Null,
        [string]$FilePath = $Null
    )


    $FinalCollection = New-Object System.Collections.ArrayList
    $FinalHash = @{}

    #\\WK-GVERIT02\Images$

    #POWERSHARE
    #10.11.26.184
    #4104
    #\\WK-GVERIT02\Images$

    #Stuff that did not work.
    #C:\Programs\DCMTK\dcmtk-3.6.6-win64-dynamic\bin\storescu.exe --verbose --propose-lossless --call POWERSHARE 10.11.26.184 4104 "D:\Export Report Patient List\Images\Greenbriar Exams\1.2.124.113532.10.155.10.100.20150519.80713.6200086\7ccdcd41c35d470cb2401be9b9d8b8f7\0e91390215544e2f801c3ad0ec8fdec2.dcm"
    #C:\Programs\DCMTK\dcmtk-3.6.6-win64-dynamic\bin\dcmconv.exe --write-xfer-little "D:\Export Report Patient List\Images\Greenbriar Exams\1.2.124.113532.10.155.10.100.20150519.80713.6200086\7ccdcd41c35d470cb2401be9b9d8b8f7\0e91390215544e2f801c3ad0ec8fdec2.dcm" "D:\Export Report Patient List\Images\Greenbriar Exams\decompressed.dcm"
    #C:\Programs\DCMTK\dcmtk-3.6.6-win64-dynamic\bin\storescu.exe --verbose --propose-lossless --call POWERSHARE 10.11.26.184 4104 "Z:\Greenbriar Exams\1.2.124.113532.12.10582.21040.20130430.104437.112406315\b29eaf8118594846aeef45b77876929c\24b0b715088540a08100489020c077cf.dcm"
    #C:\Programs\DCMTK\dcmtk-3.6.6-win64-dynamic\bin\storescu.exe --verbose --propose-j2k-lossless --call POWERSHARE 10.11.26.184 4104 "Z:\Greenbriar Exams\1.2.124.113532.12.10582.21040.20130430.104437.112406315\b29eaf8118594846aeef45b77876929c\24b0b715088540a08100489020c077cf.dcm"
    #C:\Programs\DCMTK\dcmtk-3.6.6-win64-dynamic\bin\storescu.exe --verbose --propose-jls-lossless --call POWERSHARE 10.11.26.184 4104 "Z:\Greenbriar Exams\1.2.124.113532.12.10582.21040.20130430.104437.112406315\b29eaf8118594846aeef45b77876929c\24b0b715088540a08100489020c077cf.dcm"
    #C:\Programs\DCMTK\dcmtk-3.6.6-win64-dynamic\bin\storescu.exe --verbose --call CAMCSYNTEST --aetitle FREDTEST 10.9.60.65 104 "Z:\Greenbriar Exams\1.2.124.113532.12.10582.21040.20130430.104437.112406315\b29eaf8118594846aeef45b77876929c\24b0b715088540a08100489020c077cf.dcm"

    #Trying Fuji VNA Test
    #1.2.124.113532.12.10582.21040.20130509.130753.123983194
    #E:\FredTest\9381affc3d10493b913a85f1a66c391c.dcm
    #C:\Programs\DCMTK\dcmtk-3.6.6-win64-dynamic\bin\dcmdump.exe --print-short "E:\FredTest\9381affc3d10493b913a85f1a66c391c.dcm"
    #C:\Programs\DCMTK\dcmtk-3.6.6-win64-dynamic\bin\dcmodify.exe -m "(0010,0010)=John Doe" C:\DICOM\image.dcm

    #C:\Programs\DCMTK\dcmtk-3.6.6-win64-dynamic\bin\storescu.exe --verbose --propose-lossless --call VNA_OLC_TEST --aetitle POWERSHARE 10.150.194.21 4000 "E:\FredTest\9381affc3d10493b913a85f1a66c391c.dcm"
    #C:\Programs\DCMTK\dcmtk-3.6.6-win64-dynamic\bin\findscu.exe --verbose --call VNA_OLC_TEST --aetitle POWERSHARE 10.150.194.21 4000 --study --key 0020,000D=1.2.124.113532.12.10582.21040.20130509.130753.123983194 --key 0010,0020= --key 0010,0010=
    #C:\Programs\DCMTK\dcmtk-3.6.6-win64-dynamic\bin\movescu.exe --verbose --call VNA_OLC_TEST --aetitle POWERSHARE 10.9.60.65 104 --study --key 0020,000D=1.2.124.113532.12.10582.21040.20130509.130753.123983194


    


    

    $Command = "$($DCMTK.CSTORE) --call $SCPAET $IP $Port $([char]34)$Path$([char]34)"
    #$Command
    $ReturnCollection = Invoke-Expression -Command $Command
    #$ReturnCollection

    #Create an object to hold the data.
    $Study = [PSCustomObject]@{   
        #'Command' = $Command
        'StudyDate' = [string]$Null
        'StudyAccession' = [string]$Null
        'StudyModality' = [string]$Null
        'StudyModalities' = [string]$Null
        'Description' = [string]$Null
        'PatientName' = [string]$Null
        'PatientMRN' = [string]$Null
        'PatientIssuer' = [string]$Null
        'PatientDOB' = [string]$Null
        'PatientSex' = [string]$Null
        'StudyUID' = [string]$Null
    }


    FOREACH ($Line in $ReturnCollection) {

        #Define the datapoint to look at.
        $DataPoint = $Line.Split('()')[1]

        #Parse the info returned.
        SWITCH ($DataPoint){   
			'0008,0020'{   
                $Study.Date = [string]$($Line.Split('[]')[1])   
				BREAK
			}   
			'0008,0050'{   
                $Study.Accession = [string]$($Line.Split('[]')[1])   
				BREAK
			}   
			'0008,0060'{   
                $Study.StudyModality = [string]$($Line.Split('[]')[1])   
				BREAK
			}   
			'0008,0061'{   
                $Study.StudyModalities = [string]$($Line.Split('[]')[1])
				BREAK
			}
			'0008,1030'{   
                $Study.Description = [string]$($Line.Split('[]')[1])   
				BREAK
			}   
			'0010,0010'{   
                $Study.PatientName = [string]$($Line.Split('[]')[1])   
				BREAK
			}   
			'0010,0020'{   
                $Study.PatientMRN = [string]$($Line.Split('[]')[1])   
				BREAK
			}   
			'0010,0021'{   
                $Study.PatientIssuer = [string]$($Line.Split('[]')[1])   
				BREAK
			}   
			'0010,0030'{   
                $Study.PatientDOB = [string]$($Line.Split('[]')[1])   
				BREAK
			}   
			'0010,0040'{   
                $Study.PatientSex = [string]$($Line.Split('[]')[1])   
				BREAK
			}
			'0020,000d'{
                $Study.StudyUID = [string]$($Line.Split('[]')[1])
                BREAK
			}
        }
    }


    #$Study

    RETURN $Study
    
}
