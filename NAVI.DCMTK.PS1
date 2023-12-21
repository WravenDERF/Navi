$DCMTK = [PSCustomObject]@{
    'Debug' = [bool]$False
    'CFIND' = [string]'C:\Programs\DCMTK\dcmtk-3.6.6-win64-dynamic\bin\findscu.exe'
    'CECHO' = [string]'C:\Programs\DCMTK\dcmtk-3.6.6-win64-dynamic\bin\echoscu.exe'
    'CMOVE' = [string]'C:\Programs\DCMTK\dcmtk-3.6.6-win64-dynamic\bin\movescu.exe'
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
    #W: Move response with warning status (Warning: SubOperationsCompleteOneOrMoreFailures)
    #W: Move response with error status (Failed: UnableToProcess)
    #W: Move response with error status (Failed: UnableToProcess)

    PARAM(
        [string]$SCPAET = $Null,
        [string]$SCUAET = $Null,
        [string]$Level = 'SERIES',
        [string]$StudyUID = $Null,
        [string]$StudyDate = $Null,
        [string]$StudyAccession = $Null,
        [string]$SeriesModality = $Null,
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

    $Counter = [int]0
    $Command = "$($Navi.CFIND) $(Assemble-Command -SCPAET $SCPAET -SCUAET $SCUAET -Level $Level -StudyUID $StudyUID -StudyDate $StudyDate -StudyAccession $StudyAccession -SeriesModality $SeriesModality -StudyModalities $StudyModalities -StudyDescription $StudyDescription -PatientName $PatientName -PatientMRN $PatientMRN -PatientIssuer $PatientIssuer -PatientDOB $PatientDOB -PatientSex $PatientSex -IP $IP -Port $Port)"
    $Command
    $ReturnCollection = Invoke-Expression -Command $Command
    $ReturnCollection

    [string]$StudyBreak = 'I: # Dicom-Data-Set'
    FOREACH ($Line in $ReturnCollection) {

        $StudyCount = $Line.Split(' ')
        $DataPoint = $Line.Split('()')[1]

        IF ($Line -eq $StudyBreak) {

            #Create a study object wil all details to be filled in.   
            $Study = [PSCustomObject]@{   
                'Command' = $Command
                'Date' = [string]$Null
                'Accession' = [string]$Null
                'SeriesModality' = [string]$Null
                'StudyModalities' = [string]$Null
                'Description' = [string]$Null
                'PatientName' = [string]$Null
                'PatientMRN' = [string]$Null
                'PatientIssuer' = [string]$Null
                'PatientDOB' = [string]$Null
                'PatientSex' = [string]$Null
                'StudyUID' = [string]$Null
                'ImageCount' = $Counter
            }

        } ELSE {

            #Count how many images returned.
            IF (($StudyCount[1] -eq 'Find') -and ($StudyCount[2] -eq 'Response:')) {
                $Counter = $StudyCount[3]
            }

            #Parse the info returned.
            SWITCH ($DataPoint){   
				'0008,0020'{   
                    $Study.Date = [string]$($Line.Split('[]')[1])   
					; Break   
				}   
				'0008,0050'{   
                    $Study.Accession = [string]$($Line.Split('[]')[1])   
					; Break   
				}   
				'0008,0060'{   
                    $Study.SeriesModality = [string]$($Line.Split('[]')[1])   
					; Break   
				}   
				'0008,0061'{   
                    $Study.StudyModalities = [string]$($Line.Split('[]')[1])
					; Break
				}
				'0008,1030'{   
                    $Study.Description = [string]$($Line.Split('[]')[1])   
					; Break   
				}   
				'0010,0010'{   
                    $Study.PatientName = [string]$($Line.Split('[]')[1])   
					; Break   
				}   
				'0010,0020'{   
                    $Study.PatientMRN = [string]$($Line.Split('[]')[1])   
					; Break   
				}   
				'0010,0021'{   
                    $Study.PatientIssuer = [string]$($Line.Split('[]')[1])   
					; Break   
				}   
				'0010,0030'{   
                    $Study.PatientDOB = [string]$($Line.Split('[]')[1])   
					; Break   
				}   
				'0010,0040'{   
                    $Study.PatientSex = [string]$($Line.Split('[]')[1])   
					; Break   
				}   
				'0020,1209'{   
                    $Study.SeriesInstances = [string]$($Line.Split('[]')[1])   
                    ; Break   
				}
				'0020,000D'{   
                    $Study.StudyUID = [string]$($Line.Split('[]')[1])   
                    ; Break   
				}
            }
        }
    }

    RETURN $Study
    
}

FUNCTION Execute-CECHO {

    #Gets status of DICOM listener.

    PARAM(
        [string]$WebAddress = 'https://dl.interfaceware.com/iguana/windows/6_1_5/iguana_noinstaller_6_1_5_windows_x64.zip',
        [string]$OutFile = 'C:\Installs\Iguana.zip',
        [string]$ExtractionFolder = 'C:\Programs',
        [string]$IP,
        [string]$AET,
        [string]$Port
    )

    $Command = "$($Navi.CECHO) --verbose --call $AET $IP $Port"
    $Reply = Invoke-Expression -Command $Command

    $Output = [bool]$False
    FOREACH ($ReturnedLine in $Reply) {
        IF ($ReturnedLine -eq 'I: Received Echo Response (Success)') {
            $Output = [bool]$true
        }#End IF
    } #End FOREACH

    RETURN $Output
    
}
