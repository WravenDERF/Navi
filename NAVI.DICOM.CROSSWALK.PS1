$NaviCrosswalkData = [PSCustomObject]@{
    'Vendor' = [string]'infoSpark'
    'Name' = [string]'Navi'
    'Version' = [string]'CrosswalkData 2022.04.14'
    'Debug' = [bool]$false
}

#Main
Invoke-Command -ScriptBlock {
    #Constructor
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Unrestricted -Force
    Import-Module -Name sqlserver
    [datetime]$StartTime = Get-Date
    [int]$AccessionMigration = 3900001
    [int]$MRNMigration = 1200001
    [string]$TableDB = 'OrthoAtlanta'
    [string]$OldWorkBookPath = 'C:\Users\Wraven\OneDrive\Backup\OrthoAtlanta-Medstrat\FredTestIn.csv'
    [string]$NewWorkBookPath = "C:\Users\Wraven\OneDrive\Backup\OrthoAtlanta-Medstrat\FredTestOut.csv"
    $Table = New-Object System.Collections.ArrayList
    IF ($NaviCrosswalkData.Debug) {Write-Host -Object $OldWorkBookPath -ForegroundColor Cyan}
    IF ($NaviCrosswalkData.Debug) {Write-Host -Object $NewWorkBookPath -ForegroundColor Cyan}
    IF ($NaviCrosswalkData.Debug) {PAUSE}
    
    #Import tools needed for this.


    <#Set the process priority
    Write-Host -Object $('Setting Process Priority...') -ForegroundColor Cyan
    #Set Process Priority
        #Idle
        #BelowNormal
        #Normal
        #AboveNormal
        #High
        #RealTime
    $ProcessPriority = Get-Process -Name 'powershell_ise'
    $ProcessPriority.PriorityClass = 'High'
    #>

    #Read all entries and activate the progress bar.
    Write-Host -Object $('Reading the Study List...') -ForegroundColor Cyan
    $WorkBook = Import-Csv -Path $OldWorkBookPath -Delimiter '|'
    $MaxCount = ($WorkBook.Count / 100)
    IF ($NaviCrosswalkData.Debug) {Write-Host -Object $("MaxIndex:$($WorkBook.Count)") -ForegroundColor Cyan}
    IF ($NaviCrosswalkData.Debug) {PAUSE}

    #Process each line.
    #Clear-Host
    FOREACH ($Row in $Workbook) {
        #Progress bar keeps track of how long it takes.
        IF (-not $($NaviCrosswalkData.Debug)) {
            $Index = $Index + 1
            $DifferenceTime = New-TimeSpan -Start $StartTime -End $(Get-Date)
            $Progress = [math]::Round(($Index / $MaxCount), 4)
            $Message = $DifferenceTime -replace ".{8}$"
            Write-Progress -Activity "Progress - $Message" -Status "$Progress% Complete" -PercentComplete $Progress
        }

        #Makes a new object based off the old data to translate.
        TRY {
            #This block adds the data to a Custom Object that refelexts teh old data.
            $OldRow = [PSCustomObject]@{
                MRN = [string]$($Row.mrn).trimstart('0')
                PatientName = [string]$($Row.lastname) + [char]94 + $($Row.firstname) + [char]94 + $($Row.middlename) + [char]94 + [char]94
                DOB = [string]$($Row.date_of_birth)
                Sex = [string]$($Row.sex)

                Accession = [string]$($Row.accession_number)
                Modalities = [string]$($Row.modalities)
                StudyDescription = [string]$($Row.study_description)
                StudyDate = [string]$($Row.study_date)
                StudyUID = [string]$($Row.suid)
            }
            IF ($($NaviCrosswalkData.Debug)) {Write-Host -Object $($OldRow | Sort-Object -Property 'Name' | Format-List | Out-String)}
        } CATCH {
            #Show a bad result.
            Write-Host -Object $($OldRow | Sort-Object -Property 'Name' | Format-List | Out-String) -ForegroundColor Red
            PAUSE
        }

        #Makes a new object based off new data.
        TRY {
            #This block adds the data to a Custom Object and adds it to a table to be exported to a CSV later.
            $NewRow = [PSCustomObject]@{
                OldMRN = [string]$($OldRow.MRN)
                NewMRN = $Null
                PatientName = [string]$($OldRow.PatientName)
                DOB = [string]$($OldRow.DOB)
                Sex = [string]$($OldRow.Sex)
                OldAccession = [string]$($OldRow.Accession)
                NewAccession = $Null
                Modalities = [string]$($OldRow.Modalities)
                StudyDescription = [string]$($OldRow.StudyDescription)
                StudyDate = [string]$($OldRow.StudyDate)
                StudyUID = [string]$($OldRow.StudyUID)
            }
            IF ($($NaviCrosswalkData.Debug)) {Write-Host -Object $($NewRow | Sort-Object -Property 'Name' | Format-List | Out-String)}
        } CATCH {
            #Show a bad result.
            Write-Host -Object $($NewRow | Sort-Object -Property 'Name' | Format-List | Out-String) -ForegroundColor Red
            PAUSE
        }

        #Try to crosswalk the data.
        TRY {
            #This block will crosswalk the OldMRN and if it matches, verifies the DOB. If they both match, it saves the new MRN to a veriable and sets a flag to true. If the operator stays false, it assigns a new MRN.
            $QueryText = "SELECT * FROM [Crosswalks].[dbo].[$TableDB] WHERE [OldMRN] = '$($NewRow.OldMRN)' AND [DOB] = '$($NewRow.DOB)';"
            IF ($($NaviCrosswalkData.Debug)) {Write-Host -Object $QueryText}
            $QueryResult = Invoke-Sqlcmd -ServerInstance "LOCALHOST" -Query $QueryText
            $NewRow.NewMRN = $($QueryResult.NewMRN)
            IF ($($NaviCrosswalkData.Debug)) {Write-Host -Object $($NewRow | Sort-Object -Property 'Name' | Format-List | Out-String) -ForegroundColor Green}
        } CATCH {
            #Show a bad result.
            Write-Host -Object $($NewRow | Sort-Object -Property 'Name' | Format-List | Out-String) -ForegroundColor Red
        }

        #This fills out the MRN if it was not crosswalked in the database.
        IF ($($NewRow.NewMRN) -eq $null) {
            [string]$DisplayMRN = $MRNMigration
            $NewRow.NewMRN = 'MIG' + $DisplayMRN.PadLeft(9,'0')
            $MRNMigration = $MRNMigration + 1
        } 

        #Generate Accession
        [string]$DisplayAccession = $AccessionMigration
        $NewRow.NewAccession = 'MIG' + $DisplayAccession.PadLeft(9,'0')
        $AccessionMigration = $AccessionMigration + 1
        IF ($($NaviCrosswalkData.Debug)) {Write-Host -Object $($NewRow | Sort-Object -Property 'Name' | Format-List | Out-String) -ForegroundColor Green}

        #Add New Row object to the table.
        $Table.Add($NewRow) | Out-Null
        IF ($($NaviCrosswalkData.Debug)) {$NewRow}
    }


    #$Table
    $Table | Export-Csv -Path $NewWorkBookPath -Encoding ASCII -NoTypeInformation

    #Time Reporting
    $TotalTimeSpan = New-TimeSpan -Start $StartTime -End $(Get-Date)
    $Message = "Total Run Time: $TotalTimeSpan"
    Write-Host -Object $Message -ForegroundColor Green
}
