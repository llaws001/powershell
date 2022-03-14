$vmonitorlist = "*healthcare*", "*medicine*", "*medical*", "*hippa*", "*windows*", "*data confidentiality*"
$nvdfeed = Invoke-RestMethod -Uri "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml"
$DesktopPath = [Environment]::GetFolderPath("Desktop")

$output = foreach($v in $nvdfeed.RDF.ChildNodes){
        foreach ($vmonitor in $vmonitorlist) {
            if ($v.description -like $vmonitor) {
                if ($v.Date) { 

                    if(((get-date -date "$($v.date)") -gt (($(Get-Date)) - (New-TimeSpan -Days 30)).DateTime)) {
                               
                               $vuln = New-Object PSobject -Property @{
                                "CVE"= $v.title
                                "Date" = $v.date
                                "Description" = $v.description
                                } | Select-object -Property "CVE", "Date" , "Description"
                                write-output $vuln

                } 
                   
            }

        }
    }
}

$output | export-csv -path $DesktopPath\NISTvulnerabilities.csv -NoTypeInformation





