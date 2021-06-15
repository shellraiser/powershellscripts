 function get-successfullogonhistory{

 $startDate = (get-date).AddDays(-7)# Define time for report (default is 7 days)

 # Find DC list from Active Directory
 $DCs = Get-ADDomainController -Filter *

 cls
 $Result = @()
 $successful_hash = @{}

 Write-Host "Gathering Event Logs, this can take awhile..."
 $Logs = Get-Eventlog -LogName Security -ComputerName $DCs.Hostname -after $startDate | where {($_.eventID -eq 4624) -and ($_.replacementstrings[5] -eq 'join')}
 If ($Logs)
 { Write-Host "Processing..."
 ForEach ($Log in $Logs)
 { $IP = $Log.ReplacementStrings[18]
   $Result += New-Object PSObject -Property @{
    Time = $Log.TimeWritten
    User = $Log.ReplacementStrings[5]
    IP = $IP
    Logon = "Sucessful Logon"
   }
   $successful_hash[$IP]++
   }
 $Result | Select Time,User,IP,Logon | Sort IP -Descending | Out-GridView
 $successful_hash.GetEnumerator() | Sort-Object -Property Value -Descending | Out-GridView
 Write-Host "Done."
 }
 Else
 { Write-Host "Problem with $Computer."
 Write-Host "If you see a 'Network Path not found' error, try starting the Remote Registry service on that computer."
 Write-Host "Or there are no logon/logoff events (XP requires auditing be turned on)"
 }
}

function get-failedlogonhistory{

 $startDate = (get-date).AddDays(-7) # Define time for report (default is 7 days)

 # Find DC list from Active Directory
 $DCs = Get-ADDomainController -Filter *

 cls
 $Result = @()
 $failed_hash = @{}

 Write-Host "Gathering Event Logs, this can take awhile..."
 $Logs = Get-Eventlog -LogName Security -ComputerName $DCs.Hostname -after $startDate | where {($_.eventID -eq 4625) -and ($_.replacementstrings[5] -eq 'join')}
 If ($Logs)
 { Write-Host "Processing..."
 ForEach ($Log in $Logs)
 { $IP = $Log.ReplacementStrings[19]
   $Result += New-Object PSObject -Property @{
    Time = $Log.TimeWritten
    User = $Log.ReplacementStrings[5]
    IP = $IP
    Logon = "Failed Logon"
   }
   $failed_hash[$IP]++
   }
 $Result | Select Time,User,IP,Logon | Sort IP -Descending | Out-GridView
 $failed_hash.GetEnumerator() | Sort-Object -Property Value -Descending | Out-GridView
 Write-Host "Done."
 }
 Else
 { Write-Host "Problem with $Computer."
 Write-Host "If you see a 'Network Path not found' error, try starting the Remote Registry service on that computer."
 Write-Host "Or there are no logon/logoff events (XP requires auditing be turned on)"
 }
}

get-successfullogonhistory
get-failedlogonhistory 
