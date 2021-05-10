[CmdletBinding()]
param (
    [Parameter()]
    [string]
    $Username,
    # Parameter help description
    [Parameter()]
    [switch]
    $ProcessAuditAnalytic,
    [Parameter()]
    [int]
    $HowManyToSkip,
    [Parameter()]
    [int]
    $HowManyToProcess,
    [Parameter()]
    [switch]
    $Prod
)

Try {
    # Test saviynt API
    Write-Verbose "Testing SSM API"
    $null = Get-SSMUser -Username 1710144 -ResponseFields username
}
catch {
    Throw "Not connected to SSM."
}

if ($ProcessAuditAnalytic) {
    $max = 0
    if ($HowManyToProcess) {
        $max = $HowManyToProcess
    }
    if ($HowManyToSkip) {
        $max = $max + $HowManyToSkip
    }

    if ($max -eq 0) {
        $max = 1000
    }

    Write-Verbose "Fetching analytic"
    if ($Prod) {
        Trow "Need prod analytic ID"
        #$analyticResult = Get-SSMAnalyticResult -Id 368 -Max $max    
    }
    else {
        Write-Verbose "Fetching audit analytic results"
        $analyticResult = Get-SSMAnalyticResult -Id 368 -Max $max    # Test ID
    }
    
    if ($analyticresult.result.count -eq 0) {
        Throw "No analytic results."
    }

    $UsersToProcess = @($analyticResult.result.username | Sort-Object -Unique)
    Write-Verbose "Processing $($UsersToProcess.count)"
}
else {
    Write-Verbose "Processing single user: $($username)"
    $UsersToProcess = @($username)
}



if ($UsersToProcess.count -gt 0) {
    foreach ($username in $UsersToProcess) {
        if ($prod) {
            Throw "Need prod PS"
        }
        else {
            write-verbose "Fetching ssm account: $($username)"
            $account = get-ssmaccount -Username $username -Endpoint "Office 365" -Max 6 | Where-Object Status -in ("1", "Manually provisioned")
        
            if ($account.count -gt 1) {
                throw "too many accounts."
            }
        
            $accountid = $account.accountId
            $ssmuser = get-ssmuser -username $username
            if (-not($ssmuser)) {
                throw "no user"
            }
        
            $userPrincipalName = $ssmuser."User Principal Name (CP32)"
            $CP9 = $ssmuser."Credential ID (CP9)"
            $CP24 = $ssmuser."Student Primary Division Code (CP24)"
            $CP28 = $ssmuser."O365 Support Group (CP28)"
            $CP37 = $ssmuser."Data Policy (CP37)"
            $CP3 = $ssmuser."Primary Affiliation (CP3)"
            $CP7 = $ssmuser."O365 GAL Flag (CP7)"
            $userEmail = $ssmuser.email
            $systemUserName = $ssmuser.systemUserName
        
            $mailbox = get-mailbox -identity "$($accountid)"
            if (-not($mailbox)) {
                throw "no mailbox"
            }
        
            $oldUPN = $mailbox.UserPrincipalName

            write-verbose "Set local variables: 
            CP9: $($CP9)
            CP24: $($CP24)
            CP28: $($CP28)
            CP37: $($CP37)
            CP3: $($CP3)
            CP7: $($CP7)
            UserEmail: $($userEmail)
            SystemUserName: $($systemUserName)
            UPN: $($oldUPN) 
            "
            $indexer = $oldUPN.LastIndexOf('@') + 1
            $count = $oldUPN.Length - $indexer
            $oldUPNsub = $oldUPN.SubString($indexer, $count)
            $newUPN = $userPrincipalName
            $indexer1 = $newUPN.LastIndexOf('@') + 1
            $count1 = $newUPN.Length - $indexer1
            $newUPNsub = $newUPN.SubString($indexer1, $count1)
            $newUPNsub1 = $newUPN.SubString(0, $indexer1 - 1) + "@gotestwustl.onmicrosoft.com"
            $savaccID = "$($accountid)"
        
            If ($oldUPNsub -eq $newUPNsub -Or $oldUPNsub -eq "gotestwustl.onmicrosoft.com" ) {
                Set-MsolUserPrincipalName -UserPrincipalName $oldUPN -NewUserPrincipalName $newUPN
            }
            Else {
                Set-MsolUserPrincipalName -UserPrincipalName $oldUPN -NewUserPrincipalName $newUPNsub1
                Set-MsolUserPrincipalName -UserPrincipalName $newUPNsub1 -NewUserPrincipalName $newUPN
            }
            Set-Mailbox -Identity "$($accountid)" -CustomAttribute1 "$($CP9)" -CustomAttribute3 "$($CP24)" -CustomAttribute4 "$($CP28)" -CustomAttribute6 "$($CP37)" -CustomAttribute7 "$($CP3)"

            $savemail = "$($userEmail)"
            $EmailAdd = "$($systemUserName)"
            $EmailToAdd = "smtp:" + $EmailAdd + "@emailtest.wustl.edu"
            $EmailToAddNoSMTP = $EmailAdd + "@emailtest.wustl.edu"
            If (($savemail) -and ($savemail -ne "null") -and ($savemail.Length -gt 1)) {
                Set-Mailbox -Identity $savaccID -WindowsEmailAddress $savemail -EmailAddresses @{add = $EmailToAdd}
            }
            Else {
                Set-Mailbox -Identity $savaccID -WindowsEmailAddress $EmailToAddNoSMTP
            }
            $sethiddenUser = "$($CP7)"
            If ($sethiddenUser -eq 'Y') {
                Set-Mailbox -Identity $savaccID -HiddenFromAddressListsEnabled $true
            }
            Else {
                Set-Mailbox -Identity $savaccID -HiddenFromAddressListsEnabled $false
            }      
        }
    }
}