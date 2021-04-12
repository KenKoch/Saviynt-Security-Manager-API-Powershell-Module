
$wupeopleid = "1353657261"
$account = get-ssmaccount -Username $wupeopleid -Endpoint "Office 365"

if ($account.count -gt 1) {throw "too many accounts."}

$accountid = $account.accountId
$ssmuser = get-ssmuser -username $wupeopleid
if (-not($ssmuser)) {throw "no user"}

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
if (-not($mailbox)) {throw "no mailbox"}

$oldUPN = $mailbox.UserPrincipalName
$indexer = $oldUPN.LastIndexOf('@') + 1
$count = $oldUPN.Length - $indexer
$oldUPNsub = $oldUPN.SubString($indexer, $count)
$newUPN = $userPrincipalName
$indexer1 = $newUPN.LastIndexOf('@') + 1
$count1 = $newUPN.Length - $indexer1
$newUPNsub = $newUPN.SubString($indexer1, $count1)
$newUPNsub1 = $newUPN.SubString(0, $indexer1 - 1) + "@gowustl.onmicrosoft.com"
$savaccID = "$($accountid)"

If ($oldUPNsub -eq $newUPNsub -Or $oldUPNsub -eq "gowustl.onmicrosoft.com" ) {
    Set-MsolUserPrincipalName -UserPrincipalName $oldUPN -NewUserPrincipalName $newUPN
} Else {
    Set-MsolUserPrincipalName -UserPrincipalName $oldUPN -NewUserPrincipalName $newUPNsub1
    Set-MsolUserPrincipalName -UserPrincipalName $newUPNsub1 -NewUserPrincipalName $newUPN
}
Set-Mailbox -Identity "$($accountid)" -CustomAttribute1 "$($CP9)" -CustomAttribute3 "$($CP24)" -CustomAttribute4 "$($CP28)" -CustomAttribute6 "$($CP37)" -CustomAttribute7 "$($CP3)"
$savemail = $userEmail
$EmailAdd = $systemUserName

If ($savemail -ne "null") {
    Set-Mailbox -Identity $savaccID -WindowsEmailAddress $savemail -EmailAddresses @{add = "smtp:$($EmailAdd)@email.wustl.edu"}
} Else {
    Set-Mailbox -Identity $savaccID -WindowsEmailAddress "$($EmailAdd)@email.wustl.edu"
}
$sethiddenUser = "$($CP7)"
If ($sethiddenUser -eq 'Y') {
    Set-Mailbox -Identity "$($accountid)" -HiddenFromAddressListsEnabled $true
} Else {
    Set-Mailbox -Identity "$($accountid)" -HiddenFromAddressListsEnabled $false
}

#$savmanagerID = "${dynManagerAzureID}"
#If ($savmanagerID.Length -gt 5) {
#    Set-AzureADUserManager -ObjectId $savaccID -RefObjectId $savmanagerID
#} else {
#    Remove-AzureADUserManager -ObjectId $savaccID
#}
