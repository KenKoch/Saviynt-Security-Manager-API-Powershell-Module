[CmdletBinding()]
param (
    [Parameter()]
    [String]
    $RuleName, 
    [Parameter()]
    [Switch]
    $ForceRuleFetch,
    [Parameter()]
    [String]
    $ExportFilename
)


function Get-RoleUsers ($roleName) {
    $roleDetails = Get-SSMRole -Name $roleName -IncludeUserDetails
    if ($roleDetails.userdetails -ne "User Details Not Found") {
        return $roleDetails.userdetails.username | Sort-Object -Unique
    }
    else {
        return $null
    }
}

function Get-RuleReport {
    $filename = "C:\temp\Get-RuleReport-Results.xml"
    $GetRuleReportFile = Get-ChildItem $filename 2> $null

    if (!$ForceRuleFetch -and $GetRuleReportFile -and $GetRuleReportFile.LastWriteTime -gt ((Get-Date).AddHours(-4))) {
        # Reuse the data
        $analyticResult = Import-clixml $filename
    }
    else {
        Write-Verbose "Fetching new rules"
        $null = Invoke-SSMAnalytic -Id 466 # Hardcoded
        Write-Verbose "Sleeping 15 seconds to let analytic complete"
        Start-sleep -seconds 15
        $analyticResult = Get-SSMAnalyticResult -Id 466 -Max 10000
        $analyticResult | Export-Clixml $filename
    }
    
    return $analyticResult.result
}

function Get-SQLRoleUsers ($Query) {
    $Query = $Query.Replace("a.", "user.")
    $results = (Get-SSMUser -UserQuery $Query).username | Sort-Object -Unique
    return $results
}

$TechnicalRulesWithRoles = Get-RuleReport | Where-Object RuleType -eq "Technical" | Where-Object EntitlementTypeOrEndpoint -eq "Role" | Where-Object Statuss -ne "In-Active" | Where-Object ADVANCEDQUERY -ne "" | Sort-Object -Property RuleName

[System.Collections.ArrayList]$FailedRules = @()
[System.Collections.ArrayList]$Report = @()

# $result = [PSCustomObject]@{
#     RuleName                  = "RuleName"
#     RuleType                  = "RuleType" 
#     EntitlementTypeOrEndpoint = "ActionType"
#     EntitlementNameOrAction   = "EntitlementNameOrAction"
#     AddRemove                 = "AddRemove"
#     Username                  = "Username"
# }

#$null = $Report.Add($result)

# Process a single rule
if ($RuleName) {
    $TechnicalRulesWithRoles = $TechnicalRulesWithRoles | Where-Object RuleName -eq $RuleName
}

$i = 0
foreach ($rule in $TechnicalRulesWithRoles) {
    Remove-Variable CurrentRoleUsers, SQLRoleUsers 2>$null

    $i++
    Write-Progress -Activity "Preparing role: $($rule.Rulename)" -PercentComplete (($i/$TechnicalRulesWithRoles.count)*100) 

    Try {
        $CurrentRoleUsers = Get-RoleUsers -roleName $rule.EntitlementNameOrAction
    }
    Catch {
        Write-Host -ForegroundColor red "Rule fetch current users failed. ROLE: $($rule.RuleName)"
        $FailedRules.Add($rule.RuleName)
        Continue
    }

    Try {
        $SQLRoleUsers = Get-SQLRoleUsers -Query $rule.ADVANCEDQUERY
    }
    catch {
        Write-Host -ForegroundColor red "Rule fetch SQL users failed. ROLE: $($rule.RuleName)"
        $FailedRules.Add($rule.RuleName)
        Continue
    }
    
    
    
    [System.Collections.ArrayList]$AddToRole = @()
    [System.Collections.ArrayList]$RemoveFromRole = @()

    $user = $null
    foreach ($user in $CurrentRoleUsers) {
        if ($SQLRoleUsers -notcontains $user) {
            #Remove
            $null = $RemoveFromRole.Add($user)
        }
    }
    
    $user = $null
    Foreach ($user in $SQLRoleUsers) {
        if ($CurrentRoleUsers -notcontains $user) {
            # Add
            $null = $AddToRole.Add($user)
        }
    }

    Write-Host -ForegroundColor Green "$($rule.Rulename): InRole ($($CurrentRoleUsers.count)), Query ($($SQLRoleUsers.count)), Add ($($AddToRole.count)), Remove ($($RemoveFromRole.count))"

    $user = $null
    foreach ($user in $AddToRole) {
        $result = [PSCustomObject]@{
            RuleName                  = $rule.RuleName
            RuleType                  = $rule.RuleType 
            EntitlementTypeOrEndpoint = $rule.EntitlementTypeOrEndpoint
            EntitlementNameOrAction   = $rule.EntitlementNameOrAction
            AddRemove                 = "Add"
            Username                  = $user 
        }

        $null = $Report.Add($result)
    }

    $user = $null
    foreach ($user in $RemoveFromRole) {
        $result = [PSCustomObject]@{
            RuleName                  = $rule.RuleName
            RuleType                  = $rule.RuleType 
            EntitlementTypeOrEndpoint = $rule.EntitlementTypeOrEndpoint
            EntitlementNameOrAction   = $rule.EntitlementNameOrAction
            AddRemove                 = "Remove"
            Username                  = $user 
        }
        $null = $Report.Add($result)
    }
}
Write-Verbose "Exporting report to `$global:report"
$Global:Report = $Report

Write-Verbose "Exporting FailedRules to `$global:FailedRules"
$global:FailedRules = $FailedRules

if ($ExportFilename) {
    Write-Verbose "Saving report to $($ExportFilename)"
    $Report | export-csv $ExportFilename    
}
