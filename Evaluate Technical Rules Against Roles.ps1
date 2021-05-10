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
    $ExportFilename,
    [Parameter()]
    [Switch]
    $CheckADGroupMembership
)


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

function Get-RoleUsers ($roleName) {
    $roleDetails = Get-SSMRole -Name $roleName -IncludeUserDetails
    if ($roleDetails.userdetails -ne "User Details Not Found") {
        return $roleDetails.userdetails.username | Sort-Object -Unique
    }
    else {
        return $null
    }
}

function Get-SQLRoleUsers ($Query) {
    $Query = $Query.Replace("a.", "user.")
    $Query = $Query + " and user.statuskey = 1"
    $results = (Get-SSMUser -UserQuery $Query).username | Sort-Object -Unique
    return $results
} 

function Get-ActiveDirectoryGroupMembers ($roleName) {
    $roleDetails = Get-SSMRole -Name $roleName -IncludeEntitlementValues
    if ($roleDetails.EntitlementDetails) {
        $results = (Get-ADGroupMember "$($roleDetails.EntitlementDetails.entitlement_value)" | get-aduser -Properties wustlEduId).wustlEduId
        return $results
    }
    else {
        return $results
    }    
}

$TechnicalRulesWithRoles = Get-RuleReport | Where-Object RuleType -eq "Technical" | Where-Object EntitlementTypeOrEndpoint -eq "Role" | Where-Object Statuss -ne "In-Active" | Where-Object ADVANCEDQUERY -ne "" | Sort-Object -Property RuleName

[System.Collections.ArrayList]$FailedRules = @()
[System.Collections.ArrayList]$Report = @()

# Process a single rule
if ($RuleName) {
    $TechnicalRulesWithRoles = $TechnicalRulesWithRoles | Where-Object RuleName -eq $RuleName
}

$i = 0
foreach ($rule in $TechnicalRulesWithRoles) {
    Remove-Variable CurrentRoleUsers, SQLRoleUsers 2>$null

    if ($rule.rulename -eq "Facilities Planning and Management  Staff-AD Group Provisioning") {
        $rule.rulename = "Facilities Planning and Management Staff-AD Group Provisioning"
        $rule.EntitlementNameOrAction = "Facilities Planning and Management Staff"
    }

    write-verbose $rule.rulename
    write-verbose $rule.EntitlementNameOrAction
    
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

    Try {
        if ($CheckADGroupMembership) {            
            $ADGroupMembers = Get-ActiveDirectoryGroupMembers -RoleName $rule.EntitlementNameOrAction
        }
    }
    Catch {
        Write-Host -ForegroundColor red "Rule fetch AD member users failed. ROLE: $($rule.RuleName)"
        $FailedRules.Add($rule.RuleName)
        Continue
    }
    
    
    [System.Collections.ArrayList]$AddToRole = @()
    [System.Collections.ArrayList]$RemoveFromRole = @()
        
    [System.Collections.ArrayList]$AddToADGroup = @()
    [System.Collections.ArrayList]$RemoveFromADGroup = @()

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

    if ($CheckADGroupMembership) {
        $user = $null
        foreach ($user in $ADGroupMembers) {
            if ($SQLRoleUsers -notcontains $user) {
                #Remove
                $null = $RemoveFromADGroup.Add($user)
            }
        }

        $user = $null
        foreach ($user in $ADGroupMembers) {
            if ($CurrentRoleUsers -notcontains $user) {
                # Add
                $null = $AddToADGroup.Add($user)
            }
        
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

        # Call SSAM API to add-userrole
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
