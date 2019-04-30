<#
Module file for Saviynt API access

Written by Ken Koch
    Because I got tired of using the UI :)

Created: 2019-04-27 on Saviynt v5.3.1
#>

# Set all outbound calls to TLS 1.2
[Net.ServicePointManager]::SecUrityProtocol = [Net.SecUrityProtocolType]::Tls12

function Convert-FromBase64StringWithNoPadding([string]$data) {
    # https://www.powershellgallery.com/packages/Exch-Rest/2.7/Content/functions%5Cother%5CConvert-FromBase64StringWithNoPadding.ps1
    $data = $data.Replace('-', '+').Replace('_', '/')
    switch ($data.Length % 4) {
        0 { break }
        2 { $data += '==' }
        3 { $data += '=' }
        default { throw New-Object ArgumentException('data') }
    }
    return [System.Convert]::FromBase64String($data)
}

function Convert-JWT([string]$rawToken) {
    $parts = $rawToken.Split('.');
    $headers = [System.Text.Encoding]::UTF8.GetString((Convert-FromBase64StringWithNoPadding $parts[0]))
    $claims = [System.Text.Encoding]::UTF8.GetString((Convert-FromBase64StringWithNoPadding $parts[1]))
    $signature = (Convert-FromBase64StringWithNoPadding $parts[2])

    $customObject = [PSCustomObject]@{
        headers   = ($headers | ConvertFrom-Json)
        claims    = ($claims | ConvertFrom-Json)
        signature = $signature
    }

    Write-Verbose -Message ("JWT`r`n.headers: {0}`r`n.claims: {1}`r`n.signature: {2}`r`n" -f $headers, $claims, [System.BitConverter]::ToString($signature))
    return $customObject
}


function Connect-SSMService {
    [cmdletbinding()] param(
        [Parameter(Mandatory = $true)][string]$Username, 
        [Parameter(Mandatory = $true)][string]$Password,
        [Parameter(Mandatory = $true)][string]$Hostname
    )
    
    # These are all scoped to the module for reuse
    $script:Connected = $true
    $script:Username = $Username
    $script:Password = $Password
    $script:Hostname = $Hostname

    $script:DefaultResultSize = 1000000

    if (Get-SSMAuthToken -ForceRefresh) {
        return "Connected"
    } else {
        return "Failed to connect"
    }
}

# This checks if they've done Connect-SSMService or not
function Test-SSMConnection {
    if (-not($script:Connected)) {
        Throw "Establish a connection to Saviynt prior to executing functions using Connect-SSMService"
    }
}

# Get an SSM API Auth Token JWT
function Get-SSMAuthToken ([switch]$ForceRefresh) {
    test-SSMConnection

    $url = "https://$($script:Hostname)/ECM/api/login"
    $ContentType = "application/json"
    $Method = "POST"
     
    # Check for token expiration within 5 minutes, reissue if expiring soon
    if ($script:SSMJWT -and (-not($ForceRefresh))) {

        # Add 5 min to current time for comparison
        $currentDateTimeEpoch = [int][double]::Parse((Get-Date (get-date).AddMinutes(-5).touniversaltime() -UFormat %s))
        
        # Actual token expiration
        $tokenExpiration = (Convert-JWT -rawToken $script:SSMJWT.access_token).claims.exp
   
        if ($currentDateTimeEpoch -lt $tokenExpiration) {
            # Not expired
            $SSMValidAccessToken = $script:SSMJWT.access_token
        }
    }


    if (-not($SSMValidAccessToken)) {
        # Get a new token
        $Body = (@{username = "$($script:Username)"; password = "$($script:Password)"}) | convertto-json
        $script:SSMJWT = Invoke-RestMethod -Uri "$($url)" -Body $Body -Method $Method -ContentType $ContentType
        $SSMValidAccessToken = $script:SSMJWT.access_token
    }

    return $SSMValidAccessToken
}

# Retrieves SSM roles via search criteria
function Get-SSMRole {
    [cmdletbinding()] param(
        [Parameter(Mandatory = $false)][string]$Name, 
        [Parameter(Mandatory = $false)][switch]$IncludeEntitlementValues,
        [Parameter(Mandatory = $false)][switch]$IncludeUserDetails,
        [Parameter(Mandatory = $false)][int]$Max = 50,
        [Parameter(Mandatory = $false)][hashtable]$AdditionalSearchCriteria,
        [Parameter(Mandatory = $false)][int]$ResultSize = $script:DefaultResultSize
    )
    Test-SSMConnection
    $Uri = "https://$($script:Hostname)/ECM/api/v5/getRoles"

    $Offset = 0
    $Body = @{}
    
    # Trim Max to match resultsize
    if ($ResultSize -lt $Max) { $Max = $ResultSize}

    # Add the role name first for pretty factor because that's the most common search for me
    if ($Name) {
        $Body["role_name"] = $Name
    }

    # Add EVs
    if ($IncludeEntitlementValues) {
        $Body["requestedObject"] = "entitlement_values"
    }

    # Add userdetails
    if ($IncludeUserDetails) {
        if ($Body["requestedObject"]) {
            $Body["requestedObject"] += ",users"
        } else {
        $Body["requestedObject"] = "users"
        }
    }

    # Add all the custom search fields
    if ($AdditionalSearchCriteria) {
        foreach ($key in $AdditionalSearchCriteria.GetEnumerator()) {
            $Body[$key.Name] = $Key.Value
        }
    }

    # Append the max and offset, this gets updated for each search
    $Body["max"] = $Max
    $Body["offset"] = $Offset

    if ((-not($Name)) -and (-not($AdditionalSearchCriteria))) {
        Write-Warning "Searching may be slow due to lack of search criteria."
    }

    $Results = @()
    do {
        $Continue = $false
        $token = Get-SSMAuthToken

        $Headers = @{
            Authorization = "Bearer $token";
        }
   
        # Format: json
        $Result = Invoke-RestMethod -Uri $Uri -Headers $Headers -Body $($body | Convertto-json) -method POST -ContentType application/json
               
        $Offset += $Max  
        $Body["Offset"] = $Offset

        $Results += $Result
        $ResultsTotalCount = $Results.Roledetails.Count
        
        if ($ResultsTotalCount -lt $ResultSize) { # Data count less than intended ResultSize
            if ($ResultsTotalCount -lt $Max) { # Got no data or ran out of data
                $Continue = $False
            } else { # Data count is less than max param
                $Continue = $true
            }
        } else { # Data count more than ResultSize
            $Continue = $false
        }

    } while (($Result.errorCode -eq 0) -and ($Continue))

    
    return $Results.Roledetails | Select-Object -First $ResultSize
    
}


# Get entitlements
function Get-SSMEntitlement {
    [cmdletbinding()] param(
        [Parameter(Mandatory = $false)][string]$Name, 
        [Parameter(Mandatory = $false)][string]$Username, 
        [Parameter(Mandatory = $false)][string]$Entitlementtype, 
        [Parameter(Mandatory = $false)][string]$Endpoint,         
        [Parameter(Mandatory = $false)][switch]$IncludeUserDetails,
        [Parameter(Mandatory = $false)][int]$Max = 50,
        [Parameter(Mandatory = $false)][hashtable]$EntitlementFilterCriteria,
        [Parameter(Mandatory = $false)][array]$EntitlementResponseFields,
        [Parameter(Mandatory = $false)][switch]$ExactMatch, 
        [Parameter(Mandatory = $false)][int]$ResultSize = $script:DefaultResultSize
    )
    Test-SSMConnection
    $Uri = "https://$($script:Hostname)/ECM/api/v5/getEntitlements"

    $Offset = 0
    $Body = @{}
    
    # Add userdetails
    if ($IncludeUserDetails) {
        $Body["requestedObject"] = "users"
    }

    # Append the max and offset, this gets updated for each search
    $Body["max"] = $Max
    $Body["offset"] = $Offset

    # Check for NOT
    if (-not($ExactMatch)) {
        $Body["exactmatch"] = "false"
    } 
    
    if ($username) {
        $Body["username"] = $Username
    }

    if ($Entitlementtype) {
        $Body["entitlementtype"] = $Entitlementtype
    }

    if ($Endpoint) {
        $Body["endpoint"] = $Endpoint
    }

    if ($EntitlementResponseFields) {
        $Body["entitlementResponseFields"] = $EntitlementResponseFields
    }

    if ($EntitlementFilterCriteria) {
        $Body["entitlementfiltercriteria"] = $EntitlementFilterCriteria
    }

    if ($Name) {
        $Body["entitlementfiltercriteria"] += @{entitlement_value = $Name}
    }

    $Results = @()
    do {
        $token = Get-SSMAuthToken

        $Headers = @{
            Authorization = "Bearer $token";
        }
   
        # Format: Json YAY
        $Result = Invoke-RestMethod -Uri $Uri -Headers $Headers -Body $($body | Convertto-json) -method POST -ContentType application/json
               
        $Offset += $Max  
        $Body["Offset"] = $Offset

        $Results += $Result
        $ResultsTotalCount = $Results.EntitlementDetails.Count
 
        if ($ResultsTotalCount -lt $ResultSize) { # Data count less than intended ResultSize
            if ($ResultsTotalCount -lt $Max) { # Got no data or ran out of data
                $Continue = $False
            } else { # Data count is less than max param
                $Continue = $true
            }
        } else { # Data count more than ResultSize
            $Continue = $false
        }

    } while (($Result.errorCode -eq 0) -and ($Continue))

    return $Results.EntitlementDetails | Select-Object -First $ResultSize

}


# Get endpoints
function Get-SSMEndpoint {
    [cmdletbinding()] param(
        [Parameter(Mandatory = $false)][string]$Name, 
        [Parameter(Mandatory = $false)][string]$ConnectionType, 
        [Parameter(Mandatory = $false)][string]$Endpointkey,         
        [Parameter(Mandatory = $false)][int]$Max = 50,
        [Parameter(Mandatory = $false)][hashtable]$FilterCriteria,
        [Parameter(Mandatory = $false)][int]$ResultSize = $script:DefaultResultSize
    )
    Test-SSMConnection
    $Uri = "https://$($script:Hostname)/ECM/api/v5/getEndpoints"

    $Offset = 0
    $Body = @{}
    
    # Append the max and offset, this gets updated for each search
    $Body["max"] = $Max
    $Body["offset"] = $Offset
   
    if ($ConnectionType) {
        $Body["connectionType"] = $ConnectionType
    }

    if ($Endpointkey) {
        $Body["endpointkey"] = $Endpointkey
    }

    if ($FilterCriteria) {
        $Body["filterCriteria"] = $FilterCriteria
    }

    if ($Name) {
        $Body["endpointname"] = $Name
    }

    $Results = @()
    do {
        $token = Get-SSMAuthToken

        $Headers = @{
            Authorization = "Bearer $token";
        }
   
        # Format: Json YAY
        $Result = Invoke-RestMethod -Uri $Uri -Headers $Headers -Body $($body | Convertto-json) -method POST -ContentType application/json
               
        $Offset += $Max  
        $Body["Offset"] = $Offset

        $Results += $Result
        $ResultsTotalCount = $Results.endpoints.Count
 
        if ($ResultsTotalCount -lt $ResultSize) { # Data count less than intended ResultSize
            if ($ResultsTotalCount -lt $Max) { # Got no data or ran out of data
                $Continue = $False
            } else { # Data count is less than max param
                $Continue = $true
            }
        } else { # Data count more than ResultSize
            $Continue = $false
        }

    } while (($Result.errorCode -eq 0) -and ($Continue))

    return $Results.endpoints | Select-Object -First $ResultSize
}


# Get ARS tasks
function Get-SSMTasks {
    [cmdletbinding()] param(
        [Parameter(Mandatory = $false)][int]$TaskId, 
        [Parameter(Mandatory = $false)][string][ValidateSet("PENDING", "COMPLETED", "COMPLETED_AND_DISCONTINUE")]$TaskStatus, 
        [Parameter(Mandatory = $false)][string]$SecuritySystem, 
        [Parameter(Mandatory = $false)][string]$EndpointName,
        [Parameter(Mandatory = $false)][int]$Max = 50,
        [Parameter(Mandatory = $false)][hashtable]$FilterCriteria,
        [Parameter(Mandatory = $false)][int]$ResultSize = $script:DefaultResultSize
    )

    Test-SSMConnection
    $Uri = "https://$($script:Hostname)/ECM/api/v5/fetchTasks"

    $Offset = 0
    $Body = @{}
    
    # Append the max and offset, this gets updated for each search
    $Body["max"] = $Max
    $Body["offset"] = $Offset

    
    if ($TaskId) {
        $Body["taskid"] = $TaskId
    }

    if ($TaskStatus) {
        $Body["TASKSTATUS"] = $TaskStatus
    }

    if ($EndpointName){
        $Body["endpointname"] = $EndpointName
    }

    if ($SecuritySystem) {
        $Body["securitysystemname"] = $SecuritySystem
    }


    $Results = @()
    do {
        $token = Get-SSMAuthToken

        $Headers = @{
            Authorization = "Bearer $token";
        }
   
        # Format: Json YAY
        $Result = Invoke-RestMethod -Uri $Uri -Headers $Headers -Body $($Body | Convertto-json) -method POST -ContentType application/json
        Write-Verbose "API: Fetched $($Result.tasks.count) results."
               
        $Offset += $Max
        $Body["Offset"] = $Offset

        $Results += $Result
        $ResultsTotalCount = $Results.tasks.Count

        if ($ResultsTotalCount -lt $ResultSize) { # Data count less than intended ResultSize
            if ($ResultsTotalCount -lt $Max) { # Got no data or ran out of data
                $Continue = $False
            } else { # Data count is less than max param
                $Continue = $true
            }
        } else { # Data count more than ResultSize
            $Continue = $false
        }

    } while (($Result.errorCode -eq 0) -and ($Continue))

    return $Results.tasks | Select-Object -First $ResultSize
}


# Get SSM User Details
function Get-SSMUserDetails {
    [cmdletbinding()] param(
        [Parameter(Mandatory = $false)][int]$Username, 
        [Parameter(Mandatory = $false)][int]$Email, 
        [Parameter(Mandatory = $false)][int]$Max = 50,
        [Parameter(Mandatory = $false)][hashtable]$FilterCriteria,
        [Parameter(Mandatory = $false)][array]$ResponseFields,
        [Parameter(Mandatory = $false)][int]$ResultSize = $script:DefaultResultSize
    )

    Test-SSMConnection
    $Uri = "https://$($script:Hostname)/ECM/api/v5/getUser"

    $Offset = 0
    $Body = @{}
    
    # Append the max and offset, this gets updated for each search
    $Body["max"] = $Max
    $Body["offset"] = $Offset

    if ($Username) {
        $Body["username"] = $Username
    }

    if ($Email) {
        $Body["email"] = $Email
    }

    if ($FilterCriteria) {
        $Body["filtercriteria"] = $FilterCriteria
    }

    if ($ResponseFields) {
        $Body["responsefields"] = $ResponseFields
    }

    $Results = @()
    do {
        $token = Get-SSMAuthToken

        $Headers = @{
            Authorization = "Bearer $token";
        }
   
        # Format: Json YAY
        $Result = Invoke-RestMethod -Uri $Uri -Headers $Headers -Body $($body | Convertto-json) -method POST -ContentType application/json
               
        $Offset += $Max
        $Body["Offset"] = $Offset

        $Results += $Result
        $ResultsTotalCount = $Results.userdetails.Count
 
        if ($ResultsTotalCount -lt $ResultSize) { # Data count less than intended ResultSize
            if ($ResultsTotalCount -lt $Max) { # Got no data or ran out of data
                $Continue = $False
            } else { # Data count is less than max param
                $Continue = $true
            }
        } else { # Data count more than ResultSize
            $Continue = $false
        }

    } while (($Result.errorCode -eq 0) -and ($Continue))

    return $Results.userdetails | Select-Object -First $ResultSize
}

Export-ModuleMember -function Connect-SSMService
#internal use only? Export-ModuleMember -function Get-SSMAuthToken
Export-ModuleMember -function Get-SSMRole
Export-ModuleMember -function Get-SSMEntitlement
Export-ModuleMember -Function Get-SSMEndpoint
Export-ModuleMember -Function Get-SSMTasks
Export-ModuleMember -Function Get-SSMUserDetails
Export-ModuleMember -Function Get-SSMRole2