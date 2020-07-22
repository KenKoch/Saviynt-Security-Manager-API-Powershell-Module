<#
Module file for Saviynt API access

Written by Ken Koch @ Washington University in St. Louis
https://github.com/KenKoch/Saviynt-Security-Manager-API-Powershell-Module

Created: 2019-04-27 on Saviynt v5.3.1
#>

# Set all outbound calls to TLS 1.2 for SSM Production
[Net.ServicePointManager]::SecUrityProtocol = [Net.SecUrityProtocolType]::Tls12
 
# Converts base64 to readable text
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

# Converts a JWT into a PS object 
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

    # Debugging output
    Write-Verbose -Message ("JWT`r`n.headers: {0}`r`n.claims: {1}`r`n.signature: {2}`r`n" -f $headers, $claims, [System.BitConverter]::ToString($signature))
    return $customObject
}
function New-HttpQueryString {
    [CmdletBinding()]
    param 
    (
        [Parameter(Mandatory = $true)]
        [String]
        $Uri,

        [Parameter(Mandatory = $true)]
        [Hashtable]
        $QueryParameter
    )

    # Add System.Web
    Add-Type -AssemblyName System.Web

    # Create a http name value collection from an empty string
    $nvCollection = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

    foreach ($key in $QueryParameter.Keys) {
        $nvCollection.Add($key, $QueryParameter.$key)
    }

    # Build the uri
    $uriRequest = [System.UriBuilder]$uri
    $uriRequest.Query = $nvCollection.ToString()

    return $uriRequest.Uri.OriginalString
}
# Verified API connectivity and sets credentials for the module functions  
function Connect-SSMService {
    [cmdletbinding()] param(
        [Parameter(Mandatory = $true)][string]$Username, 
        [Parameter(Mandatory = $true)][string]$Password,
        [Parameter(Mandatory = $true)][string]$Hostname
    )
    
    # These are all scoped to the module for reuse
    $script:Username = $Username
    $script:Password = $Password
    $script:Hostname = $Hostname

    $script:DefaultResultSize = 1000000

    if (Get-SSMAuthToken -ForceRefresh) {
        $script:Connected = $true
        return "Connected"
    }
    else {
        return "Failed to connect"
    }
}

# Disconnect the module from SSM. Will require a connect-ssmservice to get going again.
function Disconnect-SSMService {
    $script:SSMJWT = $null
    $script:Username = $null
    $script:Password = $null
    $Hostname = $script:Hostname
    $script:Hostname = $null
    $script:Connected = $false
    return "Disconnected from $Hostname"
}

# This checks if they've done Connect-SSMService or not
function Test-SSMConnection {
    if (-not($script:Connected)) {
        Throw "Establish a connection to Saviynt prior to executing functions using Connect-SSMService"
    }
}

# Get an SSM API Auth Token JWT
function Get-SSMAuthToken ([switch]$ForceRefresh) {
    $url = "https://$($script:Hostname)/ECM/api/login"
    $Method = "POST"

    if (-not($ForceRefresh)) {
        # Don't test the credentials since it's a manual force
        Test-SSMConnection # Make sure valid credentials were passed to the module
    }

    # (Pseudo caching for the token) Check for token expiration within 5 minutes, reissue if expiring soon
    if ($script:SSMJWT -and (-not($ForceRefresh))) {

        # Add 5 min to current time for comparison
        $currentDateTimeEpoch = [int][double]::Parse((Get-Date (get-date).AddMinutes(5).touniversaltime() -UFormat %s))
        
        # Actual token expiration
        $tokenExpiration = (Convert-JWT -rawToken $script:SSMJWT.access_token).claims.exp
        
        Write-Verbose "CurrentDateTimeEpoch: $($currentDateTimeEpoch)"
        Write-Verbose "tokenExpiration: $($tokenExpiration)"

        if ($currentDateTimeEpoch -lt $tokenExpiration) {
            # Not expired
            $SSMValidAccessToken = $script:SSMJWT.access_token
        }
    }


    # Check if  SSMValidAccessToken was set. If not, get a new token
    if (-not($SSMValidAccessToken)) {
        # Tee up the json body
        $Body = (@{username = "$($script:Username)"; password = "$($script:Password)" }) | convertto-json
        
        # Get a new token
        $script:SSMJWT = Invoke-RestMethod -Uri $url -Body $Body -Method $Method -ContentType application/json
        Write-Verbose "API: Fetched $($script:SSMJWT.count) results."

        
        $SSMValidAccessToken = $script:SSMJWT.access_token
    }

    return $SSMValidAccessToken
}

# Used for all API interaction with SSM
function Invoke-SSMAPI {
    [cmdletbinding()] param(
        [Parameter(Mandatory = $false)][hashtable]$Body, 
        [Parameter(Mandatory = $true)][string]$Method, 
        [Parameter(Mandatory = $true)][string]$URI,
        [Parameter(Mandatory = $true)][string]$ContentType,
        [Parameter(Mandatory = $true)][string]$Max,
        [Parameter(Mandatory = $true)][string]$ResultSize
    )

    $Offset = 0
    $Results = @()
    do {
        remove-variable Result 2>$null

        $token = Get-SSMAuthToken
    
        $Headers = @{
            Authorization = "Bearer $token";
        }
                   
        # Call the API
        Write-Verbose "API URI: $($URI)"
        Write-Verbose "API Headers: $($Headers | convertto-json)"
        Write-Verbose "API Body: $($Body | convertto-json)"

        # Different parameters for different methods, I wanted to re-use this same invoke-ssmapi function
        switch ($Method) {
            "GET" { $Result = Invoke-RestMethod -Uri $Uri -Headers $Headers -method $Method -ContentType $ContentType }
            "POST" {
                $Result = Invoke-RestMethod -Uri $Uri -Headers $Headers -Body $($body | Convertto-json) -method $Method -ContentType $ContentType
                $Offset += $Max
                $Body["Offset"] = $Offset
            }
        }
               
        $Results += $Result
        
        if ($VerbosePreference) {
            $Global:APIResultVariable = $Results
        }

        # Different json response depending on the endpoint. FreshDesk ticket: https://saviynt.freshdesk.com/helpdesk/tickets/109164
        # if ($Result.Total) {
        #     $APITotalRecords = $Result.Total
        #     $APITotalFetchedCount = ($Results.displaycount | Measure-Object -Sum).sum
        #     Write-Verbose "API Fetched $($Result.displaycount) results"
        # } elseif ($Result.totalEntitlementCount) {
        #     $APITotalRecords = $Result.totalEntitlementCount
        #     $APITotalFetchedCount = ($Results.entitlementsCount | Measure-Object -Sum).sum
        #     Write-Verbose "API Fetched $($Result.entitlementsCount) results"
        # } elseif ($Result.totalTasks) {
        #     $APITotalRecords = $Result.totalTasks
        #     $APITotalFetchedCount = ($Results.totalRecords | Measure-Object -Sum).sum
        #     Write-Verbose "API Fetched $($Result.totalRecords) results"
        # }

        # We have to identify the type of json response since each call isn't a standard response set for paging
        if ($Result.totalTasks -gt 0) {  # tasks
            $APITotalRecords = $Result.totalTasks # The total number available
            $APITotalFetchedCount = ($Results.totalRecords | Measure-Object -Sum).sum # Sum of all fetched records
            $APIFetchedCount = $Result.totalRecords
            Write-Verbose "API Fetched $($APIFetchedCount) results"
        } elseif ($Result.totalEntitlementCount -gt 0) { # Entitlements
            $APITotalRecords = $Result.totalEntitlementCount
            $APITotalFetchedCount = ($Results.entitlementsCount | Measure-Object -Sum).sum
            $APIFetchedCount = $Result.entitlementsCount
            Write-Verbose "API Fetched $($APIFetchedCount) results"
        } elseif ($Results.totalcount -gt 0) { # getUsers
            $APITotalRecords = $Result.totalcount
            $APITotalFetchedCount = ($Results.displaycount | Measure-Object -Sum).sum
            $APIFetchedCount = $Result.displaycount
            Write-Verbose "API Fetched $($APIFetchedCount) results"      
        } else  { # ($Results.Total) catch all..  Accounts for sure
            $APITotalRecords = $Result.total
            $APITotalFetchedCount = ($Results.displaycount | Measure-Object -Sum).sum
            $APIFetchedCount = $Result.displaycount
            Write-Verbose "API Fetched $($APIFetchedCount) results"
        }
        

        Write-Verbose "API Total Records: $APITotalRecords"
        Write-Verbose "API Total Fetched Records: $APITotalFetchedCount"
        Write-Verbose "API Fetched Results are available in variable named `$Global:APIResultVariable"

        write-verbose "If $($APITotalFetchedCount) -lt $($ResultSize)"
        write-verbose "If $($APITotalFetchedCount) -ne $($APITotalRecords)"
        write-verbose "If $($APITotalRecords)"
    } while ( `
        ($Result.errorCode -eq 0) `
            -and ($APITotalFetchedCount -lt $ResultSize) <# Total amount fetched less than specified resultSize #> `
            -and ($APITotalFetchedCount -ne $APITotalRecords) `
            -and $APITotalRecords <# There are records in the response still #> )

    return $Results
}

# Retrieves SSM roles via search criteria
function Get-SSMRole {
    [cmdletbinding()] param(
        [Parameter(Mandatory = $false)][string]$Name, 
        [Parameter(Mandatory = $false)][switch]$IncludeEntitlementValues,
        [Parameter(Mandatory = $false)][switch]$IncludeUserDetails,
        [Parameter(Mandatory = $true)][int]$Max,
        [Parameter(Mandatory = $false)][hashtable]$AdditionalSearchCriteria,
        [Parameter(Mandatory = $false)][int]$ResultSize = $script:DefaultResultSize
    )
    
    $Uri = "https://$($script:Hostname)/ECM/api/v5/getRoles"

    $Offset = 0
    $Body = @{ }
    
    # Trim Max to match resultsize
    if ($ResultSize -lt $Max) { $Max = $ResultSize }

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
        }
        else {
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

    Write-Warning "Result set limited by max parameter. ResultSize parameter is ignored."
    $Results = @(Invoke-SSMAPI -Uri $Uri -Body $body -method POST -ContentType application/json -Max $Max -ResultSize $ResultSize)

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
    $Uri = "https://$($script:Hostname)/ECM/api/v5/getEntitlements"

    $Offset = 0
    $Body = @{ }
    
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
        $Body["entitlementfiltercriteria"] += @{entitlement_value = $Name }
    }

    $Results = @(Invoke-SSMAPI -Uri $Uri -Body $body -method POST -ContentType application/json -Max $Max -ResultSize $ResultSize)

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
    $Uri = "https://$($script:Hostname)/ECM/api/v5/getEndpoints"

    $Offset = 0
    $Body = @{ }
    
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
   
        # Call the API
        $Result = Invoke-RestMethod -Uri $Uri -Headers $Headers -Body $($body | Convertto-json) -method POST -ContentType application/json
        Write-Verbose "API: Fetched $($result.endpoints.count) results."

        $Offset += $Max  
        $Body["Offset"] = $Offset

        $Results += $Result
        $ResultsTotalCount = $Results.endpoints.Count
    } while (($Result.errorCode -eq 0) -and (Test-GetMoreResultsFromAPI -TotalCount $ResultsTotalCount -ResultSize $ResultSize -Max $Max))

    return $Results.endpoints | Select-Object -First $ResultSize
}

# Get security systems
function Get-SSMSecuritySystem {
    [cmdletbinding()] param(
        [Parameter(Mandatory = $false)][string]$Name, 
        [Parameter(Mandatory = $false)][string]$ConnectionType, 
        [Parameter(Mandatory = $false)][string]$connectionName,         
        [Parameter(Mandatory = $false)][int]$Max = 50,
        [Parameter(Mandatory = $false)][int]$ResultSize = $script:DefaultResultSize
    )
    $Uri = "https://$($script:Hostname)/ECM/api/v5/getSecuritySystems"

    $Offset = 0
    $Body = @{ }
    
    # Append the max and offset, this gets updated for each search
    $Body["max"] = $Max
    $Body["offset"] = $Offset
   
    $QueryStringParameters = @{ }
    
    if ($ConnectionType) {
        $QueryStringParameters.Add("connectionType", $ConnectionType)
    }

    if ($connectionName) {
        $QueryStringParameters.Add("connectionname", $connectionName)
    }

    if ($Name) {
        $QueryStringParameters.Add("systemname", $Name)
    }
    
    $Uri = New-HttpQueryString -Uri $Uri -QueryParameter $QueryStringParameters

    $Results = @(Invoke-SSMAPI -Uri $Uri -method GET -ContentType application/json -Max $Max -ResultSize $ResultSize)

    return $Results.securitySystemDetails | Select-Object -First $ResultSize
}

# Get ARS tasks
function Get-SSMTask {
    [cmdletbinding()] param(
        [Parameter(Mandatory = $false)][int]$TaskId, 
        [Parameter(Mandatory = $false)][string][ValidateSet("PENDING", "COMPLETED", "COMPLETED_AND_DISCONTINUE")]$TaskStatus, 
        [Parameter(Mandatory = $false)][int]$SecuritySystemKey, 
        [Parameter(Mandatory = $false)][string]$Endpoint,
        [Parameter(Mandatory = $false)][int]$Max = 50,
        [Parameter(Mandatory = $false)][hashtable]$FilterCriteria,
        [Parameter(Mandatory = $false)][int]$ResultSize = $script:DefaultResultSize
    )

    $Uri = "https://$($script:Hostname)/ECM/api/v5/fetchTasks"

    $Offset = 0
    $Body = @{ }
    
    # Append the max and offset, this gets updated for each search
    $Body["max"] = $Max
    $Body["offset"] = $Offset

    
    if ($TaskId) {
        $Body["taskid"] = $TaskId
    }

    if ($TaskStatus) {
        $Body["TASKSTATUS"] = $TaskStatus
    }

    if ($Endpoint) {
        $Body["endpointname"] = $Endpoint
    }

    if ($SecuritySystem) {
        $Body["securitysystem"] = $SecuritySystemKey
    }
    
    $Results = @(Invoke-SSMAPI -Uri $Uri -Body $Body -method POST -ContentType application/json -Max $Max -ResultSize $ResultSize)
    # TODO: Verify max works correctly. Submitted a bug here, Saviynt ignores max parameter. https://saviynt.freshdesk.com/support/tickets/48855

    return $Results.tasks | Select-Object -First $ResultSize
}

# Get ARS task details
function Get-SSMTaskDetail {
    [cmdletbinding()] param(
        [Parameter(Mandatory = $true)][int]$TaskId
    )

    $Uri = "https://$($script:Hostname)/ECM/api/v5/checkTaskStatus"

    $Body = @{ }
       
    if ($TaskId) {
        $Body["taskid"] = $TaskId
    }

    $token = Get-SSMAuthToken

    $Headers = @{
        Authorization = "Bearer $token";
    }

    # Call the API
    $Result = Invoke-RestMethod -Uri $Uri -Headers $Headers -Body $($Body | Convertto-json) -method POST -ContentType application/json
    Write-Verbose "API: Fetched $($Result.count) results."

    return $Result
}
# THROW "FINSIH SSMTASKDETAIL"

# Get SSM User Details
function Get-SSMUser {
    [cmdletbinding()] param(
        [Parameter(Mandatory = $false)][string]$Username, 
        [Parameter(Mandatory = $false)][string]$Email, 
        [Parameter(Mandatory = $false)][int]$Max = 500,
        [Parameter(Mandatory = $false)][hashtable]$FilterCriteria,
        [Parameter(Mandatory = $false)][array]$ResponseFields,
        [Parameter(Mandatory = $false)][int]$ResultSize = $script:DefaultResultSize
    )

    $Uri = "https://$($script:Hostname)/ECM/api/v5/getUser"

    $Offset = 0
    $Body = @{ }
    
    # Append the max and offset, this gets updated for each search
    $Body["max"] = $Max
    $Body["offset"] = $Offset

    if ($username -or $Email -or $FilterCriteria) {
        if ($Username) {
            $Body["username"] = $Username
        }
    
        if ($Email) {
            $FilterCriteria += @{"email"="$($Email)"}
            #$Body["email"] = $Email
        }
    
        if ($FilterCriteria) {
            $Body["filtercriteria"] = $FilterCriteria
        }    
    }
    else {
        Write-Warning  "Fetching all users since Username, Email, and FilterCriteria aren't used"
        $Body["filtercriteria"] = @{"username"="*"}
    }
    
    if ($ResponseFields) {
        $Body["responsefields"] = $ResponseFields
    }

    $Results = @(Invoke-SSMAPI -URI $Uri -Method "POST" -Body $Body -ContentType application/json -ResultSize $ResultSize -Max $Max)
    
    if ($Results.userdetails.Length -gt $Results.userlist.Length) {
        return $Results.userdetails | Select-Object -First $ResultSize
    }
    else {
        return $Results.userlist | Select-Object -First $ResultSize
    }
}

# Get SSM accounts
function Get-SSMAccount {
    [cmdletbinding()] param(
        [Parameter(Mandatory = $false)][string]$Username, 
        [Parameter(Mandatory = $false)][string]$Endpoint, 
        [Parameter(Mandatory = $false)][hashtable]$AdditionalSearchCriteria,
        [Parameter(Mandatory = $false)][int]$Max = 500,
        [Parameter(Mandatory = $false)][int]$ResultSize = $script:DefaultResultSize
    )

    $Uri = "https://$($script:Hostname)/ECM/api/v5/getAccounts"

    $Offset = 0
    $Body = @{ }
    
    # Append the max and offset, this gets updated for each search
    $Body["max"] = $Max
    $Body["offset"] = $Offset

    if ($Username) {
        $Body["username"] = $Username
    }

    if ($Endpoint) {
        $Body["endpoint"] = $Endpoint
    }

    # Add all the custom search fields
    if ($AdditionalSearchCriteria) {
        $Body["advsearchcriteria"] = $AdditionalSearchCriteria | ConvertTo-Json # I believe this is formatted correctly but there's a bug in 5.3 that prevents advsearchcriteria from functioning.
    }

    $Results = @(Invoke-SSMAPI -URI $Uri -Method "POST" -Body $Body -ContentType application/json -ResultSize $ResultSize -Max $Max)

    return $Results.accountdetails | Select-Object -First $ResultSize
}

# Check if we should run again to get more results
function Test-GetMoreResultsFromAPI {
    [cmdletbinding()] param(
        [Parameter(Mandatory = $true)][int]$TotalCount, 
        [Parameter(Mandatory = $true)][int]$ResultSize, 
        [Parameter(Mandatory = $true)][int]$Max
    )

    if ($TotalCount -lt $ResultSize) {
        # Data count less than intended ResultSize
        if ($TotalCount -lt $Max) {
            # Got no data or ran out of data
            $Continue = $False
        }
        else {
            # Data count is less than max param
            $Continue = $true
        }
    }
    else {
        # Data count more than ResultSize
        $Continue = $false
    }

    # If true, then the calling function will get more results from the api
    return $Continue
}

function Test-GetMoreResultsFromAPI2 {
    [cmdletbinding()] param(
        [Parameter(Mandatory = $true)][int]$APITotalCount, 
        [Parameter(Mandatory = $true)][int]$APIFetchedCount, 
        [Parameter(Mandatory = $true)][int]$Max,
        [Parameter(Mandatory = $true)][int]$ResultSize
    )
    if ($FetchedAPICount -lt $ResultSize) {
        # Not limited on purpose by the user

    }
    if ($TotalCount -lt $ResultSize) {
        # Data count less than intended ResultSize
        if ($TotalCount -lt $Max) {
            # Got no data or ran out of data
            $Continue = $False
        }
        else {
            # Data count is less than max param
            $Continue = $true
        }
    }
    else {
        # Data count more than ResultSize
        $Continue = $false
    }

    # If true, then the calling function will get more results from the api
    return $Continue
}


# Get a list of SSM SAV_ROLES
function Get-SSMSavRole {
    [cmdletbinding()] param(
        [Parameter(Mandatory = $false)][string]$Username, 
        [Parameter(Mandatory = $false)][int]$ResultSize = $script:DefaultResultSize
    )

    $Max = 5
    $Uri = "https://$($script:Hostname)/ECM/api/v5/getSavRoles"

    if ($Username) {
        # SSM API expects this parameter to be in the body, but since we're doing a GET we shouldn't send a body.
        # Querystring worked in my testing, so I went with this model instead. Submitted a ticket as documentation defect.
        # https://saviynt.freshdesk.com/support/tickets/49189
        $Uri += "?username=$($Username)"
    }

    $Results = @()
    do {
        $token = Get-SSMAuthToken

        $Headers = @{
            Authorization = "Bearer $token";
        }
   
        # Call the API
        $Result = Invoke-RestMethod -Uri $Uri -Headers $Headers -Method GET
        Write-Verbose "API: Fetched $($Result.savRoles.count) results."
               
        $Results += $Result
        $ResultsTotalCount = $Results.savRoles.Count
    } while (($Result.errorCode -eq 0) -and (Test-GetMoreResultsFromAPI -TotalCount $ResultsTotalCount -ResultSize $ResultSize -Max $Max))

    return $Results.savRoles | Select-Object -First $ResultSize
}


# Mark a task completed with provisioning comments
function Complete-SSMTask {
    [cmdletbinding()] param(
        [Parameter(Mandatory = $true)][int]$TaskId#, 
        #[Parameter(Mandatory = $false)][string]$Comments  # Doesn't seem to work. Commenting out for now, opened a ticket with Saviynt.
    )

    $Uri = "https://$($script:Hostname)/ECM/api/v5/completetask"

    $Body = @{ }
    $Body["taskid"] = $TaskId
    $Body["provisioning"] = "true"

    if ($Comments) {
        $Body["comments"] = $Comments
    }

    $token = Get-SSMAuthToken

    $Headers = @{
        Authorization = "Bearer $token";
    }

    Write-Verbose "Body: $($body | Convertto-json)"
    # Call the API
    $Result = Invoke-RestMethod -Uri $Uri -Headers $Headers -Body $($body | Convertto-json) -method POST -ContentType application/json
    Write-Verbose "API: Fetched $($result.count) results."
            
    return $Result.result
}


# Mark a task discontinued with comments
function Discontinue-SSMTask {
    [cmdletbinding()] param(
        [Parameter(Mandatory = $true)][int]$TaskId, 
        [Parameter(Mandatory = $true)][string]$Comments  # Doesn't seem to work. Commenting out for now, opened a ticket with Saviynt.
    )

    $Uri = "https://$($script:Hostname)/ECM/api/v5/discontinueTask"

    $taskkeytodiscontinue = @{ }
    $taskkeytodiscontinue["discontinueassociatedtask"] = "true"
    $taskkeytodiscontinue["taskid"] = "$($TaskId)"

    if ($Comments) {
        $taskkeytodiscontinue["comments"] = $Comments
    }
      
    
    $Body = @{ }
    $Body["taskkeytodiscontinue"] = @($taskkeytodiscontinue) # I don't support multiple taskIDs at once. Sorry.

    $token = Get-SSMAuthToken

    $Headers = @{
        Authorization = "Bearer $token";
    }

    Write-Verbose "Body: $($body | Convertto-json)"
    # Call the API
    $Result = Invoke-RestMethod -Uri $Uri -Headers $Headers -Body $($body | Convertto-json) -method POST -ContentType application/json
    Write-Verbose "API: Fetched $($result.count) results."
            
    return $Result.result
}


# Manipulate SSM accounts
function Update-SSMAccount {
    [cmdletbinding()] param(
        [Parameter(Mandatory = $true)][string]$Name, 
        [Parameter(Mandatory = $true)][string]$Endpoint,
        [Parameter(Mandatory = $true)][string]$SecuritySystemName,
        [Parameter(Mandatory = $true)][hashtable]$AttributesToModify
    )

    $Uri = "https://$($script:Hostname)/ECM/api/v5/updateAccount"

    $token = Get-SSMAuthToken

    $Body = @{ }
    $Body["name"] = $Name
    $Body["endpoint"] = $Endpoint
    $Body["securitysystem"] = $SecuritySystemName

    $Headers = @{
        Authorization = "Bearer $token";
    }

    # Add the attributes to modify
    foreach ($key in $AttributesToModify.GetEnumerator()) {
        $Body[$key.Name] = $Key.Value
    }

    Write-Verbose "Body: $($body | Convertto-json)"
    # Call the API
    $Result = Invoke-RestMethod -Uri $Uri -Headers $Headers -Body $($body | Convertto-json) -method POST -ContentType application/json
    Write-Verbose "API: Messsage and errorcode: $($result.errorcode):$($result.message)."
            
    if ($result.errorCode -eq 0) {
        return
    }
    else {
        Write-Error -ERroraction Stop "Failed to update account. ErrorCode: $($result.errorcode), $($result.message)"
    }
}


# Assign SSM accounts to a owner (user)
function Set-SSMAccountOwner {
    [cmdletbinding()] param(
        [Parameter(Mandatory = $true)][string]$AccountName, 
        [Parameter(Mandatory = $true)][string]$Endpoint,
        [Parameter(Mandatory = $true)][string]$SecuritySystem,
        [Parameter(Mandatory = $true)][string]$Username
    )

    $Uri = "https://$($script:Hostname)/ECM/api/v5/assignAccountToUser"

    $token = Get-SSMAuthToken

    $Body = @{ }
    $Body["accountname"] = $AccountName
    $Body["endpoint"] = $Endpoint
    $Body["securitysystem"] = $SecuritySystem
    $Body["username"] = $Username

    $Headers = @{
        Authorization = "Bearer $token";
    }

    Write-Verbose "Body: $($body | Convertto-json)"
    # Call the API
    $Result = Invoke-RestMethod -Uri $Uri -Headers $Headers -Body $($body | Convertto-json) -method POST -ContentType application/json
    Write-Verbose "API: Messsage and errorcode: $($result.errorcode):$($result.message)."
            
    if ($result.errorCode -eq 0) {
        return
    }
    else {
        Write-Error -ERroraction Stop "Failed to assign account. ErrorCode: $($result.errorcode), $($result.message)"
    }
}


# Manipulate SSM accounts
function Update-SSMUser {
    [cmdletbinding()] param(
        [Parameter(Mandatory = $true)][string]$Username, 
        [Parameter(Mandatory = $false)][bool]$InlineRuleEvaluation = $true,
        [Parameter(Mandatory = $false)][ValidateSet(0, 1)]$StatusKey,
        [Parameter(Mandatory = $false)][string]$UpdatedUsername, 
        [Parameter(Mandatory = $false)][hashtable]$AttributesToModify
    )

    $Uri = "https://$($script:Hostname)/ECM/api/v5/updateUser"

    $token = Get-SSMAuthToken

    $Headers = @{
        Authorization = "Bearer $token";
    }

    $Body = @{ }
    if ($Username) { $Body["username"] = $Username }
    if ($StatusKey.Length -gt 0) { $Body["statuskey"] = $StatusKey }
    if ($UpdatedUsername) { $Body["updatedusername"] = $UpdatedUsername }
    switch ($InlineRuleEvaluation) {
        $True { $Body["inlineruleevaluation"] = "true" }
        $False { $Body["inlineruleevaluation"] = "false" }
    }

    # Add the attributes to modify
    if ($AttributesToModify) {
        foreach ($key in $AttributesToModify.GetEnumerator()) {
            $Body[$key.Name] = $Key.Value
        }    
    }
    
    Write-Verbose "Body: $($body | Convertto-json)"
    # Call the API
    $Result = Invoke-RestMethod -Uri $Uri -Headers $Headers -Body $($body | Convertto-json) -method POST -ContentType application/json
    Write-Verbose "API: Messsage and errorcode: $($result.errorcode):$($result.message)."

    if ($result.errorCode -eq 0) {
        return
    }
    else {
        Write-Error -ERroraction Stop "Failed to update user. ErrorCode: $($result.errorcode), $($result.message)"
    }
}

Export-ModuleMember -function *-SSM*