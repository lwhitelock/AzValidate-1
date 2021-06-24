function New-PartnerAccessToken {
    param (
        [String]$ApplicationId,
        [PSCredential]$Credential,
        [String]$RefreshToken,
        [String]$Scopes,
        [string]$Tenant
    )

    $AuthBody = @{
        client_id     = $ApplicationId
        scope         = $Scopes
        refresh_token = $RefreshToken
        grant_type    = "refresh_token"
        client_secret = ConvertFrom-SecureString $Credential.password -AsPlainText
    }

    if ($tenant) {
        $Uri = "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token"
    }
    else {
        $Uri = "https://login.microsoftonline.com/common/oauth2/v2.0/token"  
    }


    try {
        $ReturnCred = (Invoke-WebRequest -uri $Uri -ContentType "application/x-www-form-urlencoded" -Method POST -Body $AuthBody -ea stop).content | convertfrom-json
    }
    catch {
        Write-Error "Authentication Error Occured $_"
    }

    $ParsedCred = @{
        AccessToken = $ReturnCred.Access_Token
    }

    Return $ParsedCred

}

function Get-GraphPagedResult {
    param(
        $Headers,
        $Uri
    )
    $Results = do {
        $Results = Invoke-RestMethod -Headers $Headers -Uri $Uri  -Method "GET" -ContentType "application/json"
        if ($Results.value) {
            $Results.value
        }
        else {
            $Results
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))
    return $Results
}

function get-clientaccess {
    param(
        $uri,
        $body,
        $count = 1
    )
    try {
        $ClientToken = Invoke-RestMethod -Method post -Uri $uri -Body $body -ea stop
    }
    catch {
        if ($count -lt 10) {
            Write-Host "AppSecret not active yet attempting again: $count"
            $count++
            Start-Sleep 1
            $ClientToken = get-clientaccess -uri $uri -body $body -count $count
        }
        else {
            Throw "Could not get Client Token: $_"
        }
    }
    return $ClientToken
}
function New-MFARequest {
    param (
        [string]$EmailToPush
    )

    ######### Secrets #########
    $ApplicationId = $ENV:ApplicationID
    $ApplicationSecret = $ENV:ApplicationSecret
    $RefreshToken = $ENV:Refreshtoken
    ######### Secrets #########
    write-host "Creating credentials and tokens." -ForegroundColor Green
    Write-Host "1: $(Get-Date)"
    $credential = New-Object System.Management.Automation.PSCredential($ApplicationId, ($ApplicationSecret | Convertto-SecureString -AsPlainText -Force))
    Write-Host "2: $(Get-Date)"
    
    $UserTenantName = $EmailToPush -split '@' | Select-Object -last 1
    $UserTenantGUID = (Invoke-WebRequest "https://login.windows.net/$UserTenantName/.well-known/openid-configuration" | ConvertFrom-Json).token_endpoint.Split('/')[3] 
    $CustGraphToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes "https://graph.microsoft.com/.default" -ServicePrincipal -Tenant $UserTenantGUID
    $Header = @{
        Authorization = "Bearer $($CustGraphToken.AccessToken)"
    }
    Write-Host "3: $(Get-Date)"

    $MFAAppID = '981f26a1-7f43-403b-a875-f8b09b8cd720'
    
    write-host "Finding or Creating Service Principal" -ForegroundColor Green
    $graphApiVersion = "v1.0"
    $resource = "servicePrincipals"
    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
    $SPResult = Get-GraphPagedResult -Uri $uri -Headers $Header
    $SPID = ($SPResult | where-object { $_.appId -eq $MFAAppID }).id

    if (!$SPID) {
        Write-Host "Creating Service Principal"
        $SPBody = @{
            appId = $MFAAppID
        }
        $SPJson = $SPBody | ConvertTo-Json
        $resource = "servicePrincipals"
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $SPID = (Invoke-RestMethod -Uri $uri -Headers $Header -Method POST -ContentType "application/json" -body $SPJson).id
    }

    Write-Host "Creating Temporary Password"
    $expire = ((Get-Date).addminutes(5)).ToUniversalTime()
    $expireString = "$(Get-Date($expire) -Format s)Z"
    $start = ((Get-Date).addminutes(-5)).ToUniversalTime()
    $startString = "$(Get-Date($start) -Format s)Z"
    
    $PassReqBody = @{
        "passwordCredential" = @{
            "displayName"   = "MFA Temporary Password"
            "endDateTime"   = $expireString
            "startDateTime" = $startString
        }
    }
    $PassReqJSON = $PassReqBody | convertto-json -Depth 10

    $Resource = "servicePrincipals/$SPID/addPassword"
    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
    $TempPass = (Invoke-RestMethod -Uri $uri -Headers $Header -Method POST -body $PassReqJSON -ContentType "application/json").secretText
    Start-Sleep 5
    Write-Host "6: $(Get-Date)"
    
    write-host "Generating XML" -ForegroundColor Green

    $XML = @"
<BeginTwoWayAuthenticationRequest>
<Version>1.0</Version>
<UserPrincipalName>$EmailToPush</UserPrincipalName>
<Lcid>en-us</Lcid><AuthenticationMethodProperties xmlns:a="http://schemas.microsoft.com/2003/10/Serialization/Arrays"><a:KeyValueOfstringstring><a:Key>OverrideVoiceOtp</a:Key><a:Value>false</a:Value></a:KeyValueOfstringstring></AuthenticationMethodProperties><ContextId>69ff05bf-eb61-47f7-a70e-e7d77b6d47d0</ContextId>
<SyncCall>true</SyncCall><RequireUserMatch>true</RequireUserMatch><CallerName>radius</CallerName><CallerIP>UNKNOWN:</CallerIP></BeginTwoWayAuthenticationRequest>
"@

    $body = @{
        'resource'      = 'https://adnotifications.windowsazure.com/StrongAuthenticationService.svc/Connector'
        'client_id'     = $MFAAppID
        'client_secret' = $TempPass
        'grant_type'    = "client_credentials"
        'scope'         = "openid"
    }
    Write-Host "7: $(Get-Date)"

    $ClientUri = "https://login.microsoftonline.com/$UserTenantGUID/oauth2/token"
    $ClientToken = get-clientaccess -Uri $ClientUri -Body $body
    
    
    $ClientHeaders = @{ "Authorization" = "Bearer $($ClientToken.access_token)" }
    write-host "Generating MFA Request" -ForegroundColor Green
    
    Write-Host "8: $(Get-Date)"
    $obj = Invoke-RestMethod -uri 'https://adnotifications.windowsazure.com/StrongAuthenticationService.svc/Connector//BeginTwoWayAuthentication' -Method POST -Headers $ClientHeaders -Body $XML -ContentType 'application/xml'

    if ($obj.BeginTwoWayAuthenticationResponse.AuthenticationResult -ne $true) {
        return "Authentication failed. does the user have Push/Phone call MFA configured? Errorcode: $($obj.BeginTwoWayAuthenticationResponse.result.value | out-string)"
    }
    if ($obj.BeginTwoWayAuthenticationResponse.result) {
        return "Received a MFA confirmation: $($obj.BeginTwoWayAuthenticationResponse.result.value | Out-String)"
    }
}
