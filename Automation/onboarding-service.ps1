function buildConfiguration(){

    $config = Get-Content '.\config.json' | Out-String | ConvertFrom-json

    $confHash = [PSCustomObject]$config

    $authnMethod = $confHash.authn.type

    # Check authn methods, starting with apikey [not recommended]
    # Api Key is for demonstration or testing purposes only
    if ( $authnMethod -eq 'apikey') {

        # Check if username is null
        if ( $null -eq $confHash.conjur.host ) {

            Write-Host "No host found, please update Conjur section in config.json"

        } else {

            # Check if password is null
            if ( $null -eq $confHash.conjur.apikey ){

                Write-Host "No Api Key found, please update Conjur section in config.json"

            } else {

                # Build psCredentialObject
                $userName = $confHash.conjur.host
                [securestring]$pass = ConvertTo-SecureString $confHash.conjur.apikey -AsPlainText -Force
                [pscredential]$credentials = New-Object System.Management.Automation.PSCredential ($userName, $pass)
                $idType = "user"

            }

        } 

    }

    $conjur = New-Object PSObject -Property @{
        conjurCredential = $credentials
        master = $confHash.conjur.master
        follower = $confHash.conjur.follower
        account = $confHash.conjur.account
        hostBranch = $confHash.conjur.hostBranch
        id = $idType
        cleanup = $confHash.conjur.cleanup
    }
    $pvwa = New-Object PSObject -Property @{
        url = $confHash.pvwa.url
        logon = $confHash.pvwa.login
        pass = $confHash.pvwa.password
        platform = $confHash.pvwa.platform
    }

    $config = New-Object psobject -Property @{
        conjur = $conjur
        pvwa = $pvwa
    }

    log "Succesfully built Configuration"
    return $config

}

function Get-Spacing($functionName){

    try  {

        $spacing = 15 - $functionName.length
        " " * $spacing

    } catch {

        "    "
    }

}

function log(){
    param(
        $message,
        $functionName = $true
    )

    if ($functionName){

        $functionName = (Get-PSCallStack)[1].Command
        $spacing = Get-Spacing $functionName
        $message = "$functionName()$($spacing): $message"
    }

    Write-Host $message
    Write-EventLog -LogName "Application" -Source "Conjur Onboarding Service" -EventID 43868 -EntryType Information -Message $message
}

function parseEntity( $e, $s ){

    log -message "Parsing $e"

    $option = [System.StringSplitOptions]::RemoveEmptyEntries

    $returnEntity = $e.split("{$s}", $option)

    return $returnEntity

}

function getConjurToken( $account, $cred, $url ){
    
    # Disable SSL Verification for this function + call
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"

    $headers.Add("Accept-Encoding", "base64")
    $headers.Add("Content-Type", "text/plain")

    $encodedLogin = [System.Web.HttpUtility]::UrlEncode($cred.UserName)

    try {

        $authn_response = Invoke-RestMethod -UseBasicParsing -Headers $headers -Uri "https://$url/authn/$account/$encodedLogin/authenticate" -Method POST -Body $cred.GetNetworkCredential().password

        return $authn_response

    } catch {

        Write-Host $_

    }
    

}

function getGroups( $token, $url, $account ){

    # Disable SSL Verification for this function + call
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"

    $headers.Add("Authorization", "Token token=`"$token`"")
    
    $queryParams = @{
        kind = "group"
        search = "delegation/consumers"
    }

    try {

        $groups = Invoke-RestMethod -Uri "https://$url/resources/$account" -Body $queryParams -Method GET -Headers $headers

        log "Successfully retrieved groups"

        return $groups

    } catch {

        log $_

    }


}

function testGroup( $group, $token, $url, $account ){

    # Disable SSL Verification for this function + call
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"

    $headers.Add("Authorization", "Token token=`"$token`"")

    try {


        log "Attempting to retrieve memberships of $group"

        $members = Invoke-RestMethod -Uri "https://$url/roles/$account/group/$group" -Method GET -Headers $headers

        $membersHash = [PSCustomObject]$members

        log "Successfully retrieved memberships of $group"

        return $membersHash

    } catch {

        log $_

    }

}

function PVWA-Login( $pvwaInfo ){
    
    # PVWA Functions
    $PVWAUSR    = $pvwaInfo.logon
    $PVWAPASS   = $pvwaInfo.pass
    $PVWAURL    = $pvwaInfo.url

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/json")

    $body = "{
        `"username`": `"$PVWAUSR`",
        `"password`": `"$PVWAPASS`"
    }"

    $pvwa_uri = "https://$PVWAURL/PasswordVault/API/auth/Cyberark/Logon"

    try {
        
        log "Attempting to log into PVWA"

        $pvwa_authn_token = Invoke-RestMethod -Uri $pvwa_uri -Method POST -Headers $headers -Body $body
        
        log "Successfully logged into PVWA"
        return $pvwa_authn_token

    } catch {

        log $_
        exit
    }

}

function PVWA-LogOff($pvwa_authn_token, $uri){

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "$pvwa_authn_token")

    $pvwa_uri = "https://$uri/PasswordVault/API/Auth/Logoff"

    $response = Invoke-RestMethod -Uri $pvwa_uri -Method POST -Headers $headers

    Log "Closed PVWA Session"

}

function pasOnboard( $pvwaInfo, $hostRef, $safeRef, $conjUrl, $conjAccount ){

    $pvwa_url = $pvwaInfo.url
    $pvwa_platform = $pvwaInfo.platform
    log "Processing request for $safeRef"

    try {

        log "Parsing properties for $safeRef"

        $hostObj = [pscustomobject]$hostRef

        $hostObj.created_roles | foreach-object {

            foreach ( $property in $_.PSObject.Properties ) {

                log $property

                if ( $property.value -like "*host:$branch*" ) {

                    $TARGETHOST = $property.value.id
                    $TARGETKEY  = $property.value.api_key

                }
            }
        }

        $parseID = parseEntity $TARGETHOST ":"

        $conjAddr = "$($conjUrl):443"
        $nameParts = @($($parseID[2]).Split("/"))
        $objName = $nameParts[$nameParts.GetUpperBound(0)]

        $bodyData = @{address=$conjAddr
                      Name=$objName
                      userName=$($parseID[2])
                      platformId=$pvwa_platform
                      safeName=$safeRef                                            
                      PlatformAccountProperties=@{AWSAccessKeyID="na"}
                      secret=$TARGETKEY
        }

        $bodyJson = ConvertTo-Json -InputObject $bodyData

        log "Retrieving PVWA token from $pvwa_url"
        $SESSION_TOKEN = PVWA-Login -pvwaInfo $pvwaInfo

        $pvwa_uri = ("https://" + $pvwa_url + "/PasswordVault/api/Accounts")
        
        $headers = @{authorization=$SESSION_TOKEN}
        $response = Invoke-RestMethod -Uri $pvwa_uri -Method 'POST' -ContentType "application/json" -Headers $headers -Body $bodyJson # $body

        log "Closing connection to $pvwa_url"
        PVWA-LogOff -pvwa_authn_token $SESSION_TOKEN -uri $pvwa_url

        return $true

    } catch {

        log $_

        return $false

    }
    
}

function createHost( $thisHost, $token, $url, $account, $branch, $cleanup ){

    # Disable SSL Verification for this function + call
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"

    $headers.Add("Authorization", "Token token=`"$token`"")
    $headers.Add("Content-Type","text/yaml")

    $t = Get-Date -Format o | ForEach-Object { $_ -replace ":", "." }

    $fileName = "tmp/$t.$thisHost.declare.yml"

    $hostDeclare    = "- !host"
    $hostId         = "  id: $thisHost"
    $annoLine       = "  annotations:"
    $annoSign       = "    automation_creation_time: Created via Automation on $t"
    $whitespace     = ""
    $grantDeclare   = "- !grant"
    $grantRole      = "  role: !group authenticators"
    $grantMember    = "  member: !host $thisHost"

    try {

        log "Building host data for $thisHost"

        $hostFileTemp = New-Item -ItemType "File" -Force $fileName

        Add-Content $fileName -Encoding ASCII -Value $hostDeclare
        Add-Content $fileName -Encoding ASCII -Value $hostId
        Add-Content $fileName -Encoding ASCII -Value $annoLine
        Add-Content $fileName -Encoding ASCII -Value $annoSign
        Add-Content $fileName -Encoding ASCII -Value $whitespace
        Add-Content $fileName -Encoding ASCII -Value $grantDeclare
        Add-Content $fileName -Encoding ASCII -Value $grantRole
        Add-Content $fileName -Encoding ASCII -Value $grantMember

        # This will prevent windows from reformating the file and giving us properly formatted yaml, avoiding a 422 from Conjur
        $body = Get-Content -Path $hostFileTemp -Raw

        log "Attempting to onboard $thisHost to $branch"
        $result = Invoke-RestMethod -Uri "https://$url/policies/$account/policy/$branch" -Method PATCH -Headers $headers -Body $body

        $jsonResult = $result | ConvertTo-Json

        # Cleanup after use
        if ( $cleanup -eq "true" ){

            log "Cleaning up local cache"
            Remove-Item -Path $hostFileTemp -Force
            
            log "Successfully onboarded host"
            return $jsonResult

        } else {

            log "Successfully onboarded host"
            return $jsonResult

        }

    } catch {

        log $_

    }

}

function createEntitlement( $thisHost, $token, $url, $account, $branch, $hostBranch, $cleanup ){

        # Disable SSL Verification for this function + call
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    
        $headers.Add("Authorization", "Token token=`"$token`"")
        $headers.Add("Content-Type","text/yaml")
    
        $t = Get-Date -Format o | ForEach-Object { $_ -replace ":", "." }
    
        $fileName = "tmp/$t.$thisHost.entitlements.yml"

        $commentLine    = "# Loaded $thisHost into $branch"
        $grantDeclare   = "- !grant"
        $grantRole      = "  role: !group consumers"
        $grantMember    = "  member: !host /$hostBranch/$thisHost"
    
        try {
            
            log "Attempting to entitle $thisHost to $branch/consumers"
            $hostFileTemp = New-Item -ItemType "File" -Force $fileName
    
            Add-Content $fileName -Encoding ASCII -Value $commentLine
            Add-Content $fileName -Encoding ASCII -Value $grantDeclare
            Add-Content $fileName -Encoding ASCII -Value $grantRole
            Add-Content $fileName -Encoding ASCII -Value $grantMember
    
            # This will prevent windows from reformating the file and giving us properly formatted yaml, avoiding a 422 from Conjur
            $body = Get-Content -Path $hostFileTemp -Raw

            $result = Invoke-RestMethod -Uri "https://$url/policies/$account/policy/$branch" -Method PATCH -Headers $headers -Body $body
    
            # Cleanup after use
             if ( $cleanup -eq "true" ){
                
                log "Cleaning up local cache"
                Remove-Item -Path $hostFileTemp -Force
                log "Successfully entitled $thisHost"
                return $result
            
            } else {

                log "Successfully entitled $thisHost"
                return $result
            
            }
    
        } catch {
    
            log $_
    
        }

}

function build(){

    log "Attempting to build Configuration"
    # implement configuration handling
    $conf = buildConfiguration

    log "Instantiating Conjur Configuration"
    # instantiate conjur configuration
    $conjurConfig = $conf.conjur

    log "Instantiating PVWA Configuration"
    # instantiate pas configuration
    $pvwaConfig = $conf.pvwa

    log "Retrieving initial token"
    # retrieve token
    $token = getConjurToken -account $conjurConfig.account -cred $conjurConfig.conjurCredential -url $conjurConfig.follower

    log "Attempting to retrieve delegation groups"
    # capture groups
    $groups = getGroups -token $token -url $conjurConfig.follower -account $conjurConfig.account

    # test groups
    foreach ( $g in $groups ) {

        # Parse raw entity, separating at : to get safe path, the second index of the array. Assign this to new variable for use
        $groupEntity = parseEntity -e $g.id -s ":"
        $thisGroup = $groupEntity[2]
        
        # Parse Safe from group entity, This array represents the path to the group we are trying to construct. 2nd element of the 
        # array represents the safe name. Build object to onboard if needed
        $thisSafe = parseEntity -e $thisGroup -s "/"

        $vaultName = $thisSafe[0]
        $lobName = $thisSafe[1]
        $delPath = "delegation"
        $safeName = $thisSafe[2]

        # Entitlement Path
        $tarEntitlementPath = $vaultName + "/" + $lobName + "/" + $safeName + "/" + $delPath

        $members = testGroup -group $thisGroup -token $token -url $conjurConfig.follower -account $conjurConfig.account

        $membershipLength = $members.members.length
        
        if ( $membershipLength -eq 1 ){

            log "Found group membership equal to 1 for $safeName. Checking $safeName qualifies for onboarding"

            if ( $members.members.admin_option -eq "True" ){

                log "Creating Host for $safeName"

                # Request Admin Token to write policy
                log "Attempting to authenticate to leader"
                $adminToken = getConjurToken -account $conjurConfig.account -cred $conjurConfig.conjurCredential -url $conjurConfig.master

                log "Successfully authenticated to leader"
                log "Attempgint to create host"

                $created = createHost -thisHost $safeName -url $conjurConfig.master -account $conjurConfig.account -branch $conjurConfig.hostBranch -token $adminToken -cleanup $conjurConfig.cleanup

                $parsed = $created | ConvertFrom-Json

                log "Host onboarded to Conjur, onboarding to PVWA"
                $onboarded = pasOnboard -hostRef $parsed -pvwaInfo $pvwaConfig -safeRef $safeName -conjUrl $conjurConfig.master

                # CHECK:
                #   Is this the correct logic we want to implement, or should we first onboard the entitlement with recovery 
                #   of an api key as a secondary thought

                if ( $onboarded ) {
                    
                    log "Entitling new host"
                    $entitled = createEntitlement -thisHost $safeName -branch $tarEntitlementPath -url $conjurConfig.master -account $conjurConfig.account -token $adminToken -hostBranch $conjurConfig.hostBranch -cleanup $conjurConfig.cleanup
                    log $entitled

                }

            }

        }

    }

}

build