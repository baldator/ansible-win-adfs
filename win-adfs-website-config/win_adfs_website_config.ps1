#!powershell

# Copyright: (c) 2019, Marco Torello (@baldator) <marcotorello@gmail.com>
# MIT License

#Requires -Module Ansible.ModuleUtils.Legacy

$ErrorActionPreference = "Stop"
$skewRange = 0..15

$params = Parse-Args -arguments $args -supports_check_mode $true
$checkMode      = Get-AnsibleParam -obj $params -name "_ansible_check_mode" -type "bool" -default $false
$diffMode       = Get-AnsibleParam -obj $params -name "_ansible_diff" -type "bool" -default $false

$name                           = Get-AnsibleParam -obj $params -name "name" -type "str" -failifempty $true
$state                          = Get-AnsibleParam -obj $params -name "state" -type "str" -default "present" -validateset "absent","present"
$endpoints                      = Get-AnsibleParam -obj $params -name "endpoints" -type "list" -failifempty $true
$claimsrules                    = Get-AnsibleParam -obj $params -name "claimsrules" -type "str" -failifempty $true
$oauthClientType                = Get-AnsibleParam -obj $params -name "oauth_clients_type" -type "str" -default "Public" -validateSet "public", "confidential"
$scopes                         = Get-AnsibleParam -obj $params -name "oauth_scopes" -type "list" -default "allatclaims" -validateSet "allatclaims","openid"
# TODO: Add documentation for the options below
$signatureAlgorithm             = Get-AnsibleParam -obj $params -name "signature_algorithm" -type "str" -default "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" -validateSet "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256","http://www.w3.org/2000/09/xmldsig#rsa-sha1"
$notBeforeSkew                  = Get-AnsibleParam -obj $params -name "not_before_skew" -type "int" -default 0 -validateSet $skewRange
$tokenLifetime                  = Get-AnsibleParam -obj $params -name "token_lifetime" -type "int" -default 0
$claimsProviderName             = Get-AnsibleParam -obj $params -name "claims_provider_name" -type "list"
$encryptClaims                  = Get-AnsibleParam -obj $params -name "encrypt_claims" -type "bool" -default $true
$refreshTokenProtectionEnabled  = Get-AnsibleParam -obj $params -name "refresh_token_protection_enabled" -type "bool" -default $true
$type                           = Get-AnsibleParam -obj $params -name "type" -type "str" -default "saml" -validateSet "saml", "oauth"

$beforeValue = Get-AdfsRelyingPartyTrust -name $name
if($type -eq "oauth"){
    $beforeValueClient = Get-AdfsClient -ClientId $name
}

$result = @{
    before_value = $beforeValue
    before_value_client = $beforeValueClient
    changed = $false
    value = $value
    warn = $null
}

if($state -eq "present" -and $null -eq $beforeValue) {
    if(-not $checkMode) {
        $parameters = @{
            Identifier              = $name
            Name                    = $name
            IssuanceTransformRules  = $claimsrules
            SignatureAlgorithm      = $signatureAlgorithm
        }
        if($null -ne $notBeforeSkew){
            $parameters.NotBeforeSkew = $notBeforeSkew
        }
        if($null -ne $tokenLifetime){
            $parameters.TokenLifetime = $tokenLifetime
        }
        if($null -ne $claimsProviderName){
            $parameters.ClaimsProviderName = $claimsProviderName
        }
        if($null -ne $encryptClaims){
            $parameters.EncryptClaims = $encryptClaims
        }
        if($null -ne $refreshTokenProtectionEnabled){
            $parameters.RefreshTokenProtectionEnabled = $refreshTokenProtectionEnabled
        }

        Add-AdfsRelyingPartyTrust @parameters
    }
    $result.changed = $true

} elseif($state -eq "present" -and $null -ne $beforeValue) {
    if($($beforeValue.IssuanceTransformRules -replace "\r\n", "") -ne $claimsrules `
        -or ($beforeValue.SignatureAlgorithm -ne $signatureAlgorithm) `
        -or ($beforeValue.EncryptClaims -ne $encryptClaims) `
        -or ($beforeValue.RefreshTokenProtectionEnabled -ne $refreshTokenProtectionEnabled) `
        -or (($null -ne $claimsProviderName -and (Compare-Object -ReferenceObject $claimsProviderName -DifferenceObject $beforeValue.ClaimsProviderName))) `
        -or ($beforeValue.NotBeforeSkew -ne $notBeforeSkew)`
        -or ($beforeValue.TokenLifetime -ne $tokenLifetime)){
        if(-not $checkMode) {
            $parameters = @{
                TargetIdentifier        = $name
                IssuanceTransformRules  = $claimsrules
                SignatureAlgorithm      = $signatureAlgorithm
            }
            if($null -ne $notBeforeSkew){
                $parameters.NotBeforeSkew = $notBeforeSkew
            }
            if($null -ne $tokenLifetime){
                $parameters.TokenLifetime = $tokenLifetime
            }
            if($null -ne $claimsProviderName){
                $parameters.ClaimsProviderName = $claimsProviderName
            }
            if($null -ne $encryptClaims){
                $parameters.EncryptClaims = $encryptClaims
            }
            if($null -ne $refreshTokenProtectionEnabled){
                $parameters.RefreshTokenProtectionEnabled = $refreshTokenProtectionEnabled
            }

            Set-AdfsRelyingPartyTrust @parameters
        }
        $result.changed = $true
    }
}

# Configure SAML endpoints
if($state -eq "present"){
    $EP = @()
    $index = 0
    $endpoints | foreach-object{
        $EP += New-AdfsSamlEndpoint  -Binding $_.method -Protocol $_.protocol -Uri $_.redirecturl -index $index
        $index++
    }

    if($null -ne (Compare-Object -ReferenceObject $EP -DifferenceObject $beforeValue.SamlEndpoints)){
        if(-not $checkMode) {
            Set-AdfsRelyingPartyTrust -TargetName $name -SamlEndpoint $EP
        }
        $result.changed = $true
    }
}

write-host 1

if($type -eq "oauth" -and $state -eq "present"){
    write-host 2
    $redirectUrl = @()
    $endpoints | foreach-object{
        $redirectUrl += $_.redirecturl
    }

    $GenerateClientSecret = $false
    if($oauthClientType -eq "Confidential"){
        $GenerateClientSecret = $true
    }

    if($beforeValueClient.ClientType -ne $oauthClientType){
        Revoke-AdfsApplicationPermission -TargetClientRoleIdentifier $name -TargetServerRoleIdentifier $name
        Remove-AdfsClient -TargetName $name
    }

    if($null -eq $beforeValueClient -or ($beforeValueClient.ClientType -ne $oauthClientType)){
        $parameters = @{
            ClientId                = $name
            Name                    = $name
            ClientType              = $oauthClientType
            GenerateClientSecret    = $GenerateClientSecret
            RedirectUri             = $redirectUrl
        }

        $client = Add-AdfsClient @parameters
        $result.changed = $true
        $result.secret = $client.ClientSecret
    }
    else{
        # Check if client needs to be changed
        if(($beforeValueClient.name -ne $name) -or $null -ne (Compare-Object -ReferenceObject $redirectUrl -DifferenceObject $beforeValueClient.RedirectUri)){
            $parameters = @{
                ClientId        = $name
                TargetName      = $name
                RedirectUri     = $redirectUrl
            }

            Set-AdfsClient @parameters
            $result.changed = $true
        }
    }

    $beforeValueAppPermission = Get-AdfsApplicationPermission -ClientRoleIdentifiers $name | Where-Object {$_.serverRoleIdentifier -eq $name}

    if($null -eq $beforeValueAppPermission){
        Grant-AdfsApplicationPermission -ClientRoleIdentifier $name -ServerRoleIdentifier $name -ScopeNames $scopes
        $result.changed = $true
    }
    elseif($null -ne (Compare-Object -ReferenceObject $scopes -DifferenceObject $beforeValueAppPermission.ScopeNames)){
        Set-AdfsApplicationPermission -TargetIdentifier $beforeValueAppPermission.ObjectIdentifier -ScopeNames $scopes
        $result.changed = $true
    }

}

# Remove relying party and oauth client
if($state -eq "absent" -and $null -ne $beforeValue) {
    if(-not $checkMode) {
        if($type -eq "oauth"){
            Revoke-AdfsApplicationPermission -TargetClientRoleIdentifier $name -TargetServerRoleIdentifier $name
            Remove-AdfsClient -TargetName $name
        }
        Remove-AdfsRelyingPartyTrust -TargetIdentifier $name
    }
    $result.changed = $true
}

$result.value = Get-AdfsRelyingPartyTrust -name $name
Exit-Json -obj $result