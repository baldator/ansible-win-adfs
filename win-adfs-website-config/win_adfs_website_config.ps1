#!powershell

# Copyright: (c) 2015, Jon Hawkesworth (@jhawkesworth) <figs@unity.demon.co.uk>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#Requires -Module Ansible.ModuleUtils.Legacy

$ErrorActionPreference = "Stop"

$params = Parse-Args -arguments $args -supports_check_mode $true
$checkMode      = Get-AnsibleParam -obj $params -name "_ansible_check_mode" -type "bool" -default $false
$diffMode       = Get-AnsibleParam -obj $params -name "_ansible_diff" -type "bool" -default $false

$name            = Get-AnsibleParam -obj $params -name "name" -type "str" -failifempty $true
$state           = Get-AnsibleParam -obj $params -name "state" -type "str" -default "present" -validateset "absent","present"
$endpoints       = Get-AnsibleParam -obj $params -name "endpoints" -type "list" -failifempty $true
$claimsrules     = Get-AnsibleParam -obj $params -name "claimsrules" -type "str" -failifempty $true
$oauthClientType = Get-AnsibleParam -obj $params -name "oauth_clients_type" -type "str" -default "Public" -validateSet "public", "confidential"
$scopes          = Get-AnsibleParam -obj $params -name "oauth_scopes" -type "list" -default "allatclaims" -validateSet "allatclaims","openid"
$type            = Get-AnsibleParam -obj $params -name "type" -type "str" -default "saml" -validateSet "saml", "oauth"

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
        Add-AdfsRelyingPartyTrust -Name $name -Identifier $name -IssuanceTransformRules $claimsrules
    }
    $result.changed = $true

} elseif($state -eq "present" -and $null -ne $beforeValue) {
    if($($beforeValue.IssuanceTransformRules -replace "\r\n", "") -ne $claimsrules){
        if(-not $checkMode) {
            Set-AdfsRelyingPartyTrust -TargetIdentifier $name -IssuanceTransformRules $claimsrules
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
    
        Add-AdfsClient @parameters
        $result.changed = $true
        #TODO: return client secret
    }
    else{
        # Check if client needs to be changed
        if(-not (($beforeValueClient.name -eq $name) -and ($beforeValueClient.RedirectUri -eq $redirectUrl))){
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