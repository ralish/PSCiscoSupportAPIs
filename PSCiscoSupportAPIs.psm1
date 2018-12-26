# See the help for Set-StrictMode for the full details on what this enables.
Set-StrictMode -Version 2.0

Function Initialize-CiscoApiRequest {
    [CmdletBinding()]
    Param()

    $CallerParams = (Get-PSCallStack)[1].InvocationInfo.BoundParameters

    if (!$CallerParams.ContainsKey('ResponseFormat')) {
        if (Test-Path -Path 'Variable:\CiscoApiResponseFormat') {
            if ($CiscoApiResponseFormat -in ('JSON', 'PSObject', 'WebResponse')) {
                Write-Verbose -Message ('Using API response format from $CiscoApiResponseFormat: {0}' -f $CiscoApiResponseFormat)
                $CallerParams['ResponseFormat'] = $CiscoApiResponseFormat
            } else {
                throw 'CiscoApiResponseFormat setting is invalid: {0}' -f $CiscoApiResponseFormat
            }
        } else {
            Write-Verbose -Message 'Using default API response format: PSObject'
            $CallerParams['ResponseFormat'] = 'PSObject'
        }
    }

    $script:RequestCommand = 'Invoke-RestMethod'
    $script:RequestCommandBaseParams = @{}

    if ($CallerParams['ResponseFormat'] -ne 'PSObject') {
        $script:RequestCommand = 'Invoke-WebRequest'
        $script:RequestCommandBaseParams['UseBasicParsing'] = $true
    }

    if ($CallerParams.ContainsKey('ClientId') -xor $CallerParams.ContainsKey('ClientSecret')) {
        throw 'You must provide both the ClientId and ClientSecret parameters or neither.'
    } elseif ($CallerParams.ContainsKey('ClientId') -and $CallerParams.ContainsKey('ClientSecret')) {
        $script:ApiToken = Get-CiscoApiAccessToken -ClientId $CallerParams['ClientId'] -ClientSecret $CallerParams['ClientSecret']
    } else {
        $script:ApiToken = Get-CiscoApiAccessToken
    }
}

# https://apiconsole.cisco.com/files/Token_Access.pdf
Function Get-CiscoApiAccessToken {
    [CmdletBinding()]
    [OutputType([Collections.Hashtable])]
    Param(
        [ValidateNotNullOrEmpty()]
        [String]$ClientId,

        [ValidateNotNullOrEmpty()]
        [String]$ClientSecret
    )

    if ($PSBoundParameters.ContainsKey('ClientId') -and $PSBoundParameters.ContainsKey('ClientSecret')) {
        Write-Verbose -Message 'Using API client ID & secret provided as parameters ...'
    } elseif ($PSBoundParameters.ContainsKey('ClientId') -xor $PSBoundParameters.ContainsKey('ClientSecret')) {
        throw 'You must provide both the ClientId and ClientSecret parameters or neither.'
    } else {
        if ((Test-Path -Path 'Variable:\CiscoApiClientId') -and $CiscoApiClientId) {
            $ClientId = $CiscoApiClientId
        } else {
            throw 'CiscoApiClientId is not defined or the empty string.'
        }

        if ((Test-Path -Path 'Variable:\CiscoApiClientSecret') -and $CiscoApiClientSecret) {
            $ClientSecret = $CiscoApiClientSecret
        } else {
            throw 'CiscoApiClientSecret is not defined or the empty string.'
        }

        Write-Verbose -Message 'Using API client ID & secret retrieved from session variables ...'
    }

    $Uri = 'https://cloudsso.cisco.com/as/token.oauth2?grant_type=client_credentials&client_id={0}&client_secret={1}' -f $ClientId, $ClientSecret
    $Response = Invoke-RestMethod -Uri $Uri -Method Post

    $AuthzHeader = @{
        Authorization=('{0} {1}' -f $Response.token_type, $Response.access_token)
    }

    return $AuthzHeader
}
