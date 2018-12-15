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

#region Product Information API
Function Get-CiscoProductInformation {
    <#
        .SYNOPSIS
        Retrieve product information by serial number or product identifier

        .DESCRIPTION
        This function wraps the Cisco Product Information API to allow easy querying from PowerShell.

        .PARAMETER ClientId
        Use the specified client ID for API authentication.

        This overrides any default specified in $CiscoApiClientId.

        .PARAMETER ClientSecret
        Use the specified client secret for API authentication.

        This overrides any default specified in $CiscoApiClientSecret.

        .PARAMETER MetadataFramework
        Retrieve metadata framework identifiers associated with the specified product identifier(s).

        .PARAMETER PageIndex
        Index number of the page to return.

        If not specified the first page will be returned.

        .PARAMETER ProductIDs
        Retrieve product information associated with the specified product identifier(s).

        Up to five product identifiers can be entered specified as an array of strings.

        .PARAMETER ResponseFormat
        Format in which to return the API response.

        Valid formats are:
        - JSON                  The JSON response as a string
        - PSObject              A PSCustomObject built from the JSON response
        - WebResponse           The BasicHtmlWebResponseObject returned by Invoke-WebRequest

        The default is PSObject which is optimised for viewing and interacting with on the CLI.

        This may include:
        - Splitting each record into its own custom PowerShell object
        - Adding custom types to objects to apply custom view definitions
        - Removing typically unneeded JSON objects (e.g. pagination records)

        A global default may be specified by setting $CiscoApiResponseFormat.

        .PARAMETER SerialNumbers
        Retrieve product information associated with the specified serial number(s).

        Up to five serial numbers can be entered specified as an array of strings.

        .EXAMPLE
        Get-CiscoProductInformation -SerialNumbers REF_CSJ07306405,SPE181700LN

        Retrieve product information for the provided serial numbers.

        .EXAMPLE
        Get-CiscoProductInformation -ProductIDs ASR1001,UBR10012

        Retrieve product information for the provided product IDs.

        .NOTES
        The provided API credentials must have access to the Cisco Product Information API.

        .LINK
        https://developer.cisco.com/docs/support-apis/#!product-information
    #>

    [CmdletBinding()]
    Param(
        [Parameter(ParameterSetName='Serial', Mandatory)]
        [ValidateCount(1, 5)]
        [ValidateLength(1, 40)]
        [String[]]$SerialNumbers,

        [Parameter(ParameterSetName='Pid', Mandatory)]
        [ValidateCount(1, 5)]
        [ValidateLength(1, 40)]
        [String[]]$ProductIDs,

        [Parameter(ParameterSetName='Pid')]
        [Switch]$MetadataFramework,

        [ValidateRange(1, 99)]
        [Int]$PageIndex=1,

        [ValidateSet('JSON', 'PSObject', 'WebResponse')]
        [String]$ResponseFormat='PSObject',

        [ValidateNotNullOrEmpty()]
        [String]$ClientId,

        [ValidateNotNullOrEmpty()]
        [String]$ClientSecret
    )

    Initialize-CiscoApiRequest

    $BaseUri = 'https://api.cisco.com/product/v1'
    $QueryParams = @{
        page_index = $PageIndex
    }

    if ($PSCmdlet.ParameterSetName -eq 'Serial') {
        $Uri = '{0}/information/serial_numbers/{1}' -f $BaseUri, [String]::Join(',', $SerialNumbers)
    } else {
        if ($MetadataFramework) {
            $Uri = '{0}/information/product_ids_mdf/{1}' -f $BaseUri, [String]::Join(',', $ProductIDs)
        } else {
            $Uri = '{0}/information/product_ids/{1}' -f $BaseUri, [String]::Join(',', $ProductIDs)
        }
    }

    try {
        $Response = & $RequestCommand @RequestCommandBaseParams -Uri $Uri -Method Get -Headers $ApiToken -Body $QueryParams
    } catch {
        throw $_
    }

    switch ($PSBoundParameters['ResponseFormat']) {
        'WebResponse' { return $Response }
        'JSON' { return $Response.Content }
    }

    $ApiResponse = $Response.product_list
    if ($PSCmdlet.ParameterSetName -eq 'Serial') {
        $ApiResponse | ForEach-Object { $_.PSObject.TypeNames.Insert(0, 'PSCiscoSupportAPIs.ProductInformation.Serial') }
    } else {
        if ($MetadataFramework) {
            $ApiResponse | ForEach-Object { $_.PSObject.TypeNames.Insert(0, 'PSCiscoSupportAPIs.ProductInformation.PidMdf') }
        } else {
            $ApiResponse | ForEach-Object { $_.PSObject.TypeNames.Insert(0, 'PSCiscoSupportAPIs.ProductInformation.Pid') }
        }
    }

    return $ApiResponse
}
#endregion
