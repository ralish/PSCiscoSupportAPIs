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

#region Software Suggestion API
Function Get-CiscoSoftwareSuggestion {
    <#
        .SYNOPSIS
        Retrieve suggested software releases by product identifier(s) or metadata framework identifier(s)

        .DESCRIPTION
        This function wraps the Cisco Software Suggestion API to allow easy querying from PowerShell.

        .PARAMETER ClientId
        Use the specified client ID for API authentication.

        This overrides any default specified in $CiscoApiClientId.

        .PARAMETER ClientSecret
        Use the specified client secret for API authentication.

        This overrides any default specified in $CiscoApiClientSecret.

        .PARAMETER CurrentImage
        Filter the results on current image identifier.

        Identifier should be provided as the image name (e.g. c2801-adventerprisek9-mz.151-4.M6.bin).

        .PARAMETER CurrentRelease
        Filter the results on current release version.

        Version should be provided in one of the following two forms: 15.0(24)T7 or 15.0.24T7.

        .PARAMETER IncludeImages
        Include software image details corresponding to the suggested software releases(s).

        .PARAMETER MdfID
        Retrieve compatible and suggested software release(s) associated with the specified metadata framework identifier.

        .PARAMETER MdfIDs
        Retrieve suggested software release(s) associated with the specified metadata framework identifier(s).

        Up to ten metadata framework identifiers can be entered specified as an array of strings.

        .PARAMETER PageIndex
        Index number of the page to return.

        If not specified the first page will be returned.

        .PARAMETER ProductID
        Retrieve compatible and suggested software release(s) associated with the specified product identifier.

        .PARAMETER ProductIDs
        Retrieve suggested software release(s) associated with the specified product identifier(s).

        Up to ten product identifiers can be entered specified as an array of strings.

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

        .PARAMETER SupportedFeatures
        Filter the results on supported feature(s).

        Up to ten feature names can be entered specified as an array of strings.

        .PARAMETER SupportedHardware
        Filter the results on supported hardware identifier(s).

        .EXAMPLE
        Get-CiscoSoftwareSuggestion -ProductIDs ASR-903,CISCO2811,N7K-C7018 -IncludeImages

        Retrieve suggested software release(s) with image details for the provided product identifiers.

        .EXAMPLE
        Get-CiscoSoftwareSuggestion -ProductID ASR1013 -CurrentImage asr1000rpx86-universalk9.16.02.01.SPA.bin

        Retrieve suggested software release(s) for the ASR 1013 platform currently running IOS XE 16.2.1.

        .NOTES
        The provided API credentials must have access to the Cisco Software Suggestion API.

        .LINK
        https://developer.cisco.com/docs/support-apis/#!software-suggestion
    #>

    [CmdletBinding()]
    Param(
        [Parameter(ParameterSetName='Pids', Mandatory)]
        [ValidateCount(1, 10)]
        [ValidateLength(1, 20)]
        [String[]]$ProductIDs,

        [Parameter(ParameterSetName='Pid', Mandatory)]
        [ValidateLength(1, 20)]
        [String]$ProductID,

        [Parameter(ParameterSetName='MdfIds', Mandatory)]
        [ValidateCount(1, 10)]
        [ValidateLength(1, 20)]
        [String[]]$MdfIDs,

        [Parameter(ParameterSetName='MdfId', Mandatory)]
        [ValidateLength(1, 20)]
        [String]$MdfID,

        [Parameter(ParameterSetName='Pids')]
        [Parameter(ParameterSetName='MdfIds')]
        [Switch]$IncludeImages,

        [Parameter(ParameterSetName='Pid')]
        [Parameter(ParameterSetName='MdfId')]
        [ValidateLength(1, 59)]
        [String]$CurrentImage,

        [Parameter(ParameterSetName='Pid')]
        [Parameter(ParameterSetName='MdfId')]
        [ValidateLength(1, 15)]
        [String]$CurrentRelease,

        [Parameter(ParameterSetName='Pid')]
        [Parameter(ParameterSetName='MdfId')]
        [ValidateCount(1, 10)]
        [String[]]$SupportedFeatures,

        [Parameter(ParameterSetName='Pid')]
        [Parameter(ParameterSetName='MdfId')]
        [String[]]$SupportedHardware,

        [ValidateRange(1, 9999)]
        [Int]$PageIndex=1,

        [ValidateSet('JSON', 'PSObject', 'WebResponse')]
        [String]$ResponseFormat='PSObject',

        [ValidateNotNullOrEmpty()]
        [String]$ClientId,

        [ValidateNotNullOrEmpty()]
        [String]$ClientSecret
    )

    Initialize-CiscoApiRequest

    $BaseUri = 'https://api.cisco.com/software/suggestion/v2'
    $QueryParams = @{
        pageIndex = $PageIndex
    }

    if ($PSCmdlet.ParameterSetName -in ('Pids', 'MdfIds')) {
        if ($PSCmdlet.ParameterSetName -eq 'Pids') {
            $IDs = $ProductIDs
            $BaseId = 'productIds'
        } else {
            $IDs = $MdfIDs
            $BaseId = 'mdfIds'
        }

        if ($IncludeImages) {
            $Uri = '{0}/suggestions/software/{1}/{2}' -f $BaseUri, $BaseId, [String]::Join(',', $IDs)
        } else {
            $Uri = '{0}/suggestions/releases/{1}/{2}' -f $BaseUri, $BaseId, [String]::Join(',', $IDs)
        }
    } else {
        if ($PSCmdlet.ParameterSetName -eq 'Pid') {
            $ID = $ProductID
            $BaseId = 'productId'
        } else {
            $ID = $MdfID
            $BaseId = 'mdfId'
        }

        $Uri = '{0}/suggestions/compatible/{1}/{2}' -f $BaseUri, $BaseId, $ID

        if ($PSBoundParameters.ContainsKey('CurrentImage')) {
            $QueryParams['currentImage'] = $CurrentImage
        }

        if ($PSBoundParameters.ContainsKey('CurrentRelease')) {
            $QueryParams['currentRelease'] = $CurrentRelease
        }

        if ($PSBoundParameters.ContainsKey('SupportedFeatures')) {
            $QueryParams['supportedFeatures'] = [String]::Join(',', $SupportedFeatures)
        }

        if ($PSBoundParameters.ContainsKey('SupportedHardware')) {
            $QueryParams['supportedHardware'] = [String]::Join(',', $SupportedHardware)
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

    if ($PSCmdlet.ParameterSetName -in ('Pids', 'MdfIds')) {
        $ApiResponse = $Response.productList

        if ($PSCmdlet.ParameterSetName -eq 'Pids') {
            $ApiResponse | ForEach-Object { $_.PSObject.TypeNames.Insert(0, 'PSCiscoSupportAPIs.SoftwareSuggestion.Pids') }
        } else {
            $ApiResponse | ForEach-Object { $_.PSObject.TypeNames.Insert(0, 'PSCiscoSupportAPIs.SoftwareSuggestion.MdfIds') }
        }
    } else {
        $ApiResponse = $Response.suggestions

        if ($PSCmdlet.ParameterSetName -eq 'Pid') {
            $ApiResponse | ForEach-Object { $_.PSObject.TypeNames.Insert(0, 'PSCiscoSupportAPIs.SoftwareSuggestion.Pid') }
        } else {
            $ApiResponse | ForEach-Object { $_.PSObject.TypeNames.Insert(0, 'PSCiscoSupportAPIs.SoftwareSuggestion.MdfId') }
        }
    }

    return $ApiResponse
}
#endregion
