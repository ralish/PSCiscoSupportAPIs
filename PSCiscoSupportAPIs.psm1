# See the help for Set-StrictMode for the full details on what this enables.
Set-StrictMode -Version 2.0

#region Internal

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

    $Script:RequestCommand = 'Invoke-RestMethod'
    $Script:RequestCommandBaseParams = @{ }

    if ($CallerParams['ResponseFormat'] -ne 'PSObject') {
        $Script:RequestCommand = 'Invoke-WebRequest'
        $Script:RequestCommandBaseParams['UseBasicParsing'] = $true
    }

    if ($CallerParams.ContainsKey('ClientId') -xor $CallerParams.ContainsKey('ClientSecret')) {
        throw 'You must provide both the ClientId and ClientSecret parameters or neither.'
    } elseif ($CallerParams.ContainsKey('ClientId') -and $CallerParams.ContainsKey('ClientSecret')) {
        $Script:ApiToken = Get-CiscoApiAccessToken -ClientId $CallerParams['ClientId'] -ClientSecret $CallerParams['ClientSecret']
    } else {
        $Script:ApiToken = Get-CiscoApiAccessToken
    }
}

# https://apiconsole.cisco.com/files/Token_Access.pdf
Function Get-CiscoApiAccessToken {
    [CmdletBinding()]
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
        Authorization = ('{0} {1}' -f $Response.token_type, $Response.access_token)
    }

    return $AuthzHeader
}

#endregion

#region Automated Software Distribution API

Function Get-CiscoSoftwareChecksum {
    <#
        .SYNOPSIS
        Retrieve software checksum information by image name

        .DESCRIPTION
        This function wraps the Cisco Automated Software Distribution API to allow easy querying from PowerShell.

        .PARAMETER ClientId
        Use the specified client ID for API authentication.

        This overrides any default specified in $CiscoApiClientId.

        .PARAMETER ClientSecret
        Use the specified client secret for API authentication.

        This overrides any default specified in $CiscoApiClientSecret.

        .PARAMETER ImageNames
        Retrieve software checksum information for the specified image name(s).

        Up to five image names can be entered specified as an array of strings.

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

        .EXAMPLE
        Get-CiscoSoftwareChecksum -ImageNames c2960-lanlitek9-mz.150-2.SE5.bin,mc3810-ik9s-mz.123-9e.bin

        Retrieve software checksum information for the provided image names.

        .NOTES
        The provided API credentials must have access to the Cisco Automated Software Distribution API.

        .LINK
        https://developer.cisco.com/docs/support-apis/#!automated-software-distribution
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [ValidateCount(1, 5)]
        [ValidateLength(1, 256)]
        [String[]]$ImageNames,

        [ValidateSet('JSON', 'PSObject', 'WebResponse')]
        [String]$ResponseFormat = 'PSObject',

        [ValidateNotNullOrEmpty()]
        [String]$ClientId,

        [ValidateNotNullOrEmpty()]
        [String]$ClientSecret
    )

    Initialize-CiscoApiRequest

    $BaseUri = 'https://api.cisco.com/software/v3.0'
    $QueryParams = @{ }

    $Uri = '{0}/checksum/image_names/{1}' -f $BaseUri, [String]::Join(',', $ImageNames)

    try {
        $Response = & $RequestCommand @RequestCommandBaseParams -Uri $Uri -Method Get -Headers $ApiToken -Body $QueryParams
    } catch {
        throw $_
    }

    switch ($PSBoundParameters['ResponseFormat']) {
        'WebResponse' { return $Response }
        'JSON' { return $Response.Content }
    }

    $ApiResponse = $Response.checksums
    $ApiResponse | ForEach-Object { $_.PSObject.TypeNames.Insert(0, 'PSCiscoSupportAPIs.SoftwareChecksum') }

    return $ApiResponse
}

Function Get-CiscoSoftwareRelease {
    <#
        .SYNOPSIS
        Retrieve software release information by product identifier(s)

        .DESCRIPTION
        This function wraps the Cisco Automated Software Distribution API to allow easy querying from PowerShell.

        .PARAMETER ClientId
        Use the specified client ID for API authentication.

        This overrides any default specified in $CiscoApiClientId.

        .PARAMETER ClientSecret
        Use the specified client secret for API authentication.

        This overrides any default specified in $CiscoApiClientSecret.

        .PARAMETER CurrentReleases
        Current release version on which to filter the results.

        A current release version must be specified for each provided product identifier.

        .PARAMETER ImageNames
        Retrieve software release information for the specified image name(s).

        Up to 25 image names can be entered specified as an array of strings.

        .PARAMETER OutputReleases
        Output release version on which to filter the results.

        A output release version must be specified for each provided product identifier.

        Valid values are:
        - Above
        - Latest

        .PARAMETER PageIndex
        Index number of the page to return.

        If not specified the first page will be returned.

        .PARAMETER ProductID
        Retrieve software release information associated with the specified product identifier.

        .PARAMETER ProductIDs
        Retrieve software release information associated with the specified product identifier(s).

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

        .EXAMPLE
        Get-CiscoSoftwareRelease -ProductIDs R2XX-D500GCSATA,WS-C2960-8TC-S -CurrentReleases '1.4(2b)',15.0.2-SE5 -OutputReleases Latest,Latest

        Retrieve software release information for the provided product IDs filtered on the given respective current release version and returning only the latest respective release version.

        .EXAMPLE
        Get-CiscoSoftwareRelease -ProductID WS-F4531= -ImageNames cat4000-i5s-mz.122-25.EWA7.bin

        Retrieve software release information for the provided product ID and image name.

        .NOTES
        The provided API credentials must have access to the Cisco Automated Software Distribution API.

        .LINK
        https://developer.cisco.com/docs/support-apis/#!automated-software-distribution
    #>

    [CmdletBinding()]
    Param(
        [Parameter(ParameterSetName = 'Pids', Mandatory)]
        [ValidateCount(1, 5)]
        [ValidateLength(1, 20)]
        [String[]]$ProductIDs,

        [Parameter(ParameterSetName = 'Pids', Mandatory)]
        [ValidateCount(1, 5)]
        [ValidateLength(1, 20)]
        [String[]]$CurrentReleases,

        [Parameter(ParameterSetName = 'Pids', Mandatory)]
        [ValidateCount(1, 5)]
        [ValidateSet('Above', 'Latest')]
        [String[]]$OutputReleases,

        [Parameter(ParameterSetName = 'Pid', Mandatory)]
        [ValidateLength(1, 20)]
        [String]$ProductID,

        [Parameter(ParameterSetName = 'Pid', Mandatory)]
        [ValidateCount(1, 25)]
        [ValidateLength(1, 256)]
        [String[]]$ImageNames,

        [Parameter(ParameterSetName = 'Pids')]
        [ValidateRange(1, 99999)]
        [Int]$PageIndex = 1,

        [ValidateSet('JSON', 'PSObject', 'WebResponse')]
        [String]$ResponseFormat = 'PSObject',

        [ValidateNotNullOrEmpty()]
        [String]$ClientId,

        [ValidateNotNullOrEmpty()]
        [String]$ClientSecret
    )

    Initialize-CiscoApiRequest

    if ($PSCmdlet.ParameterSetName -eq 'Pids') {
        if ($CurrentReleases.Count -ne $ProductIDs.Count) {
            throw 'A current release version must be specified for each product ID.'
        } elseif ($OutputReleases.Count -ne $ProductIDs.Count) {
            throw 'A output release version must be specified for each product ID.'
        }
    }

    $BaseUri = 'https://api.cisco.com/software/v3.0'
    $QueryParams = @{ }

    if ($PSCmdlet.ParameterSetName -eq 'Pids') {
        $Uri = '{0}/metadata/pids/{1}/current_releases/{2}/output_releases/{3}' -f $BaseUri, [String]::Join(',', $ProductIDs), [String]::Join(',', $CurrentReleases), [String]::Join(',', $OutputReleases)
        $QueryParams['page_index'] = $PageIndex
    } else {
        $Uri = '{0}/metadata/pid/{1}/image_names/{2}' -f $BaseUri, $ProductID, [String]::Join(',', $ImageNames)
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

    $ApiResponse = $Response.metadata_response
    if ($ApiResponse.PSObject.Properties['asd_metadata_exception']) {
        if ($ApiResponse.asd_metadata_exception.exception_code -eq 'NO_DATA_FOUND') {
            return
        } else {
            throw $ApiResponse.asd_metadata_exception.exception_message
        }
    }

    $ApiResponseFlattened = @()
    foreach ($ApiResponsePid in $ApiResponse.metadata_pid_list) {
        foreach ($ApiResponseMdfid in $ApiResponsePid.metadata_mdfid_list) {
            foreach ($ApiResponseSoftware in $ApiResponseMdfid.software_response_list) {
                foreach ($ApiResponsePlatform in $ApiResponseSoftware.platform_list) {
                    foreach ($ApiResponseRelease in $ApiResponsePlatform.release_list) {
                        $ApiResponseRelease | Add-Member -MemberType NoteProperty -Name metadata_trans_id -Value $ApiResponse.metadata_trans_id
                        $ApiResponseRelease | Add-Member -MemberType NoteProperty -Name pid -Value $ApiResponsePid.pid
                        $ApiResponseRelease | Add-Member -MemberType NoteProperty -Name mdfid -Value $ApiResponseMdfid.mdfid
                        $ApiResponseRelease | Add-Member -MemberType NoteProperty -Name mdf_concept_name -Value $ApiResponseMdfid.mdf_concept_name
                        $ApiResponseRelease | Add-Member -MemberType NoteProperty -Name software_type_id -Value $ApiResponseSoftware.software_type_id
                        $ApiResponseRelease | Add-Member -MemberType NoteProperty -Name software_type_name -Value $ApiResponseSoftware.software_type_name
                        $ApiResponseRelease | Add-Member -MemberType NoteProperty -Name operating_platform -Value $ApiResponsePlatform.operating_platform
                        $ApiResponseRelease.PSObject.TypeNames.Insert(0, 'PSCiscoSupportAPIs.SoftwareRelease')
                        $ApiResponseFlattened += $ApiResponseRelease
                    }
                }
            }
        }
    }

    return $ApiResponseFlattened
}

Function Get-CiscoSoftwareStatus {
    <#
        .SYNOPSIS
        Retrieve software status information by image name

        .DESCRIPTION
        This function wraps the Cisco Automated Software Distribution API to allow easy querying from PowerShell.

        .PARAMETER ClientId
        Use the specified client ID for API authentication.

        This overrides any default specified in $CiscoApiClientId.

        .PARAMETER ClientSecret
        Use the specified client secret for API authentication.

        This overrides any default specified in $CiscoApiClientSecret.

        .PARAMETER ImageNames
        Retrieve software status information for the specified image name(s).

        Up to 25 image names can be entered specified as an array of strings.

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

        .EXAMPLE
        Get-CiscoSoftwareStatus -ImageNames c2960-lanlitek9-mz.150-2.SE5.bin,mc3810-ik9s-mz.123-9e.bin

        Retrieve software status information for the provided image names.

        .NOTES
        The provided API credentials must have access to the Cisco Automated Software Distribution API.

        .LINK
        https://developer.cisco.com/docs/support-apis/#!automated-software-distribution
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [ValidateCount(1, 25)]
        [ValidateLength(1, 256)]
        [String[]]$ImageNames,

        [ValidateSet('JSON', 'PSObject', 'WebResponse')]
        [String]$ResponseFormat = 'PSObject',

        [ValidateNotNullOrEmpty()]
        [String]$ClientId,

        [ValidateNotNullOrEmpty()]
        [String]$ClientSecret
    )

    Initialize-CiscoApiRequest

    $BaseUri = 'https://api.cisco.com/software/v3.0'
    $QueryParams = @{ }

    $Uri = '{0}/swstatus/image_names/{1}' -f $BaseUri, [String]::Join(',', $ImageNames)

    try {
        $Response = & $RequestCommand @RequestCommandBaseParams -Uri $Uri -Method Get -Headers $ApiToken -Body $QueryParams
    } catch {
        throw $_
    }

    switch ($PSBoundParameters['ResponseFormat']) {
        'WebResponse' { return $Response }
        'JSON' { return $Response.Content }
    }

    $ApiResponse = $Response.metadata_List
    $ApiResponse | ForEach-Object { $_.PSObject.TypeNames.Insert(0, 'PSCiscoSupportAPIs.SoftwareStatus') }

    return $ApiResponse
}

#endregion

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
        [Parameter(ParameterSetName = 'Serial', Mandatory)]
        [ValidateCount(1, 5)]
        [ValidateLength(1, 40)]
        [String[]]$SerialNumbers,

        [Parameter(ParameterSetName = 'Pid', Mandatory)]
        [ValidateCount(1, 5)]
        [ValidateLength(1, 40)]
        [String[]]$ProductIDs,

        [Parameter(ParameterSetName = 'Pid')]
        [Switch]$MetadataFramework,

        [ValidateRange(1, 99)]
        [Int]$PageIndex = 1,

        [ValidateSet('JSON', 'PSObject', 'WebResponse')]
        [String]$ResponseFormat = 'PSObject',

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

#region Serial Number to Information API

Function Get-CiscoCoverageInformation {
    <#
        .SYNOPSIS
        Retrieve coverage information by serial or instance number

        .DESCRIPTION
        This function wraps the Cisco Serial Number to Information API to allow easy querying from PowerShell.

        .PARAMETER ClientId
        Use the specified client ID for API authentication.

        This overrides any default specified in $CiscoApiClientId.

        .PARAMETER ClientSecret
        Use the specified client secret for API authentication.

        This overrides any default specified in $CiscoApiClientSecret.

        .PARAMETER InstanceNumbers
        Retrieve coverage information associated with the specified instance number(s).

        Up to 75 instance numbers can be entered specified as an array of strings.

        .PARAMETER PageIndex
        Index number of the page to return.

        If not specified the first page will be returned.

        This parameter is ignored when retrieving coverage information by serial number with a report type of Status or Owner.

        .PARAMETER ReportType
        The type of information to retrieve for the specified serial number(s).

        Valid values are:
        - Summary               Coverage status, warranty, and product identifier details
        - Status                Coverage status
        - Owner                 Owner coverage status

        The default is Summary information.

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
        Retrieve coverage information associated with the specified serial number(s).

        Up to 75 serial numbers can be entered specified as an array of strings.

        .EXAMPLE
        Get-CiscoCoverageInformation -SerialNumbers FOC0903N5J9,INM07501EC3

        Retrieve coverage summary information for the provided serial numbers.

        .EXAMPLE
        Get-CiscoCoverageInformation -SerialNumbers SAL09232Q0Z,32964768 -ReportType Owner

        Retrieve owner coverage status information for the provided serial numbers.

        .NOTES
        The provided API credentials must have access to the Cisco Serial Number to Information API.

        .LINK
        https://developer.cisco.com/docs/support-apis/#!serial-number-to-information
    #>

    [CmdletBinding()]
    Param(
        [Parameter(ParameterSetName = 'Serial', Mandatory)]
        [ValidateCount(1, 75)]
        [ValidateLength(1, 40)]
        [String[]]$SerialNumbers,

        [Parameter(ParameterSetName = 'Instance', Mandatory)]
        [ValidateCount(1, 75)]
        [ValidateLength(1, 40)]
        [String[]]$InstanceNumbers,

        [Parameter(ParameterSetName = 'Serial')]
        [ValidateSet('Owner', 'Status', 'Summary')]
        [String]$ReportType = 'Summary',

        [ValidateRange(1, 99)]
        [Int]$PageIndex = 1,

        [ValidateSet('JSON', 'PSObject', 'WebResponse')]
        [String]$ResponseFormat = 'PSObject',

        [ValidateNotNullOrEmpty()]
        [String]$ClientId,

        [ValidateNotNullOrEmpty()]
        [String]$ClientSecret
    )

    Initialize-CiscoApiRequest

    $BaseUri = 'https://api.cisco.com/sn2info/v2'
    $QueryParams = @{ }

    if ($PSCmdlet.ParameterSetName -eq 'Serial') {
        switch ($ReportType) {
            'Summary' {
                $Uri = '{0}/coverage/summary/serial_numbers/{1}' -f $BaseUri, [String]::Join(',', $SerialNumbers)
                $QueryParams['page_index'] = $PageIndex
            }
            'Status' { $Uri = '{0}/coverage/status/serial_numbers/{1}' -f $BaseUri, [String]::Join(',', $SerialNumbers) }
            'Owner' { $Uri = '{0}/coverage/owner_status/serial_numbers/{1}' -f $BaseUri, [String]::Join(',', $SerialNumbers) }
        }
    } else {
        $Uri = '{0}/coverage/summary/instance_numbers/{1}' -f $BaseUri, [String]::Join(',', $InstanceNumbers)
        $QueryParams['page_index'] = $PageIndex
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

    if ($PSCmdlet.ParameterSetName -eq 'Serial') {
        $ApiResponse = $Response.serial_numbers

        switch ($ReportType) {
            'Summary' { $ApiResponse | ForEach-Object { $_.PSObject.TypeNames.Insert(0, 'PSCiscoSupportAPIs.CoverageInformation.SerialSummary') } }
            'Status' { $ApiResponse | ForEach-Object { $_.PSObject.TypeNames.Insert(0, 'PSCiscoSupportAPIs.CoverageInformation.SerialStatus') } }
            'Owner' { $ApiResponse | ForEach-Object { $_.PSObject.TypeNames.Insert(0, 'PSCiscoSupportAPIs.CoverageInformation.SerialOwner') } }
        }
    } else {
        $ApiResponse = $Response.instance_numbers
        $ApiResponse | ForEach-Object { $_.PSObject.TypeNames.Insert(0, 'PSCiscoSupportAPIs.CoverageInformation.InstanceSummary') }
    }

    return $ApiResponse
}

Function Get-CiscoOrderableProductId {
    <#
        .SYNOPSIS
        Retrieve the orderable product identifier by serial number

        .DESCRIPTION
        This function wraps the Cisco Serial Number to Information API to allow easy querying from PowerShell.

        .PARAMETER ClientId
        Use the specified client ID for API authentication.

        This overrides any default specified in $CiscoApiClientId.

        .PARAMETER ClientSecret
        Use the specified client secret for API authentication.

        This overrides any default specified in $CiscoApiClientSecret.

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
        Retrieve the orderable product identifier(s) associated with the specified serial number(s).

        Up to 75 serial numbers can be entered specified as an array of strings.

        .EXAMPLE
        Get-CiscoOrderableProductId -SerialNumbers FOC10220LK9

        Retrieve the orderable product identifier for the provided serial number.

        .NOTES
        The provided API credentials must have access to the Cisco Serial Number to Information API.

        .LINK
        https://developer.cisco.com/docs/support-apis/#!serial-number-to-information
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [ValidateCount(1, 75)]
        [ValidateLength(1, 40)]
        [String[]]$SerialNumbers,

        [ValidateSet('JSON', 'PSObject', 'WebResponse')]
        [String]$ResponseFormat = 'PSObject',

        [ValidateNotNullOrEmpty()]
        [String]$ClientId,

        [ValidateNotNullOrEmpty()]
        [String]$ClientSecret
    )

    Initialize-CiscoApiRequest

    $BaseUri = 'https://api.cisco.com/sn2info/v2'
    $QueryParams = @{ }

    $Uri = '{0}/identifiers/orderable/serial_numbers/{1}' -f $BaseUri, [String]::Join(',', $SerialNumbers)

    try {
        $Response = & $RequestCommand @RequestCommandBaseParams -Uri $Uri -Method Get -Headers $ApiToken -Body $QueryParams
    } catch {
        throw $_
    }

    switch ($PSBoundParameters['ResponseFormat']) {
        'WebResponse' { return $Response }
        'JSON' { return $Response.Content }
    }

    $ApiResponse = $Response.serial_numbers
    $ApiResponse | ForEach-Object { $_.PSObject.TypeNames.Insert(0, 'PSCiscoSupportAPIs.OrderableProductId') }

    return $ApiResponse
}

#endregion

#region Service Order Return (RMA) API

Function Get-CiscoServiceOrderReturn {
    <#
        .SYNOPSIS
        Retrieve RMAs (Return Material Authorization) by RMA number or user ID

        .DESCRIPTION
        This function wraps the Cisco Service Order Return (RMA) API to allow easy querying from PowerShell.

        .PARAMETER ClientId
        Use the specified client ID for API authentication.

        This overrides any default specified in $CiscoApiClientId.

        .PARAMETER ClientSecret
        Use the specified client secret for API authentication.

        This overrides any default specified in $CiscoApiClientSecret.

        .PARAMETER FromDate
        Beginning date from which to return results.

        The date should be specified in UTC time.

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

        .PARAMETER RmaNumber
        Retrieve details for the specified RMA number.

        .PARAMETER SortBy
        Sort the results by the specified criteria.

        Valid values are:
        - OrderDate
        - Status

        .PARAMETER Status
        Filter the results on the specified status.

        Valid values are:
        - Booked
        - Cancelled
        - Closed
        - Hold
        - Open

        .PARAMETER ToDate
        End date from which to return results.

        The date should be specified in UTC time.

        .PARAMETER UserID
        Retrieve details for all RMAs associated with the specified user identifier.

        .EXAMPLE
        Get-CiscoServiceOrderReturn -RmaNumber 84894022

        Retrieve details for the provided RMA number.

        .EXAMPLE
        Get-CiscoServiceOrderReturn -UserID svorma8 -FromDate 2013-08-01 -ToDate 2013-08-15

        Retrieve details for all RMAs associated with the user "svorma8" over the provided time period.

        .NOTES
        The provided API credentials must have access to the Cisco Service Order Return (RMA) API.

        .LINK
        https://developer.cisco.com/docs/support-apis/#!service-order-return-rma
    #>

    [CmdletBinding()]
    Param(
        [Parameter(ParameterSetName = 'Rma', Mandatory)]
        [ValidateRange(1, 9999999999)]
        [Long]$RmaNumber,

        [Parameter(ParameterSetName = 'User', Mandatory)]
        [ValidateLength(1, 20)]
        [String]$UserID,

        [Parameter(ParameterSetName = 'User')]
        [DateTime]$FromDate,

        [Parameter(ParameterSetName = 'User')]
        [DateTime]$ToDate,

        [Parameter(ParameterSetName = 'User')]
        [ValidateSet('Booked', 'Cancelled', 'Closed', 'Hold', 'Open')]
        [String]$Status,

        [Parameter(ParameterSetName = 'User')]
        [ValidateSet('OrderDate', 'Status')]
        [String]$SortBy,

        [ValidateSet('JSON', 'PSObject', 'WebResponse')]
        [String]$ResponseFormat = 'PSObject',

        [ValidateNotNullOrEmpty()]
        [String]$ClientId,

        [ValidateNotNullOrEmpty()]
        [String]$ClientSecret
    )

    Initialize-CiscoApiRequest

    $BaseUri = 'https://api.cisco.com/return/v1.0'
    $QueryParams = @{ }

    if ($PSCmdlet.ParameterSetName -eq 'Rma') {
        $Uri = '{0}/returns/rma_numbers/{1}' -f $BaseUri, $RmaNumber
    } else {
        $Uri = '{0}/returns/users/user_ids/{1}' -f $BaseUri, $UserID

        if ($PSBoundParameters.ContainsKey('FromDate')) {
            $QueryParams['fromDate'] = $FromDate.ToString('yyyy-MM-dd')
        }

        if ($PSBoundParameters.ContainsKey('ToDate')) {
            $QueryParams['toDate'] = $ToDate.ToString('yyyy-MM-dd')
        }

        if ($PSBoundParameters.ContainsKey('Status')) {
            $QueryParams['status'] = $Status.ToLower()
        }

        if ($PSBoundParameters.ContainsKey('SortBy')) {
            $QueryParams['sortBy'] = $SortBy.ToLower()
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

    if ($PSCmdlet.ParameterSetName -eq 'Rma') {
        if ($Response.PSObject.Properties['returns']) {
            $ApiResponse = $Response.returns.RmaRecord
            $ApiResponse | ForEach-Object { $_.PSObject.TypeNames.Insert(0, 'PSCiscoSupportAPIs.ServiceOrderReturn.Rma') }
        } else {
            throw $Response.APIError.Error[0].errorDescription
        }
    } else {
        if ($Response.OrderList.PSObject.Properties['users']) {
            $ApiResponse = $Response.OrderList.users
            $ApiResponse | ForEach-Object { $_.PSObject.TypeNames.Insert(0, 'PSCiscoSupportAPIs.ServiceOrderReturn.User') }
            $ApiResponse.returns | ForEach-Object { $_.PSObject.TypeNames.Insert(0, 'PSCiscoSupportAPIs.ServiceOrderReturn.User.Return') }
        } else {
            throw $Response.OrderList.APIError.Error[0].errorDescription
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
        [Parameter(ParameterSetName = 'Pids', Mandatory)]
        [ValidateCount(1, 10)]
        [ValidateLength(1, 20)]
        [String[]]$ProductIDs,

        [Parameter(ParameterSetName = 'Pid', Mandatory)]
        [ValidateLength(1, 20)]
        [String]$ProductID,

        [Parameter(ParameterSetName = 'MdfIds', Mandatory)]
        [ValidateCount(1, 10)]
        [ValidateLength(1, 20)]
        [String[]]$MdfIDs,

        [Parameter(ParameterSetName = 'MdfId', Mandatory)]
        [ValidateLength(1, 20)]
        [String]$MdfID,

        [Parameter(ParameterSetName = 'Pids')]
        [Parameter(ParameterSetName = 'MdfIds')]
        [Switch]$IncludeImages,

        [Parameter(ParameterSetName = 'Pid')]
        [Parameter(ParameterSetName = 'MdfId')]
        [ValidateLength(1, 59)]
        [String]$CurrentImage,

        [Parameter(ParameterSetName = 'Pid')]
        [Parameter(ParameterSetName = 'MdfId')]
        [ValidateLength(1, 15)]
        [String]$CurrentRelease,

        [Parameter(ParameterSetName = 'Pid')]
        [Parameter(ParameterSetName = 'MdfId')]
        [ValidateCount(1, 10)]
        [String[]]$SupportedFeatures,

        [Parameter(ParameterSetName = 'Pid')]
        [Parameter(ParameterSetName = 'MdfId')]
        [String[]]$SupportedHardware,

        [ValidateRange(1, 9999)]
        [Int]$PageIndex = 1,

        [ValidateSet('JSON', 'PSObject', 'WebResponse')]
        [String]$ResponseFormat = 'PSObject',

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
