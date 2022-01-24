PSCiscoSupportAPIs
==================

[![pwsh ver](https://img.shields.io/powershellgallery/v/PSCiscoSupportAPIs)](https://www.powershellgallery.com/packages/PSCiscoSupportAPIs)
[![pwsh dl](https://img.shields.io/powershellgallery/dt/PSCiscoSupportAPIs)](https://www.powershellgallery.com/packages/PSCiscoSupportAPIs)
[![license](https://img.shields.io/github/license/ralish/PSCiscoSupportAPIs)](https://choosealicense.com/licenses/mit/)

[![Open in Visual Studio Code](https://open.vscode.dev/badges/open-in-vscode.svg)](https://open.vscode.dev/ralish/PSCiscoSupportAPIs)

A PowerShell interface to the [Cisco Support APIs](https://developer.cisco.com/site/support-apis/).

- [Requirements](#requirements)
- [Installing](#installing)
- [Configuring](#configuring)
- [API endpoints](#api-endpoints)
- [Troubleshooting](#troubleshooting)
- [License](#license)

Requirements
------------

- PowerShell 3.0 (or later)
- [Cisco Support APIs credentials](https://apiconsole.cisco.com/)

Installing
----------

### PowerShellGet (included with PowerShell 5.0)

The module is published to the [PowerShell Gallery](https://www.powershellgallery.com/packages/PSCiscoSupportAPIs):

```posh
Install-Module -Name PSCiscoSupportAPIs
```

### ZIP File

Download the [ZIP file](https://github.com/ralish/PSCiscoSupportAPIs/archive/stable.zip) of the latest release and unpack it to one of the following locations:

- Current user: `C:\Users\<your.account>\Documents\WindowsPowerShell\Modules\PSCiscoSupportAPIs`
- All users: `C:\Program Files\WindowsPowerShell\Modules\PSCiscoSupportAPIs`

### Git Clone

You can also clone the repository into one of the above locations if you'd like the ability to easily update it via Git.

### Did it work?

You can check that PowerShell is able to locate the module by running the following at a PowerShell prompt:

```posh
Get-Module PSCiscoSupportAPIs -ListAvailable
```

Configuring
-----------

### API credentials

You must provide your API credentials to make requests. This can be done by either:

- Setting the `$CiscoApiClientId` and `$CiscoApiClientSecret` variables globally.
- Providing the `-ClientId` and `-ClientSecret` parameters on command invocation.

Command parameters take precedence over any globally configured API credentials.

### Response formats

All commands support outputting the response in several formats:

- `PSObject` (_default_)  
  A `PSCustomObject` which maps the fields in the JSON response. The raw response may be manipulated to improve its representation (e.g. using optimal .NET types). Formatting information is included for these objects, making them typically the easiest to work with, particularly interactively.
- `JSON`  
  A `String` containing the raw JSON response. You can pipe this to `ConvertFrom-Json` to generate a `PSCustomObject` representation. Note this will not give you the same result as the `PSObject` response format, which performs additional manipulation alongside formatting data to provide a "_native_" PowerShell experience.
- `WebResponse`  
  A `BasicHtmlWebResponseObject` which includes the response metadata (e.g. status code, HTTP headers, etc ...) alongside the response content. The `Content` property contains the raw JSON response and is identical to that returned in the `JSON` response format.

The response format is controlled by:

- Setting the `$CiscoApiResponseFormat` variable globally.
- Providing the `-ResponseFormat` parameter on command invocation.

Command parameters take precedence over any globally configured response format.

API endpoints
-------------

The following table shows the required API for each command:

| API Name                                                                                                           | API Version | Command(s) |
| ------------------------------------------------------------------------------------------------------------------ | ------------| ---------- |
| [Automated Software Distribution](https://developer.cisco.com/docs/support-apis/#!automated-software-distribution) | v4          | `Get-CiscoSoftwareDownload`<br>`Get-CiscoSoftwareRelease`<br>`Get-CiscoSoftwareStatus` |
| [Product Information](https://developer.cisco.com/docs/support-apis/#!product-information)                         | v1          | `Get-CiscoProductInformation` |
| [Serial Number to Information](https://developer.cisco.com/docs/support-apis/#!serial-number-to-information)       | v2          | `Get-CiscoCoverageInformation`<br>`Get-CiscoOrderableProductId` |
| [Service Order Return (RMA)](https://developer.cisco.com/docs/support-apis/#!service-order-return-rma)             | v1          | `Get-CiscoServiceOrderReturn` |
| [Software Suggestion](https://developer.cisco.com/docs/support-apis/#!software-suggestion)                         | v2          | `Get-CiscoSoftwareSuggestion` |

Troubleshooting
---------------

Encountering unexpected behaviour or other problems? You may wish to run the problematic command with the `-Verbose` parameter for more details. You can also add the `-Debug` parameter for even more details on the command processing.

If you think you've found a bug please consider [opening an issue](https://github.com/ralish/PSCiscoSupportAPIs/issues) so that I can look into it and hopefully get it fixed!

License
-------

All content is licensed under the terms of [The MIT License](LICENSE).
