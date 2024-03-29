#
# Module manifest for module 'PSCiscoSupportAPIs'
#

@{

    # Script module or binary module file associated with this manifest.
    RootModule = 'PSCiscoSupportAPIs.psm1'

    # Version number of this module.
    ModuleVersion = '0.3.3'

    # Supported PSEditions
    # CompatiblePSEditions = @()

    # ID used to uniquely identify this module
    GUID = '608a30da-9f1a-4c63-9943-9e7d3a31b911'

    # Author of this module
    Author = 'Samuel Leslie'

    # Company or vendor of this module
    # CompanyName = ''

    # Copyright statement for this module
    Copyright = '(c) Samuel Leslie. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'PowerShell interface to the Cisco Support APIs'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '3.0'

    # Name of the PowerShell host required by this module
    # PowerShellHostName = ''

    # Minimum version of the PowerShell host required by this module
    # PowerShellHostVersion = ''

    # Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    # DotNetFrameworkVersion = ''

    # Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    # ClrVersion = ''

    # Processor architecture (None, X86, Amd64) required by this module
    # ProcessorArchitecture = ''

    # Modules that must be imported into the global environment prior to importing this module
    #
    # Automatic module import doesn't apply to types which a module exposes. We
    # use the Microsoft.PowerShell.Commands.BasicHtmlWebResponseObject type,
    # which is exposed by the Microsoft.PowerShell.Utility module, and so must
    # ensure it's imported before any commands we expose are run. If not, an
    # exception will be thrown on any invocation due to the missing type.
    RequiredModules = @('Microsoft.PowerShell.Utility')

    # Assemblies that must be loaded prior to importing this module
    # RequiredAssemblies = @()

    # Script files (.ps1) that are run in the caller's environment prior to importing this module.
    # ScriptsToProcess = @()

    # Type files (.ps1xml) to be loaded when importing this module
    # TypesToProcess = @()

    # Format files (.ps1xml) to be loaded when importing this module
    FormatsToProcess = @('PSCiscoSupportAPIs.format.ps1xml')

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    # NestedModules = @()

    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport = @(
        # Automated Software Distribution API
        'Get-CiscoSoftwareDownload',
        'Get-CiscoSoftwareRelease',
        'Get-CiscoSoftwareStatus',
        # Product Information API
        'Get-CiscoProductInformation',
        # Serial Number to Information API
        'Get-CiscoCoverageInformation',
        'Get-CiscoOrderableProductId',
        # Service Order Return (RMA) API
        'Get-CiscoServiceOrderReturn',
        # Software Suggestion API
        'Get-CiscoSoftwareSuggestion'
    )

    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = '*'

    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport = @()

    # DSC resources to export from this module
    # DscResourcesToExport = @()

    # List of all modules packaged with this module
    # ModuleList = @()

    # List of all files packaged with this module
    # FileList = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData = @{

        PSData = @{

            # Tags applied to this module. These help with module discovery in online galleries.
            Tags = @(
                'cisco'
                'PSEdition_Desktop', 'PSEdition_Core'
            )

            # A URL to the license for this module.
            LicenseUri = 'https://github.com/ralish/PSCiscoSupportAPIs/blob/stable/LICENSE'

            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/ralish/PSCiscoSupportAPIs'

            # A URL to an icon representing this module.
            # IconUri = ''

            # ReleaseNotes of this module
            ReleaseNotes = 'https://github.com/ralish/PSCiscoSupportAPIs/blob/stable/CHANGELOG.md'

            # Prerelease string of this module
            # Prerelease = ''

            # Flag to indicate whether the module requires explicit user acceptance for install/update/save
            # RequireLicenseAcceptance = $false

            # External dependent modules of this module
            #
            # See the RequiredModules setting for why we depend on this module.
            # We have to also specify it here as it's part of PowerShell itself
            # and so not published to the PowerShell Gallery.
            ExternalModuleDependencies = @('Microsoft.PowerShell.Utility')

        } # End of PSData hashtable

    } # End of PrivateData hashtable

    # HelpInfo URI of this module
    # HelpInfoURI = ''

    # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
    # DefaultCommandPrefix = ''

}
