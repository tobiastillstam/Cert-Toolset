@{
    # PSScriptAnalyzer settings for Cert-Toolset (picked up by VS Code and by
    # Invoke-ScriptAnalyzer -Settings .\PSScriptAnalyzerSettings.psd1).
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # Write-Log writes plain timestamped lines with Write-Host on purpose:
        # they are captured by the transcript, which is the audit log.
        'PSAvoidUsingWriteHost',

        # Write-Log is the house logging helper name (same as other Tillnet
        # tools); it does not exist as a cmdlet in Windows PowerShell 5.1.
        'PSAvoidOverwritingBuiltInCmdlets',

        # Helpers such as New-DerElement and Stop-ToolsetTranscript only build
        # data in memory or manage the transcript. Every real state change is
        # gated by ShouldProcess at script level.
        'PSUseShouldProcessForStateChangingFunctions'
    )
}
