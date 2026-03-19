<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Ramin Delsouz
    LinkedIn        : linkedin.com/in/alireza-delsouz
    GitHub          : github.com/ramin61092
    Date Created    : 2026-03-16
    Last Modified   : 2026-03-16
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000500

.TESTED ON
    Date(s) Tested  : 2026-03-16
    Tested By       : Ramin Delsouz
    Systems Tested  : 
    PowerShell Ver. : 5.1.26100.7920

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN10-AU-000500).ps1 
#>

# Define the registry path, value name, and value data

$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
$name         = "MaxSize"
$value        = 0x8000  # You can also use the decimal equivalent: 32768

# Check if the registry key path exists; if not, create it
if (!(Test-Path -Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

# Set the registry value to the specified DWord
Set-ItemProperty -Path $registryPath -Name $name -Value $value -Type DWord -Force

Write-Host "Registry value updated successfully." -ForegroundColor Green
