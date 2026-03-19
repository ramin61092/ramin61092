<#
.SYNOPSIS
    Disable SMBv1 client
.NOTES
    Author          : Ramin Delsouz
    LinkedIn        : linkedin.com/in/alireza-delsouz
    GitHub          : github.com/ramin61092
    Date Created    : 2026-03-18
    Last Modified   : 2026-03-18
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-00-000170

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 5.1.26100.7920

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN10-AU-000500).ps1 
#> 
#To disable
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart

#To enable (Give vulnerability)
To give Vulnerability 
Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -All -NoRestart
Restart-Computer
