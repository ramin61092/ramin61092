<#
.SYNOPSIS
    Turn off indexing of encrypted files
.NOTES
    Author          : Ramin Delsouz
    LinkedIn        : linkedin.com/in/alireza-delsouz
    GitHub          : github.com/ramin61092
    Date Created    : 2026-03-20
    Last Modified   : 2026-03-20
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000305

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 5.1.26100.7920

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN11-CC-000305).ps1 
#> 
#To turn off
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" `
  -Name "AllowIndexingEncryptedStoresOrItems" -PropertyType DWord -Value 0 -Force | Out-Null


#Verify
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowIndexingEncryptedStoresOrItems"
