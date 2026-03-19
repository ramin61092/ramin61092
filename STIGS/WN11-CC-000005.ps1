<#
.SYNOPSIS
    Camera access from the lock screen must be disabled
.NOTES
    Author          : Ramin Delsouz
    LinkedIn        : linkedin.com/in/alireza-delsouz
    GitHub          : github.com/ramin61092
    Date Created    : 2026-03-18
    Last Modified   : 2026-03-18
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000005

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 5.1.26100.7920

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN11-CC-000005).ps1 
#> 
#To disable
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" `
  -Name "NoLockScreenCamera" -PropertyType DWord -Value 1 -Force | Out-Null


#Verify
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" `
  -Name "NoLockScreenCamera"
