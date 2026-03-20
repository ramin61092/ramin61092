<#
.SYNOPSIS
    WinRM client must not use Basic authentication
.NOTES
    Author          : Ramin Delsouz
    LinkedIn        : linkedin.com/in/alireza-delsouz
    GitHub          : github.com/ramin61092
    Date Created    : 2026-03-20
    Last Modified   : 2026-03-20
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000330

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 5.1.26100.7920

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN11-CC-000330).ps1 
#> 

#Don't use Basic authentication
# 64-bit policy location (what STIG check expects)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" `
  -Name "AllowBasic" -PropertyType DWord -Value 0 -Force | Out-Null

# 32-bit policy location (in case the setting was applied via 32-bit host)
New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\WinRM\Client" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\WinRM\Client" `
  -Name "AllowBasic" -PropertyType DWord -Value 0 -Force | Out-N


#Verify
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowBasic"
