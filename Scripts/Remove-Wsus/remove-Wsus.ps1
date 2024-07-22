Stop-Service -Name BITS, wuauserv -Force
Remove-ItemProperty -Name AccountDomainSid, PingID, SusClientId, SusClientIDValidation -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\ -ErrorAction SilentlyContinue
Remove-ItemProperty -Name * -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\ -ErrorAction SilentlyContinue 
Remove-ItemProperty -Name * -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU -ErrorAction SilentlyContinue
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\au | Remove-ItemProperty -ErrorAction SilentlyContinue

Remove-Item "$env:SystemRoot\SoftwareDistribution\" -Recurse -Force -ErrorAction SilentlyContinue

Start-Service -Name BITS, wuauserv
wuauclt /resetauthorization /detectnow
(New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow()
