# *************************************************************************************************************************************
# * SYNOPSIS                                                                                                                          *
# * Applies a Default Configuration to a new Windows Server.                                                                          *
# *************************************************************************************************************************************
# * DESCRIPTION                                                                                                                       *
# * Applies a Default Configuration to a new Windows Server.                                                                          *
# *                                                                                                                                   *
# *                                                                                                                                   *
# REQUIREMENTS:                                                                                                                       *
# *                                                                                                                                   *
# * PowerShell execution policy must be configured to allow script execution; for example,                                            *
# * with a command such as the following:                                                                                             *
# * Set-ExecutionPolicy RemoteSigned                                                                                                  *
# *                                                                                                                                   *
# * Explenation:                                                                                                                      *
# * In the Varibale Difintion you need to modify the Parmaeters for $true or $False to determin what applications                     *
# * there will be installed.                                                                                                          *
# *                                                                                                                                   *
# * There are some Extra Parameters that are needed vor the installation of Azure Arc and Azure Analitics Worksapce Agent.            *
# * Also ther is a variable that determend the Reboot end the Timeout in Seconds,                                                     *
# * that will we used to reboot the Server at the end of the Script                                                                   *
# *                                                                                                                                   *
# * Thanks:                                                                                                                           *
# * My thanks to the Autor of the Baseline Powershell Script. I made some minor changes so the the logging goes only To file          *
# * Not to the Screen. To keep the screen output clean.                                                                               *
# *                                                                                                                                   *
# *************************************************************************************************************************************
# * This Script is created by Ronald Bok owner of the Firm T.E.S. - Com..                                                             *
# * You may make modifications in order to make the script better. But please let me know so i                                        *
# * Can integrate the changes in my version. If we all work to gather this script will be Great (and it will make it a better World)  *
# * Thanks in advanced.                                                                                                               *
# *                                                                                                                                   *
# * Ronald Bok                                                                                                                        *
# * T.E.S. - Com.                                                                                                                     *
# * Ronald@TES-Com.nl                                                                                                                 *
# *************************************************************************************************************************************

# *************************************************************************************************************************************
# * Varibale Difinitions You need to Fill in                                                                                          *
# *************************************************************************************************************************************
# ****************************************************************************************************************************
# Add the service principal application ID and secret For Windows ARC here                                                   *
# ****************************************************************************************************************************
$servicePrincipalClientId = ""
$servicePrincipalSecret = ""
$ResourceGroup = "" 
$TenantId = ""
$Location = ""
$SubscriptionId = ""
$AUTH_TYPE = "";
$Cloud = "" 
$CorrelationId = ""

# ****************************************************************************************************************************
# Add the Workspace ID and key For Windows LogAnalicis Agent here                                                            *
# ****************************************************************************************************************************
$WORKSPACE_ID=""
$WORKSPACE_KEY=""

# ****************************************************************************************************************************
# * Varibale Difinitions if needed change                                                                                    *
# ****************************************************************************************************************************
$scriptdir = (Get-Location).path

# ****************************************************************************************************************************
# Set the timeout to reboot                                                                                                  *
# ****************************************************************************************************************************
$Reboot = $False
$Reboottimeout = 30

# ****************************************************************************************************************************
# Determen what to Security Reccomendations to install                                                                       *
# ****************************************************************************************************************************
$DisbaleServices = $True
$DisbaleSMB = $True

$InstallSecurityReccomandationsAccounts = $True
$InstallSecurityReccomandationsApplications = $True
$InstallSecurityReccomandationsNetwork = $True
$InstallSecurityReccomandationsNetworkAssessment = $True
$InstallSecurityReccomandationsOS = $True
$InstallSecurityReccomandationsSecurityControls = $True

# ****************************************************************************************************************************
# Determen what Windows Default behaiver to change                                                                           *
# ****************************************************************************************************************************
$ServerManager = $True

# ****************************************************************************************************************************
# Determen what to Programs to install                                                                                       *
# ****************************************************************************************************************************
$InstallLAPS = $True
$InstallTotalCommander = $True
$InstallARC = $False

# ****************************************************************************************************************************
# Always install Following (Do Not Edit)                                                                                     *
# ****************************************************************************************************************************
$OnboardDefender = $True
$InstallLogAnalitics = $True
$InstallWindowsUpdates = $True
$InstallRemoteManagement = $True

# ****************************************************************************************************************************
# Variable for Password Defenition if a Administrator Account is Created                                                     *
# ****************************************************************************************************************************
$Computername = $env:computername.ToLower()
$username = ""
$Password = ""

# *************************************************************************************************************************************
# *                                              ===--- end of Variable ---===                                                        *
# *************************************************************************************************************************************

# *************************************************************************************************************************************
# *                                                  ===--- Functions ---===                                                          *
# *************************************************************************************************************************************

# ****************************************************************************************************************************
# * this function will do The Logging for the Script                                                                         *
# ****************************************************************************************************************************
Function Log-Message()
{
 param
    (
    [Parameter(Mandatory=$true)] [string] $Message
    )
    Try {
        $LogDate = (Get-Date).toString("dd-MM-yyyy")
        $LogFile = $Scriptdir + "\logs\"+ $Computername + " " + $LogDate + ".txt"
        $TimeStamp = (Get-Date).toString("dd/MM/yyyy HH:mm:ss:fff tt")
        $Line = "$TimeStamp - $Message"
        Add-content -Path $Logfile -Value $Line
     }
    Catch {
        Write-host -f Red "Error:" $_.Exception.Message
    }
}

# ****************************************************************************************************************************
# * this function will Check if Registry Property Exist                                                                      *
# ****************************************************************************************************************************
function Test-RegistryValue {
  param (
  [parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Path,
  [parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Name,
  [parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Value,
  [parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Type
  )
  
  try {
    Get-ItemProperty -Path $Path -ErrorAction Stop | Select-Object -ExpandProperty $Name -ErrorAction Stop | Out-Null
    $Check =  Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $name
    If ($Check -eq $Value) {log-Message " Value Set..." ; Write-Host " Value Set..." -nonewline ; log-Message " done!" ; Write-Host "  done!" -foregroundcolor Green} 
    Else { New-ItemProperty -Path $Path -name $Name -Value $Value -PropertyType $type -force | Out-Null ; log-Message " Value Created..." ; Write-Host " Value Created..." -Nonewline ; log-Message " done!" ; Write-Host "  done!" -foregroundcolor Green}
  }
  catch {
    New-ItemProperty -Path $Path -name $Name -Value $Value -PropertyType $type -force | Out-Null
    log-Message " Value Created..." ; Write-Host " Value Created..." -Nonewline ; log-Message " done!" ; Write-Host "  done!" -foregroundcolor Green
    Return $False
  }
}


# ****************************************************************************************************************************
# * this function will DisbaleServer Manager at Startup                                                                      *
# ****************************************************************************************************************************
function ServerManager
{
  Log-Message "do not start Server manager at startup " ; Write-host "do not start Server manager at startup " -NoNewline
  $regpath = "HKLM:\SOFTWARE\Microsoft\ServerManager"
  $regname = "DoNotPopWACConsoleAtSMLaunch"
  $regval  = "1"
  Set-ItemProperty -Path $regpath -Name $regname -Value $regval | Out-Null
  $regpath = "HKLM:\SOFTWARE\Microsoft\ServerManager"
  $regname = "DoNotOpenServerManagerAtLogon"
  $regval  = "1"
  Set-ItemProperty -Path $regpath -Name $regname -Value $regval | Out-Null
  Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green
}

# ****************************************************************************************************************************
# * this function will do specific w2008 stuff                                                                               *
# ****************************************************************************************************************************
function W2008stuff 
{
MicrosoftEdge
}

# ****************************************************************************************************************************
# * this function will do specific w2012 stuff                                                                               *
# ****************************************************************************************************************************
function W2012stuff 
{
  $psv = [string]$PSVersionTable.PSVersion.Major +'.'+ [string]$PSVersionTable.PSVersion.Minor
  if ($PSV -eq "5.1") {
    Log-Message "Found Powershell Version $PSV ..."; Write-Host "Found Powershell Version " $PSV "..." -ForegroundColor Green
    }
  Else {
    Log-Message "Install Microsoft Powershell 5.1..." ; Write-Host "Install Microsoft Powershell 5.1..." -NoNewline
    Start-Process -filepath "wusa.exe" -Wait -ArgumentList "$scriptdir\Applications\Powershell\windows8.1-kb4025333-x64_b7373c4640f07e670e09b95624e8fd046085e201.msu /quiet /norestart /Log:$scriptdir\Powershell\logs\$Computername.txt"
    Start-Process -filepath "wusa.exe" -Wait -ArgumentList "$scriptdir\Applications\Powershell\Win8.1AndW2K12R2-KB3191564-x64.msu /quiet /norestart /Log:$scriptdir\Powershell\logs\$Computername.txt"
    Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

    Log-Message "Microsoft Powershell 5.1 is installed. Please Reboot Server and start the script again..." ; Write-Host "Microsoft Powershell 5.1 is installed. Please Reboot Server and start the script again..." -ForegroundColor Yellow
    Exit
  }
  MicrosoftEdge
}

# ****************************************************************************************************************************
# * this function will do specific w2016 stuff                                                                               *
# ****************************************************************************************************************************
function W2016stuff 
{
  MicrosoftEdge
}

# ****************************************************************************************************************************
# * this function will do specific w2019 stuff                                                                               *
# ****************************************************************************************************************************
function W2019stuff 
{
  MicrosoftEdge
}

# ****************************************************************************************************************************
# * this function will do specific w2022 stuff                                                                               *
# ****************************************************************************************************************************
function W2022stuff 
{
}

# ****************************************************************************************************************************
# * this function will do specific w2025 stuff                                                                               *
# ****************************************************************************************************************************
function W2025stuff 
{
}

# ****************************************************************************************************************************
# * this function will set Windows Services to Disbaled or Manual                                                            *
# ****************************************************************************************************************************
function DisableServices 
{
  Log-Message " " ; Write-host " " 
  Log-Message "Setting Status of Servives" ; Write-Host "Setting Status of Servives" -ForegroundColor Blue

  Log-Message "On This Windows Server, Various services are being disabled..." ; Write-Host "On This Windows Server, Various services are being disabled..." 
  # First Empty all Array's
  $servicesDisabeld = @() # make sure the array is empty
  $servicesVDisabeld = @() # make sure the array is empty
  $servicesAllDisabeld = @() # make sure the array is empty
  $servicesManual = @() # make sure the array is empty
  $servicesAllDisabeld = @("AppMgmt", "AudioEndpointBuilder", "Audiosrv", "AxInstSV", "lltdsvc", "NcbService", "PrintNotify", "RemoteAccess", "ScDeviceEnum",  "ScardSvr", "SecLogon", "SharedAccess", "ShellHWDetection", "Spooler", "SSDPSRV", "upnphost", "WiaRpc", "wlidsvc", "WMIApSrv")
 
  switch ($OS)
  {
     "w2008" { }
     "w2012" { $servicesVDisabeld = @("AdobeARMservice", "Alerter", "Aobelm Service", "Clipbook", "OSE", "OSE64",, "SammSS", "STisvc", "WSCSVC") }
     "w2016" { $servicesVDisabeld =  @("CDPUserSvc", "dmwappushservice", "FrameServer", "icssvc", "lfsvc", "MapsBroker", "NgcCtnrSvc", "NgcSvc", "OneSyncSvc", "PcaSvc", "PhoneSvc", "PimIndexMaintenanceSvc", "QWAVE", "RmSvc", "ScardSvr", "SensorDataService", "SensorService", "SensrSvc", "stisvc", "UnistoreSvc", "UserDataSvc", "WalletService", "wisvc", "WpnService", "WpnUserService", "XblAuthManager", "XblGameSave") }
     "w2019" { $servicesVDisabeld = @("AJRouter", "bthserv", "CDPUserSvc",  "dmwappushservice", "dot3svc", "FrameServer", "FrameServerMonitor", "lfsvc", "mapsbroker", "NgcCtnrSvc", "NgcSvc", "PcaSvc", "PimIndexMaintenancesvc", "QWAVE", "RmSvc", "ScardSvr", "SensorDataService", "SensorService", "SensrSvc", "stisvc", "TabletInputService", "TapiSrv", "Themes", "tzautoupdate", "UnistoreSvc", "UserDataSvc", "WalletService", "WbioSrvc", "wisvc", "WMPNetworkSvc", "WpnService", "WpnUserService") }
     "w2022" { $servicesVDisabeld = @("AJRouter", "bthserv", "CDPUserSvc",  "dmwappushservice", "dot3svc", "FrameServer", "FrameServerMonitor", "lfsvc", "mapsbroker", "NgcCtnrSvc", "NgcSvc", "PcaSvc", "PimIndexMaintenancesvc", "QWAVE", "RmSvc", "ScardSvr", "SensorDataService", "SensorService", "SensrSvc", "stisvc", "TabletInputService", "TapiSrv", "Themes", "tzautoupdate", "UnistoreSvc", "UserDataSvc", "WalletService", "WbioSrvc", "wisvc", "WMPNetworkSvc", "WpnService", "WpnUserService") }
     "w2025" { }
  }
  $servicesDisabeld = $servicesAllDisabeld + $servicesVDisabeld

  foreach ($serv in $servicesDisabeld) {
    $service = Get-Service -Name $serv -ErrorAction SilentlyContinue
    if($service -eq $null) {
      Log-Message "$serv Service does not exist" ; Write-Host "$serv Service does not exist" -foregroundColor Yellow
      }
    else {
      #Service does exist
      try {
        Set-Service $service -StartupType Disabled -ErrorAction SilentlyContinue
        Log-Message "$serv is Disabled" ; Write-Host "$serv is Disabled... " -Nonewline ; Write-Host "Done! "-foregroundColor Green } 
      catch {
	Log-Message "$serv Access Denied" ; Write-Host "$serv Access Denied" -foregroundColor Yellow }
    } 
  }
  Log-Message "Disabeling of services... done!" ; Write-Host "Disabeling of services... " -nonewline ; Write-Host " done!" -ForegroundColor Green

  Log-Message " " ; Write-host " " 
  Log-Message "On This Windows Server,Various services are being set to manual..." ; Write-Host "On This Windows Server,Various services are being set to manual..."
  $ServicesManual = @("CryptSvc", "DiagTrack", "HidServ", "LMHosts", "RPCLocator", "SWprv")
  
  foreach ($ServM in $ServicesManual) {
    $ServiceM = Get-Service -Name $ServM -ErrorAction SilentlyContinue
    if($ServiceM -eq $null) {
      Log-Message "$ServM Service does not exist" ; Write-Host "$ServM Service does not exist" -ForegroundColor Yellow
      }
    else {
      Set-Service $ServiceM -StartupType Manual -ErrorAction SilentlyContinue
      Log-Message "$ServM is set to Manual" ; Write-Host "$ServM is set to Manual... " -nonewline ; Write-Host " done!" -ForegroundColor Green
      }
    } 
  Log-Message "Manual Setting of services... done!" ; Write-Host "Manual Setting of services..." -nonewline ; Write-Host " done!" -ForegroundColor Green
}

# ****************************************************************************************************************************
# * this function will Implement Security Recomandations For the Accounts Section                                            *
# ****************************************************************************************************************************
function SecurityReccomendationsAccounts
{
  Log-Message " " ; Write-host " " 
  Log-Message "Starting the Implemantation Of The Security Recomandations for the Account Section" ; Write-Host "Starting the Implemantation Of The Security Recomandations for the Account Section" -foregroundColor Blue

  # ****************************************************************************************************************************
  # * the next lines only work with Powershell5 and higher.                                                                    *
  # ****************************************************************************************************************************
  if ((gwmi win32_computersystem).partofdomain -eq $False) 
    {
    Log-Message "Computer is not part of a Domain. Disabling the BuildIn Administrator Will make the server inaccesable" ;  Write-Host "Computer is not part of a Domain. Disabling the BuildIn Administrator Will make the server inaccesable" -foregroundcolor Yellow
    log-message "Therefor Create The Scholt Energy Account..." ; Write-Host "Therefor Create The Scholt Energy Account..." -foregroundcolor Yellow
    $sec_pass = ConvertTo-SecureString -String $password -AsPlainText -Force

    log-message "Checking if username ""$username"" Exist..." ; Write-Host "Checking if username ""$username"" Exist..." -nonewline
    if (-not (Get-LocalUser -Name $username -ErrorAction SilentlyContinue))
      {
      New-LocalUser -name $username -Fullname "Scholt Energy" -Description "Account Voor ICT Operation Na Hardening Server" -PasswordNeverExpires:$true -Password $sec_pass | out-null
      log-message " User does not exist..." ; Write-Host " User does not exist..." -nonewline
      Add-localgroupmember  -group "Administrators" -Member Scholtenergy
      Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green
      }
    else
      {
       log-message " User Exist" ; Write-Host " Users Exist" -nonewline
       Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green
      }
     if (Get-LocalUser -Name $username -ErrorAction SilentlyContinue) 
       { 
       Log-Message "Disable the built-in Administrator account and empty fullname and Description..." ;  Write-Host "Disable the built-in Administrator account and empty fullname and Description..." -nonewline
       Get-LocalUser | Where-Object -Property SID -like "*500" | set-localuser -Description " "  -fullname " "
       Get-LocalUser | Where-Object -Property SID -like "*500" | Disable-LocalUser
       Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green  
       }
    }
  else
    {
    Log-Message "Disable the built-in Administrator account..." ;  Write-Host "Disable the built-in Administrator account..." -nonewline
    Get-LocalUser | Where-Object -Property SID -like "*500" | set-localuser -Description " " | Disbale-LocalUser
    Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green
    }

  Log-Message "Local groups housekeeping..."
  Write-Host "Local groups housekeeping..." -NoNewline
  Remove-LocalGroupMember -Member "Guest" -Group "Guests" -ErrorAction SilentlyContinue
  Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

  Log-Message "Set Minimum password length to 14 or more characters..." ; Write-Host "Set Minimum password length to 14 or more characters..." -nonewline
  Net Accounts /MinPWLen:14 | out-null
  log-message " " ; Write-Host " done!" -ForegroundColor Green

  Log-Message "Set Enforce password history to 24 or more password(s)" ; Write-Host "Set Enforce password history to 24 or more password(s)" -nonewline
  Net Accounts /UNIQUEPW:24 | out-null
  log-message " " ; Write-Host " done!" -ForegroundColor Green

  Log-Message "Set Minimum password age to 1 or more day(s)..." ; Write-host "Set Minimum password age to 1 or more day(s)..." -nonewline
  Net Accounts /MINPWAGE:1 | out-null
  log-message " " ; Write-Host " done!" -ForegroundColor Green

  Log-Message "Set Account lockout duration to 15 minutes or more..." ; Write-Host "Set Account lockout duration to 15 minutes or more..." -nonewline
  net accounts /lockoutduration:15 | out-null
  log-message " " ; Write-Host " done!" -ForegroundColor Green

  Log-Message "Set lockout Account Threshold to 5 attemps or more..." ; Write-Host "Set lockout Account Threshold to 5 attemps or more..." -nonewline
  net accounts /lockoutThreshold:5 | out-null
  log-message " " ; Write-Host " done!" -ForegroundColor Green

  Log-Message "Set Reset account lockout counter after to 15 minutes or more..." ; Write-Host "Set Reset account lockout counter after to 15 minutes or more..." -nonewline
  net accounts /lockoutwindow:15 | out-null
  log-message " " ; Write-Host " done!" -ForegroundColor Green

  Log-Message "Enable Local Admin password management..." ; Write-host "Enable Local Admin password management..." -nonewline
  $regkey = 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' ; $regname = 'AdmPwdEnabled' ; $regValue = '1' ; $RegType = 'DWord' 
  $RegExist = Test-Path $regkey ; If ($regExist -eq $true) {Log-Message " Regkey already Exist..." ; Write-host " Regkey already Exist..."-nonewline} Else { New-Item -Path $regkey -force | Out-Null ; Log-Message " Regkey Created..." ; Write-host " Regkey Created..."-nonewline}
  Test-RegistryValue $Regkey $regname $regvalue $RegType
}

# ****************************************************************************************************************************
# * this function will Implement Security Recomandations For the Applications Section                                        *
# ****************************************************************************************************************************
function SecurityReccomandationsApplications
{
  Log-Message " " ; Write-host " " 
  Log-Message "Starting the Implemantation Of The Security Recomandations for the Application Section" ; Write-Host "Starting the Implemantation Of The Security Recomandations for the Application Section" -foregroundColor Blue

  Log-Message "Block outdated ActiveX controls for Internet Explorer" ; Write-host "Block outdated ActiveX controls for Internet Explorer" -NoNewline
  $regkey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Ext' ; $regname = 'VersionCheckEnabled' ; $regValue = '1' ; $RegType = 'DWord' 
  $RegExist = Test-Path $regkey ; If ($regExist -eq $true) {Log-Message " Regkey already Exist..." ; Write-host " Regkey already Exist..."-nonewline} Else { New-Item -Path $regkey -force | Out-Null ; Log-Message " Regkey Created..." ; Write-host " Regkey Created..."-nonewline}
  Test-RegistryValue $Regkey $regname $regvalue $RegType

  Log-Message "Disable running or installing downloaded software with invalid signature" ; Write-host "Disable running or installing downloaded software with invalid signature" -NoNewline
  $regkey = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Download' ; $regname = 'RunInvalidSignatures' ; $regValue = '0' ; $RegType = 'DWord' 
  $RegExist = Test-Path $regkey ; If ($regExist -eq $true) {Log-Message " Regkey already Exist..." ; Write-host " Regkey already Exist..."-nonewline} Else { New-Item -Path $regkey -force | Out-Null ; Log-Message " Regkey Created..." ; Write-host " Regkey Created..."-nonewline}
  Test-RegistryValue $Regkey $regname $regvalue $RegType
}

# ****************************************************************************************************************************
# * this function will Implement Security Recomandations For the Network Section                                             *
# ****************************************************************************************************************************
function SecurityReccomandationsNetwork
{
  Log-Message " " ; Write-host " " 
  Log-Message "Starting the Implemantation Of The Security Recomandations for the Network Section" ; Write-Host "Starting the Implemantation Of The Security Recomandations for the network Section" -foregroundColor Blue

  Log-Message "Set user authentication for remote connections by using Network Level Authentication to Enabled..." ; Write-host "Set user authentication for remote connections by using Network Level Authentication to Enabled..." -nonewline
  $regkey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' ; $regname = 'UserAuthentication' ; $regValue = '1' ; $RegType = 'DWord' 
  $RegExist = Test-Path $regkey ; If ($regExist -eq $true) {Log-Message " Regkey already Exist..." ; Write-host " Regkey already Exist..."-nonewline} Else { New-Item -Path $regkey -force | Out-Null ; Log-Message " Regkey Created..." ; Write-host " Regkey Created..."-nonewline}
  Test-RegistryValue $Regkey $regname $regvalue $RegType

  Log-Message "Disable Installation and configuration of Network Bridge on your DNS domain network..." ; Write-host Disable Installation and configuration of Network Bridge on your DNS domain network"..." -nonewline
  $regkey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections' ; $regname = 'NC_AllowNetBridge_NLA' ; $regValue = '0' ; $RegType = 'DWord' 
  $RegExist = Test-Path $regkey ; If ($regExist -eq $true) {Log-Message " Regkey already Exist..." ; Write-host " Regkey already Exist..."-nonewline} Else { New-Item -Path $regkey -force | Out-Null ; Log-Message " Regkey Created..." ; Write-host " Regkey Created..."-nonewline}
  Test-RegistryValue $Regkey $regname $regvalue $RegType

  Log-Message "Enable Require domain users to elevate when setting a network's location..." ; Write-host "Enable Require domain users to elevate when setting a network's location..." -nonewline
  $regkey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections' ; $regname = 'NC_StdDomainUserSetLocation' ; $regValue = '1' ; $RegType = 'DWord' 
  $RegExist = Test-Path $regkey ; If ($regExist -eq $true) {Log-Message " Regkey already Exist..." ; Write-host " Regkey already Exist..."-nonewline} Else { New-Item -Path $regkey -force | Out-Null ; Log-Message " Regkey Created..." ; Write-host " Regkey Created..."-nonewline}
  Test-RegistryValue $Regkey $regname $regvalue $RegType

  Log-Message "Set IPv6 source routing to highest protection..." ; Write-host "Set IPv6 source routing to highest protection..." -nonewline
  $regkey = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' ; $regname = 'DisableIPSourceRouting' ; $regValue = '2' ; $RegType = 'DWord' 
  $RegExist = Test-Path $regkey ; If ($regExist -eq $true) {Log-Message " Regkey already Exist..." ; Write-host " Regkey already Exist..."-nonewline} Else { New-Item -Path $regkey -force | Out-Null ; Log-Message " Regkey Created..." ; Write-host " Regkey Created..."-nonewline}
  Test-RegistryValue $Regkey $regname $regvalue $RegType

  Log-Message "Set LAN Manager authentication level to Send NTLMv2 response only. Refuse LM & NTLM..." ; Write-host "Set LAN Manager authentication level to Send NTLMv2 response only. Refuse LM & NTLM..." -nonewline
  $regkey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' ; $regname = 'LmCompatibilityLevel' ; $regValue = '5' ; $RegType = 'DWord' 
  $RegExist = Test-Path $regkey ; If ($regExist -eq $true) {Log-Message " Regkey already Exist..." ; Write-host " Regkey already Exist..."-nonewline} Else { New-Item -Path $regkey -force | Out-Null ; Log-Message " Regkey Created..." ; Write-host " Regkey Created..."-nonewline}
  Test-RegistryValue $Regkey $regname $regvalue $RegType

# Disbaling of Ip Source Routing makes the Server not reachable any more. This can be becourse we use a VPN to connect to AZure. Testing Needed.
#  Log-Message "Disable IP source routing..." ; Write-host "Disable IP source routing..." -nonewline
#  $regkey = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' ; $regname = 'DisableIPSourceRouting' ; $regValue = '2' ; $RegType = 'DWord' 
#  $RegExist = Test-Path $regkey ; If ($regExist -eq $true) {Log-Message " Regkey already Exist..." ; Write-host " Regkey already Exist..."-nonewline} Else { New-Item -Path $regkey -force | Out-Null ; Log-Message " Regkey Created..." ; Write-host " Regkey Created..."-nonewline}
#  Test-RegistryValue $Regkey $regname $regvalue $RegType

  Log-Message "Enable Microsoft network client: Digitally sign communications (always)..." ; Write-host "Enable Microsoft network client: Digitally sign communications (always)..." -nonewline
  $regkey = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' ; $regname = 'RequireSecuritySignature' ; $regValue = '1' ; $RegType = 'DWord' 
  $RegExist = Test-Path $regkey ; If ($regExist -eq $true) {Log-Message " Regkey already Exist..." ; Write-host " Regkey already Exist..."-nonewline} Else { New-Item -Path $regkey -force | Out-Null ; Log-Message " Regkey Created..." ; Write-host " Regkey Created..."-nonewline}
  Test-RegistryValue $Regkey $regname $regvalue $RegType

  Log-Message "Disable sending unencrypted password to third-party SMB servers..." ; Write-host "Disable sending unencrypted password to third-party SMB servers..." -nonewline
  $regkey = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' ; $regname = 'EnablePlainTextPassword' ; $regValue = '0' ; $RegType = 'DWord' 
  $RegExist = Test-Path $regkey ; If ($regExist -eq $true) {Log-Message " Regkey already Exist..." ; Write-host " Regkey already Exist..."-nonewline} Else { New-Item -Path $regkey -force | Out-Null ; Log-Message " Regkey Created..." ; Write-host " Regkey Created..."-nonewline}
  Test-RegistryValue $Regkey $regname $regvalue $RegType

  Log-Message "Enable Network Protection" ; Write-Host "Enable Network Protection" -nonewline
  Set-MpPreference -EnableNetworkProtection Enabled
  Log-Message " Done!" ; Write-Host " Done!" -ForegroundColor Green
}

# ****************************************************************************************************************************
# * this function will Implement Security Recomandations For the Network Assessment Section                                  *
# ****************************************************************************************************************************
function SecurityReccomandationsNetworkAssessment
{
  Log-Message " " ; Write-host " " 
  Log-Message "Starting the Implemantation Of The Security Recomandations for the Network Assessment Section" ; Write-Host "Starting the Implemantation Of The Security Recomandations for the Network Assessment Section" -foregroundColor Blue

  Log-Message "No Security Reccomandations At this time for the Section Network Assessment" ; Write-Host "No Security REccomandations At this time for the Section Network Assessment" -foregroundcolor Yellow
}

# ****************************************************************************************************************************
# * this function will Implement Security Recomandations For the Operating System Section                                    *
# ****************************************************************************************************************************
function SecurityReccomandationsOS
{
  Log-Message " " ; Write-host " " 
  Log-Message "Starting the Implemantation Of The Security Recomandations for the Operating System Section" ; Write-Host "Starting the Implemantation Of The Security Recomandations for the Operating System Section" -foregroundColor Blue

  Log-Message "Disable Allow Basic authentication for WinRM Client..." ; Write-host "Disable Allow Basic authentication for WinRM Client..." -nonewline
  $regkey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' ; $regname = 'AllowBasic' ; $regValue = '0' ; $RegType = 'DWord' 
  $RegExist = Test-Path $regkey ; If ($regExist -eq $true) {Log-Message " Regkey already Exist..." ; Write-host " Regkey already Exist..."-nonewline} Else { New-Item -Path $regkey -force | Out-Null ; Log-Message " Regkey Created..." ; Write-host " Regkey Created..."-nonewline}
  Test-RegistryValue $Regkey $regname $regvalue $RegType

  Log-Message "Disable Allow Basic authentication for WinRM Service..." ; Write-host "Disable Allow Basic authentication for WinRM Service..." -nonewline
  $regkey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' ; $regname = 'AllowBasic' ; $regValue = '0' ; $RegType = 'DWord'
  $RegExist = Test-Path $regkey ; If ($regExist -eq $true) {Log-Message " Regkey already Exist..." ; Write-host " Regkey already Exist..."-nonewline} Else { New-Item -Path $regkey -force | Out-Null ; Log-Message " Regkey Created" ; Write-host " Regkey Created"-nonewline}
  Test-RegistryValue $Regkey $regname $regvalue $RegType

  Log-Message "Disable Anonymous enumeration of shares..." ; Write-host "Disable Anonymous enumeration of shares..." -nonewline
  $regkey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' ; $regname = 'RestrictAnonymous' ; $regValue = '1' ; $RegType = 'DWord'
  $RegExist = Test-Path $regkey ; If ($regExist -eq $true) {Log-Message " Regkey already Exist" ; Write-host " Regkey already Exist"-nonewline} Else { New-Item -Path $regkey -force | Out-Null ; Log-Message " Regkey Created" ; Write-host " Regkey Created"-nonewline}
  Test-RegistryValue $Regkey $regname $regvalue $RegType
  Log-Message "Disable Anonymous enumeration of shares (lsa)..." ; Write-host "Disable Anonymous enumeration of shares (lsa)..." -nonewline
  $regkey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' ; $regname = 'RunAsPPL' ; $regValue = '1' ; $RegType = 'DWord'
  Test-RegistryValue $Regkey $regname $regvalue $RegType

  Log-Message "Disable Autoplay for all drives..." ; Write-host "Disable Autoplay for all drives..." -nonewline
  $regkey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' ; $regname = 'NoDriveTypeAutoRun' ; $regValue = '255' ; $RegType = 'DWord'
  $RegExist = Test-Path $regkey ; If ($regExist -eq $true) {Log-Message " Regkey already Exist" ; Write-host " Regkey already Exist"-nonewline} Else { New-Item -Path $regkey -force | Out-Null ; Log-Message " Regkey Created" ; Write-host " Regkey Created"-nonewline}
  Test-RegistryValue $Regkey $regname $regvalue $RegType

  Log-Message "Disable Autoplay for non-volume devices..." ; Write-host "Disable Autoplay for non-volume devices..." -nonewline
  $regkey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' ; $regname = 'NoAutoplayfornonVolume' ; $regValue = '1' ; $RegType = 'DWord'
  $RegExist = Test-Path $regkey ; If ($regExist -eq $true) {Log-Message " Regkey already Exist" ; Write-host " Regkey already Exist"-nonewline} Else { New-Item -Path $regkey -force | Out-Null ; Log-Message " Regkey Created" ; Write-host " Regkey Created"-nonewline}
  Test-RegistryValue $Regkey $regname $regvalue $RegType

  Log-Message "Disable Enumerate administrator accounts on elevation..." ; Write-host "Disable Enumerate administrator accounts on elevation..." -nonewline
  $regkey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI' ; $regname = 'EnumerateAdministrators' ; $regValue = '0' ; $RegType = 'DWord'
  $RegExist = Test-Path $regkey ; If ($regExist -eq $true) {Log-Message " Regkey already Exist" ; Write-host " Regkey already Exist"-nonewline} Else { New-Item -Path $regkey -force | Out-Null ; Log-Message " Regkey Created" ; Write-host " Regkey Created"-nonewline}
  Test-RegistryValue $Regkey $regname $regvalue $RegType

  Log-Message "Disable Solicited Remote Assistance..." ; Write-host "Disable Solicited Remote Assistance..." -nonewline
  $regkey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' ; $regname = 'fAllowToGetHelp' ; $regValue = '0' ; $RegType = 'DWord'
  $RegExist = Test-Path $regkey ; If ($regExist -eq $true) {Log-Message " Regkey already Exist" ; Write-host " Regkey already Exist"-nonewline} Else { New-Item -Path $regkey -force | Out-Null ; Log-Message " Regkey Created" ; Write-host " Regkey Created"-nonewline}
  Test-RegistryValue $Regkey $regname $regvalue $RegType

  Log-Message "Enable Local Security Authority (LSA) protection..." ; Write-host "Enable Local Security Authority (LSA) protection..." -nonewline
  $regkey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' ; $regname = 'RunAsPPL' ; $regValue = '2' ; $RegType = 'DWord'
  $RegExist = Test-Path $regkey ; If ($regExist -eq $true) {Log-Message " Regkey already Exist" ; Write-host " Regkey already Exist"-nonewline} Else { New-Item -Path $regkey -force | Out-Null ; Log-Message " Regkey Created" ; Write-host " Regkey Created"-nonewline}
  Log-Message " To do!!" ; Write-Host " To do!!" -ForegroundColor Yellow

  Log-Message "Set default behavior for AutoRun to Enabled: Do not execute any autorun commands..." ; Write-host "Set default behavior for AutoRun to Enabled: Do not execute any autorun commands..." -nonewline
  $regkey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' ; $regname = 'NoAutorun' ; $regValue = '1' ; $RegType = 'DWord'
  $RegExist = Test-Path $regkey ; If ($regExist -eq $true) {Log-Message " Regkey already Exist" ; Write-host " Regkey already Exist"-nonewline} Else { New-Item -Path $regkey -force | Out-Null ; Log-Message " Regkey Created" ; Write-host " Regkey Created"-nonewline}
  Test-RegistryValue $Regkey $regname $regvalue $RegType

  Log-Message "Set User Account Control (UAC) to automatically deny elevation requests..." ; Write-host "Set User Account Control (UAC) to automatically deny elevation requests..." -nonewline
  $regkey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' ; $regname = 'ConsentPromptBehaviorUser' ; $regValue = '0' ; $RegType = 'DWord'
  $RegExist = Test-Path $regkey ; If ($regExist -eq $true) {Log-Message " Regkey already Exist" ; Write-host " Regkey already Exist"-nonewline} Else { New-Item -Path $regkey -force | Out-Null ; Log-Message " Regkey Created" ; Write-host " Regkey Created"-nonewline}
  Test-RegistryValue $Regkey $regname $regvalue $RegType

  Log-Message "Fix unquoted service path for Windows services" ; Write-host "Fix unquoted service path for Windows services..." -Nonewline
  $LogDate = (Get-Date).toString("dd-MM-yyyy")
  $LogFilePathEnumerate = $Scriptdir + "\Scripts\Windows_path_enumerate\logs\"+ $Computername + "_" + $LogDate + ".log"
  invoke-expression -Command "$scriptdir\Scripts\Windows_path_enumerate\Windows_Path_Enumerate.ps1 -logname $LogFilePathEnumerate" | out-null
  Log-Message " Logfile is at location: $LogFilePathEnumerate" ; Write-host " Logfile is at location:"$LogFilePathEnumerate"..." -nonewline
  Log-Message " Done!" ; Write-Host " Done!" -ForegroundColor Green
} 

# ****************************************************************************************************************************
# * this function will Implement Security Recomandations For the Security Controls Section                                   *
# ****************************************************************************************************************************
function SecurityReccomandationsSecurityControls
{
  Log-Message "  " ; Write-Host " "
  Log-Message "Starting the Implemantation Of The Security Recomandations for the Security Controls Section" ; Write-Host "Starting the Implemantation Of The Security Recomandations for the Security Controls Section" -foregroundColor Blue

  Log-Message "Set controlled folder access to enabled or audit mode..." ; Write-host "Set controlled folder access to enabled or audit mode..." -nonewline
  $regkey = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access' ; $regname = 'EnableControlledFolderAccess' ; $regValue = '1' ; $RegType = 'DWord' 
  $RegExist = Test-Path $regkey ; If ($regExist -eq $true) {Log-Message " Regkey already Exist..." ; Write-host " Regkey already Exist..."-nonewline} Else { New-Item -Path $regkey -force | Out-Null ; Log-Message " Regkey Created..." ; Write-host " Regkey Created..."-nonewline}
  Test-RegistryValue $Regkey $regname $regvalue $RegType

  Log-Message "Disable merging of local Microsoft Defender Firewall connection rules with group policy firewall rules for the Public profile..." ; Write-host "Disable merging of local Microsoft Defender Firewall connection rules with group policy firewall rules for the Public profile..." -nonewline
  $regkey = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile' ; $regname = 'AllowLocalIPsecPolicyMerge' ; $regValue = '0' ; $RegType = 'DWord' 
  $RegExist = Test-Path $regkey ; If ($regExist -eq $true) {Log-Message " Regkey already Exist..." ; Write-host " Regkey already Exist..."-nonewline} Else { New-Item -Path $regkey -force | Out-Null ; Log-Message " Regkey Created..." ; Write-host " Regkey Created..."-nonewline}
  Test-RegistryValue $Regkey $regname $regvalue $RegType

  Log-Message "Enable Microsoft Defender Antivirus email scanning..." ; Write-host "Enable Microsoft Defender Antivirus email scanning..." -nonewline
  $regkey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan' ; $regname = 'DisableEmailScanning' ; $regValue = '0' ; $RegType = 'DWord' 
  $RegExist = Test-Path $regkey ; If ($regExist -eq $true) {Log-Message " Regkey already Exist..." ; Write-host " Regkey already Exist..."-nonewline} Else { New-Item -Path $regkey -force | Out-Null ; Log-Message " Regkey Created..." ; Write-host " Regkey Created..."-nonewline}
  Test-RegistryValue $Regkey $regname $regvalue $RegType

  Log-Message "Encrypt all BitLocker-supported drives" ; Write-Host "Encrypt all BitLocker-supported drives" -NoNewline
  Bitlocker


  Log-Message "Turn on PUA protection in block mode" ; Write-Host "Turn on PUA protection in block mode" -NoNewline
  Set-MpPreference -PUAProtection Enabled
 Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

  Log-Message "Turn on Microsoft Defender Credential Guard..." ; Write-host "Turn on Microsoft Defender Credential Guard..." -nonewline
  $regkey = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' ; $regname = 'EnableVirtualizationBasedSecurity' ; $regValue = '1' ; $RegType = 'DWord' 
  $RegExist = Test-Path $regkey ; If ($regExist -eq $true) {Log-Message " Regkey already Exist..." ; Write-host " Regkey already Exist..."-nonewline} Else { New-Item -Path $regkey -force | Out-Null ; Log-Message " Regkey Created..." ; Write-host " Regkey Created..."-nonewline}
  Test-RegistryValue $Regkey $regname $regvalue $RegType
  $regkey = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' ; $regname = 'RequirePlatformSecurityFeatures' ; $regValue = '1' ; $RegType = 'DWord' 
  $RegExist = Test-Path $regkey ; If ($regExist -eq $true) {Log-Message " Regkey already Exist..." ; Write-host " Regkey already Exist..."-nonewline} Else { New-Item -Path $regkey -force | Out-Null ; Log-Message " Regkey Created..." ; Write-host " Regkey Created..."-nonewline}
  Test-RegistryValue $Regkey $regname $regvalue $RegType
  $regkey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' ; $regname = 'LsaCfgFlags' ; $regValue = '2' ; $RegType = 'DWord' 
  $RegExist = Test-Path $regkey ; If ($regExist -eq $true) {Log-Message " Regkey already Exist..." ; Write-host " Regkey already Exist..."-nonewline} Else { New-Item -Path $regkey -force | Out-Null ; Log-Message " Regkey Created..." ; Write-host " Regkey Created..."-nonewline}
  Test-RegistryValue $Regkey $regname $regvalue $RegType

  Log-Message " " ; Write-Host " "
  Log-Message "Implementing en Enable ASR Rules" ; Write-Host "Implementing en Enable ASR Rules" -foregroundcolor blue 
 
  Log-Message "Block abuse of exploited vulnerable signed drivers" ; Write-Host "Block abuse of exploited vulnerable signed drivers" -NoNewline
  Add-MpPreference -AttackSurfaceReductionRules_Ids 56a863a9-875e-4185-98a7-b882c64b5ce5 -AttackSurfaceReductionRules_Actions Enabled
  Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

  Log-Message "Block Adobe Reader from creating child processes" ; Write-Host "Block Adobe Reader from creating child processes" -NoNewline
  Add-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions Enabled
  Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

  Log-Message "Block all Office applications from creating child processes" ; Write-Host "Block all Office applications from creating child processes" -NoNewline
  Add-MpPreference -AttackSurfaceReductionRules_Ids d4f940ab-401b-4efc-aadc-ad5f3c50688a -AttackSurfaceReductionRules_Actions Enabled
  Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

  Log-Message "Block credential stealing from the Windows local security authority subsystem (lsass.exe)" ; Write-Host "Block credential stealing from the Windows local security authority subsystem (lsass.exe)" -NoNewline
  Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled
  Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

  Log-Message "Block executable content from email client and webmail" ; Write-Host "Block executable content from email client and webmail" -NoNewline
  Add-MpPreference -AttackSurfaceReductionRules_Ids be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 -AttackSurfaceReductionRules_Actions Enabled
  Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

  Log-Message "Block executable files from running unless they meet a prevalence, age, or trusted list criterion" ; Write-Host "Block executable files from running unless they meet a prevalence, age, or trusted list criterion" -NoNewline
  Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions Enabled
  Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

  Log-Message "Block execution of potentially obfuscated scripts" ; Write-Host "Block execution of potentially obfuscated scripts" -NoNewline
  Add-MpPreference -AttackSurfaceReductionRules_Ids 5beb7efe-fd9a-4556-801d-275e5ffc04cc -AttackSurfaceReductionRules_Actions Enabled
  Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

  Log-Message "Block JavaScript or VBScript from launching downloaded executable content" ; Write-Host "Block JavaScript or VBScript from launching downloaded executable content" -NoNewline
  Add-MpPreference -AttackSurfaceReductionRules_Ids d3e037e1-3eb8-44c8-a917-57927947596d -AttackSurfaceReductionRules_Actions Enabled
  Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

  Log-Message "Block Office applications from creating executable content" ; Write-Host "Block Office applications from creating executable content" -NoNewline
  Add-MpPreference -AttackSurfaceReductionRules_Ids 3b576869-a4ec-4529-8536-b80a7769e899 -AttackSurfaceReductionRules_Actions Enabled
  Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

  Log-Message "Block Office applications from injecting code into other processes" ; Write-Host "Block Office applications from injecting code into other processes" -NoNewline
  Add-MpPreference -AttackSurfaceReductionRules_Ids 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84 -AttackSurfaceReductionRules_Actions Enabled
  Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

  Log-Message "Block Office communication application from creating child processes" ; Write-Host "Block Office communication application from creating child processes" -NoNewline
  Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49e8-8b27-eb1d0a1ce869 -AttackSurfaceReductionRules_Actions Enabled
  Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

  Log-Message "Block persistence through WMI event subscription" ; Write-Host "Block persistence through WMI event subscription" -NoNewline
  Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled
  Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

  Log-Message "Block process creations originating from PSExec and WMI commands" ; Write-Host "Block process creations originating from PSExec and WMI commands" -NoNewline
  Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions Enabled
  Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

  Log-Message "Block rebooting machine in Safe Mode (preview)" ; Write-Host "Block rebooting machine in Safe Mode (preview)" -NoNewline
  Add-MpPreference -AttackSurfaceReductionRules_Ids 33ddedf1-c6e0-47cb-833e-de6133960387 -AttackSurfaceReductionRules_Actions Enabled
  Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

  Log-Message "Block untrusted and unsigned processes that run from USB" ; Write-Host "Block untrusted and unsigned processes that run from USB" -NoNewline
  Add-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions Enabled
  Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

  Log-Message "Block Webshell creation for Servers" ; Write-Host "Block Webshell creation for Servers" -NoNewline
  Add-MpPreference -AttackSurfaceReductionRules_Ids a8f5898e-1dc8-49a9-9878-85004b8a61e6 -AttackSurfaceReductionRules_Actions Enabled
  Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

  Log-Message "Block Win32 API calls from Office macros" ; Write-Host "Block Win32 API calls from Office macros" -NoNewline
  Add-MpPreference -AttackSurfaceReductionRules_Ids 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b -AttackSurfaceReductionRules_Actions Enabled
  Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

  Log-Message "Use advanced protection against ransomware" ; Write-Host "Use advanced protection against ransomware" -NoNewline
  Add-MpPreference -AttackSurfaceReductionRules_Ids c1db55ab-c21a-4637-bb3f-a12568109d35 -AttackSurfaceReductionRules_Actions Enabled
  Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green
}


# ****************************************************************************************************************************
# *  this function will check/install and active bitlocker                                                                   *
# ****************************************************************************************************************************
function Bitlocker
{
  $Checkbitlocker = get-command -module bitlocker
  if ($checkbitlocker = "" )
    {
    Log-Messgae "Bitlocker is not installed. Going to install it..." ; write-host "Bitlocker is not installed. Goning to install it..." -nonewline
    Install-WindowsFeature BitLocker -IncludeAllSubFeature -IncludeManagementTools -NoRestart
    Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green
    Log-Message "Bitlocker is Installed. Start Encryption of Drives..." ; Write-Host "Bitlocker is Installed. Start Encryption of Drives..." -nonewline
    }
  Else
    {
    Log-Message "Bitlocker is Installed. Start Encryption of Drives..." ; Write-Host "Bitlocker is Installed. Start Encryption of Drives..." -nonewline
    }

  Log-Message "Check if Drive is Encrypted..." ; Write-host "Check if Drive is Encrypted..." -nonewline
  $RecoveryKey = (Get-BitLockerVolume -MountPoint C).KeyProtector

  If ($Recoverkey)
    { 
    Log-Message "Drive is Not encrypted. Starting Encryption..." ; Write-Host "Drive is Not encrypted. Starting Encryption..." -nonewline
    Enable-BitLocker -MountPoint c: -EncryptionMethod Aes256 -TpmProtector -UsedSpaceOnly -SkipHardwareTest
    $TimeStamp = (Get-Date).toString("dd/MM/yyyy HH:mm:ss:fff tt")
    $BitLogDate = (Get-Date).toString("dd-MM-yyyy")
    $bitlockerSave = $Scriptdir + "\Bitlocker\"+ $Computername + " " + $BitLogDate + ".txt"
    $Line = "$TimeStamp - Start Enabling Bitlocker on Drive"   
    $line | out-file -filepath @bitlockersave -append
    $RecoveryKey = (Get-BitLockerVolume -MountPoint C).KeyProtector
    $RecoveryKey | Out-File -FilePath $bitlockersave -Append
    } 
  Else
    {
    Log-Message "Drive is Already encrypted. Encryption not Nessesary..." ; Write-Host "Drive is Already encrypted. Encryption not Nessesary..." -nonewline -foregroundclolor Yellow
    }
  Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green
}

# ****************************************************************************************************************************
# *  this function will Disable SMB1 protocol                                                                                *
# ****************************************************************************************************************************
function SMB
{
  Log-Message "Disabling and Removing SMB1 protocol..." ; Write-Host "Disabling and Removing SMB1 protocol..." -NoNewline
  Set-SmbServerConfiguration -EnableSMB1Protocol $false -Confirm:$false
  Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

  Log-Message "remove SMB1 server role..." ; Write-Host "remove SMB1 server role..." -NoNewLine
  Remove-WindowsFeature FS-SMB1 | Out-Null
  Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

  Log-Message "remove SMB1 client config..." ; Write-Host "remove SMB1 client config..." -NoNewLine
  sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi | Out-Null
  sc.exe config mrxsmb10 start= disabled | Out-Null
  Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

  Log-Message "re-enable sharing in firewall, only when removed by scripting (Remove-WindowsFeature)... " ; Write-Host "re-enable sharing in firewall, only when removed by scripting (Remove-WindowsFeature)... " -NoNewLine
  Enable-NetFirewallRule -DisplayName "File and Printer Sharing (SMB-In)"
  Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green
}

# ****************************************************************************************************************************
# * Now Download and install Micrsoft LAPS                                                                                   *
# ****************************************************************************************************************************
function LAPS
{
  Log-Message " " ; Write-Host " "
  Log-Message "Checking if LAPS is Installed" ; Write-Host "Checking if LAPS is Installed" -Foregroundcolor blue
  If (-not (get-package "Local Administrator Password*" -ErrorAction SilentlyContinue)){ 
   Log-Message "Install Microsoft LAPS..."
    Write-Host "Install Microsoft LAPS..." -NoNewline
    Start-Process msiexec.exe -Wait -ArgumentList "/I $scriptdir\Applications\Laps\laps.x64.msi /qn /L*v $scriptdir\Applications\laps\logs\$Computername.txt"
    }
  Else {
    Log-Message "Microsoft LAPS already installed..."
    Write-Host "Microsoft LAPS already installed..." -NoNewline
    }
  Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green
}

# ****************************************************************************************************************************
# * Install Ghisler Total Commander                                                                                          *
# ****************************************************************************************************************************
function TotalCommander
{
  Log-Message " " ;   Write-Host " "
  Log-Message "Checking if Total Commander is Installed" ; Write-Host "Checking if Total Commander is Installed" -Foregroundcolor blue
  If (-not (get-package "Total Commander*" -ErrorAction SilentlyContinue)){ 
    Log-Message "Installing Total Commander..."
    Write-host "Installing Total Commander..." -nonewline
    Start-Process $scriptdir\Applications\total-commander\tcmd1000x64-custum.exe -Wait -ArgumentList "/AHMGU" 
    }
  Else {
    Log-Message "Total Commander already installed..." ; Write-host "Total Commander already installed..." -nonewline
    }
  Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green
}

# ****************************************************************************************************************************
# * Install MicroSoft Edge                                                                                                   *
# ****************************************************************************************************************************
function MicrosoftEdge
{
  Log-Message " " ;   Write-Host " "
  Log-Message "Checking if Microsoft Edge is Installed" ; Write-Host "Checking if Microsoft Edge is Installed" -Foregroundcolor blue
  If (-not (get-package "Microsoft Edge*" -ErrorAction SilentlyContinue)){ 
    Log-Message "Installing Microsoft Edge..." ; Write-host "Installing Microsoft Edge..." -nonewline
    Start-Process msiexec.exe -Wait -ArgumentList "/I $scriptdir\Applications\edge\MicrosoftEdgeEnterpriseX64.msi /qn /L*v $scriptdir\Applications\edge\logs\$Computername.txt"  }
  Else {
    Log-Message "Microsoft Edge is already installed..." ; Write-host "Microsoft Edge is Already installed..." -nonewline
    }
  Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green
}

# ****************************************************************************************************************************
# * Download and install Micrsoft ARC and register it to the company Azure Site                                              *
# ****************************************************************************************************************************
function ARC
{
  Log-Message " " ;   Write-Host " "
  Log-Message "Download and Install Microsoft ARC..." ; Write-Host "Download and Install Microsoft ARC..." -NoNewline
  [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
  # Download the installation package
  Invoke-WebRequest -Uri https://aka.ms/azcmagent-windows -TimeoutSec 30 -OutFile "$env:TEMP\install_windows_azcmagent.ps1"
  # Install the hybrid agent
  & "$env:TEMP\install_windows_azcmagent.ps1"
  if($LASTEXITCODE -ne 0) 
    {throw "Failed to install the hybrid agent"}

  # Run connect command
  & "$env:ProgramW6432\AzureConnectedMachineAgent\azcmagent.exe" connect --service-principal-id "$servicePrincipalClientId" --service-principal-secret "$servicePrincipalSecret" --resource-group "$ResourceGroup" --tenant-id "$TenantId" --location "$Location" --subscription-id "$SubscriptionId" --cloud "$Cloud" --correlation-id "$CorrelationId"
  if($LastExitCode -eq 0)
    {Write-Host -ForegroundColor yellow "To view your onboarded server(s), navigate to https://portal.azure.com/blade/HubsExtension/BrowseResource/resourceType/Microsoft.HybridCompute%2Fmachines"}
  Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green
}

# ****************************************************************************************************************************
# * Onboarding Server to Micrsoft Windows Defender (https://Security.microsoft.com)                                          *
# ****************************************************************************************************************************
function Defender
  {
  if ($os -eq "W2012" -or $os -eq "w2016") {
    Log-Message " " ; Write-Host " "
    Log-Message "Checking if Defender For Old Servers is installed" ; Write-Host "Checking if Defender For Old Servers is installed" -Foregroundcolor blue

    If (-not (get-package "Microsoft Defender*" -ErrorAction SilentlyContinue)){ 
      Log-Message "Installing Microsoft Defender..." ; Write-host "Installing Microsoft Defender..." -nonewline
      Start-Process msiexec.exe -Wait -ArgumentList "/I $scriptdir\Applications\WindowsDefender\md4ws.msi /qn /L*v $scriptdir\Applications\WindowsDefender\logs\$Computername.txt"
      Log-Message "Microsoft Defender is installed. Please Reboot Server and start the script again..." ; Write-Host "Microsoft Defener is installed. Please Reboot Server and start the script again..." -ForegroundColor Yellow
      Exit
      }
    Else {
      Log-Message "Microsoft Defender already installed..." ; Write-host "Microsoft Defender already installed..." -nonewline
      }
    Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green


    }

    $defenderStatus = get-MpComputerStatus | select AntivirusEnabled
    if ($defenderstatus.AntivirusEnabled -eq "True") {
      Log-Message "Server Already Onboarded to Microsoft Windows Defender..." ; Write-Host "Server already Onboarded to Microsoft Windows Defender..." -NoNewline
    }
    Else {
      Log-Message "Onboarding Server to Microsoft Windows Defender..." ; Write-Host "Onboarding Server to Microsoft Windows Defender..." -NoNewline
      Start-Process $scriptdir\Applications\WindowsDefender\WindowsDefenderATPLocalOnboardingScript.cmd -Wait 
    }
    Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green 
  }


# ****************************************************************************************************************************
# * install Micrsoft log analistic workspace agent                                                                           *
# ****************************************************************************************************************************
function LogAnalistic
{
  Log-Message "Micrsoft log analistic workspace agent..." ; Write-Host "Micrsoft log analistic workspace agent..." -NoNewline
  Start-Process $scriptdir\Applications\log-agent\setup.exe -Wait -ArgumentList "/qn NOAPM=1 ADD_OPINSIGHTS_WORKSPACE=1 OPINSIGHTS_WORKSPACE_AZURE_CLOUD_TYPE=0 OPINSIGHTS_WORKSPACE_ID=$WORKSPACE_ID OPINSIGHTS_WORKSPACE_KEY=$WORKSPACE_KEY AcceptEndUserLicenseAgreement=1 /qn /L*v $scriptdir\log-agent\logs\$Computername.txt"
  Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green 
}

# ****************************************************************************************************************************
# * Install Windows Updates (Powershell 5.1 needed)                                                                          *
# ****************************************************************************************************************************
function WindowsUpdates
{
  Log-Message " " ; Write-Host " "
  Log-Message "Installing Windows Updates" ; Write-Host "Installing Windows Updates" -foregroundcolor Blue
  Log-Message "Settings Windows Updates PreRequirements..." ; Write-Host "Settings Windows Updates PreRequirements..." 
  Log-Message "Setting Windows to Use TLS 1.2..." ; Write-Host "Setting Windows to Use TLS 1.2..." -NoNewLine
  [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
  Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

  Log-Message "Check if NuGet is Installed. Else Download and Installing NuGet Package..." ; Write-Host "Check if NuGet is Installed. Else Download and Installing NuGet Package..." -NoNewLine
  if (-not (Get-PackageProvider -Name "nuGet" -ErrorAction SilentlyContinue))
    {
    Log-Message "download and installing NuGet... " ; Write-Host "download and installing NUGet... " -NoNewLine
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Confirm:$False | Out-Null
    Register-PSRepository -Default
    }
  Else
    {
     Log-Message "Module is already Installed... " ; Write-Host "Module is already installed... " -NoNewLine
    }
  Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

  Log-Message "Check is Windows Update module is Installed... " ; Write-Host "Check is Windows Update module is Installed... "-NoNewLine
  if (-not (Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue))
    {
    Log-Message "download and installing PSWindowsupdate... " ; Write-Host "download and installing PSWindowsupdate... " -NoNewLine
    Install-Module PSWindowsUpdate -force -Confirm:$False | Out-Null
    }
  Else
    {
     Import-Module PSWindowsUpdate 
     Log-Message "Module is already Installed... " ; Write-Host "Module is already installed... " -NoNewLine
    }

  Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

  Log-Message "Download and Install Microsoft Windows Updates, This can Take a While... " ; Write-Host "Download and Install Microsoft Windows Updates, This can Take a While... " -NoNewline
  Get-WindowsUpdate -AcceptAll -Install -IgnoreReboot | Out-Null
  Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green
}

# ****************************************************************************************************************************
# * Enable Remote Management (for RSAT tools and Windows Admin Center) and enable Windows Firewall rules                     *
# ****************************************************************************************************************************
function RemoteManagement
{ Log-Message "Enable Remote Management..." ; Write-Host "Enable Remote Management..." -NoNewline
 Enable-PSRemoting -Force | Out-Null
 Enable-WSManCredSSP -Role server -Force | Out-Null
 try {
   Get-NetFirewallRule -DisplayGroup $wmiFirewallRuleDisplayGroup -Enabled true -ErrorAction Stop | Out-Null
  } 
catch {
 Set-NetFirewallRule -DisplayGroup $wmiFirewallRuleDisplayGroup -Enabled true -PassThru | Out-Null
  }
 
try {
  Get-NetFirewallRule -DisplayGroup $remoteEventLogFirewallRuleDisplayGroup -Enabled true -ErrorAction Stop | Out-Null
  }
catch {
  Set-NetFirewallRule -DisplayGroup $remoteEventLogFirewallRuleDisplayGroup -Enabled true -PassThru | Out-Null
  }
Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green
}

# *************************************************************************************************************************************
# *                                                ===--- end Functions ---===                                                        *
# *************************************************************************************************************************************

# *************************************************************************************************************************************
# *                                           ===--- main script starts here ---===                                                   *
# *************************************************************************************************************************************
$wmiFirewallRuleDisplayGroup = "Windows Management Instrumentation (WMI)"
$remoteEventLogFirewallRuleDisplayGroup = "Remote Event Log Management"
$uacRegKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$uacRegKeyName = "EnableLUA"
$interActiveLogonRegKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$interActiveLogonRegKeyName = "DontDisplayLastUsername"
$rdpPrinterMappingRegKeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$rdpPrinterMappingRegKeyName = "fDisableCpm"

# ****************************************************************************************************************************
# * Clear the Screen so all log messages are displayed                                                                       *
# ****************************************************************************************************************************
Cls
Log-Message "Script Execution Started" ; Write-Host "Script Execution Started" -foregroundcolor blue

# ****************************************************************************************************************************
# * this suppress any powershell progress bar, i.e loading of modules, uninstalling software                                 *
# ****************************************************************************************************************************
$ProgressPreference=’SilentlyContinue’

# ****************************************************************************************************************************
# * Check the version of the opperating system so to aplly specific settings                                                 *
# ****************************************************************************************************************************
Log-Message "Checking If Powershell Runs with Administrator Rights... " ; Write-Host "Checking If Powershell Runs with Administrator Rights... " -NoNewline
$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$p = New-Object System.Security.Principal.WindowsPrincipal($id)
if ($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)){
  Log-Message "Powershell is Running in Administrator mode" ;  Write-Host "Powershell is Running in Administrator mode"  -ForegroundColor Green
  } 
else { 
  Log-Message "Powershell is Running in Not Administrator mode" ; Write-Host "Powershell is Running in Not Administrator mode"  -ForegroundColor red
  Write-Host " "
  Log-Message " "
  Log-Message ". Quitting script!!!" ; Write-Host ". Quitting script!!!" -BackgroundColor Red -ForegroundColor White
  Exit
  }   

Log-Message "Checking the operating system version... "
Write-Host "Checking the operating system version... " -NoNewline
$osname = Get-CimInstance Win32_Operatingsystem | select -expand Caption
if ($osname -like "Microsoft Windows Server 2008*")    {$os = "w2008";   Log-Message " Found $osname ..."; Write-Host " Found " $osname"..." }
if ($osname -like "Microsoft Windows Server 2012*")    {$os = "w2012";   Log-Message " Found $osname ..."; Write-Host " Found " $osname"..." }
if ($osname -like "Microsoft Windows Server 2016*")    {$os = "w2016";   Log-Message " Found $osname ..."; Write-Host " Found " $osname"..." }
if ($osname -like "Microsoft Windows Server 2019*")    {$os = "w2019";   Log-Message " Found $osname ..."; Write-Host " Found " $osname"..." }
if ($osname -like "Microsoft Windows Server 2022*")    {$os = "w2022";   Log-Message " Found $osname ..."; Write-Host " Found " $osname"..." }
if ($osname -like "Microsoft Windows Server 2025*")    {$os = "w2025";   Log-Message " Found $osname ..."; Write-Host " Found " $osname"..." }


if ($os -eq "w2025" -or $os -eq "w2022" -or $os -eq "w2019" -or $os -eq "w2016" -or $os -eq "w2012" -or $os -eq "w2008") {
  Log-Message " " ; Write-Host " "
  Log-Message "!!! This script is Support on $osname" ; Write-Host "!!! This script is Support on $osname" -ForegroundColor Green
  }
  Else {
  Log-Message "!!! This script does not support $osname" ; Write-Host "!!! This script does not support " -NoNewline
  Log-Message "$osname " ; Write-Host "$osname " -NoNewline -BackgroundColor Red -ForegroundColor White
  Log-Message " " ; Write-Host " "
  Log-Message ". Quitting script!!!" ; Write-Host ". Quitting script!!!"
  Exit
  }

# ****************************************************************************************************************************
# * this suppress Security Warnings Dialogs During the Run of this script                                                    *
# ****************************************************************************************************************************
Log-Message " " ; Write-Host " "
Log-Message "Start Implementing Default settings and settings to execute the script" ; Write-Host "StartImplementing Defsult settings and settings to execute the script" -foregroundcolor blue

Log-Message "Disable Security Warnings During the Execution of the Script... " ; Write-Host "Disable Security Warnings During the Execution of the Script..." -NoNewline
$regkey = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Associations' ; $regname = 'LowRiskFileTypes' ; $regValue = '.cmd;.ps1;.msi;.exe' ; $RegType = 'String' 
$RegExist = Test-Path $regkey ; If ($regExist -eq $true) {Log-Message " Regkey already Exist..." ; Write-host " Regkey already Exist..."-nonewline} Else { New-Item -Path $regkey -force | Out-Null ; Log-Message " Regkey Created..." ; Write-host " Regkey Created..."-nonewline}
Test-RegistryValue $Regkey $regname $regvalue $RegType

# ****************************************************************************************************************************
# * Enable User Account Control (UAC)
# ****************************************************************************************************************************
Log-Message "Enable User Account Control..." ; Write-Host "Enable User Account Control..." -NoNewline
Set-ItemProperty -Path $uacRegKeyPath -Name $uacRegKeyName -Value 1 -Type DWord | Out-Null
Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

# **************************************************************************************************************************** 
# * Set the Interactive Login to Don't display the last username
# ****************************************************************************************************************************
Log-Message "Set the Interactive Login to Don't display the last username..." ; Write-Host "Set the Interactive Login to Don't display the last username..." -NoNewline
Set-ItemProperty -Path $interActiveLogonRegKeyPath -Name $interActiveLogonRegKeyName -Value 1 | Out-Null
Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

# ****************************************************************************************************************************
# * Disable RDP printer mapping
# ****************************************************************************************************************************
Log-Message "Disable RDP printer mapping..." ; Write-Host "Disable RDP printer mapping..." -NoNewline
Set-ItemProperty -Path $rdpPrinterMappingRegKeyPath -Name $rdpPrinterMappingRegKeyName -Value 1 | Out-Null
Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

# ****************************************************************************************************************************
# * Change Drive Letter For Optical Drive to z:                                                                              *
# ****************************************************************************************************************************
Log-Message "Changing drive letter to Z: for the first CD-drive..." ; Write-Host "Changing drive letter to Z: for the first CD-drive..." -NoNewline
Get-WmiObject -Class Win32_volume -Filter 'DriveType=5' | Select-Object -First 1 | Set-WmiInstance -Arguments @{DriveLetter='Z:'} | Out-Null
Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

# ****************************************************************************************************************************
# * Set Volume Label for c drive (Disbaled otherwise PRTG gives errors on existing servers                                   *
# ****************************************************************************************************************************
# Log-Message "Setting C: drive label to 'System'..." ; Write-Host "Setting C: drive label to 'System'..." -NoNewline
# Set-Volume -DriveLetter "C" -NewFileSystemLabel "System"
# Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

# ****************************************************************************************************************************
# * Change MEmory Dump File Settings.								                             *
# ****************************************************************************************************************************
Log-Message "Setting Automatic memory dump to small..." ; Write-Host "Setting Automatic memory dump to small..." -NoNewline
Get-WmiObject -Class Win32_OSRecoveryConfiguration -EnableAllPrivileges | Set-WmiInstance -Arguments @{ DebugInfoType=3 } | Out-Null
Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

# ****************************************************************************************************************************
# * Disbale Netbios ans LMHosts Lookup                                                                                       *
# ****************************************************************************************************************************
Log-Message "Disabel Netbios ans LMHosts Lookup..." ; Write-Host "Disabel Netbios ans LMHosts Lookup..." -NoNewline
$NICS = Get-WmiObject win32_NetworkAdapterConfiguration
foreach ($NIC in $NICS){
  $NIC.settcpipnetbios(2) | Out-Null
} 
$nicClass = Get-WmiObject -list Win32_NetworkAdapterConfiguration
$nicClass.enablewins($false,$false) | Out-Null
Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

# ****************************************************************************************************************************
# * first install windows-version independent stuff and settings                                                             *
# * Starting with a time sync to the Europe pool time server                                                                 *
# ****************************************************************************************************************************
Log-Message " " ; Write-Host " "
Log-Message "Start setting Regional al Language Settings and timesync" ;Write-Host "Start setting Regional al Language Settings and timesync" -foregroundcolor blue

Log-Message "Import Powershell Module International" ;Write-Host "Import Powershell Module International" -NoNewline
Import-Module International
Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

Log-Message "Set Time Zone to Wesern Europe (Amsterdam)" ; Write-Host "Set Time Zone to Wesern Europe (Amsterdam)" -NoNewline
Set-TimeZone -Name "W. Europe Standard Time"
Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

Log-Message "Set Country to Netherlands" ; Write-Host "Set Country to Netherlands" -NoNewline
Set-WinSystemLocale NL-nl 
Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

Log-Message "Region to Netherlands" ; Write-Host "Region to Netherlands" -NoNewline
Set-WinHomeLocation -GeoId 176
Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

Log-Message "Set Regional format to English-Netherlands" ; Write-Host "Set Regional format to English-Netherlands" -NoNewline
set-culture en-NL
Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

Log-Message "Syncing time..." ; Write-Host "Syncing time..." -NoNewline
w32tm /config /update /manualpeerlist:europe.pool.ntp.org | Out-Null
w32tm /resync /force | Out-Null
Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

# ****************************************************************************************************************************
# * now install OS specific software and settings                                                                            *
# * this includes: disabling various services                                                                                *
# ****************************************************************************************************************************
if ($os -eq "w2008") {w2008stuff}
if ($os -eq "w2012") {w2012stuff}
if ($os -eq "w2016") {w2016stuff}
if ($os -eq "w2019") {w2019stuff}
if ($os -eq "w2022") {w2022stuff}
if ($os -eq "w2025") {w2025stuff}

# ****************************************************************************************************************************
# * Install Apllications if Wanted                                                                                           *
# ****************************************************************************************************************************
if ($ServerManager -eq $True) {Servermanager} Else { Log-Message " " ; Write-Host " " ; Log-Message "Disbale The Server manager at Statup is not Wanted" ; write-host "Disbale The Server manager at Statup is not Wanted" -ForegroundColor Yellow}
if ($OnboardDefender -eq $True) {Defender} Else {  Log-Message " " ; Write-Host " " ; Log-Message "Onboarding Defender is not Wanted" ; write-host "Onboarding Defender is not Wanted" -ForegroundColor Yellow}
if ($InstallLogAnalitics -eq $True) {LogAnalistic} Else {  Log-Message " " ; Write-Host " " ; Log-Message "Installing of Log Analistic Agent is not Wanted"; write-host "Installing of Log Analistic Agent is not Wanted"-ForegroundColor Yellow}
if ($DisbaleServices -eq -$True) {DisableServices} Else {  Log-Message " " ; Write-Host " " ; Log-Message "Disbaling of Services is not Wanted"; write-host "Disbaling of Services is not Wanted"-ForegroundColor Yellow}
if ($InstallSecurityReccomandationsAccounts -eq -$True) {SecurityReccomendationsAccounts} Else { Log-Message " " ; Write-Host " " ; Log-Message "Appling Security Reccomandations for Accounts Sections is not Wanted"; write-host "Appling Security Reccomandations for Accounts Sections is not Wanted"-ForegroundColor Yellow}
if ($InstallSecurityReccomandationsApplications -eq -$True) {SecurityReccomandationsApplications} Else { Log-Message " " ; Write-Host " " ; Log-Message "Appling Security Reccomandations for AApplications Sections is not Wanted"; write-host "Appling Security Reccomandations for Applications Sections is not Wanted"-ForegroundColor Yellow}
if ($InstallSecurityReccomandationsNetwork -eq -$True) {SecurityReccomandationsNetwork} Else { Log-Message " " ; Write-Host " " ; Log-Message "Appling Security Reccomandations for Network Sections is not Wanted"; write-host "Appling Security Reccomandations for Network Sections is not Wanted"-ForegroundColor Yellow}
if ($InstallSecurityReccomandationsNetworkAssessment -eq -$True) {SecurityReccomandationsNetworkAssessment} Else { Log-Message " " ; Write-Host " " ; Log-Message "Appling Security Reccomandations for Network Assessment Sections is not Wanted"; write-host "Appling Security Reccomandations for Network Assessment Sections is not Wanted"-ForegroundColor Yellow}
if ($InstallSecurityReccomandationsOS -eq -$True) {SecurityReccomandationsOS} Else { Log-Message " " ; Write-Host " " ; Log-Message "Appling Security Reccomandations for Opersting System Sections is not Wanted"; write-host "Appling Security Reccomandations for Operating Systems Sections is not Wanted"-ForegroundColor Yellow}
if ($InstallSecurityReccomandationsSecurityControls -eq -$True) {SecurityReccomandationsSecurityControls} Else { Log-Message " " ; Write-Host " " ; Log-Message "Appling Security Reccomandations for Security Controls Sections is not Wanted"; write-host "Appling Security Reccomandations for Security Control Sections is not Wanted"-ForegroundColor Yellow}
if ($DisbaleSMB -eq $True) {SMB} Else { Log-Message " " ; Write-Host " " ; Log-Message "Disbaling of SMB1 is not Wanted"; write-host "Disbaling of SMB1 is not Wanted"-ForegroundColor Yellow}

Log-Message " " ; Write-Host " "
Log-Message "Installing Applications..." ; Write-Host "Installing Applications..." -foregroundcolor blue
if ($InstallLAPS -eq $True) {LAPS} Else { Log-Message " " ; Write-Host " " ; Log-Message "Installing of LAPS is not Wanted"; write-host "Installing of LAPS is not Wanted"-ForegroundColor Yellow}
if ($InstallTotalCommander -eq $True) {TotalCommander} Else { Log-Message " " ; Write-Host " " ; Log-Message "Installing of Total Commander is not Wanted"; write-host "Installing of Total Commander is not Wanted"-ForegroundColor Yellow}
if ($InstallARC -eq $True) {ARC} Else { Log-Message " " ; Write-Host " " ; Log-Message "Installing of ARC is not Wanted"; write-host "Installing of ARC is not Wanted"-ForegroundColor Yellow}

if ($InstallWindowsUpdates -eq $True) {WindowsUpdates} Else { Log-Message " " ; Write-Host " " ; Log-Message "Installing of Windows Updates is not Wanted"; write-host "Installing of Windows Updates is not Wanted"-ForegroundColor Yellow}

if ($InstallRemoteManagement -eq $True) {RemoteManagement} Else { Log-Message " " ; Write-Host " " ; Log-Message "Enable Remote Mamagement is not Wanted"; write-host "Enable Remote Mamagement is not Wanted"-ForegroundColor Yellow}


# ****************************************************************************************************************************
# * Cleanup the Envirment end ending the script                                                                              *
# ****************************************************************************************************************************
Log-Message " " ; Write-Host " "
Log-Message "Cleanup the Envirment end ending the script" ; Write-Host "Cleanup the Envirment end ending the script" -foregroundcolor blue

# ****************************************************************************************************************************
# * Cleaning up Windows Installation                                                                                         *
# ****************************************************************************************************************************
Log-Message "Cleaning up Windows Installation..." ; Write-Host "Cleaning up Windows Installation..." -NoNewline
if (test-path "c:\logs") { Remove-Item -Recurse -Force -Path c:\logs -ErrorAction Ignore}
if (test-path "c:\perflogs") { Remove-Item -Recurse -Force -Path c:\perflogs -ErrorAction Ignore}
if (test-path "c:\users\administrator\appdata\local\temp") {Remove-Item -Recurse -Force -Path c:\users\administrator\appdata\local\temp\* -ErrorAction Ignore}
if (test-path "c:\windows\logs") {Remove-Item -Recurse -Force -Path c:\windows\logs\* -ErrorAction Ignore}
if (test-path "c:\windows\temp") {Remove-Item -Recurse -Force -Path c:\windows\temp\* -ErrorAction Ignore}
Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green

# ****************************************************************************************************************************
# * this enable Security Warnings Dialogs                                                                                    *
# ****************************************************************************************************************************
Log-Message "Enable Security Warnings... "
Write-Host "Enable Security Warnings" -NoNewline
Remove-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Associations' -force
Log-Message " done!" ; Write-Host " done!" -ForegroundColor Green


# ****************************************************************************************************************************
# * Ending the script                                                                                                        *
# ****************************************************************************************************************************
Log-Message " " ; Write-Host " "
Log-Message "All done, all done! Have a nice day..." ; Write-Host "All done, all done! Have a nice day..." -ForegroundColor Cyan

Write-Host
If ($Reboot -eq $true){
  Log-Message "System Will be Restarted in $Reboottimeout Seconds" ; Write-Host "System Will be Restarted in" $Reboottimeout "Seconds" -ForegroundColor Red -BackgroundColor White
  Start-Sleep -s $Reboottimeout
  Restart-Computer
  }
Else
  {
  Log-Message "  ---=== Don't Forget to Reboot the Server ===---  " ; Write-Host "  ---=== Don't Forget to Reboot the Server ===---  " -ForegroundColor Red -BackgroundColor White
  }
Log-Message "Script Execution Completed"
Exit

# *************************************************************************************************************************************
# * EXIT									                                                      *
# *************************************************************************************************************************************
:Exit

# *************************************************************************************************************************************
# *                                            ===--- main script ends here ---===                                                    *
# *************************************************************************************************************************************
