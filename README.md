# Hardening-Servers
***********************************************************
SYNOPSIS                                                
Applies a Default Configuration to a new Windows Server, or Update the Security on an Existing Server.           
***********************************************************
DESCRIPTION                                             
This Script is built to make Windows Servers Compliant with the Recommendations that are done in Windows Security Center.
But Also Applies Default settings to the Server and Install Applications that are needed or that you want to install always

At this moment the scripts is for the Following Operating Systems:
-	Windows Server 2008R2
-	Windows Server 2012R2
-	Windows Server 2019
-	Windows Server 2022
***********************************************************
REQUIREMENTS:
Powershell 5.1 must be used. So in Older Servers this will be installed during the script. But installing Powershell 5.1 needs a reboot.
PowerShell Needs to be run in Administrative mode.
PowerShell execution policy must be configured to allow script execution.
For example, with a command such as the following: Set-ExecutionPolicy RemoteSigned        
***********************************************************
Explanation:                                            
There are some Parameters that are needed for the installation of Azure Arc and Azure Analytics           
Workspace Agent. Also there is a variable that determine the Reboot end the Timeout in Seconds,                  
that will we used to reboot the Server at the end of the Script                                                  
                                                        
Also You need to download some scripts for the Security Portal to Onboard Devices to defender.
I am looking for a Solution to Implement these scripts into the hardening scripts. But Microsoft
Only Release the Script for a Working for 10 devices. If someone knows how to implement it
To the Harding script please let me know.

Then there are some Applications that will be installed by the scripts. In the Variable 
definition you need to modify the Parameters for $true or $False to determine what applications there will be installed.                   
To make the Installation Possible you will need to download the Latest installations files and put them in the Applications Folder.
Applications that are installed throw this script are:
   - Microsoft Edge (https://www.microsoft.com/nl-nl/edge/business/download?form=MA13FJ)
   - Microsoft LAPS (https://www.microsoft.com/en-us/download/details.aspx?id=46899)
   - Microsoft Log Analitics agent 
   - Microsoft Powershell 5.1 (Windows 2008r2 and Windows 2012R2 Only)
   - Microsoft Windows Defender (Security.microsoft.com-->Settings-->Endpoints-->Onboarding)
   - Ghisler Total Commander (https://totalcommander.ch/1103/tcmd1103x64.exe)
                                                         
****************************************************************
Thanks:                                                 
My thanks to the Author of the Baseline PowerShell Script and the Author of the Windows Path Enumerate Script.
****************************************************************
This Script is created by Ronald Bok owner of the Firm T.E.S. - Com.                                          
You may make modifications in order to make the script better. But please let me know so i                     
Can integrate the changes in my version. If we all work to gather this script will be Great
(and it will make it a better World)                            
Thanks in advanced.                                     
                                                        
Ronald Bok                                              
T.E.S. - Com.                                           
Ronald@TES-Com.nl                                       
***********************************************************
