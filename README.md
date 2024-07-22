# Hardening-Servers
***********************************************************
SYNOPSIS                                                
Applies a Default Configuration to a new Windows Server, or Update the Security on an Existing Server.           
***********************************************************
DESCRIPTION                                             
Applies a Default Configuration to a new Windows Server, or Update the Security on an Existing Server.           
                                                         
REQUIREMENTS:                                           
Powershell Needs to be run in Administrative mode.
PowerShell execution policy must be configured to allow script execution.
For example, with a command such as the following:                   
        -Set-ExecutionPolicy RemoteSigned        
                                                        
Explenation:                                            
There are some Parameters that are needed for the installation of Azure Arc and Azure Analitics           
Worksapce Agent. Also there is a variable that determend the Reboot end the Timeout in Seconds,                  
that will we used to reboot the Server at the end of the Script                                                  
                                                        
Also You need to download some scripts for the Security Portal to Onboard Devices to defendere.
I am looing for a Solution to Implented these scripts into the hardening scripts. But Micrsoft
Only Release the Script for a Working periode of 10 day's. If someone knows how to implement it
To the hardingscript please let me know.

Then ther are some Applications that will be installed by the scripts. In the Varibale 
difintion you need to modify the Parameters for $true or $False to determin what applications there will be installed.                   
To make the Installation Posiable you will need to download the Latest installations files and put them in the Applications Folder.
Applicatiosn that are installed throw this scipt are:
   - Microsoft Edge (https://www.microsoft.com/nl-nl/edge/business/download?form=MA13FJ)
   - Microsoft LAPS (https://www.microsoft.com/en-us/download/details.aspx?id=46899)
   - Microsoft Log Analitics agent 
   - Microsoft Powershell 5.1
   - Microsoft Windows Defender (Security.microsoft.com-->Settings-->Endpoints-->Onboarding)
   - Ghisler Total Commander (https://totalcommander.ch/1103/tcmd1103x64.exe)

Thanks:                                                 
My thanks to the Author of the Baseline Powershell Script and the Author of the Windows Path Enumerate Script.
                                                         
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
