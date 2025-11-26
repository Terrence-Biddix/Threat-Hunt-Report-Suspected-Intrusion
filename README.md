# Threat-Hunt-Report-Suspected-Intrusion

## 🎯 Scenario
Port of Entry
INCIDENT BRIEF - Azuki Import/Export - 梓貿易株式会社
SITUATION:
Competitor undercut our 6-year shipping contract by exactly 3%. Our supplier contracts and pricing data appeared on underground forums.

### COMPANY:
Azuki Import/Export Trading Co. - 23 employees, shipping logistics Japan/SE Asia

#### COMPROMISED SYSTEMS:

AZUKI-SL (IT admin workstation)

#### 🖥️ EVIDENCE AVAILABLE:
Microsoft Defender for Endpoint logs


#### INVESTIGATION QUESTIONS:
Initial access method?
Compromised accounts?
Data stolen?
Exfiltration method?
Persistent access remaining?

DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))

## 🏳️ Flags
#### 🏳️Flag 1: INITIAL ACCESS - Remote Access Source

Remote Desktop Protocol connections leave network traces that identify the source of unauthorised access. Determining the origin helps with threat actor attribution and blocking ongoing attacks.

##### Objective
Identify the source IP address of the Remote Desktop Protocol connection.

##### What to Hunt
The origin of the RemoteIP used for the unauthorised access
#### KQL Query
<img width="601" height="113" alt="Flag 1 KQL" src="https://github.com/user-attachments/assets/6aca25ff-6eda-4ada-af93-5308d00012c6" />

<img width="862" height="262" alt="Flag 1 evidence" src="https://github.com/user-attachments/assets/5a3706df-c410-4822-89ae-13470a62a7db" />

To identify the source IP address used for the unauthorized Remote Desktop Protocol (RDP) access, I began by reviewing the Microsoft Defender for Endpoint logon telemetry associated with the compromised system. During the incident timeframe, I searched the DeviceLogonEvents table because this dataset records all successful and failed logon attempts, including those performed interactively through RDP. Filtering the logs to the exact window of interest (2025-11-19 to 2025-11-20) and ensuring the query looks specifically for remote interactive logon, returned the events and showed the originating IP address (88.97.178.12) of the RDP session. This IP is the answer for the initial access flag, and it provides insight into where the attacker connected from.

#### 🏳️Flag 2: Account Name

##### Objective
Identify the account name of the Remote Desktop Protocol connection.

##### What to Hunt
The origin of the account name used for the unauthorised access

<img width="862" height="262" alt="Flag 1 evidence" src="https://github.com/user-attachments/assets/5a3706df-c410-4822-89ae-13470a62a7db" />

kenji.sato

#### 🏳️Flag 3: DISCOVERY - Network Reconnaissance

Attackers enumerate network topology to identify lateral movement opportunities and high-value targets. This reconnaissance activity is a key indicator of advanced persistent threats.

##### Objective
Identify the command and argument used to enumerate network neighbours

##### What to Hunt
Look for commands that reveal local network devices and their hardware addresses. Check DeviceProcessEvents for network enumeration utilities executed after initial access.
#### KQL Query
<img width="713" height="104" alt="Flag 3 KQL" src="https://github.com/user-attachments/assets/c7b2cef9-232b-4fd9-8ba5-854ada826778" />

<img width="895" height="127" alt="Flag 3 evidence" src="https://github.com/user-attachments/assets/ef078312-d1bd-401a-8ab6-f5f9cf5ab018" />

I discovered that the attacker ran the arp -a command on the compromised workstation azuki-sl, which shows all local network neighbors along with their hardware (MAC) addresses. Seeing this in the logs confirmed that the attacker was performing network reconnaissance to map out nearby systems and identify potential lateral-movement targets right after gaining initial access.

#### 🏳️Flag 4: DEFENCE EVASION - Malware Staging Directory
Attackers establish staging locations to organise tools and stolen data. Identifying these directories reveals the scope of compromise and helps locate additional malicious artefacts.


##### Objective
Identify the PRIMARY staging directory where malware was stored

##### What to Hunt
Search for newly created directories in system folders that were subsequently hidden from normal view. Look for mkdir or New-Item commands followed by attrib commands that modify folder attributes.

#### KQL Query


#### 🏳️Flag 5: DEFENCE EVASION - File Extension Exclusions
Attackers add file extension exclusions to Windows Defender to prevent scanning of malicious files. Counting these exclusions reveals the scope of the attacker's defense evasion strategy.


##### Objective
Determine how many file extensions were excluded from Windows Defender scanning

##### What to Hunt
Search DeviceRegistryEvents for registry modifications to Windows Defender's exclusion settings. Look for the RegistryValueName field containing file extensions. Count the unique file extensions added to the "Exclusions\Extensions" registry key during the attack timeline.

#### KQL Query


#### 🏳️Flag 6: DEFENCE EVASION - Temporary Folder Exclusion
Attackers add folder path exclusions to Windows Defender to prevent scanning of directories used for downloading and executing malicious tools. These exclusions allow malware to run undetected.


##### Objective
FInd the temporary folder path that was excluded from Windows Defender scanning

##### What to Hunt
Search DeviceRegistryEvents for folder path exclusions added to Windows Defender configuration. Focus on the RegistryValueName field. Look for temporary folder paths added to the exclusions list during the attack timeline. Copy the path exactly as it appears in the RegistryValueName field. The registry key contains "Exclusions\Paths" under Windows Defender configuration.
#### KQL Query


#### 🏳️Flag 7: DEFENCE EVASION - Download Utility Abuse
Legitimate system utilities are often weaponized to download malware while evading detection. Identifying these techniques helps improve defensive controls.


##### Objective
Identify the Windows-native binary the attacker abused to download files

##### What to Hunt
Look for built-in Windows tools with network download capabilities being used during the attack. Search DeviceProcessEvents for processes with command lines containing URLs and output file paths.

#### KQL Query


#### 🏳️Flag 8: PERSISTENCE - Scheduled Task Name
Scheduled tasks provide reliable persistence across system reboots. The task name often attempts to blend with legitimate Windows maintenance routines.


##### Objective
Identify the name of the scheduled task created for persistence

##### What to Hunt
Search for scheduled task creation commands executed during the attack timeline. Look for schtasks.exe with the /create parameter in DeviceProcessEvents.

#### KQL Query


#### 🏳️Flag 9: PERSISTENCE - Scheduled Task Target
The scheduled task action defines what executes at runtime. This reveals the exact persistence mechanism and the malware location.


##### Objective
Identify the executable path configured in the scheduled task

##### What to Hunt
Extract the task action from the scheduled task creation command line. Look for the /tr parameter value in the schtasks command.
#### KQL Query


#### 🏳️Flag 10: COMMAND & CONTROL - C2 Server Address
Command and control infrastructure allows attackers to remotely control compromised systems. Identifying C2 servers enables network blocking and infrastructure tracking.


##### Objective
Identify the IP address of the command and control server

##### What to Hunt
Analyse network connections initiated by the suspicious executable shortly after it was downloaded. Use DeviceNetworkEvents to find outbound connections from the malicious process to external IP addresses.

#### KQL Query


#### 🏳️Flag 11: COMMAND & CONTROL - C2 Communication Port
C2 communication ports can indicate the framework or protocol used. This information supports network detection rules and threat intelligence correlation.


##### Objective
Identify the destination port used for command and control communications

##### What to Hunt
Examine the destination port for outbound connections from the malicious executable. Check DeviceNetworkEvents for the RemotePort field associated with C2 traffic.
#### KQL Query


#### 🏳️Flag 12: CREDENTIAL ACCESS - Credential Theft Tool
Credential dumping tools extract authentication secrets from system memory. These tools are typically renamed to avoid signature-based detection.


##### Objective
Identify the filename of the credential dumping tool

##### What to Hunt
Look for executables downloaded to the staging directory with very short filenames. Search for files created shortly before LSASS memory access events.

#### KQL Query


#### 🏳️Flag 13: CREDENTIAL ACCESS - Memory Extraction Module
Credential dumping tools use specific modules to extract passwords from security subsystems. Documenting the exact technique used aids in detection engineering.


##### Objective
Identify the module used to extract logon passwords from memory

##### What to Hunt
Examine the command line arguments passed to the credential dumping tool. Look for module::command syntax in the process command line or output redirection.

#### KQL Query


#### 🏳️Flag 14: COLLECTION - Data Staging Archive
Attackers compress stolen data for efficient exfiltration. The archive filename often includes dates or descriptive names for the attacker's organisation.


##### Objective
Identify the compressed archive filename used for data exfiltration

##### What to Hunt
Search for ZIP file creation in the staging directory during the collection phase. Look for Compress-Archive commands or examine files created before exfiltration activity.

#### KQL Query


#### 🏳️Flag 15: EXFILTRATION - Exfiltration Channel
Cloud services with upload capabilities are frequently abused for data theft. Identifying the service helps with incident scope determination and potential data recovery.


##### Objective
Identify the cloud service used to exfiltrate stolen data

##### What to Hunt
Analyse outbound HTTPS connections and file upload operations during the exfiltration phase. Check DeviceNetworkEvents for connections to common file sharing or communication platforms.

#### KQL Query


#### 🏳️Flag 16: ANTI-FORENSICS - Log Tampering
Clearing event logs destroys forensic evidence and impedes investigation efforts. The order of log clearing can indicate attacker priorities and sophistication.


##### Objective
Identify the first Windows event log cleared by the attacker

##### What to Hunt
Search for event log clearing commands near the end of the attack timeline. Look for wevtutil.exe executions and identify which log was cleared first.

#### KQL Query


#### 🏳️Flag 17: IMPACT - Persistence Account
Hidden administrator accounts provide alternative access for future operations. These accounts are often configured to avoid appearing in normal user interfaces.


##### Objective
Identify the backdoor account username created by the attacker

##### What to Hunt
Search for account creation commands executed during the impact phase. Look for commands with the /add parameter followed by administrator group additions.

#### KQL Query


#### 🏳️Flag 18: EXECUTION - Malicious Script
Attackers often use scripting languages to automate their attack chain. Identifying the initial attack script reveals the entry point and automation method used in the compromise.


##### Objective
Identify the PowerShell script file used to automate the attack chain

##### What to Hunt
Search DeviceFileEvents for script files created in temporary directories during the initial compromise phase. Look for PowerShell or batch script files downloaded from external sources shortly after initial access.
#### KQL Query


#### 🏳️Flag 19: LATERAL MOVEMENT - Secondary Target
Lateral movement targets are selected based on their access to sensitive data or network privileges. Identifying these targets reveals attacker objectives.


##### Objective
Find the IP address that was targeted for lateral movement

##### What to Hunt
Examine the target system specified in remote access commands during lateral movement. Look for IP addresses used with cmdkey or mstsc commands near the end of the attack timeline.
#### KQL Query


#### 🏳️Flag 20: LATERAL MOVEMENT - Remote Access Tool
Built-in remote access tools are preferred for lateral movement as they blend with legitimate administrative activity. This technique is harder to detect than custom tools.


##### Objective
Identify the remote access tool used for lateral movement

##### What to Hunt
Search for remote desktop connection utilities executed near the end of the attack timeline. Look for processes launched with remote system names or IP addresses as arguments.
#### KQL Query

