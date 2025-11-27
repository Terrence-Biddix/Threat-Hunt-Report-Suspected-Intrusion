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
<img width="979" height="149" alt="Flag 4 KQL" src="https://github.com/user-attachments/assets/3b9d799f-4340-497a-a41f-6cdc3929f1d7" />

<img width="826" height="278" alt="Flag 4 evidence" src="https://github.com/user-attachments/assets/0d7a9ba6-57dd-4244-836b-7d5993db7869" />

During my investigation, I filtered Microsoft Defender for Endpoint DeviceProcessEvents on the compromised workstation AZUKI-SL and looked specifically for attacker behavior that matched the staging-directory pattern: a newly created folder followed shortly after by an attrib command that hides it. By focusing on commands such as mkdir, New-Item, and attrib +h +s, I identified a sequence where the attacker first created a directory and then modified its attributes to conceal it from normal view. This activity clearly indicated the establishment of a malware staging location. Based on the evidence, I confirmed that the primary staging directory used by the attacker was: C:\ProgramData\WindowsCache.



#### 🏳️Flag 5: DEFENCE EVASION - File Extension Exclusions
Attackers add file extension exclusions to Windows Defender to prevent scanning of malicious files. Counting these exclusions reveals the scope of the attacker's defense evasion strategy.


##### Objective
Determine how many file extensions were excluded from Windows Defender scanning

##### What to Hunt
Search DeviceRegistryEvents for registry modifications to Windows Defender's exclusion settings. Look for the RegistryValueName field containing file extensions. Count the unique file extensions added to the "Exclusions\Extensions" registry key during the attack timeline.

#### KQL Query
<img width="639" height="120" alt="Flag 5 KQL" src="https://github.com/user-attachments/assets/b8610a03-ff81-4b69-b111-7d4093beaa7e" />

<img width="131" height="81" alt="Flag 5 evidence" src="https://github.com/user-attachments/assets/0fa8e1ee-f3c5-4b7c-9a0a-d79ba83fba31" />

To determine how many file extensions the attacker excluded from Windows Defender, I searched the DeviceRegistryEvents table for any registry modifications under the Windows Defender exclusions path during the attack window. I filtered specifically for changes to the Exclusions\Extensions key and looked for RegistryValueSet actions, since those indicate an extension being added. Then I counted the distinct values in the RegistryValueName field, which represents each excluded file type. From this, I confirmed that the attacker added 3 file extension exclusions.



#### 🏳️Flag 6: DEFENCE EVASION - Temporary Folder Exclusion
Attackers add folder path exclusions to Windows Defender to prevent scanning of directories used for downloading and executing malicious tools. These exclusions allow malware to run undetected.


##### Objective
FInd the temporary folder path that was excluded from Windows Defender scanning

##### What to Hunt
Search DeviceRegistryEvents for folder path exclusions added to Windows Defender configuration. Focus on the RegistryValueName field. Look for temporary folder paths added to the exclusions list during the attack timeline. Copy the path exactly as it appears in the RegistryValueName field. The registry key contains "Exclusions\Paths" under Windows Defender configuration.
#### KQL Query
<img width="641" height="99" alt="Flag 6 KQL" src="https://github.com/user-attachments/assets/ac6e288f-1a26-4806-b342-f1f4623cc187" />

<img width="934" height="322" alt="Flag 6 evidence" src="https://github.com/user-attachments/assets/2f2be722-2144-4ef5-8ddd-0cf45a165f9c" />

During the investigation, I searched the DeviceRegistryEvents table on the compromised system azuki-sl and filtered the results to the attack window. I specifically looked for changes made to the Windows Defender exclusions list under the Exclusions\Paths registry key. By reviewing entries where a new path was added, I identified that the attacker created a Windows Defender folder-path exclusion pointing to a temporary directory. The registry event showed that the excluded folder path was C:\Users\KENJI~1.SAT\AppData\Local\Temp, confirming that the attacker attempted to evade detection by ensuring any malicious tools placed in that temp folder would not be scanned.



#### 🏳️Flag 7: DEFENCE EVASION - Download Utility Abuse
Legitimate system utilities are often weaponized to download malware while evading detection. Identifying these techniques helps improve defensive controls.


##### Objective
Identify the Windows-native binary the attacker abused to download files

##### What to Hunt
Look for built-in Windows tools with network download capabilities being used during the attack. Search DeviceProcessEvents for processes with command lines containing URLs and output file paths.

#### KQL Query
<img width="620" height="285" alt="Flag 7 KQL" src="https://github.com/user-attachments/assets/9c9a6079-668d-4ec0-88da-388216f90e2e" />

<img width="755" height="268" alt="Flag 7 evidence" src="https://github.com/user-attachments/assets/58298bff-22eb-4ffa-a9b6-b9722cdfa920" />

I focused on identifying any Windows-native utilities that may have been abused to download malicious files. I filtered DeviceProcessEvents on the compromised system and searched for processes that included URLs in their command lines. From there, I narrowed the results to known Living-off-the-Land binaries that attackers commonly misuse for covert downloads. This analysis revealed that certutil.exe was executed with network parameters, indicating it was leveraged to pull files from an external source. Based on this evidence, I concluded that the attacker abused certutil.exe to download their payload.



#### 🏳️Flag 8: PERSISTENCE - Scheduled Task Name
Scheduled tasks provide reliable persistence across system reboots. The task name often attempts to blend with legitimate Windows maintenance routines.


##### Objective
Identify the name of the scheduled task created for persistence

##### What to Hunt
Search for scheduled task creation commands executed during the attack timeline. Look for schtasks.exe with the /create parameter in DeviceProcessEvents.

#### KQL Query
<img width="570" height="113" alt="Flag 8 KQL" src="https://github.com/user-attachments/assets/ca7b7cb3-89d6-4fbb-8844-880366774741" />

<img width="1058" height="211" alt="Flag 8 evidence" src="https://github.com/user-attachments/assets/630e584d-7a18-4e4a-a2ac-74514009f0a0" />

I filtered DeviceProcessEvents on the compromised IT admin workstation and searched for any execution of schtasks.exe with the /create parameter during the attack window. This allowed me to isolate any malicious scheduled tasks created for persistence. When I reviewed the command line details, I identified a suspicious task designed to blend in with normal OS activity. The scheduled task created by the attacker for persistence was named “Windows Update Check.”



#### 🏳️Flag 9: PERSISTENCE - Scheduled Task Target
The scheduled task action defines what executes at runtime. This reveals the exact persistence mechanism and the malware location.


##### Objective
Identify the executable path configured in the scheduled task

##### What to Hunt
Extract the task action from the scheduled task creation command line. Look for the /tr parameter value in the schtasks command.
#### KQL Query
<img width="655" height="156" alt="Flag 9 KQL" src="https://github.com/user-attachments/assets/98ff5f61-84a2-4e99-825d-6f4eb263fed8" />

<img width="1068" height="177" alt="Flag 9 evidence" src="https://github.com/user-attachments/assets/6853a342-8d4d-4d26-b412-947772eafa9b" />

To identify the executable path used for persistence, I filtered DeviceProcessEvents on the compromised workstation and focused on any schtasks /create commands. I reviewed the full command line to locate the /tr parameter, since that value reveals what the scheduled task actually runs. After extracting the /tr argument, I confirmed that the attacker configured the scheduled task to execute C:\ProgramData\WindowsCache\svchost.exe, which is the persistence mechanism left behind on the system.



#### 🏳️Flag 10: COMMAND & CONTROL - C2 Server Address
Command and control infrastructure allows attackers to remotely control compromised systems. Identifying C2 servers enables network blocking and infrastructure tracking.


##### Objective
Identify the IP address of the command and control server

##### What to Hunt
Analyse network connections initiated by the suspicious executable shortly after it was downloaded. Use DeviceNetworkEvents to find outbound connections from the malicious process to external IP addresses.

#### KQL Query
<img width="857" height="114" alt="Flag 10 KQL" src="https://github.com/user-attachments/assets/558f8db8-d231-47c3-88af-6ead99fa1dba" />

<img width="1085" height="175" alt="Flag 10 evidence" src="https://github.com/user-attachments/assets/b17b40bf-0560-4bb2-9435-35234dbbc024" />

To find the suspicious executable and identify the C2 server, I first reviewed all process activity on azuki-sl during the incident window and focused on processes that looked unusual or capable of making outbound connections. From there, I checked network events tied to those processes. By filtering DeviceNetworkEvents to only show outbound connections initiated by powershell.exe between November 19 and 20, I isolated the traffic associated with the malicious activity. Reviewing these events showed an external connection to 78.141.196.6, which I identified as the attacker’s command-and-control server.


#### 🏳️Flag 11: COMMAND & CONTROL - C2 Communication Port
C2 communication ports can indicate the framework or protocol used. This information supports network detection rules and threat intelligence correlation.


##### Objective
Identify the destination port used for command and control communications

##### What to Hunt
Examine the destination port for outbound connections from the malicious executable. Check DeviceNetworkEvents for the RemotePort field associated with C2 traffic.
#### KQL Query
<img width="575" height="128" alt="Flag 11 KQL" src="https://github.com/user-attachments/assets/454fb419-22c1-4f08-bda4-9a3b6ff3d4a4" />

<img width="724" height="285" alt="Flag 11 evidence" src="https://github.com/user-attachments/assets/36b0e2b9-f490-4494-8749-6ee21b46ff6d" />

To identify the command-and-control destination port, I started by reviewing the DeviceNetworkEvents for the compromised workstation azuki-sl during the suspected intrusion window. I filtered the results to show only outbound connections tied to suspicious executables and then examined the RemotePort field for any traffic that didn’t match normal business operations. As I traced network activity generated by the malicious process, I found repeated outbound connections to an external IP using port 443, which indicated that the attacker was tunneling their C2 traffic over standard HTTPS to blend in with normal network behavior.



#### 🏳️Flag 12: CREDENTIAL ACCESS - Credential Theft Tool
Credential dumping tools extract authentication secrets from system memory. These tools are typically renamed to avoid signature-based detection.


##### Objective
Identify the filename of the credential dumping tool

##### What to Hunt
Look for executables downloaded to the staging directory with very short filenames. Search for files created shortly before LSASS memory access events.

#### KQL Query
<img width="615" height="117" alt="Flag 12 KQL" src="https://github.com/user-attachments/assets/df355e95-2286-4eda-b61b-71cd06e7ecdc" />

<img width="731" height="284" alt="Flag 12 evidence" src="https://github.com/user-attachments/assets/27ef20da-81fd-478a-a08d-bbed5ccf5dfe" />

To identify the credential-dumping tool, I focused on detecting processes that executed known credential-theft commands rather than relying on LSASS access telemetry. I filtered DeviceProcessEvents on the compromised system azuki-sl during the incident window, then searched process command-lines for strings commonly associated with credential dumping, such as "mimikatz", "::", "sekurlsa", and "lsadump". By reviewing the resulting processes and their executable names, I was able to pinpoint the malicious binary responsible for credential access activity. The process executing these commands was mm.exe, confirming it as the credential-dumping tool used in this attack.



#### 🏳️Flag 13: CREDENTIAL ACCESS - Memory Extraction Module
Credential dumping tools use specific modules to extract passwords from security subsystems. Documenting the exact technique used aids in detection engineering.


##### Objective
Identify the module used to extract logon passwords from memory

##### What to Hunt
Examine the command line arguments passed to the credential dumping tool. Look for module::command syntax in the process command line or output redirection.

#### KQL Query
<img width="615" height="117" alt="Flag 12 KQL" src="https://github.com/user-attachments/assets/76122276-d8e0-4d2d-a520-c02937ae1b8a" />

<img width="701" height="145" alt="FLag 13 evidence" src="https://github.com/user-attachments/assets/e75b4d89-b553-4a71-9aa3-241725fe82fd" />

During my review of the DeviceProcessEvents for azuki-sl between November 19–20, I filtered for any process executions containing Mimikatz indicators such as "::", "sekurlsa", or "lsadump". I examined the full ProcessCommandLine values to determine whether a credential-dumping module was invoked. In the results, I found a command line explicitly calling the Mimikatz sekurlsa::logonpasswords module, which is used to extract logon credentials directly from LSASS memory. Based on this evidence, I concluded that the attacker used sekurlsa::logonpasswords to dump logon passwords from memory.



#### 🏳️Flag 14: COLLECTION - Data Staging Archive
Attackers compress stolen data for efficient exfiltration. The archive filename often includes dates or descriptive names for the attacker's organisation.


##### Objective
Identify the compressed archive filename used for data exfiltration

##### What to Hunt
Search for ZIP file creation in the staging directory during the collection phase. Look for Compress-Archive commands or examine files created before exfiltration activity.

#### KQL Query
<img width="560" height="256" alt="Flag 14 KQL" src="https://github.com/user-attachments/assets/5ff4cb6d-6ba5-432f-81d7-97729bd3eb35" />

<img width="938" height="116" alt="Flag 14 evidence" src="https://github.com/user-attachments/assets/f17190d9-4791-4751-8385-624280e53e8d" />


To identify the archive used for exfiltration, I filtered Microsoft Defender for Endpoint logs for DeviceFileEvents on the compromised system azuki-sl during the suspected collection window. I looked specifically for ZIP file creation, focusing on staging directories and any use of Compress-Archive, 7-Zip, or other compression utilities. By reviewing the resulting file creation events and inspecting the process command lines tied to them, I confirmed that the attackers created a ZIP archive to stage the stolen data. The filename used for exfiltration was export-data.zip.




#### 🏳️Flag 15: EXFILTRATION - Exfiltration Channel
Cloud services with upload capabilities are frequently abused for data theft. Identifying the service helps with incident scope determination and potential data recovery.


##### Objective
Identify the cloud service used to exfiltrate stolen data

##### What to Hunt
Analyse outbound HTTPS connections and file upload operations during the exfiltration phase. Check DeviceNetworkEvents for connections to common file sharing or communication platforms.

#### KQL Query
<img width="556" height="185" alt="Flag 15 KQL" src="https://github.com/user-attachments/assets/31066028-c0c7-4dc5-9979-eedc659ffb52" />

<img width="402" height="171" alt="Flag 15 evidence" src="https://github.com/user-attachments/assets/7047c7ae-c51a-4cf3-aae7-3d597ff86aaf" />

To determine which cloud service was used for exfiltration, I first filtered outbound HTTPS traffic from the compromised device during the incident window. When I noticed that the entry with the highest connection count didn’t include a RemoteUrl, I pivoted to the RemoteIP field and treated it as the destination instead. From there, I performed a reverse lookup and correlated the IP range with known cloud and communication platforms. Once I matched the traffic pattern, connection behavior, and hosting provider, I confirmed that the destination belonged to Discord, identifying it as the exfiltration channel.


#### 🏳️Flag 16: ANTI-FORENSICS - Log Tampering
Clearing event logs destroys forensic evidence and impedes investigation efforts. The order of log clearing can indicate attacker priorities and sophistication.


##### Objective
Identify the first Windows event log cleared by the attacker

##### What to Hunt
Search for event log clearing commands near the end of the attack timeline. Look for wevtutil.exe executions and identify which log was cleared first.

#### KQL Query
<img width="561" height="121" alt="Flag 16 KQL" src="https://github.com/user-attachments/assets/47324df1-c5fa-4dd8-aeda-d91d73938693" />

<img width="546" height="125" alt="Flag 16 evidence" src="https://github.com/user-attachments/assets/f8555381-342f-465b-b55b-22caf1fb6c80" />

To determine which Windows event log the attacker cleared first, I filtered DeviceProcessEvents for activity on azuki-sl during the suspected intrusion window. I focused specifically on executions of wevtutil.exe, since that command is used to clear Windows logs. After sorting those events in ascending order by timestamp, I reviewed the earliest command the attacker ran. The first wevtutil cl entry targeted the Security log, confirming that the attacker prioritized removing evidence of authentication and privilege-related activity.



#### 🏳️Flag 17: IMPACT - Persistence Account
Hidden administrator accounts provide alternative access for future operations. These accounts are often configured to avoid appearing in normal user interfaces.


##### Objective
Identify the backdoor account username created by the attacker

##### What to Hunt
Search for account creation commands executed during the impact phase. Look for commands with the /add parameter followed by administrator group additions.

#### KQL Query
<img width="668" height="171" alt="Flag 17 KQL" src="https://github.com/user-attachments/assets/921582b9-0127-4481-b65d-270e0c306031" />

<img width="545" height="212" alt="Flag 17 evidence" src="https://github.com/user-attachments/assets/9cc58111-f52d-481e-b6b8-7b1410acf5f0" />

To identify the backdoor account, I focused on commands that attackers typically use to create hidden local administrator accounts. First, I filtered the DeviceProcessEvents for activity on azuki-sl within the incident timeframe. Then I looked specifically for commands containing /add, since this parameter is commonly used when adding new users, and I also checked for references to the Administrators group. Next, I searched for both net user and net localgroup syntax to ensure I captured either user creation or privilege escalation. Once I isolated these commands, I extracted the username embedded in the command line—this revealed the hidden persistence account the attacker created.



#### 🏳️Flag 18: EXECUTION - Malicious Script
Attackers often use scripting languages to automate their attack chain. Identifying the initial attack script reveals the entry point and automation method used in the compromise.


##### Objective
Identify the PowerShell script file used to automate the attack chain

##### What to Hunt
Search DeviceFileEvents for script files created in temporary directories during the initial compromise phase. Look for PowerShell or batch script files downloaded from external sources shortly after initial access.
#### KQL Query
<img width="762" height="135" alt="Flag 18 KQL" src="https://github.com/user-attachments/assets/4d8bd24f-7f25-422b-82c8-a2df1fc78f9a" />

<img width="1309" height="203" alt="Flag 18 evidence" src="https://github.com/user-attachments/assets/3ab9e8b4-62d9-48aa-a271-e4c1fa0b5ca2" />

I started by examining the DeviceFileEvents for the compromised workstation, AZUKI-SL, focusing on the timeframe of November 19 to 20, 2025. I specifically looked for any PowerShell scripts created in temporary directories, since attackers often drop their automation scripts there during an initial compromise. I filtered for .ps1 files and checked if any were associated with external downloads using PowerShell commands. Through this process, I identified the malicious script that automated the attack chain, and the file responsible was wupdate.ps1.

#### 🏳️Flag 19: LATERAL MOVEMENT - Secondary Target
Lateral movement targets are selected based on their access to sensitive data or network privileges. Identifying these targets reveals attacker objectives.


##### Objective
Find the IP address that was targeted for lateral movement

##### What to Hunt
Examine the target system specified in remote access commands during lateral movement. Look for IP addresses used with cmdkey or mstsc commands near the end of the attack timeline.
#### KQL Query
<img width="640" height="150" alt="Flag 19 KQL" src="https://github.com/user-attachments/assets/377cc508-5732-42b8-9434-20d4bcbd0a66" />

<img width="314" height="105" alt="Flag 19 evidence" src="https://github.com/user-attachments/assets/6ec00b2c-c2bc-4a33-a4e1-892b28446150" />

To find the lateral movement target, I filtered the DeviceProcessEvents for activity on azuki-sl during the attack window. I looked specifically for commands that indicate credential reuse or remote access, such as cmdkey or mstsc, since these often contain the destination system. After isolating those events, I extracted any IP addresses embedded in the command lines to see where the attacker attempted to move next. From this analysis, I identified 10.1.0.188 as the system the attacker targeted for lateral movement.



#### 🏳️Flag 20: LATERAL MOVEMENT - Remote Access Tool
Built-in remote access tools are preferred for lateral movement as they blend with legitimate administrative activity. This technique is harder to detect than custom tools.


##### Objective
Identify the remote access tool used for lateral movement

##### What to Hunt
Search for remote desktop connection utilities executed near the end of the attack timeline. Look for processes launched with remote system names or IP addresses as arguments.
#### KQL Query
<img width="831" height="134" alt="Flag 20 KQL" src="https://github.com/user-attachments/assets/c676f23d-fcba-4595-9a2c-1ec914ca7e7d" />

<img width="878" height="436" alt="Flag 20 evidence" src="https://github.com/user-attachments/assets/65ed2d47-cc7d-4e6c-bef9-1fe42f79e1fd" />



During my investigation, I reviewed the process activity on the compromised admin workstation AZUKI‑SL and focused on events near the end of the attack timeline. I searched for any built‑in remote access utilities that could indicate lateral movement. When I filtered for processes commonly used for Remote Desktop Protocol activity, I found mstsc.exe executed with a remote system specified in the command line. This confirmed that the attacker used the native Windows Remote Desktop client (mstsc.exe) to move laterally within the environment.
