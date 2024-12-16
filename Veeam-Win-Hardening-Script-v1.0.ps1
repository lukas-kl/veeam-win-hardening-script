Start-Transcript -Path "C:\Install\Output-Veeam-Win-Hardening-Script.txt"
# -----------------------------------
# Veeam Windows Hardening Script v1.0
# -----------------------------------
# by Lukas Klostermann
#
# Run this script as Administrator

# Check for Administrator privileges
If (-Not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole] "Administrator")) {
    Write-Host "Please run this script as Administrator."
    exit 1
}

Write-Host "Starting the comprehensive Veeam Windows hardening script..."

# Prompt for new local administrator user credentials
Write-Host "Prompting for new local administrator user credentials..."
$newAdminUser = Read-Host "Enter the new local administrator username"
$newAdminPass = Read-Host "Enter the password for '$newAdminUser'" -AsSecureString

# Create the new local administrator user and set password policies
Write-Host "Creating the new local administrator user and setting password policies..."
try {
    # Create the new local admin user
    Write-Host "Creating the new local admin user account..."
    New-LocalUser -Name $newAdminUser -Password $newAdminPass -Description "Local Administrator" -ErrorAction Stop
    Write-Host "Setting the password to never expire for the new admin user..."
    Set-LocalUser -Name $newAdminUser -PasswordNeverExpires $true
    Write-Host "Adding the new admin user to the 'Administrators' group..."
    Add-LocalGroupMember -Group "Administrators" -Member $newAdminUser -ErrorAction SilentlyContinue
    Write-Host "Adding the new admin user to the 'Remote Desktop Users' group..."
    Add-LocalGroupMember -Group "Remote Desktop Users" -Member $newAdminUser -ErrorAction SilentlyContinue
} catch {
    Write-Error "Error creating the new local administrator: $($_.Exception.Message)"
}

# Create the new service account
Write-Host "Creating the new service account..."
$serviceAccount = Read-Host "Enter the new service account username"
$newServicePass = Read-Host "Enter the password for '$serviceAccount'" -AsSecureString

Write-Host "Creating the new service account and setting password policies..."
try {
    Write-Host "Creating the service account..."
    New-LocalUser -Name $serviceAccount -Password $newServicePass -Description "Veeam Service Account" -ErrorAction Stop
    Write-Host "Setting the password to never expire for the service account..."
    Set-LocalUser -Name $serviceAccount -PasswordNeverExpires $true
    Write-Host "Adding the service account to the 'Administrators' group..."
    Add-LocalGroupMember -Group "Administrators" -Member $serviceAccount -ErrorAction SilentlyContinue
} catch {
    Write-Error "Error creating service account: $($_.Exception.Message)"
}

# Disable the built-in Administrator account
Write-Host "Prompting for the built-in Administrator account password..."
$builtinAdminPass = Read-Host "Enter the password for the built-in Administrator account (Administrator):" -AsSecureString

Write-Host "Disabling the built-in Administrator account by setting its password and deactivating it..."
Try {
    Write-Host "Setting new password for the built-in Administrator account..."
    net user Administrator $((New-Object System.Net.NetworkCredential("", $builtinAdminPass)).Password)
    Write-Host "Deactivating the built-in Administrator account..."
    net user Administrator /active:no
} catch {
    Write-Error "Error disabling the built-in Administrator: $($_.Exception.Message)"
}

# Modify 'Allow log on through Remote Desktop Services' user right assignments
Write-Host "Modifying 'Allow log on through Remote Desktop Services' user right assignments..."
Write-Host "Removing 'Administrators' group from 'Allow log on through Remote Desktop Services'..."
& "C:\Install\ntrights.exe" -u "Administrators" -r SeRemoteInteractiveLogonRight
Write-Host "Adding 'Remote Desktop Users' group to 'Allow log on through Remote Desktop Services'..."
& "C:\Install\ntrights.exe" -u "Remote Desktop Users" -a SeRemoteInteractiveLogonRight

# Grant "Log on as a service" right to Veeam Service Account
Write-Host "Granting 'Log on as a service' right to the Veeam Service Account..."
& "C:\Install\ntrights.exe" -u $serviceAccount +r SeServiceLogonRight

# Deny "Log on as a service" right to built-in Administrator account
Write-Host "Granting 'Log on as a service' right to the Veeam Service Account..."
& "C:\Install\ntrights.exe" -u Administrator +r SeDenyServiceLogonRight

# Deny "Log on as a service" right to new local admin account
Write-Host "Granting 'Log on as a service' right to the Veeam Service Account..."
& "C:\Install\ntrights.exe" -u $newAdminUser +r SeDenyServiceLogonRight

# Set Account Lockout Policies
Write-Host "Setting Account Lockout Policies..."
Write-Host "Configuring lockout threshold..."
net accounts /lockoutthreshold:5
Write-Host "Configuring lockout duration..."
net accounts /lockoutduration:15
Write-Host "Configuring lockout window..."
net accounts /lockoutwindow:15

# Enable 'AllowAdminLockout' in registry
Write-Host "Enabling 'AllowAdminLockout' in registry..."
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "AllowAdminLockout" -Value 1 -Type DWord

# ----------------------------
# Activate the "High Performance" Power Plan
# ----------------------------

Write-Host "Activating the 'High Performance' Power Plan..."
$HighPerfGUID = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
powercfg -setactive $HighPerfGUID

# Optional: Verify that the High Performance plan is active
$currentPlan = powercfg -getactivescheme
Write-Host "Active Power Plan: $currentPlan"

# ----------------------------
# Accounts Section
# ----------------------------

# Block Microsoft accounts
Write-Host "Blocking Microsoft account user authentication..."
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'NoConnectedUser' -Type DWord -Value 3

# Disable Guest account
Write-Host "Disabling the Guest account..."
net user guest /active:no

# Limit local account use of blank passwords to console logon only
Write-Host "Enabling limitation for blank password use..."
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'limitblankpassworduse' -Type DWord -Value 1

# ----------------------------
# Audit Section
# ----------------------------

Write-Host "Configuring Audit Policies..."
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Application Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:disable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Plug and Play Events" /success:enable /failure:disable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable
auditpol /set /subcategory:"Account Lockout" /success:disable /failure:enable
auditpol /set /subcategory:"Group Membership" /success:enable /failure:disable
auditpol /set /subcategory:"Logoff" /success:enable /failure:disable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:disable
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:disable
auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:disable
auditpol /set /subcategory:"Authorization Policy Change" /success:enable /failure:disable
auditpol /set /subcategory:"Other Policy Change Events" /success:disable /failure:enable
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:enable
auditpol /set /subcategory:"Other System Events" /success:enable /failure:enable
auditpol /set /subcategory:"Security State Change" /success:enable /failure:disable
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:disable
auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable

# ----------------------------
# Devices Section
# ----------------------------

# Prevent users from installing printer drivers
Write-Host "Preventing users from installing printer drivers..."
$printerPolicyPath = 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers'
if (-not (Test-Path $printerPolicyPath)) {
    New-Item -Path $printerPolicyPath -Force | Out-Null
}
Set-ItemProperty -Path $printerPolicyPath -Name 'PreventUserInstall' -Type DWord -Value 1

# ----------------------------
# Interactive logon Section
# ----------------------------

Write-Host "Configuring Interactive Logon settings..."
# Do not require CTRL+ALT+DEL
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DisableCAD' -Type DWord -Value 0

# Don't display last signed-in user name
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DontDisplayLastUserName' -Type DWord -Value 1

# Machine inactivity limit
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'InactivityTimeoutSecs' -Type DWord -Value 900

# Number of previous logons to cache
$winlogonPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
if (-not (Test-Path $winlogonPath)) {
    New-Item -Path $winlogonPath -Force | Out-Null
}
Set-ItemProperty -Path $winlogonPath -Name 'CachedLogonsCount' -Type String -Value "3"

# ----------------------------
# Microsoft network server Section
# ----------------------------

Write-Host "Configuring Microsoft Network Server settings..."
$lanmanPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
if (-not (Test-Path $lanmanPath)) {
    New-Item -Path $lanmanPath -Force | Out-Null
}
Set-ItemProperty -Path $lanmanPath -Name 'AutoDisconnect' -Type DWord -Value 15

# ----------------------------
# Network access Section
# ----------------------------

Write-Host "Configuring Network Access settings..."
# Let Everyone permissions apply to anonymous users
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'EveryoneIncludesAnonymous' -Type DWord -Value 0

# Shares that can be accessed anonymously
$nullSessionSharesPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
if (-not (Test-Path $nullSessionSharesPath)) {
    New-Item -Path $nullSessionSharesPath -Force | Out-Null
}
Set-ItemProperty -Path $nullSessionSharesPath -Name 'NullSessionShares' -Type MultiString -Value @()

# Sharing and security model for local accounts
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'ForceGuest' -Type DWord -Value 0

# ----------------------------
# Shutdown Section
# ----------------------------

Write-Host "Configuring Shutdown settings..."
# Allow system to be shut down without having to log on
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ShutdownWithoutLogon' -Type DWord -Value 0

# ----------------------------
# System objects Section
# ----------------------------

Write-Host "Configuring System Objects settings..."
# Strengthen default permissions of internal system objects
$sessionManagerPath = 'HKLM:\System\CurrentControlSet\Control\Session Manager'
if (-not (Test-Path $sessionManagerPath)) {
    New-Item -Path $sessionManagerPath -Force | Out-Null
}
Set-ItemProperty -Path $sessionManagerPath -Name 'ProtectionMode' -Type DWord -Value 1

# ----------------------------
# System Services
# ----------------------------

Write-Host "Configuring System Services..."
# Print Spooler: disabled
Stop-Service -Name Spooler -Force
Set-Service -Name Spooler -StartupType Disabled

# ----------------------------
# Windows Firewall
# ----------------------------

# Windows Defender Firewall with Advanced Security settings
# Domain Profile
Set-NetFirewallProfile -Name Domain -Enabled True -LogFileName '%SystemRoot%\System32\logfiles\firewall\domainfw.log' -LogMaxSizeKilobytes 16384 -LogBlocked True

# Private Profile
Set-NetFirewallProfile -Name Private -Enabled True -LogFileName '%SystemRoot%\System32\logfiles\firewall\privatefw.log' -LogMaxSizeKilobytes 16384 -LogBlocked True

# Public Profile
Set-NetFirewallProfile -Name Public -Enabled True -LogFileName '%SystemRoot%\System32\logfiles\firewall\publicfw.log' -LogMaxSizeKilobytes 16384 -LogBlocked True

# ----------------------------
# GPO: Administrative Templates (Computer)
# ----------------------------

Write-Host "Configuring GPO Administrative Templates..."

# Function to safely create and set registry values
function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [string]$Type,
        $Value
    )

    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }

    Set-ItemProperty -Path $Path -Name $Name -Type $Type -Value $Value
}

# Prevent enabling lock screen camera: enabled
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" `
                 -Name "NoLockScreenCamera" `
                 -Type DWord `
                 -Value 1

# Prevent enabling lock screen slideshow: enabled
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" `
                 -Name "NoLockScreenSlideshow" `
                 -Type DWord `
                 -Value 1

# Allow users to enable online speech recognition services: disabled
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Speech" `
                 -Name "AllowOnlineSpeechRecognition" `
                 -Type DWord `
                 -Value 0

# Allow online tips: disabled
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" `
                 -Name "DisableSoftLanding" `
                 -Type DWord `
                 -Value 1

# Configure SMB v1 server: disabled
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
                 -Name "SMB1" `
                 -Type DWord `
                 -Value 0

# Enable certificate padding: enabled
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography" `
                 -Name "EnableCertificatePaddingCheck" `
                 -Type DWord `
                 -Value 1

# WDigest authentication: disabled
Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest" `
                 -Name "UseLogonCredential" `
                 -Type DWord `
                 -Value 0

# MSS - Enable automatic logon: disabled
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" `
                 -Name "AutoAdminLogon" `
                 -Type String `
                 -Value "0"

# MSS - DisableIPSourceRouting (IPv6): Highest protection
Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters" `
                 -Name "DisableIPSourceRouting" `
                 -Type DWord `
                 -Value 2

# MSS - DisableIPSourceRouting (IPv4): Highest protection
Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" `
                 -Name "DisableIPSourceRouting" `
                 -Type DWord `
                 -Value 2

# MSS - (EnableICMPRedirect): disabled
Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" `
                 -Name "EnableICMPRedirect" `
                 -Type DWord `
                 -Value 0

# MSS - (KeepAliveTime): 300,000 ms
Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" `
                 -Name "KeepAliveTime" `
                 -Type DWord `
                 -Value 300000

# MSS - (NoNameReleaseOnDemand): enabled
Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Services\NetBT\Parameters" `
                 -Name "NoNameReleaseOnDemand" `
                 -Type DWord `
                 -Value 1

# MSS - (PerformRouterDiscovery): disabled
Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" `
                 -Name "PerformRouterDiscovery" `
                 -Type DWord `
                 -Value 0

# MSS - (SafeDllSearchMode): enabled
Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Control\Session Manager" `
                 -Name "SafeDllSearchMode" `
                 -Type DWord `
                 -Value 1

# MSS - (ScreenSaverGracePeriod): enabled (example: 5 seconds)
Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" `
                 -Name "ScreenSaverGracePeriod" `
                 -Type String `
                 -Value "5"

# MSS - (TcpMaxDataRetransmissions IPv6): enabled (3)
Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters" `
                 -Name "TcpMaxDataRetransmissions" `
                 -Type DWord `
                 -Value 3

# MSS - (TcpMaxDataRetransmissions IPv4): enabled - 3
Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" `
                 -Name "TcpMaxDataRetransmissions" `
                 -Type DWord `
                 -Value 3

# MSS - (WarningLevel): enabled - 90%
Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Services\Eventlog\Security" `
                 -Name "WarningLevel" `
                 -Type DWord `
                 -Value 90

# Turn off multicast name resolution: enabled
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
                 -Name "EnableMulticast" `
                 -Type DWord `
                 -Value 0

# Enable font providers: disabled
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
                 -Name "EnableFontProviders" `
                 -Type DWord `
                 -Value 0

# Enable insecure guest logons: disabled
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" `
                 -Name "AllowInsecureGuestAuth" `
                 -Type DWord `
                 -Value 0

# Turn off Microsoft Peer-to-Peer networking services: enabled
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Peernet" `
                 -Name "Disabled" `
                 -Type DWord `
                 -Value 1

# Prohibit installation and configuration of network bridge on your DNS domain network: enabled
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" `
                 -Name "NC_AllowNetBridge_NLA" `
                 -Type DWord `
                 -Value 0

# Prohibit use of internet connection sharing on your DNS domain network: enabled
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" `
                 -Name "NC_AllowICS_NLA" `
                 -Type DWord `
                 -Value 0

# Require domain users to elevate when setting a network's location: enabled
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" `
                 -Name "NC_StdDomainUserSetLocation" `
                 -Type DWord `
                 -Value 1

# Hardened UNC paths: enabled with mutual auth, integrity, privacy
$hardenedPathsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"
if (-not (Test-Path $hardenedPathsPath)) {
    New-Item -Path $hardenedPathsPath -Force | Out-Null
}
Set-ItemProperty -Path $hardenedPathsPath -Name "\\*\NETLOGON" -Type String -Value "RequireMutualAuthentication=1,RequireIntegrity=1,RequirePrivacy=1"
Set-ItemProperty -Path $hardenedPathsPath -Name "\\*\SYSVOL" -Type String -Value "RequireMutualAuthentication=1,RequireIntegrity=1,RequirePrivacy=1"

# TCPIP6 parameter "DisabledComponents": 0xFF (255)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" `
                 -Name "DisabledComponents" `
                 -Type DWord `
                 -Value 0xFF

# Configuration of wireless settings using Windows Connect Now: disabled
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI" `
                 -Name "DisableWcnUi" `
                 -Type DWord `
                 -Value 1

# Prohibit access of the Windows Connect Now wizards: enabled
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI" `
                 -Name "DisableWcnUi" `
                 -Type DWord `
                 -Value 1

# Minimize the number of simultaneous connections: enabled (Prevent Wi-Fi when on Ethernet)
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" `
                 -Name "fMinimizeConnections" `
                 -Type DWord `
                 -Value 1

# Allow print spooler to accept client connections: disabled
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" `
                 -Name "RegisterSpoolerRemoteRpcEndPoint" `
                 -Type DWord `
                 -Value 2

# Configure Redirection Guard: enabled
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
                 -Name "fBlockRedirectedEndpoints" `
                 -Type DWord `
                 -Value 1

# Configure RPC connection settings: Protocol to use for outgoing RPC: RPC over TCP
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" `
                 -Name "DefaultProtocol" `
                 -Type String `
                 -Value "ncacn_tcp"

# Configure RPC connection settings: Use authentication for outgoing RPC: default
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" `
                 -Name "EnableAuthEpResolution" `
                 -Type DWord `
                 -Value 1

# Configure RPC listener settings: Protocols for incoming RPC: RPC over TCP
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" `
                 -Name "EnabledProtocols" `
                 -Type String `
                 -Value "ncacn_tcp"

# Configure RPC listener settings: Authentication protocol for incoming RPC: negotiate
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" `
                 -Name "DefaultAuthServices" `
                 -Type DWord `
                 -Value 9

# Configure RPC over TCP port: 0
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" `
                 -Name "ServerTcpPort" `
                 -Type DWord `
                 -Value 0

# Limits print driver installation to Administrators: enabled
$pointAndPrintPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
if (-not (Test-Path $pointAndPrintPath)) {
    New-Item -Path $pointAndPrintPath -Force | Out-Null
}
Set-ItemProperty -Path $pointAndPrintPath -Name "RestrictDriverInstallationToAdministrators" -Type DWord -Value 1

# Point and Print restrictions - Show warning and elevation prompt
Set-ItemProperty -Path $pointAndPrintPath -Name "NoWarningNoElevationOnInstall" -Type DWord -Value 0
Set-ItemProperty -Path $pointAndPrintPath -Name "UpdatePromptSettings" -Type DWord -Value 2

# Turn off notifications network usage: enabled
$pushNotificationsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
if (-not (Test-Path $pushNotificationsPath)) {
    New-Item -Path $pushNotificationsPath -Force | Out-Null
}
Set-ItemProperty -Path $pushNotificationsPath -Name "DisableCloudNotifications" -Type DWord -Value 1

# Include command line in process creation events: enabled
$auditPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $auditPath)) {
    New-Item -Path $auditPath -Force | Out-Null
}
Set-ItemProperty -Path $auditPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Type DWord -Value 1

# Encryption Oracle Remediation: force updated clients
$credSSPPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters"
if (-not (Test-Path $credSSPPath)) {
    New-Item -Path $credSSPPath -Force | Out-Null
}
Set-ItemProperty -Path $credSSPPath -Name "AllowEncryptionOracle" -Type DWord -Value 2

# Remote host allows delegation of non-exportable credentials: enabled
$credDelegationPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"
if (-not (Test-Path $credDelegationPath)) {
    New-Item -Path $credDelegationPath -Force | Out-Null
}
Set-ItemProperty -Path $credDelegationPath -Name "AllowProtectedCreds" -Type DWord -Value 1

# Virtualization based security
$deviceGuardPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
if (-not (Test-Path $deviceGuardPath)) {
    New-Item -Path $deviceGuardPath -Force | Out-Null
}
Set-ItemProperty -Path $deviceGuardPath -Name "EnableVirtualizationBasedSecurity" -Type DWord -Value 1
Set-ItemProperty -Path $deviceGuardPath -Name "PlatformSecurityLevel" -Type DWord -Value 1
Set-ItemProperty -Path $deviceGuardPath -Name "RequireSecureLaunch" -Type DWord -Value 1

# Prevent device metadata retrieval from the internet: enabled
$deviceMetadataPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata"
if (-not (Test-Path $deviceMetadataPath)) {
    New-Item -Path $deviceMetadataPath -Force | Out-Null
}
Set-ItemProperty -Path $deviceMetadataPath -Name "PreventDeviceMetadataFromNetwork" -Type DWord -Value 1

# Boot-Start driver initialization policy: good, unknown, bad but critical
$earlyLaunchPath = "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch"
if (-not (Test-Path $earlyLaunchPath)) {
    New-Item -Path $earlyLaunchPath -Force | Out-Null
}
Set-ItemProperty -Path $earlyLaunchPath -Name "DriverLoadPolicy" -Type DWord -Value 3

# Registry and security policy processing
Write-Host "Configuring Registry and Security Policy Processing..."
# Configure registry policy processing - Do not apply during periodic background: false
$groupPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\GroupPolicy"
if (-not (Test-Path $groupPolicyPath)) {
    New-Item -Path $groupPolicyPath -Force | Out-Null
}
Set-ItemProperty -Path $groupPolicyPath -Name "DisableBkGndRegistryPolicy" -Type DWord -Value 0
# Process even if GPO not changed: true
Set-ItemProperty -Path $groupPolicyPath -Name "NoGPOListChanges" -Type DWord -Value 0

# Security policy processing
$secEditPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\GroupPolicy\SecEdit"
if (-not (Test-Path $secEditPath)) {
    New-Item -Path $secEditPath -Force | Out-Null
}
# Do not apply during periodic background: false
Set-ItemProperty -Path $secEditPath -Name "DisableBkGndSecurityPolicy" -Type DWord -Value 0
# Process even if GPO not changed: true
Set-ItemProperty -Path $secEditPath -Name "NoGPOListChanges" -Type DWord -Value 0

# Continue experiences on this device: disabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Type DWord -Value 0

# Turn off background refresh of Group Policy: disabled (set to 0 to allow)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\GroupPolicy" -Name "DisableBkGndPolicy" -Type DWord -Value 0

# Turn off downloading of print drivers over HTTP: enabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableWebPnPDownload" -Type DWord -Value 1

# Turn off handwriting personalization data sharing: enabled
$handwritingErrorReportsPath = "HKLM:\SOFTWARE\Policies\Microsoft\HandwritingErrorReports"
if (-not (Test-Path $handwritingErrorReportsPath)) {
    New-Item -Path $handwritingErrorReportsPath -Force | Out-Null
}
Set-ItemProperty -Path $handwritingErrorReportsPath -Name "PreventHandwritingDataSharing" -Type DWord -Value 1

# Turn off handwriting recognition error reporting: enabled
Set-ItemProperty -Path $handwritingErrorReportsPath -Name "PreventHandwritingErrorReports" -Type DWord -Value 1

# Turn off Internet Connection Wizard if referring to Microsoft.com: enabled
$icwPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Connection Wizard"
if (-not (Test-Path $icwPath)) {
    New-Item -Path $icwPath -Force | Out-Null
}
Set-ItemProperty -Path $icwPath -Name "DisableICW" -Type DWord -Value 1

# Turn off Internet download for Web publishing wizards: enabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableWebPublishingWizard" -Type DWord -Value 1

# Turn off printing over HTTP: enabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableHTTPPrinting" -Type DWord -Value 1

# Turn off Registration if URL referring to Microsoft.com: enabled
$registrationWizardPath = "HKLM:\SOFTWARE\Policies\Microsoft\RegistrationWizard"
if (-not (Test-Path $registrationWizardPath)) {
    New-Item -Path $registrationWizardPath -Force | Out-Null
}
Set-ItemProperty -Path $registrationWizardPath -Name "DisableRegistration" -Type DWord -Value 1

# Turn off Search Companion content file updates: enabled
$searchCompanionPath = "HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion"
if (-not (Test-Path $searchCompanionPath)) {
    New-Item -Path $searchCompanionPath -Force | Out-Null
}
Set-ItemProperty -Path $searchCompanionPath -Name "DisableContentFileUpdates" -Type DWord -Value 1

# Turn off the "Order Prints": enabled
$photoPrintingWizardPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PhotoPrintingWizard"
if (-not (Test-Path $photoPrintingWizardPath)) {
    New-Item -Path $photoPrintingWizardPath -Force | Out-Null
}
Set-ItemProperty -Path $photoPrintingWizardPath -Name "DisableOnlinePrints" -Type DWord -Value 1

# Turn off the "Publish to Web" task: enabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisablePublishToWebTask" -Type DWord -Value 1

# Turn off the Windows Messenger CEIP: enabled
$messengerCEIPPath = "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\CEIP"
if (-not (Test-Path $messengerCEIPPath)) {
    New-Item -Path $messengerCEIPPath -Force | Out-Null
}
Set-ItemProperty -Path $messengerCEIPPath -Name "DisableCEIP" -Type DWord -Value 1

# Turn off Windows CEIP: enabled
$sqmClientPath = "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows"
if (-not (Test-Path $sqmClientPath)) {
    New-Item -Path $sqmClientPath -Force | Out-Null
}
Set-ItemProperty -Path $sqmClientPath -Name "CEIPEnable" -Type DWord -Value 0

# Turn off Windows Error Reporting: enabled
$errorReportingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"
if (-not (Test-Path $errorReportingPath)) {
    New-Item -Path $errorReportingPath -Force | Out-Null
}
Set-ItemProperty -Path $errorReportingPath -Name "Disabled" -Type DWord -Value 1

# Password Policies (Complexity and Length)
Write-Host "Configuring Password Policies..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "PasswordComplexity" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "MinimumPasswordLength" -Type DWord -Value 15
# Enable password encryption (no reversible encryption):
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "ClearTextPassword" -Type DWord -Value 0

# Allow Custom SSPs and APs: disabled
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableCustomSSPs" -Type DWord -Value 1

# LSASS as a protected process: enabled
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Type DWord -Value 1

# Disallow copying user input methods to system account for sign-in: enabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisallowCopyingInputMethodsToSystemAccount" -Type DWord -Value 1

# Sign-in UI Settings
Write-Host "Configuring Sign-in UI Settings..."
# Block user from showing account details: enabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
                -Name "BlockUserFromShowingAccountDetailsOnSignin" `
                -Type DWord `
                -Value 1

# Do not display network selection UI: enabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
                -Name "DontDisplayNetworkSelectionUI" `
                -Type DWord `
                -Value 1

# Turn off app notifications on lock screen: enabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
                -Name "DisableLockScreenAppNotifications" `
                -Type DWord `
                -Value 1

# Turn off picture password sign-in: enabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
                -Name "BlockDomainPicturePassword" `
                -Type DWord `
                -Value 1

# Turn on convenience PIN sign-in: disabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
                -Name "AllowDomainPINLogon" `
                -Type DWord `
                -Value 0

# Require a password when a computer wakes:
Write-Host "Configuring power settings for wake-up password requirements..."
powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_NONE CONSOLELOCK 1
powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_NONE CONSOLELOCK 1

# Remote Assistance settings: disabled
Write-Host "Disabling Remote Assistance settings..."
$terminalServicesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
if (-not (Test-Path $terminalServicesPath)) {
    New-Item -Path $terminalServicesPath -Force | Out-Null
}
Set-ItemProperty -Path $terminalServicesPath -Name "fAllowToGetHelp" -Type DWord -Value 0
Set-ItemProperty -Path $terminalServicesPath -Name "fAllowUnsolicited" -Type DWord -Value 0

# Enable RPC Endpoint Mapper Client Auth: enabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" `
                -Name "EnableAuthEpResolution" `
                -Type DWord `
                -Value 1

# Restrict Unauthenticated RPC clients: authenticated
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" `
                -Name "RestrictRemoteClients" `
                -Type DWord `
                -Value 1

# MSDT interactive communication with support provider: disabled
$msdtPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy"
if (-not (Test-Path $msdtPath)) {
    New-Item -Path $msdtPath -Force | Out-Null
}
Set-ItemProperty -Path $msdtPath -Name "DisableQueryRemoteServer" -Type DWord -Value 1

# PerfTrack: disabled
$perfTrackPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{9C5A3C52-EE91-4AFA-9A20-101346A0F8A3}"
if (-not (Test-Path $perfTrackPath)) {
    New-Item -Path $perfTrackPath -Force | Out-Null
}
Set-ItemProperty -Path $perfTrackPath -Name "ScenarioExecutionEnabled" -Type DWord -Value 0

# Windows NTP Client: enabled, Windows NTP Server: disabled
$ntpClientPath = "HKLM:\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient"
$ntpServerPath = "HKLM:\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpServer"

if (-not (Test-Path $ntpClientPath)) {
    New-Item -Path $ntpClientPath -Force | Out-Null
}
if (-not (Test-Path $ntpServerPath)) {
    New-Item -Path $ntpServerPath -Force | Out-Null
}

Set-ItemProperty -Path $ntpClientPath -Name "Enabled" -Type DWord -Value 1
Set-ItemProperty -Path $ntpServerPath -Name "Enabled" -Type DWord -Value 0

# Allow Microsoft accounts to be optional: enabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
                -Name "MSAOptional" `
                -Type DWord `
                -Value 1

# Disallow Autoplay for non-volume devices: enabled
$explorerPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
if (-not (Test-Path $explorerPath)) {
    New-Item -Path $explorerPath -Force | Out-Null
}
Set-ItemProperty -Path $explorerPath -Name "NoAutoplayfornonVolume" -Type DWord -Value 1

# Turn off Autoplay: all drives
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
                -Name "NoDriveTypeAutoRun" `
                -Type DWord `
                -Value 255

# Set default behavior for AutoRun: do not execute any autorun commands
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
                -Name "NoAutorun" `
                -Type DWord `
                -Value 1

# Configure enhanced anti-spoofing: enabled
$facialFeaturesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures"
if (-not (Test-Path $facialFeaturesPath)) {
    New-Item -Path $facialFeaturesPath -Force | Out-Null
}
Set-ItemProperty -Path $facialFeaturesPath -Name "EnhancedAntiSpoofing" -Type DWord -Value 1

# Allow Use of Camera: disabled
$cameraPath = "HKLM:\SOFTWARE\Policies\Microsoft\Camera"
if (-not (Test-Path $cameraPath)) {
    New-Item -Path $cameraPath -Force | Out-Null
}
Set-ItemProperty -Path $cameraPath -Name "AllowCamera" -Type DWord -Value 0

# Turn off cloud consumer account state content: enabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" `
                -Name "DisableConsumerAccountStateContent" `
                -Type DWord `
                -Value 1

# Turn off cloud optimized content: enabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" `
                -Name "DisableCloudOptimizedContent" `
                -Type DWord `
                -Value 1

# Turn off Microsoft consumer experiences: enabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" `
                -Name "DisableWindowsConsumerFeatures" `
                -Type DWord `
                -Value 1

# Require pin for pairing: enabled - always
$connectPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect"
if (-not (Test-Path $connectPath)) {
    New-Item -Path $connectPath -Force | Out-Null
}
Set-ItemProperty -Path $connectPath -Name "RequirePinForPairing" -Type DWord -Value 1

# Enumerate administrator accounts on elevation: disabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "FilterAdministratorToken" `
                -Type DWord `
                -Value 1

# Allow Diagnostic Data: enabled - diagnostic data off
$dataCollectionPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
if (-not (Test-Path $dataCollectionPath)) {
    New-Item -Path $dataCollectionPath -Force | Out-Null
}
Set-ItemProperty -Path $dataCollectionPath -Name "AllowTelemetry" -Type DWord -Value 0

# Configure Authenticated Proxy usage for Telemetry: disable authenticated proxy usage
Set-ItemProperty -Path $dataCollectionPath -Name "DisableEnterpriseAuthProxy" -Type DWord -Value 1

# Disable OneSettings Downloads: enabled
Set-ItemProperty -Path $dataCollectionPath -Name "DisableOneSettingsDownloads" -Type DWord -Value 1

# Do not show feedback notifications: enabled
$siufPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SIUF"
if (-not (Test-Path $siufPath)) {
    New-Item -Path $siufPath -Force | Out-Null
}
Set-ItemProperty -Path $siufPath -Name "DisableNotifications" -Type DWord -Value 1

# Enable OneSettings Auditing: enabled
Set-ItemProperty -Path $dataCollectionPath -Name "EnableOneSettingsAuditing" -Type DWord -Value 1

# Limit Diagnostic Log Collection: enabled
Set-ItemProperty -Path $dataCollectionPath -Name "LimitDiagnosticLogCollection" -Type DWord -Value 1

# Limit Dump Collection: enabled
Set-ItemProperty -Path $dataCollectionPath -Name "LimitDumpCollection" -Type DWord -Value 1

# App Installer settings: disabled
$appInstallerPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller"
if (-not (Test-Path $appInstallerPath)) {
    New-Item -Path $appInstallerPath -Force | Out-Null
}
Set-ItemProperty -Path $appInstallerPath -Name "EnableAppInstaller" -Type DWord -Value 0
Set-ItemProperty -Path $appInstallerPath -Name "EnableAppInstallerExpFeatures" -Type DWord -Value 0
Set-ItemProperty -Path $appInstallerPath -Name "EnableHashOverride" -Type DWord -Value 0
Set-ItemProperty -Path $appInstallerPath -Name "EnableAppInstallerProtocol" -Type DWord -Value 0

# Event log size and behavior (Application, Security, Setup, System)
Write-Host "Configuring Event Log sizes..."

# Function to set Event Log MaxSize
function Set-EventLogMaxSize {
    param (
        [string]$LogName,
        [int]$MaxSizeKB
    )

    $eventLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\$LogName"
    if (-not (Test-Path $eventLogPath)) {
        New-Item -Path $eventLogPath -Force | Out-Null
    }
    Set-ItemProperty -Path $eventLogPath -Name "MaxSize" -Type DWord -Value $MaxSizeKB
}

# Application Log
Set-EventLogMaxSize -LogName "Application" -MaxSizeKB 32768

# Security Log
Set-EventLogMaxSize -LogName "Security" -MaxSizeKB 196608

# Setup Log
Set-EventLogMaxSize -LogName "Setup" -MaxSizeKB 32768

# System Log
Set-EventLogMaxSize -LogName "System" -MaxSizeKB 32768

# Turn off location: enabled
Write-Host "Disabling location services..."
$locationAndSensorsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"
if (-not (Test-Path $locationAndSensorsPath)) {
    New-Item -Path $locationAndSensorsPath -Force | Out-Null
}
Set-ItemProperty -Path $locationAndSensorsPath -Name "DisableLocation" -Type DWord -Value 1

# Allow Message Service Cloud Sync: disabled
$messagingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging"
if (-not (Test-Path $messagingPath)) {
    New-Item -Path $messagingPath -Force | Out-Null
}
Set-ItemProperty -Path $messagingPath -Name "AllowMessageSync" -Type DWord -Value 0

# Block all consumer Microsoft account user authentication: enabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
                -Name "NoConnectedUser" `
                -Type DWord `
                -Value 3

# Configure local setting override for Microsoft MAPS: disabled
$spyNetPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\SpyNet"
if (-not (Test-Path $spyNetPath)) {
    New-Item -Path $spyNetPath -Force | Out-Null
}
Set-ItemProperty -Path $spyNetPath -Name "LocalSettingOverride" -Type DWord -Value 0

# Join Microsoft MAPS: disabled
Set-ItemProperty -Path $spyNetPath -Name "SpyNetReporting" -Type DWord -Value 0

# Configure Attack Surface Reduction rules: enabled
$asrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR"
if (-not (Test-Path $asrPath)) {
    New-Item -Path $asrPath -Force | Out-Null
}
Set-ItemProperty -Path $asrPath -Name "ASRRules" -Type DWord -Value 1

# Prevent users and apps from accessing dangerous websites: block
$smartScreenPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen"
if (-not (Test-Path $smartScreenPath)) {
    New-Item -Path $smartScreenPath -Force | Out-Null
}
Set-ItemProperty -Path $smartScreenPath -Name "ConfigureAppInstallControl" -Type DWord -Value 2

# Turn off Microsoft Defender AntiVirus: disabled (AV on)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" `
                -Name "DisableAntiSpyware" `
                -Type DWord `
                -Value 0

# Prevent usage of OneDrive for file storage: enabled
$oneDrivePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
if (-not (Test-Path $oneDrivePath)) {
    New-Item -Path $oneDrivePath -Force | Out-Null
}
Set-ItemProperty -Path $oneDrivePath -Name "DisableFileSyncNGSC" -Type DWord -Value 1

# RDP Settings
Write-Host "Configuring RDP Settings..."
# Restrict RDS users to a single session: enabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "fSingleSessionPerUser" `
                -Type DWord `
                -Value 1

# Allow UI Automation redirection: disabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "fDisableUARedirection" `
                -Type DWord `
                -Value 1

# Do not allow COM/LPT/drive/location/PlugAndPlay/WebAuthn redirection: enabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "fDisableCcm" `
                -Type DWord `
                -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "fDisableLPT" `
                -Type DWord `
                -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "fDisableCdm" `
                -Type DWord `
                -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "fDisablePNPRedir" `
                -Type DWord `
                -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "fDisableWebAuthnRedir" `
                -Type DWord `
                -Value 1

# Always prompt for password upon connection: enabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "fPromptForPassword" `
                -Type DWord `
                -Value 1

# Require secure RPC communication: enabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "fEncryptRPCTraffic" `
                -Type DWord `
                -Value 1

# Require specific security layer: SSL (2)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "SecurityLayer" `
                -Type DWord `
                -Value 2

# Require NLA: enabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "UserAuthentication" `
                -Type DWord `
                -Value 1

# Set client connection encryption level: High (3)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "MinEncryptionLevel" `
                -Type DWord `
                -Value 3

# Set time limit for active but idle sessions: 15 minutes
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "MaxIdleTime" `
                -Type DWord `
                -Value 900000

# Set time limit for disconnected sessions: 1 minute
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
                -Name "MaxDisconnectionTime" `
                -Type DWord `
                -Value 60000

# Do not delete temp folders upon exit: disabled (default)
# Do not use temporary folders per session: disabled (default)

# Turn off KMS Client Online AVS Validation: enabled
$KMSOnlineAVSValid = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform"
if (-not (Test-Path $KMSOnlineAVSValid)) {
    New-Item -Path $KMSOnlineAVSValid -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" `
                -Name "NoCbsAvsValidation" `
                -Type DWord `
                -Value 1

# Configure Windows Defender SmartScreen: warn and prevent bypass
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
                -Name "EnableSmartScreen" `
                -Type DWord `
                -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
                -Name "ConfigureAppInstallControl" `
                -Type DWord `
                -Value 2

# Allow suggested apps in Windows Ink Workspace: disabled
$WindowsInkWSPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"
if (-not (Test-Path $WindowsInkWSPath)) {
    New-Item -Path $WindowsInkWSPath -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" `
                -Name "AllowSuggestedAppsInWindowsInkWorkspace" `
                -Type DWord `
                -Value 0

# Allow Windows Ink Workspace: disabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" `
                -Name "AllowWindowsInkWorkspace" `
                -Type DWord `
                -Value 0

# Prevent IE security prompt for Windows Installer scripts: disabled (no registry needed if default)

# Sign-in and lock last interactive user automatically after a restart: disabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "DisableAutomaticRestartSignOn" `
                -Type DWord `
                -Value 1

# Turn on PowerShell Script Block Logging: enabled
$scriptBlockLoggingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (-not (Test-Path $scriptBlockLoggingPath)) {
    New-Item -Path $scriptBlockLoggingPath -Force | Out-Null
}
Set-ItemProperty -Path $scriptBlockLoggingPath -Name "EnableScriptBlockLogging" -Type DWord -Value 1

# Turn on PowerShell Transcription: enabled
$transcriptionPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
if (-not (Test-Path $transcriptionPath)) {
    New-Item -Path $transcriptionPath -Force | Out-Null
}
Set-ItemProperty -Path $transcriptionPath -Name "EnableTranscripting" -Type DWord -Value 1

# WinRM Client settings
Write-Host "Configuring WinRM Client settings..."
$winrmClientPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
if (-not (Test-Path $winrmClientPath)) {
    New-Item -Path $winrmClientPath -Force | Out-Null
}
Set-ItemProperty -Path $winrmClientPath -Name "AllowBasic" -Type DWord -Value 0
Set-ItemProperty -Path $winrmClientPath -Name "AllowUnencryptedTraffic" -Type DWord -Value 0
Set-ItemProperty -Path $winrmClientPath -Name "AllowDigest" -Type DWord -Value 0

# WinRM Service
Write-Host "Configuring WinRM Service settings..."
$winrmServicePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
if (-not (Test-Path $winrmServicePath)) {
    New-Item -Path $winrmServicePath -Force | Out-Null
}
Set-ItemProperty -Path $winrmServicePath -Name "AllowBasic" -Type DWord -Value 0
Set-ItemProperty -Path $winrmServicePath -Name "AllowUnencryptedTraffic" -Type DWord -Value 0
Set-ItemProperty -Path $winrmServicePath -Name "DisableRunAs" -Type DWord -Value 1
Set-ItemProperty -Path $winrmServicePath -Name "DisableAutoConfig" -Type DWord -Value 1

# Windows Remote Shell: disabled
Write-Host "Disabling Windows Remote Shell..."
$winrsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\WinRS"
if (-not (Test-Path $winrsPath)) {
    New-Item -Path $winrsPath -Force | Out-Null
}
Set-ItemProperty -Path $winrsPath -Name "AllowRemoteShellAccess" -Type DWord -Value 0

# App and browser protection:
Write-Host "Configuring App and Browser Protection..."
$appBrowserProtectionPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Security Center\App And Browser Protection"
if (-not (Test-Path $appBrowserProtectionPath)) {
    New-Item -Path $appBrowserProtectionPath -Force | Out-Null
}
Set-ItemProperty -Path $appBrowserProtectionPath -Name "DisallowExploitProtectionOverride" -Type DWord -Value 1

# Legacy Policies:
Write-Host "Configuring Legacy Policies..."
# No auto-restart with logged on users: disabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
                -Name "NoAutoRebootWithLoggedOnUsers" `
                -Type DWord `
                -Value 0

# Select when Preview Builds and Feature Updates are received: enabled - 180 days
$deferUpgradePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DeferUpgrade"
if (-not (Test-Path $deferUpgradePath)) {
    New-Item -Path $deferUpgradePath -Force | Out-Null
}
Set-ItemProperty -Path $deferUpgradePath -Name "DeferFeatureUpdates" -Type DWord -Value 1
Set-ItemProperty -Path $deferUpgradePath -Name "DeferFeatureUpdatesPeriodInDays" -Type DWord -Value 180

# Select when Quality Updates are received: enabled - 0 days
Set-ItemProperty -Path $deferUpgradePath -Name "DeferQualityUpdates" -Type DWord -Value 1
Set-ItemProperty -Path $deferUpgradePath -Name "DeferQualityUpdatesPeriodInDays" -Type DWord -Value 0

# Disable remote UAC to be able to use the service account for Veeam services
Write-Host "Disabling remote UAC for service accounts..."
$remoteUACPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if (-not (Test-Path $remoteUACPath)) {
    New-Item -Path $remoteUACPath -Force | Out-Null
}
Set-ItemProperty -Path $remoteUACPath -Name "LocalAccountTokenFilterPolicy" -Type DWord -Value 1

# ----------------------------
# Finalizing the script
# ----------------------------

Write-Host "All policies have been applied."
Write-Host "A reboot is recommended for all changes to take effect."
Write-Host "Please test this system thoroughly in a test environment before production use."
Write-Host "The output file is located at C:\Install."

# Löschen der Datei
Remove-Item -Path "C:\Install\ntrights.exe" -Force -ErrorAction Stop

Stop-Transcript

Write-Host "The system will reboot in 30 seconds..."
Start-Process "shutdown" -ArgumentList "-r","-t","30"