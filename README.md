# Veeam Hardening Script for Windows (CIS contents)

## Disclaimer:
Important: I do not provide any guarantee that the script, which has been successfully tested by me, will run without errors in every environment. The script is intended solely to simplify and standardize hardening standards, which may not be suitable for every environment! Additionally, I do not guarantee the completeness of the tests!

## Requirements and procedure:
The scripts are designed for new and existing installations. They supports systems that have used a previous version of my script before as well as systems that have not been hardened and optimized at all.
The server must not be a domain member
Initial script execution (new installations only) must be performed with the built-in Administrator
Script execution for pre-hardened systems can be performed with any administrator
OS: Windows Server 2022 or 2025 Standard or Datacenter

## Procedure for new installations:
1. Install Windows Server (as required).
2. Install drivers (VMware Tools or vendor-specific drivers).
3. Set IP configurations (assign IP address, etc.) and disable IPv6 (optional).
4. Set server name and workgroup, then restart the server.
5. Create a folder named “Install” on drive C:.
6. Copy the contents of the ZIP file (script and ntrights.exe) into the Install folder.
7. Execute the script with administrative privileges (PowerShell) and select "new installation" when prompted.
8. Allow the server to restart and install Veeam, specifying the service account.
9. Apply / implement the Veeam Security & Compliance script.

## Procedure for new installations (PAW only):
1. Install Windows Server (as required).
2. Install drivers (VMware Tools or vendor-specific drivers).
3. Set IP configurations (assign IP address, etc.) and disable IPv6 (optional).
4. Set server name and workgroup, then restart the server.
5. Create a folder named “Install” on drive C:.
6. Copy the contents of the ZIP file (script and ntrights.exe) into the Install folder.
7. Execute the PAW script with administrative privileges (PowerShell) and select "new installation" when prompted.
8. Allow the server to restart and install tools as required.

## Procedure for existing installations:
1. Create a folder named "Install" on drive C: (if not already existing).
2. Copy the script into the Install folder.
3. Execute the script with administrative privileges (PowerShell) and select "existing installation" when prompted.
4. Allow the server to restart and verify Veeam service availability (await the services set to "delayed start" by default).
5. Apply / re-run the Veeam Security & Compliance script.

## Procedure for existing installations (PAW only):
1. Create a folder named "Install" on drive C: (if not already existing).
2. Copy the script into the Install folder.
3. Execute the PAW script with administrative privileges (PowerShell) and select "existing installation" when prompted.
4. Allow the server to restart and verify tool availability (as required).

Note: ntrights.exe is not required for existing installations.

Important: I recommend familiarizing yourself with the content listed below, as it introduces changes that may affect the operation of the system!
For example, an idle timeout of 15 minutes is configured. This means that an active session will be disconnected after 15 minutes, and all open windows and processes within that session will be terminated. This does not apply for the PAW script!

## Additional information:
- The output file (manuscript) is located at C:\Install after the script execution
- The ntrights.exe will be deleted at the end of the script - this is expected!
- Take a look at the script's contents: e.g. an idle timeout of 15min will potentially change workflows!
