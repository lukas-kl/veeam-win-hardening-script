# Veeam Hardening Script for Windows (CIS contents)

## Disclaimer:
Important - I do not provide any guarantees that the script I have successfully tested will run without errors in every environment.
The script is solely intended to simplify and standardize hardening standards, which may not be applicable or appropriate for all environments!
Furthermore, I do not guarantee the completeness of the tests!


## Prerequisities and limitations:

The script is primarily designed for new installations!

- The script is tested for Veeam Backup & Replication, Veeam Enterprise Manager and Veeam ONE workloads / systems
- The script is not tested and designed for Veeam components within a management domain (Active Directory)
- The operating system has to be Windows Server 2022 or 2025 Standard or Datacenter (other systems are not tested)
- The operating system language has to be English (no language pack on another language is allowed!)


## Actions to apply the script:
1. Install Windows Server 2022 or Windows Server 2025
2. Install drivers (VMware Tools or hardware vendor drivers)
3. Configure IP settings
4. Configure hostname and workgroup and reboot
5. Create folder "Install" at "C:\" (root folder)
6. Copy both the PowerShell script and the ntrights.exe into the newly created Install folder
7. Run the PowerShell script as built-in Administrator
8. Let the server reboot as desired
9. Install / verify Veeam services
10. Run the Veeam Security & Compliance script


## Additional information:
- The output file (manuscript) is located at C:\Install after the script execution
- The ntrights.exe will be deleted at the end of the script - this is expected!
- Take a look at the script's contents: e.g. an idle timeout of 15min will potentially change workflows!
