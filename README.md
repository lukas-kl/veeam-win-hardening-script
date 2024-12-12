# veeam-win-hardening-script
Veeam Hardening Script for Windows (CIS contents)


Prerequisities and limitations:
- The script is tested for Veeam Backup & Replication and Veeam Enterprise Manager workloads / systems
- The script is not tested and designed for Veeam components within a management domain (Active Directory)
- The operating system has to be Windows Server 2022 Standard or Datacenter (other systems are not tested)


Actions to apply the script:
1. Install Windows Server 2022
2. Install drivers (VMware Tools or hardware vendor drivers)
3. Configure IP settings
4. Configure hostname and workgroup and reboot
5. Create folder "Install" at "C:\" (root folder)
6. Copy both the PowerShell script and the ntrights.exe into the newly created Install folder
7. Run the PowerShell script as built-in Administrator
8. Let the server reboot as desired
9. Install / verify Veeam services
10. Run the Veeam Security & Compliance script


Additional information:
- The output file (manuscript) is located at C:\Install after the script execution
- The ntrights.exe will be deleted at the end of the script - this is expected!
- Take a look at the script's contents: e.g. an idle timeout of 15min will potentially change workflows!
