# AzsLab
Script, tools and modules to Automate Azure Stack Labs

Still working on some proper documentation. But highh level:
Build a management environment that consist out of the next roles:
-   Domain Controller
-   SQL Server
-   WDS Deployment Server
-   Remote Desktop Gateway / Web server
You can create this environment quickly with the Create-ASLAB.ps1 script after you have created a Win2016 VHD and updated the IP addresses.

Then for each role there is scripts placed in folders to automate the process and configure the roles on the VM. Make sure you have the Microsoft products downloaded. We need:
-   Microsoft SQL Server 2016
-   System Center Service Management Automation
-   Windows Server 2016

Before you run scripts, please make sure variables are matching your environment or updated according your needs.
If you need any help with the deployment of the management envrionment i am happy to help.
