New-NetFirewallRule -DisplayName "SQL Server" -Name "SQL-Server" -Profile Any -LocalPort 1433 -Protocol TCP -RemoteAddress Any -RemotePort Any | Out-Null
New-NetFirewallRule -DisplayName "SQL Server Named Instance" -Name "SQL-Server-Named-Instance" -Profile Any -LocalPort 1434 -Protocol UDP -RemoteAddress Any -RemotePort Any | Out-Null
New-NetFirewallRule -DisplayName "SQL Hadr Endpoint" -Name "SQL-Server-HadrEndpoint" -Profile Any -LocalPort 5022 -Protocol TCP -RemoteAddress Any -RemotePort Any | Out-Null
New-NetFirewallRule -DisplayName "SQL SSMS" -Name "SQL-Server-SSMS" -Profile Any -LocalPort 1434 -Protocol TCP -RemoteAddress Any -RemotePort Any | Out-Null
New-Item -Path C:\Install\Scripts -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
New-Item -Path D:\SQLBACKUP -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
New-Item -Path E:\MSSQLSERVER -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
New-Item -Path F:\MSSQLSERVER -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
Write-Host -ForegroundColor Cyan "Installing Windows Feature Net-Framework-Core"
Install-WindowsFeature NET-Framework-Core -source C:\Install\sxs\ 
New-Item -ItemType Directory C:\Install\SQL2016 -ErrorAction SilentlyContinue | Out-Null
cmd /c C:\Install\SQL2016\setup.exe /ConfigurationFile=C:\INSTALL\Scripts\ConfigurationFile.ini /INDICATEPROGRESS /IACCEPTSQLSERVERLICENSETERMS /Q 
#Remove-Item -Path C:\Install\Scripts\ConfigurationFile.ini -Force -ErrorAction SilentlyContinue | Out-Null
net localgroup administrators AZURESTACK\admsma /add
#make admsma SQL DB Admin
Invoke-WebRequest -Uri http://go.microsoft.com/fwlink/?LinkID=828615 -OutFile C:\Install\SSMS.exe -UseBasicParsing
start-process c:\install\SSMS.exe '/install /quiet /norestart' -Wait