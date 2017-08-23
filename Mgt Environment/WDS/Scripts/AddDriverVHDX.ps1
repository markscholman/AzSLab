Set-Location C:\Users\mark-s\Desktop
Dism /Get-ImageInfo /ImageFile:C:\Users\mark-s\Desktop\cloudbuilder.vhdx
Dism /Mount-Image /ImageFile:C:\Users\mark-s\Desktop\cloudbuilder.vhdx /Index:1 /MountDir:C:\Users\mark-s\Desktop\offline
Dism /Image:C:\Users\mark-s\Desktop\offline /Add-Driver /Driver:C:\Users\mark-s\Desktop\DL380 /Recurse
Dism /Image:C:\Users\mark-s\Desktop\offline /Get-Drivers
Dism /Unmount-Image /MountDir:C:\Users\mark-s\Desktop\offline /Commit