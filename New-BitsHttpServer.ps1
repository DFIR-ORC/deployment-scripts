<#
    .SYNOPSIS
        This script installs a IIS website and sets it up with suitable configuration to be used as an upload website by DFIR-ORC with the `http://` URI scheme. It enables BITS upload with anonymous logon and prints out the XML configuration to use in the local configuration file for DFIR-ORC.
    .PARAMETER Path
        Path of the virtual directory where files will be uploaded. Required.
    .PARAMETER Site
        Name of the website to create or reuse (if it already exists). Defaults to "Default Web Site".
    .PARAMETER AppPool
        Application Pool to use when creating a new website. Defaults to "DefaultAppPool".
    .PARAMETER Port
        TCP Port to bind to when creating a new website. You cannot use an already bound port. Defaults to 80.
    .EXAMPLE
        PS> New-BitsHttpServer -Path C:\website\upload
        Configure a virtual directory inside the default web site provided by IIS and configure it to enable BITS upload and tighten its NTFS permissions.
    .NOTES
        SPDX-License-Identifier: LGPL-2.1-or-later
        Copyright (c) 2011-2021 ANSSI. All Rights Reserved.
        Author: Sebastien Chapiron (ANSSI)
#>
Param(
        [Parameter(Mandatory=$true)][String]$Path,
        [String]$Site = "Default Web Site",
        [String]$AppPool = "DefaultAppPool",
        [Int]$Port = "80"
)

if ([threading.thread]::CurrentThread.GetApartmentState() -eq "MTA") {
    write-host "PowerShell is currently using MultiThread Apartment which prevents the use of BITS ADSI extension, restarting using SingleThread Apartment" -ForegroundColor Cyan
    & $PSHome\powershell.exe -sta $MyInvocation.MyCommand.Path "-Path '$Path' -Site '$Site' -AppPool '$AppPool' -Port $Port"
    return
}


Import-Module serverManager
if ( (Get-WindowsFeature BITS-IIS-Ext).installed -eq $false){
    Add-WindowsFeature BITS-IIS-Ext
    Add-WindowsFeature Web-Windows-Auth
}

# Create the upload directory with suitable permissions only for IUSR (S-1-5-17) and IIS_IUSRS (S-1-5-32-568) users and the user executing this script
$SitePhysicalPath = New-Item -Type directory $Path -force
$Acl = Get-Acl -Path $SitePhysicalPath
# Clear all access rules
$Acl.SetAccessRuleProtection($true, $false)
$Acl.Access | ForEach-Object { $Acl.RemoveAccessRule($_) | Out-Null }
# Add a new access rules for each user
("S-1-5-17", "S-1-5-32-568") | ForEach-Object {
    $AclUser = (New-Object System.Security.Principal.SecurityIdentifier($_)).Translate([System.Security.Principal.NTAccount])
    $FileSystemAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($AclUser, "Read, Write, Delete", "ContainerInherit, ObjectInherit", "None", [System.Security.AccessControl.AccessControlType]::Allow)
    $Acl.AddAccessRule($FileSystemAccessRule)
}
$Acl.AddAccessRule($(New-Object System.Security.AccessControl.FileSystemAccessRule($env:UserName, "FullControl", "ContainerInherit, ObjectInherit", "None", [System.Security.AccessControl.AccessControlType]::Allow)))
# Apply ACL
Set-Acl -Path $SitePhysicalPath -AclObject $Acl

Import-Module WebAdministration

# Create a new WebSite if it does not exist
$WebSite = (Get-Website | Where { $_.Name -eq $Site })
if ( -not $WebSite) {
    write-host "Creating new WebSite: $Site on port:$Port in $SitePhysicalPath using $AppPool" -ForegroundColor Cyan
    $WebSite = New-WebSite -Name $Site -Port $Port -PhysicalPath $SitePhysicalPath -ApplicationPool $AppPool
}
else {
    Write-Host "Reusing existing WebSite $Site" -ForegroundColor Cyan
}

# Create a new VirtualDirectory if it does not exist
$WebVirtualDirectory = Get-WebVirtualDirectory -Site "$($WebSite.Name)" -Name "$($SitePhysicalPath.BaseName)"
if ( -not $WebVirtualDirectory) {
    write-host "Creating new VirtualDirectory: $($SitePhysicalPath.BaseName) from path $SitePhysicalPath" -ForegroundColor Cyan
    $WebVirtualDirectory = New-WebVirtualDirectory -Site "$($WebSite.Name)" -Name "$($SitePhysicalPath.BaseName)" -PhysicalPath "$SitePhysicalPath"
}
else {
    Write-Host "Reusing existing VirtualDirectory $($SitePhysicalPath.BaseName)" -ForegroundColor Cyan
}
$VirtualDirName = $($WebVirtualDirectory.path.split('/')[-1])
# Enable 7z mime type (required to check ORC archive existence)
$MimeProperty = Get-WebConfigurationProperty -PSPath "IIS:\Sites\$($WebSite.Name)\$VirtualDirName" -Filter "system.webServer/staticContent" -name Collection | where { $_.FileExtension -eq ".7z" }
if (-not $MimeProperty) {
    Add-WebConfigurationProperty -PSPath "IIS:\Sites\$($WebSite.Name)\$VirtualDirName" -Filter "system.webServer/staticContent" -name Collection -value @{fileextension='.7z' ; mimeType='application/octet-stream'}
}
# Enable bits upload on the virtual directory
Write-Host "Enabling BITS upload with anonymous authentication on the VirtualDirectory" -ForegroundColor Cyan
$VirtualDirEntry = New-Object System.DirectoryServices.DirectoryEntry("IIS://Localhost/W3SVC/$($WebSite.Id)/root/$VirtualDirName")
$VirtualDirEntry.EnableBitsUploads()
# Allow overwrites
$VirtualDirEntry.BITSAllowOverwrites = 1
# Allow anonymous logon
$VirtualDirEntry.AuthFlags = 1
$VirtualDirEntry.CommitChanges()

[xml]$Doc = New-Object System.Xml.XmlDocument
$Upload = $Doc.CreateNode("element", "upload", $null)
$Upload.SetAttribute("job", "orc")
$Upload.SetAttribute("method", "bits")
$Upload.SetAttribute("mode", "async")
$Upload.SetAttribute("operation", "move")
$IpAddress = (Test-Connection -ComputerName (hostname) -Count 1).IPV4Address
$Upload.SetAttribute("server", "http://$IpAddress")
$Upload.SetAttribute("path", $VirtualDirName)
$Doc.AppendChild($Upload) | Out-Null
Write-Host "Add this <upload/> XML element inside your DFIR-ORC local configuration file:" -ForegroundColor Green
$Doc.innerXml

try {
    Write-Host "Starting WebSite" -ForegroundColor Cyan
    $WebSite.Start()
}
catch [System.Runtime.InteropServices.COMException] {
    Write-Error ("Website '{0}' could not be started, please check that its bindings ({1}) do not conflict with another started website. This is the list of current Websites: {2} " -f $WebSite.Name, $($WebSite.bindings.Collection), (Get-WebSite | Out-String))
}
