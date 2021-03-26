<#
    .SYNOPSIS
        This script creates a directory and shares it through SMB with suitable permissions (ie. write-only) for it to be used as an upload directory by DFIR-ORC with the `file://` URI scheme.
    .PARAMETER Path
        Path of the local directory that will be shared through SMB. Required.
    .PARAMETER Mode
        Mode of operation:
        - DomainJoined (default): the server is domain-joined and this script will configure the share's ACL to allow "Domain Computers" well-known SID
        - StandaloneGuest (strongly discouraged): will setup the SMB share to allow guest access. Warning: this will prevent Windows 10/2016/2019 clients from accessing the share ! See https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/guest-access-in-smb2-is-disabled-by-default
        - StandaloneAuthenticated will setup the SMB share to allow an explicit local SID to access the share.
    .PARAMETER AccountName
        Explicit users or groups to allow write access to. This parameter is passed as is to Set-SmbShareAccess so it must include the domain name if a domain account/group is desired (eg: EXAMPLE\Administrator). Required when $Mode = StandaloneAuthenticated.
        Defaults to @("EXAMPLE\Domain Computers","EXAMPLE\Domain Controllers","NT Authority\SYSTEM") when $Mode = DomainJoined and defaults to "Guests" when $Mode = StandaloneGuest. Note that even if it is possible to provide more than one user and/or group with this option, it is only possible to use one user in DFIR-ORC local configuration file.
    .PARAMETER ShareName
        Name of the share
    .PARAMETER Audit
        Add Audit rules on the shared directory. Do not use in production ! Use it only for debugging purposes !
        You will still need to activate manually the "Object Access/File System" audit policy:
        auditpol.exe /set /subcategory:"File System" /success:enable /failure:enable
    .PARAMETER ShareDescription
        Description of the share
    .EXAMPLE
        PS> New-BitsSmbServer -Path D:\orc_smb_share
        Create the directory D:\orc_smb_share and share it via SMB with an ACL to allow write access to "Domain Computers"
    .EXAMPLE
        PS> New-BitsSmbServer -Path D:\orc_smb_share -Mode StandaloneAuthenticated -AccountName Administrator
        Create the directory D:\orc_smb_share and share it via SMB with an ACL to allow write access to the local Administrator account
    .NOTES
        SPDX-License-Identifier: LGPL-2.1-or-later
        Copyright (c) 2011-2021 ANSSI. All Rights Reserved.
        Author: Sebastien Chapiron (ANSSI)
#>
Param(
    [Parameter(Mandatory=$true)][String]$Path,

    [ValidateSet('DomainJoined','StandaloneGuest','StandaloneAuthenticated')]
    [String]$Mode = "DomainJoined",

    [System.Security.Principal.NTAccount[]]$AccountName = @(),

    [String]$ShareName = $null,

    [String]$ShareDescription = "Data collection share",

    [Switch]$Audit = $false
)

$EveryoneAccount = (New-Object Security.Principal.SecurityIdentifier("S-1-1-0")).Translate([Security.Principal.NTAccount])
$SystemAccount = (New-Object Security.Principal.SecurityIdentifier("S-1-5-18")).Translate([Security.Principal.NTAccount])

# Set AccountName to its default value depending on the mode of operation
if (-not $AccountName) {
    if ($Mode -eq "DomainJoined") {
        # Default value for DomainJoined is an array of 3 items:
        #   - Domain Computers
        #   - Domain Controllers
        #   - S-1-5-18 because this is the account this computer will use to access its own share
        # In order to reliably use the first two, the script must use their SID (since their name is localized).
        # And for that, it needs to find out the Domain SID from a known and non-localized account, in this case: krbtgt

        # First, check if computer is domain-joined
        [int] $DomainRole = Get-WmiObject Win32_ComputerSystem | Select -Expand DomainRole
        if (($DomainRole -ne 0) -and ($DomainRole -ne 2)) {
            # Retrieve Domain name to use for translating krbtgt account into its SID
            $DomainName = Get-WmiObject Win32_ComputerSystem | Select -Expand Domain
            # Extract Domain SID from krbtgt SID
            $DomainSID = (New-Object Security.Principal.NTAccount "$DomainName\krbtgt").Translate([Security.Principal.SecurityIdentifier]) | Select -Expand AccountDomainSid
            # Construct both Principals (Domain Computers and Domain Controllers) from Domain SID and their well known RID
            # The translation from SecurityIdentifier to NTAccount is not strictly necessary but it helps for debug messages
            $AccountName += (New-Object Security.Principal.SecurityIdentifier([Security.Principal.WellKnownSidType]::AccountComputersSid, $DomainSID)).Translate([Security.Principal.NTAccount])
            $AccountName += (New-Object Security.Principal.SecurityIdentifier([Security.Principal.WellKnownSidType]::AccountControllersSid, $DomainSID)).Translate([Security.Principal.NTAccount])
            $AccountName += $SystemAccount
        }
        else {
            Write-Error -Exception ([System.Management.Automation.GetValueException]"Computer needs to be domain-joined for this mode") -ErrorAction Stop
        }
    }
    elseif ($Mode -eq "StandaloneGuest") {
        # Guests group is a well known SID : S-1-5-32-546
        $AccountName = @(New-Object Security.Principal.SecurityIdentifier("S-1-5-32-546"))
    }
    else {
        Write-Error -Exception ([System.Management.Automation.ParameterBindingException]"Parameter AccountName is required when using -Mode $Mode") -ErrorAction Stop
    }
}

Write-Host "Setting up $Path as an SMB share with write access for $AccountName" -Foreground Cyan

# Create the share directory
$SharePhysicalPath = New-Item -Type directory $Path -force
if (-not $ShareName) {
    $ShareName = $SharePhysicalPath.Name
}

$Acl = Get-Acl -Path $SharePhysicalPath
# Clear all access rules
$Acl.SetAccessRuleProtection($true, $false)
$Acl.Access | ForEach-Object { $Acl.RemoveAccessRule($_) | Out-Null }
# Apply suitable NTFS permissions : write-only for $AccountName
$AccountName | ForEach-Object {
    $LoopAccount = $_
    Write-Host "Adding write-only access rule for account $LoopAccount to filesystem path $SharePhysicalPath" -Foreground Cyan
    $FileSystemAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($LoopAccount, "CreateFiles, WriteAttributes, ReadAttributes, Delete, Synchronize", "ContainerInherit, ObjectInherit", "None", [System.Security.AccessControl.AccessControlType]::Allow)
    try {
        $Acl.AddAccessRule($FileSystemAccessRule)
    }
    catch {
        Write-Warning -Message "Could not add an access rule for account $LoopAccount. Does this account exist ? : $PSItem"
    }
}
# Give full access to the current user
Write-Host "Adding full access for account $env:UserName to filesystem path $SharePhysicalPath" -Foreground Cyan
$Acl.AddAccessRule($(New-Object System.Security.AccessControl.FileSystemAccessRule($env:UserName, "FullControl", "ContainerInherit, ObjectInherit", "None", [System.Security.AccessControl.AccessControlType]::Allow)))
# Debug: Add audit rules
if ($Audit) {
    Write-Host "Adding full audit rule on filesystem path $SharePhysicalPath" -Foreground Cyan
    $Acl.AddAuditRule($(New-Object System.Security.AccessControl.FileSystemAuditRule($EveryoneAccount,"FullControl",[System.Security.AccessControl.AuditFlags]::Success)))
    $Acl.AddAuditRule($(New-Object System.Security.AccessControl.FileSystemAuditRule($EveryoneAccount,"FullControl",[System.Security.AccessControl.AuditFlags]::Failure)))
}
# Apply ACL
Set-Acl -Path $SharePhysicalPath -AclObject $Acl

# Powershell < 3.0 does not have SmbShare module and must use WMI
if (Get-Command Get-SmbShare -errorAction SilentlyContinue) {
    # Share the directory if it isn't already shared
    if (-not ($Share = Get-SmbShare | Where-Object {$_.Path -eq $SharePhysicalPath.FullName})) {
        Write-Host "Creating a new SMB share on $SharePhysicalPath" -Foreground Cyan
        $Share = New-SmbShare -Path $SharePhysicalPath -Name $ShareName -Description $ShareDescription
    }
    # Apply suitable SMB permissions : change for $AccountName
    Write-Host "Resetting SMB share access on $ShareName" -Foreground Cyan
    $Share | Revoke-SmbShareAccess -AccountName $EveryoneAccount -Force | Out-Null
    $AccountName | ForEach-Object {
        $LoopAccount = $_
        Write-Host "Granting 'Change' SMB share access to account $LoopAccount on $ShareName" -Foreground Cyan
        try {
            $Share | Grant-SmbShareAccess -AccountName $LoopAccount -AccessRight Change -Force | Out-Null
        }
        catch {
            Write-Warning -Message "Could not grant SMB share access to account $LoopAccount. Does this account exist ? : $PSItem"
        }
    }
}
else {
    $Share = Get-WmiObject -Class Win32_share -filter "Path='$([regex]::escape($SharePhysicalPath.FullName))'"
    if (-not $Share) {
        Write-Host "Creating a new SMB share on $SharePhysicalPath" -Foreground Cyan
        $result = ([WMICLASS] "\\.\Root\Cimv2:Win32_Share").Create($SharePhysicalPath, $ShareName, 0)
        switch ($result.ReturnValue) {
            2 {Write-Error -ErrorAction Stop -Message "Error $($result.ReturnValue) while sharing $SharePhysicalPath : Access Denied" }
            8 {Write-Error -ErrorAction Stop -Message "Error $($result.ReturnValue) while sharing $SharePhysicalPath : Unknown Failure" }
            9 {Write-Error -ErrorAction Stop -Message "Error $($result.ReturnValue) while sharing $SharePhysicalPath : Invalid Name"}
            10 {Write-Error -ErrorAction Stop -Message "Error $($result.ReturnValue) while sharing $SharePhysicalPath : Invalid Level" }
            21 {Write-Error -ErrorAction Stop -Message "Error $($result.ReturnValue) while sharing $SharePhysicalPath : Invalid Parameter" }
            22 {Write-Warning -Message "Error $($result.ReturnValue) while sharing $SharePhysicalPath : Duplicate Share"}
            23 {Write-Error -ErrorAction Stop -Message "Error $($result.ReturnValue) while sharing $SharePhysicalPath : Redirected Path" }
            24 {Write-Error -ErrorAction Stop -Message "Error $($result.ReturnValue) while sharing $SharePhysicalPath : Unknown Device or Directory" }
            25 {Write-Error -ErrorAction Stop -Message "Error $($result.ReturnValue) while sharing $SharePhysicalPath : Net Name Not Found" }
        }
        $Share = Get-WmiObject -Class Win32_share -filter "Path='$([regex]::escape($SharePhysicalPath.FullName))'"
    }

    # Apply suitable SMB permissions : change for $AccountName
    $SecDesc = ([WMIClass] "\\.\root\cimv2:Win32_SecurityDescriptor").CreateInstance()
    $AccountName | ForEach-Object {
        $LoopAccount = New-Object System.Security.Principal.NTAccount($_)
        Write-Host "Granting 'Change' SMB share access to account $LoopAccount on $ShareName" -Foreground Cyan
        # Build a new Trustee object from the account SID (translated from the account name)
        $Trustee = ([WMIClass] "\\.\root\cimv2:Win32_Trustee").CreateInstance()
        try {
            $Sid = New-Object System.Security.Principal.SecurityIdentifier($LoopAccount.Translate([System.Security.Principal.SecurityIdentifier]))
        }
        catch {
            Write-Warning -Message "Failed to translate account name $LoopAccount into SID: $PSItem"
            Continue
        }
        $Trustee.SID = ([WMI] "\\.\root\cimv2:Win32_SID.SID='$($Sid.Value)'").BinaryRepresentation
        # Build a new ACE with the trustee
        $Ace = ([WMIClass] "\\.\root\cimv2:Win32_ACE").CreateInstance()
        $Ace.AccessMask = 1245631   # "Change" permission
        $Ace.AceType = 0   # Access Allowed
        $Ace.AceFlags = 3    # OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
        $Ace.Trustee = $Trustee
        $SecDesc.dacl += $Ace.psobject.baseobject
    }
    $result = $Share.SetShareInfo($null, $ShareDescription, $SecDesc)
    if ($result.ReturnValue -ne 0) {
        Write-Error -Message "Failed to apply security descriptor to SMB share $ShareName : Error $($result.ReturnValue)" -ErrorAction Stop
    }
}

Write-Host "Setup is complete" -Foreground Cyan

# Output the XML snippet to use this share in DFIR-Orc local configuration
[xml]$Doc = New-Object System.Xml.XmlDocument
$Upload = $Doc.CreateNode("element", "upload", $null)
$Upload.SetAttribute("job", "orc")
$Upload.SetAttribute("method", "bits")
$Upload.SetAttribute("mode", "async")
$Upload.SetAttribute("operation", "move")
$IpAddress = (Test-Connection -ComputerName (hostname) -Count 1).IPV4Address
$Upload.SetAttribute("server", "file://$IpAddress")
$Upload.SetAttribute("path", $ShareName)
if ($Mode -eq "StandaloneAuthenticated") {
    $Upload.SetAttribute("user", "$(hostname)\$($AccountName | Select -First 1)")
    $Upload.SetAttribute("password", "__CHANGE_ME__")
}

$Doc.AppendChild($Upload) | Out-Null
Write-Host "Add this <upload/> XML element inside your DFIR-ORC local configuration file:" -ForegroundColor Green
$Doc.innerXml
