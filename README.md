# DFIR-ORC deployment scripts

Repository of scripts to assist in the deployment of DFIR-ORC for Windows

## New-BitsHttpServer.ps1

This script installs a IIS website and sets it up with suitable configuration to be used as an upload website by DFIR-ORC with the `http://` URI scheme. It enables BITS upload with anonymous logon and prints out the XML configuration to use in the local configuration file for DFIR-ORC.

#### Prerequisites

* Windows Server 2008R2+
* Powershell 2.0+
* Local admin privileges

#### Syntax

```powershell
New-BitsHttpServer.ps1 [-Path] <String> [[-Site] <String>] [[-AppPool] <String>] [[-Port] <Int32>] [<CommonParameters>]
```

#### Parameters
```
-Path <String>
    Path of the virtual directory where files will be uploaded. Required.

-Site <String>
    Name of the website to create or reuse (if it already exists). Defaults to "Default Web Site".

-AppPool <String>
    Application Pool to use when creating a new website. Defaults to "DefaultAppPool".

-Port <Int32>
    TCP Port to bind to when creating a new website. You cannot use an already bound port. Defaults to 80.
```

#### Examples

Configure a virtual directory inside the default web site provided by IIS.
```powershell
New-BitsHttpServer -Path C:\website\upload
```

## New-BitsSmbServer.ps1

This script creates a directory and shares it through SMB with suitable permissions (ie. write-only) for it to be used as an upload directory by DFIR-ORC with the `file://` URI scheme.

#### Prerequisites

* Windows Server 2008R2+
* Powershell 2.0+
* Local admin privileges

#### Syntax

```powershell
New-BitsSmbServer.ps1 [-Path] <String> [[-Mode] <String>] [[-AccountName] <String[]>] [[-ShareName] <String>] [[-ShareDescription] <String>] [-Audit] [<CommonParameters>]
```

#### Parameters

```
-Path <String>
    Path of the local directory that will be shared through SMB. Required.

-Mode <String>
    Mode of operation:
    - DomainJoined (default): the server is domain-joined and this script will configure the share's ACL to allow "Domain Computers" well-known SID
    - StandaloneGuest (strongly discouraged): will setup the SMB share to allow guest access. Warning: this will prevent Windows 10/2016/2019 clients from accessing the share ! See https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/guest-access-in-smb2-is-disabled-by-default
    - StandaloneAuthenticated will setup the SMB share to allow an explicit local SID to access the share.

-AccountName <String[]>
    Explicit users or groups to allow write access to. This parameter is passed as is to Set-SmbShareAccess so it must include the domain name if a domain account/group is desired (eg: EXAMPLE\Administrator). Required when $Mode = StandaloneAuthenticated. Defaults to "EXAMPLE\Domain Computers" when $Mode = DomainJoined and defaults to "Guest" when $Mode = StandaloneGuest. Note that even if it is possible to provide more than one user and/or group with this option, it is only possible to use one user in DFIR-ORC local configuration file.

-ShareName <String>
    Name of the share

-ShareDescription <String>
    Description of the share

-Audit [<SwitchParameter>]
    Add Audit rules on the shared directory. Do not use in production ! Use it only for debugging purposes !
    You will still need to activate manually the "Object Access/File System" audit policy:
    auditpol.exe /set /subcategory:"File System" /success:enable /failure:enable
```

#### Examples

Create the directory D:\orc_smb_share and share it via SMB with an ACL to allow write access to "Domain Computers"
```powershell
New-BitsHttpServer -Path D:\orc_smb_share
```

Create the directory D:\orc_smb_share and share it via SMB with an ACL to allow write access to the local Administrator account
```powershell
New-BitsHttpServer -Path D:\orc_smb_share -Mode StandaloneAuthenticated -AccountName Administrator
```

## License
Le contenu de ce dépôt est disponible sous licence LGPL2.1+, tel qu'indiqué [ici](LICENSE.txt)

Le nom DFIR ORC et le logo associé appartiennent à l'ANSSI, aucun usage n'est permis sans autorisation expresse.

The contents of this repository is available under [LGPL2.1+](LICENSE.txt).

The name DFIR ORC and the associate logo belongs to ANSSI, no use is permitted without its express approval.
