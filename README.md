# windows-lpe-lite

windows Local privilege escalation for xp sp3+ (x86/x64)

## Tested Products

| Product                        | Build | CVE-2014-4113 | CVE-2015-1701 | CVE-2017-0213 |
| :----------------------------- | :---: | :-----------: | :-----------: | :-----------: |
| Windows XP  X86 SP3            | 2600  |       √       |       X       |               |
| Windows 7   X86 SP1            | 7601  |       √       |       √       |               |
| Windows 7   X64 SP1            | 7601  |               |       √       |               |
| Windows 8.1 X64                |       |               |               |               |
| Windows 10  X64                | 1703  |               |               |               |
| Windows Server 2003 X86 R2 SP2 | 3790  |       √       |       √       |               |
| Windows Server 2003 X64 R2 SP2 | 3790  |               |       √       |               |
| Windows Server 2008 X86        |       |               |               |               |
| Windows Server 2008 X64        |       |               |               |               |
| Windows Server 2008 X64 R2 SP1 | 7601  |               |       √       |               |
| Windows Server 2012 X64        |       |               |               |               |
| Windows Server 2012 X64 R2     |       |               |               |               |
| Windows Server 2016 X64        |       |               |               |               |




## CVE-2014-4113(MS14-058)

**Code:** Anonym

**Report:** 20141015

**Description:** Windows Kernel-mode Driver/ Win32k.sys

**References:** https://support.microsoft.com/en-us/help/3000061/ms14-058-vulnerabilities-in-kernel-mode-driver-could-allow-remote-code-execution-october-14,-2014

## CVE-2015-1701(MS15-051)

**Code:** zcgonvh

**Report:** 20150421

**Description:** Windows Kernel-mode Driver/ Win32k.sys

**References:** https://support.microsoft.com/en-us/help/3045171/ms15-044-and-ms15-051-description-of-the-security-update-for-windows-font-drivers

## CVE-2017-0213(MS17-023)

**Code:** Google Security Research

**Report:** 20170509

**Description:** Windows COM Elevation of Privilege Vulnerability

**References:** https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0213

## Usage

> *.exe whoami

> *.exe cmd.exe

