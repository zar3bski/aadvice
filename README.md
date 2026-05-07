# aadvice

![Gitlab Pipeline Status](https://img.shields.io/gitlab/pipeline-status/zar3bski%2Faadvice?branch=main&style=flat-square)
![Static Badge](https://img.shields.io/badge/arch-ARM64-blue?style=flat-square)
![Static Badge](https://img.shields.io/badge/arch-AMD64-blue?style=flat-square)
![GitLab Release](https://img.shields.io/gitlab/v/release/zar3bski%2Faadvice?style=flat-square)

D-Bus based AppArmor notifier for org.freedesktop.Notifications

> This project is hosted on **Gitlab** and merely **mirrored on Github**. For any question or issue submission, please go to the [project's Gitlab repository](https://gitlab.com/zar3bski/aadvice)

## Installation

Simply download the binary for your architecture [here](https://gitlab.com/zar3bski/aadvice/-/releases) somewhere in your `PATH` (like `$HOME/.local/bin/aadvice`). Then

```shell
# make it executable
chmod +x $HOME/.local/bin/aadvice

# make sure it is found in your PATH 
aadvice --help
```

## Configuration

The configuration is pretty similar to the `aa-notify` setting detailed in [Arch linux Wiki](https://wiki.archlinux.org/title/AppArmor#Get_desktop_notification_on_DENIED_actions)

### audit log_group setting

The **audit framework** should be up and running and your user should belong to the `log_group` set in `/etc/audit/auditd.conf`

```shell
cat /etc/audit/auditd.conf | grep log_group 
log_group = audit

id                                                                                                                                                                                                              
uid=1000(zar3bski) gid=1000(zar3bski) groupes=1000(zar3bski),950(audit),998(wheel)
```

If necessary, edit `/etc/audit/auditd.conf` and create the group

```shell
groupadd -r audit
gpasswd -a user audit
```

### autostart

`aadvice` can be launched via an autostart desktop entry. 

**~/.config/autostart/aadvice-notify.desktop**
```
[Desktop Entry]
Type=Application
Name=AppArmor Notify
Comment=Receive on-screen notifications of AppArmor denials
TryExec=aadvice
Exec=aadvice
StartupNotify=false
NoDisplay=true
```

After reboot, make sure `aadvice` is running

```shell
pgrep -ax aadvice
```

## Motivation and functional perimeter

The main motivation behind this project was my growing frustration with the false positives reported by [aa-notify](https://man.archlinux.org/man/aa-notify.8). To the credit of its maintainer, since it had to interface with apparmor C libraries to handle profile edition and relies on `LibAppArmor.parse_record`, the source of the problem probably was upstream but, at the end of the day, all I needed was an audit log parser able to notify me of `DENIED` events. I thus wrote `aadvice`, a simple Rust based audit log parser.

Aadvice **currently handles**:
* audit log parsing of **AppArmor** based `AVC` records
* desktop notifications though D-Bus `org.freedesktop.Notifications` interface (should work with any desktop environment plugged to this bus)

Based on the needs and users feedback, future releases of `aadvice` **may handle**:
* fetch `DENIED` events from D-Bus itself instead of parsing *audit.log* (dispensing users from setting audit file logging)
* `SELinux` events handling
* regex based filters for the profiles to be displayed (or not)
* a flag to silent event of profiles in **complain mode**

Aadvice **will never handle**:
* **AppArmor** profile edition
