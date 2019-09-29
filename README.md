# djoin
Join RHEL and Debian based systems to Active Directory.


Tested with:
Centos 7
Centos 8
Fedora Server 30
Debian 9
Debian 10
Ubuntu Server 18.04LTS
and Ubuntu Server 19.04


Known Issues:
Some of the Debian based distros require a reboot to register in dns, if they will at all.


Usage: ./djoin.sh [options]
Joins Linux system to an AD domain.

  -h, --help                        Print this help and exit successfully.
  -n, --newname \<hostname\>          Renames host before joining to domain.
  -r, --reboot                      Reboots host after domain join.
  -f, --force                       Ignore system compatability checks. Only works on RHEL and Debian based systems.
  -u, --user \<username\>             Specifies domain join user.
  -v, --verbose                     Prints verbose output.
  -d, --domain \<domain\>             Specifies domain to join.
  -a, --authorized-group \<group\>    Specifies AD group allowed to login in to system. Default is to allow all groups.
  -s, --sudo-group \<group\>          Specifies AD group to add to sudoers list.
  -p, --no-sudo-pass                Allow sudo without a password for AD sudoers group.
  -o, --ou-path \<oupath\>            Specifies OU path.


