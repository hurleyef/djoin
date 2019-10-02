# djoin</br>
Join RHEL and Debian based systems to Active Directory.</br>
</br>
</br>
Tested with:</br>
Centos 7</br>
Centos 8</br>
Fedora Server 30</br>
Debian 9</br>
Debian 10</br>
Raspbian 10</br>
Ubuntu Server 18.04LTS</br>
Ubuntu Server 19.04</br>
</br>
</br>
Known Issues:</br>
Self registering in DNS fails on DHCP managed scopes. Either manually create the record or configure your DHCP server to do so.</br>
</br>
</br>
Usage: ./djoin.sh [options]</br>
Joins Linux system to an AD domain.</br>
</br>
  -h, --help                        Print this help and exit successfully.</br>
  -n, --newname \<hostname\>          Renames host before joining to domain.</br>
  -r, --reboot                      Reboots host after domain join.</br>
  -f, --force                       Ignore system compatability checks. Only works on RHEL and Debian based systems.</br>
  -u, --user \<username\>             Specifies domain join user.</br>
  -v, --verbose                     Prints verbose output.</br>
  -d, --domain \<domain\>             Specifies domain to join.</br>
  -a, --authorized-group \<group\>    Specifies AD group allowed to login in to system. Default is to allow all groups.</br>
  -s, --sudo-group \<group\>          Specifies AD group to add to sudoers list.</br>
  -p, --no-sudo-pass                Allow sudo without a password for AD sudoers group.</br>
  -o, --ou-path \<oupath\>            Specifies OU path.</br>
