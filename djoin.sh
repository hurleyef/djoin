#!/bin/bash


#saner programming env: these switches turn some bugs into errors
set -o errexit -o pipefail -o noclobber -o nounset


#function to find commands
find_command() {
    if [[ -f /usr/sbin/$1 ]]; then
        echo "/usr/sbin/$1"
    elif [[ -f /usr/bin/$1 ]]; then
        echo "/usr/bin/$1"
    elif [[ -f /bin/$1 ]]; then
        echo "/bin/$1"
    else
            exit 1
    fi
}


#find commands
ipCmd=$(find_command ip) || exit $?
grepCmd=$(find_command grep) || exit $?
sleepCmd=$(find_command sleep) || exit $?
systemctlCmd=$(find_command systemctl) || exit $?
chmodCmd=$(find_command chmod) || exit $?
sedCmd=$(find_command sed) || exit $?
hostnameCmd=$(find_command hostname) || exit $?
unameCmd=$(find_command uname) || exit $?


#check for root
if [[ $(/usr/bin/id -u) -ne 0 ]]; then
   echo "This script must be run as root. Try: \"sudo $0\""
   exit 1
fi


#test getopt
[[ $(/usr/bin/getopt --test; echo $?) = 4 ]] || exit 1


#enumerate options
options=hn:rfu:vd:a:ps:o:
longOpts=help,newname:,reboot,force,user:,verbose,domain:,authorized-group:,no-sudo-pass,sudo-group:,ou-path:


#test args
parsed=$(/usr/bin/getopt --options=$options --longoptions=$longOpts --name "$0" -- "$@") || exit $?


#read getopt’s output this way to handle the quoting right:
eval set -- "$parsed"


#define default option values
reboot=false
force=false
verbose=false
noPass=false
help=false
djoinAccount=""
oldDomain=$($hostnameCmd -d)
if [[ "$oldDomain" != "localdomain" ]]; then
    domain=$oldDomain
else
    domain=""
fi
oldHostname=$($hostnameCmd -s)
if [[ "$oldHostname" != "localhost" ]]; then
    hostname=$oldHostname
else
    hostname=""
fi
authGroup=""
sudoGroup=""
ouPath=""


#parse arguments
while true; do
    case "$1" in
        -h|--help)
            help=true
            break
            ;;
        -r|--reboot)
            reboot=true
            shift
            ;;
        -f|--force)
            force=true
            shift
            ;;
        -v|--verbose)
            verbose=true
            shift
            ;;
        -u|--user)
            djoinAccount="$2"
            shift 2
            ;;
        -d|--domain)
            domain="$2"
            shift 2
            ;;
        -n|--newname)
            hostname="$2"
            shift 2
            ;;
        -a|--authorized-group)
            authGroup="$2"
            shift 2
            ;;
        -p|--no-sudo-pass)
            noPass=true
            shift
            ;;
        -s|--sudo-group)
            sudoGroup="$2"
            shift 2
            ;;
        -o|--ou-path)
            ouPath="$2"
            shift 2
            ;;
        --)
            shift
            break
            ;;
        *)
            echo "Programming error"
            exit 3
            ;;
    esac
done


#help
if $help; then
    echo "Usage: $0 [options]"
    echo "Joins Linux system to an AD domain."
    echo ""
    echo "  -h, --help                        Print this help and exit successfully."
    echo "  -n, --newname <hostname>          Renames host before joining to domain."
    echo "  -r, --reboot                      Reboots host after domain join."
    echo "  -f, --force                       Ignore system compatability checks. Only works on RHEL and Debian based systems."
    echo "  -u, --user <username>             Specifies domain join user."
    echo "  -v, --verbose                     Prints verbose output."
    echo "  -d, --domain <domain>             Specifies domain to join."
    echo "  -a, --authorized-group <group>    Specifies AD group allowed to login in to system. Default is to allow all groups."
    echo "  -s, --sudo-group <group>          Specifies AD group to add to sudoers list."
    echo "  -p, --no-sudo-pass                Allow sudo without a password for AD sudoers group."
    echo "  -o, --ou-path <oupath>            Specifies OU path."
    echo ""
    echo "Report bugs to https://github.com/hurleyef/djoin/"
    exit 0
fi


#set verbose mode
$verbose && pipeToNull="" || pipeToNull='1>/dev/null'


#detect OS
if $force; then
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release &>/dev/null
    else
        ID=$($unameCmd -o)
        VERSION_ID=$($unameCmd -r)
    fi
    if [[ -f /usr/bin/yum ]]; then
        distro="EL"
    elif [[ -f /usr/bin/apt ]]; then
        distro="DEB"
    else
        echo "ERROR: System not compatible. Must be RHEL or Debian based."
        exit 1
    fi
elif . /etc/os-release &>/dev/null; then
    if [[ "$ID" = "centos" ]] || [[ "$ID" = "fedora" ]] || [[ "$ID" = "rhel" ]]; then
        distro="EL"
    elif [[ "$ID" = "debian" ]] || [[ "$ID" = "ubuntu" ]] || [[ "$ID" = "raspbian" ]]; then
        distro="DEB"
    fi
else
    echo "ERROR: System not compatible. Use --force to ignore this check."
    exit 1
fi


#wait for network, fail after 20 seconds
netWait=0
until $ipCmd route | $grepCmd default &>/dev/null; do
    if [[ $netWait -gt 20 ]]; then
        echo "ERROR: No network detected."
        exit 1
    fi
    $sleepCmd 1
    netWait=$((netWait+1))
done


#install vmware guest additions if applicable
if [[ $(/usr/bin/systemd-detect-virt | $grepCmd vmware) ]]; then
    eval echo "VMWARE GUEST DETECTED, INSTALLING GUEST ADDITIONS" $pipeToNull
    if [[ "$distro" = "EL" ]]; then
        eval /usr/bin/yum install open-vm-tools -y $pipeToNull
        eval "$systemctlCmd" enable --now vmtoolsd $pipeToNull
    elif [[ "$distro" = "DEB" ]]; then
        eval /usr/bin/apt install open-vm-tools -y $pipeToNull
        eval "$systemctlCmd" enable --now open-vm-tools $pipeToNull
    fi
fi


#install dependancies
eval echo "INSTALLING DEPENDANCIES" $pipeToNull
if [[ "$distro" = "EL" ]]; then
    DEPS="realmd sssd adcli PackageKit sudo samba-common-tools oddjob oddjob-mkhomedir krb5-workstation bind-utils"
    eval /usr/bin/yum update -y $pipeToNull
    eval /usr/bin/yum install -y "$DEPS" $pipeToNull
elif [[ "$distro" = "DEB" ]]; then
    DEPS="realmd sssd adcli packagekit sudo samba-common sssd-tools samba-common-bin samba-libs krb5-user dnsutils"
    /usr/bin/apt-get update &>/dev/null
    eval DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get upgrade -qq $pipeToNull
    eval DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get install -qq "$DEPS" $pipeToNull
fi


#work around bug in adcli version in ubuntu 19.10 repo
if [[ -f /etc/os-release ]] && $grepCmd "Ubuntu 19.10" /etc/os-release &>/dev/null; then
    /usr/bin/wget http://ftp.us.debian.org/debian/pool/main/a/adcli/adcli_0.9.0-1_amd64.deb -O /tmp/adcli_0.9.0-1_amd64.deb
    /usr/bin/dpkg -i /tmp/adcli_0.9.0-1_amd64.deb
    /usr/bin/rm /tmp/adcli_0.9.0-1_amd64.deb
fi


#enable sssd
[[ "$distro" = "EL" ]] && $systemctlCmd enable --now sssd.service &>/dev/null || true


#generate ssh keys
eval echo "GENERATING NEW SSH HOST KEYS" $pipeToNull
eval /usr/bin/ssh-keygen -A $pipeToNull


#configure pam
if [[ "$distro" = "DEB" ]] && ! $grepCmd "session required pam_mkhomedir.so skel=/etc/skel/ umask=077" /etc/pam.d/common-session; then
    echo "session required pam_mkhomedir.so skel=/etc/skel/ umask=077" | /usr/bin/tee -a /etc/pam.d/common-session &>/dev/null
fi


#prompt for domain to join if not provided or parsed
[[ "$hostname" ]] || read -rp "New Hostname: " hostname


#prompt for domain to join if not provided or parsed
[[ "$domain" ]] || read -rp "Domain: " domain


#test domain connectivity
eval echo "LOCATING DOMAIN CRONTROLLER FOR ${domain^^}" $pipeToNull
if ! eval /usr/bin/nslookup -type=SRV _ldap._tcp.dc._msdcs."$domain" $pipeToNull; then
    echo "ERROR: Cannot locate domain $domain."
    exit 1
fi


#configure hostname
/usr/bin/hostnamectl set-hostname "$hostname"."$domain"


#configure kerberos
/usr/bin/tee /etc/krb5.conf 1>/dev/null << EOF
[libdefaults]
 dns_lookup_realm = false
 ticket_lifetime = 24h
 renew_lifetime = 7d
 forwardable = true
 default_realm = ${domain^^}
 default_ccache_name = KEYRING:persistent:%{uid}
[realms]
 ${domain^^} = {
 }

[$domain]
 $domain = ${domain^^}
 .$domain = ${domain^^}
EOF


#configure realmd
/usr/bin/tee /etc/realmd.conf 1>/dev/null << EOF
[active-directory]
os-name = ${ID^}
os-version = $VERSION_ID

[service]
automatic-install = yes

[users]
default-home = /home/%u
default-shell = /bin/bash

[$domain]
user-principal = yes
fully-qualified-names = no
EOF


#prompt for domain join account if not already provided
[[ "$djoinAccount" ]] || read -rp "Username: " djoinAccount


#define realm command arguments
realmArgs="'$domain' --user '$djoinAccount' --membership-software=adcli"
if [[ "$ouPath" ]]; then
    ouPath=${ouPath^^}
    if [[ "${ouPath:0:3}" != "OU=" ]] && [[ "${ouPath:0:3}" != "CN=" ]]; then
        ouPath="OU=$ouPath"
    fi
    realmArgs+=" --computer-ou='$ouPath'"
fi


#join domain
joinCounter=0
until /usr/sbin/realm list | eval "$grepCmd" "'$domain'" &>/dev/null; do
    if [[ $joinCounter -gt 2 ]]; then
        echo "ERROR: Authorization failure."
        [[ "$oldDomain" ]] && oldHostname+=".$oldDomain"
        /usr/bin/hostnamectl set-hostname "$oldHostname"
        exit 1
    fi
    #prompt for password
    read -srp "Password: " DJOINPASSWORD
    echo ""
    echo "$DJOINPASSWORD" | eval /usr/sbin/realm join "$realmArgs" &>/dev/null || true
    joinCounter=$((joinCounter+1))
done


#configure sssd
/usr/bin/tee /etc/sssd/sssd.conf 1>/dev/null << EOF
[sssd]
domains = $domain
config_file_version = 2
services = nss, pam

[domain/$domain]
ad_domain = $domain
krb5_realm = ${domain^^}
#default_domain_suffix = $domain
use_fully_qualified_names = False

realmd_tags = manages-system joined-with-samba
cache_credentials = True
id_provider = ad
krb5_store_password_if_offline = True
default_shell = /bin/bash
fallback_homedir = /home/%u
auth_provider = ad
chpass_provider = ad
access_provider = ad

ldap_schema = ad

dyndns_update = true
dyndns_refresh_interval = 43200
dyndns_update_ptr = true
dyndns_ttl = 3600
ldap_id_mapping = true
ldap_idmap_autorid_compat = true
EOF
$chmodCmd 600 /etc/sssd/sssd.conf
$systemctlCmd restart sssd.service


#configure authorization
if [[ "$authGroup" ]] && [[ ! $(/usr/sbin/realm list | $grepCmd "permitted-groups.*$authGroup")  ]]; then
    /usr/sbin/realm permit --groups "$authGroup"
fi


#print realm status
eval /usr/sbin/realm list $pipeToNull


#configure sudo
if [[ "$sudoGroup" ]]; then
    #escape spaces in group name
    sudoGroup="$($sedCmd "s/ /\\\\\ /g" <<< "$sudoGroup")"
    #remove any preexisting authorization for group
    < /etc/sudoers $sedCmd "/%$($sedCmd 's/\\/\\\\/g' <<< "$sudoGroup")/Id" | EDITOR="/usr/bin/tee" /usr/sbin/visudo &>/dev/null
    #authorize group
    if $noPass; then
        echo "%$sudoGroup    ALL=(ALL)    NOPASSWD:    ALL" | EDITOR="/usr/bin/tee -a" /usr/sbin/visudo &>/dev/null
    else
        echo "%$sudoGroup    ALL=(ALL)    ALL" | EDITOR="/usr/bin/tee -a" /usr/sbin/visudo &>/dev/null
    fi
fi


#configure ssh to use gssapi and disable root login
$sedCmd -i "s/$($grepCmd "GSSAPIAuthentication" < /etc/ssh/sshd_config)/GSSAPIAuthentication yes/g" /etc/ssh/sshd_config &>/dev/null
$sedCmd -i "s/$($grepCmd "GSSAPICleanupCredentials" < /etc/ssh/sshd_config)/GSSAPICleanupCredentials yes/g" /etc/ssh/sshd_config &>/dev/null
$sedCmd -i "s/$($grepCmd "PermitRootLogin [yn]" < /etc/ssh/sshd_config)/PermitRootLogin no/g" /etc/ssh/sshd_config &>/dev/null


#restart ssh
$systemctlCmd restart sshd.service


#purge user kerberos tickets on logout
/usr/bin/touch /etc/bash.bash_logout
if [[ ! $($grepCmd kdestroy < /etc/bash.bash_logout) ]]; then
    echo kdestroy | /usr/bin/tee /etc/bash.bash_logout &>/dev/nullcat
fi


#remove domain join cronjob and delete script
#/usr/bin/crontab -l | eval $grepCmd -v $0  | /usr/bin/crontab - || true
#/usr/bin/rm -- "$0"


#reboot system
$reboot && $systemctlCmd reboot


#fin
exit 0
