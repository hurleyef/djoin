#!/usr/bin/env bash


#find and set echo command
if [ -f /usr/bin/echo ]; then
    ECHOCMD="/usr/bin/echo"
elif [ -f /bin/echo ]; then
    ECHOCMD="/bin/echo"
else
    exit 1
fi


#find and set ip command
if [ -f /usr/sbin/ip ]; then
    IPCMD="/usr/sbin/ip"
elif [ -f /sbin/ip ]; then
    IPCMD="/sbin/ip"
else
    exit 1
fi


#find and set grep command
if [ -f /usr/bin/grep ]; then
    GREPCMD="/usr/bin/grep"
elif [ -f /bin/grep ]; then
    GREPCMD="/bin/grep"
else
    exit 1
fi


#find and set sleep command
if [ -f /usr/bin/sleep ]; then
    SLEEPCMD="/usr/bin/sleep"
elif [ -f /bin/sleep ]; then
    SLEEPCMD="/bin/sleep"
else
    exit 1
fi


#find and set systemctl command
if [ -f /usr/bin/systemctl ]; then
    SYSTEMCTLCMD="/usr/bin/systemctl"
elif [ -f /bin/systemctl ]; then
    SYSTEMCTLCMD="/bin/systemctl"
else
    exit 1
fi


#find and set chmod command
if [ -f /usr/bin/chmod ]; then
    CHMODCMD="/usr/bin/chmod"
elif [ -f /bin/chmod ]; then
    CHMODCMD="/bin/chmod"
else
    exit 1
fi


#find and set sed command
if [ -f /usr/bin/sed ]; then
    SEDCMD="/usr/bin/sed"
elif [ -f /bin/sed ]; then
    SEDCMD="/bin/sed"
else
    exit 1
fi


#find and set hostname command
if [ -f /usr/bin/hostname ]; then
    HOSTNAMECMD="/usr/bin/hostname"
elif [ -f /bin/hostname ]; then
    HOSTNAMECMD="/bin/hostname"
else
    exit 1
fi


#find and set true
if [ -f /usr/bin/true ]; then
    TRUE="/usr/bin/true"
elif [ -f /bin/true ]; then
    TRUE="/bin/true"
else
    exit 1
fi


#find and set false
if [ -f /usr/bin/false ]; then
    FALSE="/usr/bin/false"
elif [ -f /bin/false ]; then
    FALSE="/bin/false"
else
    exit 1
fi


#check for root
if [ $(id -u) -ne 0 ]; then
   $ECHOCMD "This script must be run as root"
   exit 1
fi


# saner programming env: these switches turn some bugs into errors
set -o errexit -o pipefail -o noclobber -o nounset


#test getopt
! /usr/bin/getopt --test > /dev/null 
if [[ ${PIPESTATUS[0]} -ne 4 ]]; then
    exit 1
fi


#enumerate options
OPTIONS=hn:rfu:vd:a:ps:o:
LONGOPTS=help,newname:,reboot,force,user:,verbose,domain:,authorized-group:,no-sudo-pass,sudo-group:,ou-path:


#test args
! PARSED=$(/usr/bin/getopt --options=$OPTIONS --longoptions=$LONGOPTS --name "$0" -- "$@")
if [[ ${PIPESTATUS[0]} -ne 0 ]]; then
    exit 2
fi


# read getopt’s output this way to handle the quoting right:
eval set -- "$PARSED"


#define default option values
REBOOT=$FALSE
FORCE=$FALSE
VERBOSE=$FALSE
NOPASS=$FALSE
HELP=$FALSE
DJOINACCOUNT=""
OLDDOMAIN=`$HOSTNAMECMD -d`
if [ "$OLDDOMAIN" != "localdomain" ]; then
    DOMAIN=$OLDDOMAIN
else
    DOMAIN=""
fi
OLDHNAME=`$HOSTNAMECMD -s`
HNAME=$OLDHNAME
AUTHGROUP=""
SUDOGROUP=""
OUPATH=""


#parse arguments
while true; do
    case "$1" in
        -h|--help)
            HELP=$TRUE
            break
            ;;
        -r|--reboot)
            REBOOT=$TRUE
            shift
            ;;
        -f|--force)
            FORCE=$TRUE
            shift
            ;;
        -v|--verbose)
            VERBOSE=$TRUE
            shift
            ;;
        -u|--user)
            DJOINACCOUNT="$2"
            shift 2
            ;;
        -d|--domain)
            DOMAIN="$2"
            shift 2
            ;;
        -n|--newname)
            HNAME="$2"
            shift 2
            ;;
        -a|--authorized-group)
            AUTHGROUP="$2"
            shift 2
            ;;
        -p|--no-sudo-pass)
            NOPASS=$TRUE
            shift
            ;;
        -s|--sudo-group)
            SUDOGROUP="$2"
            shift 2
            ;;
        -o|--ou-path)
            OUPATH="$2"
            shift 2
            ;;
        --)
            shift
            break
            ;;
        *)
            $ECHOCMD "Programming error"
            exit 3
            ;;
    esac
done

#help
if $HELP; then
    $ECHOCMD "Usage: $0 [options]"
    $ECHOCMD "Joins Linux system to an AD domain."
    $ECHOCMD ""
    $ECHOCMD "  -h, --help                        Print this help and exit successfully."
    $ECHOCMD "  -n, --newname <hostname>          Renames host before joining to domain."
    $ECHOCMD "  -r, --reboot                      Reboots host after domain join."
    $ECHOCMD "  -f, --force                       Ignore system compatability checks. Only works on RHEL and Debian based systems."
    $ECHOCMD "  -u, --user <username>             Specifies domain join user."
    $ECHOCMD "  -v, --verbose                     Prints verbose output."
    $ECHOCMD "  -d, --domain <domain>             Specifies domain to join."
    $ECHOCMD "  -a, --authorized-group <group>    Specifies AD group allowed to login in to system. Default is to allow all groups."
    $ECHOCMD "  -s, --sudo-group <group>          Specifies AD group to add to sudoers list."
    $ECHOCMD "  -p, --no-sudo-pass                Allow sudo without a password for AD sudoers group."
    $ECHOCMD "  -o, --ou-path <oupath>            Specifies OU path."
    $ECHOCMD ""
    $ECHOCMD "Report bugs to https://github.com/hurleyef/djoin/"
    exit 0
fi

#set verbose mode
PIPETONULL='&>/dev/null'
if $VERBOSE; then
    PIPETONULL=""
fi


#detect OS
. /etc/os-release
if $FORCE; then
    if [ -f /usr/bin/yum ]; then
        DISTRO="EL"
    elif [ -f /usr/bin/apt ]; then
        DISTRO="DEB"
    else
        $ECHOCMD "ERROR: System not compatible. Must be RHEL or Debian based."
        exit 1
    fi
elif [ "$ID" == "centos" ] || [ "$ID" == "fedora" ] || [ "$ID" == "rhel" ]; then
        DISTRO="EL"
    elif [ "$ID" == "debian" ] || [ "$ID" == "ubuntu" ]; then
        DISTRO="DEB"
    else
        $ECHOCMD "ERROR: System not compatible. Use --force to ignore this check."
        exit 1
fi


#wait for network, fail after 20 seconds
NETWAIT=0
until $IPCMD route | $GREPCMD default &>/dev/null; do
    if [ $NETWAIT -gt 20 ]; then
        $ECHOCMD "ERROR: No network detected."
        exit 1
    fi
    $SLEEPCMD 1
    NETWAIT=$((NETWAIT+1))
done


#install dependancies
eval $ECHOCMD "INSTALLING DEPENDANCIES" $PIPETONULL
if [ "$DISTRO" == "EL" ]; then
    DEPS="realmd sssd adcli PackageKit sudo samba-common-tools oddjob oddjob-mkhomedir krb5-workstation bind-utils"
    eval /usr/bin/yum install -y $DEPS $PIPETONULL
    eval /usr/bin/yum update -y $PIPETONULL
elif [ "$DISTRO" == "DEB" ]; then
    DEPS="realmd sssd adcli packagekit sudo samba-common sssd-tools samba-common-bin samba-libs krb5-user dnsutils"
    /usr/bin/apt-get update &>/dev/null
    eval /usr/bin/apt-get upgrade -qq $PIPETONULL
    eval DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get install -qq $DEPS $PIPETONULL
fi


#prompt for domain to join if not provided or parsed
if [ ! "$DOMAIN" ]; then
    read -p "Domain: " DOMAIN
fi


#test domain connectivity
eval $ECHOCMD "LOCATING DOMAIN CRONTROLLER FOR ${DOMAIN^^}" $PIPETONULL
if ! eval /usr/bin/nslookup -type=SRV _ldap._tcp.dc._msdcs.$DOMAIN $PIPETONULL; then
    $ECHOCMD "ERROR: Cannot locate domain $DOMAIN."
    exit 1
fi


#install vmware guest additions if applicable
if [ `/usr/bin/systemd-detect-virt | $GREPCMD vmware` ]; then
    eval $ECHOCMD "VMWARE GUEST DETECTED, INSTALLING GUEST ADDITIONS" $PIPETONULL
    if [ "$DISTRO" == "EL" ]; then
        eval /usr/bin/yum install open-vm-tools -y $PIPETONULL
        eval $SYSTEMCTLCMD enable --now vmtoolsd $PIPETONULL
    elif [ "$DISTRO" == "DEB" ]; then
        eval /usr/bin/apt install open-vm-tools -y $PIPETONULL
        eval $SYSTEMCTLCMD enable --now open-vm-tools $PIPETONULL
    fi
fi


#enable sssd
if [ "$DISTRO" == "EL" ]; then
    $SYSTEMCTLCMD enable --now sssd.service &>/dev/null
fi


#generate ssh keys
eval $ECHOCMD "GENERATING NEW SSH HOST KEYS" $PIPETONULL
eval /usr/bin/ssh-keygen -A $PIPETONULL


#configure pam
if [ "$DISTRO" == "DEB" ]; then
    $ECHOCMD "session required pam_mkhomedir.so skel=/etc/skel/ umask=077" | /usr/bin/tee -a /etc/pam.d/common-session &>/dev/null
fi


#configure hostname
/usr/bin/hostnamectl set-hostname $HNAME.$DOMAIN


#configure kerberos
/usr/bin/tee /etc/krb5.conf 1>/dev/null << EOF
[libdefaults]
 dns_lookup_realm = false
 ticket_lifetime = 24h
 renew_lifetime = 7d
 forwardable = true
 default_realm = ${DOMAIN^^}
 default_ccache_name = KEYRING:persistent:%{uid}

 default_realm = ${DOMAIN^^}
[realms]
 ${DOMAIN^^} = {
 }

[$DOMAIN]
 $DOMAIN = ${DOMAIN^^}
 .$DOMAIN = ${DOMAIN^^}
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

[$DOMAIN]
user-principal = yes
fully-qualified-names = no
EOF


#prompt for domain join account if not provided
if [ ! "$DJOINACCOUNT" ]; then
    read -p "Username: " DJOINACCOUNT
fi


#define realm command arguments
REALMARGS="$DOMAIN --user $DJOINACCOUNT --membership-software=adcli"
if [ "$OUPATH" ]; then
    OUPATH=${OUPATH^^}
    if [ "${OUPATH:0:3}" != "OU=" ]; then
    OUPATH="OU=$OUPATH"
    fi
    REALMARGS+=" --computer-ou=\"$OUPATH\""
fi


#join domain
JOINCOUNTER=0
until /usr/sbin/realm list | eval $GREPCMD $DOMAIN &>/dev/null; do
    if [ $JOINCOUNTER -gt 2 ]; then
        $ECHOCMD "ERROR: Authorization failure."
        if [ "$OLDDOMAIN" ]; then
            OLDHNAME+=".$OLDDOMAIN"
        fi
        /usr/bin/hostnamectl set-hostname $OLDHNAME
        exit 1
    fi
    #prompt for password
    read -srp "Password: " DJOINPASSWORD
    $ECHOCMD ""
    $ECHOCMD $DJOINPASSWORD | eval /usr/sbin/realm join $REALMARGS &>/dev/null || $TRUE
    JOINCOUNTER=$((JOINCOUNTER+1))
done


#configure sssd
/usr/bin/tee /etc/sssd/sssd.conf 1>/dev/null << EOF
[sssd]
domains = $DOMAIN
config_file_version = 2
services = nss, pam

[domain/$DOMAIN]
ad_domain = $DOMAIN
krb5_realm = ${DOMAIN^^}
#default_domain_suffix = $DOMAIN
use_fully_qualified_names = false

re_expression = (((?P<domain>[^\\\]+)\\\(?P<name>.+$))|((?P<name>[^@]+)@(?P<domain>.+$))|(^(?P<name>[^@\\\]+)$))
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
EOF
$CHMODCMD 600 /etc/sssd/sssd.conf
$SYSTEMCTLCMD restart sssd.service


#configure authorization
if [ "$AUTHGROUP" ]; then
    /usr/sbin/realm permit --groups "$AUTHGROUP"
fi


#print realm status
eval /usr/sbin/realm list $PIPETONULL


#configure sudo
if [ "$SUDOGROUP" ]; then
    SUDOGROUP="`$SEDCMD "s/ /\\\\\ /g" <<<"$SUDOGROUP"`"
    if $NOPASS; then
        $ECHOCMD "%$SUDOGROUP    ALL=(ALL)    NOPASSWD:    ALL" | /usr/bin/tee -a /etc/sudoers &>/dev/null
    else
        $ECHOCMD "%$SUDOGROUP    ALL=(ALL)    ALL" | /usr/bin/tee -a /etc/sudoers &>/dev/null
    fi
fi


#configure ssh to use gssapi and disable root login
$SEDCMD -i "s/GSSAPICleanupCredentials no/GSSAPICleanupCredentials yes/g" /etc/ssh/sshd_config
$SEDCMD -i "s/PermitRootLogin yes/#PermitRootLogin yes/g" /etc/ssh/sshd_config
if [ "$DISTRO" == "EL" ]; then
    $SEDCMD -i "s/GSSAPICleanupCredentials no/GSSAPICleanupCredentials yes/g" /etc/ssh/sshd_config
    $SEDCMD -i "s/PermitRootLogin yes/PermitRootLogin no/g" /etc/ssh/sshd_config
elif [ "$DISTRO" == "DEB" ]; then
    $SEDCMD -i "s/#GSSAPIAuthentication no/GSSAPIAuthentication yes/g" /etc/ssh/sshd_config
    $SEDCMD -i '/GSSAPICleanupCredentials/s/^#//g' /etc/ssh/sshd_config
    $SEDCMD -i "/PermitRootLogin yes/d" /etc/ssh/sshd_config
fi


#restart ssh
$SYSTEMCTLCMD restart sshd.service


#purge user kerberos tickets on logout
$ECHOCMD kdestroy | /usr/bin/tee /etc/bash.bash_logout &>/dev/null


#remove domain join cronjob and delete script
#/usr/bin/crontab -l | eval $GREPCMD -v 'djoin.sh'  | /usr/bin/crontab - || true
#/usr/bin/rm -- "$0"


#reboot system
if $REBOOT; then
    $SYSTEMCTLCMD reboot
fi


#fin
exit 0

