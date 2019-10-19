#!/usr/bin/env bash


#saner programming env: these switches turn some bugs into errors
set -o errexit -o pipefail -o noclobber -o nounset


#find and set echo command
if [[ -f /usr/bin/echo ]]; then
    ECHOCMD="/usr/bin/echo"
elif [[ -f /bin/echo ]]; then
    ECHOCMD="/bin/echo"
else
    exit 3
fi


#function to find commands
function find_command() {
    if [[ -f /usr/sbin/$1 ]]; then
        $ECHOCMD "/usr/sbin/$1"
    elif [[ -f /usr/bin/$1 ]]; then
        $ECHOCMD "/usr/bin/$1"
    elif [[ -f /bin/$1 ]]; then
        $ECHOCMD "/bin/$1"
    else
            exit 1
    fi
}


#find commands
IPCMD=$(find_command ip) || exit $?
GREPCMD=$(find_command grep) || exit $?
SLEEPCMD=$(find_command sleep) || exit $?
SYSTEMCTLCMD=$(find_command systemctl) || exit $?
CHMODCMD=$(find_command chmod) || exit $?
SEDCMD=$(find_command sed) || exit $?
HOSTNAMECMD=$(find_command hostname) || exit $?
TRUE=$(find_command true) || exit $?
FALSE=$(find_command false) || exit $?


#check for root
if [[ $(/usr/bin/id -u) -ne 0 ]]; then
   $ECHOCMD "This script must be run as root. Try: \"sudo $0\""
   exit 1
fi


#test getopt
if [[ $(/usr/bin/getopt --test; echo $?) != 4 ]]; then
    exit 1
fi


#enumerate options
OPTIONS=hn:rfu:vd:a:ps:o:
LONGOPTS=help,newname:,reboot,force,user:,verbose,domain:,authorized-group:,no-sudo-pass,sudo-group:,ou-path:


#test args
PARSED=$(/usr/bin/getopt --options=$OPTIONS --longoptions=$LONGOPTS --name "$0" -- "$@") || exit $?


#read getopt’s output this way to handle the quoting right:
eval set -- "$PARSED"


#define default option values
REBOOT=$FALSE
FORCE=$FALSE
VERBOSE=$FALSE
NOPASS=$FALSE
HELP=$FALSE
DJOINACCOUNT=""
OLDDOMAIN=$($HOSTNAMECMD -d)
if [[ "$OLDDOMAIN" != "localdomain" ]]; then
    DOMAIN=$OLDDOMAIN
else
    DOMAIN=""
fi
OLDHNAME=$($HOSTNAMECMD -s)
if [[ "$OLDHNAME" != "localhost" ]]; then
    HNAME=$OLDHNAME
else
    HNAME=""
fi
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
$VERBOSE && PIPETONULL=""


#detect OS
. /etc/os-release
if $FORCE; then
    if [[ -f /usr/bin/yum ]]; then
        DISTRO="EL"
    elif [[ -f /usr/bin/apt ]]; then
        DISTRO="DEB"
    else
        $ECHOCMD "ERROR: System not compatible. Must be RHEL or Debian based."
        exit 1
    fi
elif [[ "$ID" = "centos" ]] || [[ "$ID" = "fedora" ]] || [[ "$ID" = "rhel" ]]; then
        DISTRO="EL"
    elif [[ "$ID" = "debian" ]] || [[ "$ID" = "ubuntu" ]] || [[ "$ID" = "raspbian" ]]; then
        DISTRO="DEB"
    else
        $ECHOCMD "ERROR: System not compatible. Use --force to ignore this check."
        exit 1
fi


#wait for network, fail after 20 seconds
NETWAIT=0
until $IPCMD route | $GREPCMD default &>/dev/null; do
    if [[ $NETWAIT -gt 20 ]]; then
        $ECHOCMD "ERROR: No network detected."
        exit 1
    fi
    $SLEEPCMD 1
    NETWAIT=$((NETWAIT+1))
done


#install vmware guest additions if applicable
if [[ $(/usr/bin/systemd-detect-virt | $GREPCMD vmware) ]]; then
    eval $ECHOCMD "VMWARE GUEST DETECTED, INSTALLING GUEST ADDITIONS" $PIPETONULL
    if [[ "$DISTRO" = "EL" ]]; then
        eval /usr/bin/yum install open-vm-tools -y $PIPETONULL
        eval "$SYSTEMCTLCMD" enable --now vmtoolsd $PIPETONULL
    elif [[ "$DISTRO" = "DEB" ]]; then
        eval /usr/bin/apt install open-vm-tools -y $PIPETONULL
        eval "$SYSTEMCTLCMD" enable --now open-vm-tools $PIPETONULL
    fi
fi


#install dependancies
eval $ECHOCMD "INSTALLING DEPENDANCIES" $PIPETONULL
if [[ "$DISTRO" = "EL" ]]; then
    DEPS="realmd sssd adcli PackageKit sudo samba-common-tools oddjob oddjob-mkhomedir krb5-workstation bind-utils"
    eval /usr/bin/yum update -y $PIPETONULL
    eval /usr/bin/yum install -y "$DEPS" $PIPETONULL
elif [[ "$DISTRO" = "DEB" ]]; then
    DEPS="realmd sssd adcli packagekit sudo samba-common sssd-tools samba-common-bin samba-libs krb5-user dnsutils"
    /usr/bin/apt-get update &>/dev/null
    eval DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get upgrade -qq $PIPETONULL
    eval DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get install -qq "$DEPS" $PIPETONULL
fi


#enable sssd
[[ "$DISTRO" = "EL" ]] && $SYSTEMCTLCMD enable --now sssd.service &>/dev/null


#generate ssh keys
eval $ECHOCMD "GENERATING NEW SSH HOST KEYS" $PIPETONULL
eval /usr/bin/ssh-keygen -A $PIPETONULL


#configure pam
if [[ "$DISTRO" == "DEB" ]]; then
    $ECHOCMD "session required pam_mkhomedir.so skel=/etc/skel/ umask=077" | /usr/bin/tee -a /etc/pam.d/common-session &>/dev/null
fi


#prompt for domain to join if not provided or parsed
[[ "$HNAME" ]] || read -rp "New Hostname: " HNAME


#prompt for domain to join if not provided or parsed
[[ "$DOMAIN" ]] || read -rp "Domain: " DOMAIN


#test domain connectivity
eval $ECHOCMD "LOCATING DOMAIN CRONTROLLER FOR ${DOMAIN^^}" $PIPETONULL
if ! eval /usr/bin/nslookup -type=SRV _ldap._tcp.dc._msdcs."$DOMAIN" $PIPETONULL; then
    $ECHOCMD "ERROR: Cannot locate domain $DOMAIN."
    exit 1
fi


#configure hostname
/usr/bin/hostnamectl set-hostname "$HNAME"."$DOMAIN"


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


#prompt for domain join account if not already provided
[[ "$DJOINACCOUNT" ]] || read -rp "Username: " DJOINACCOUNT


#define realm command arguments
REALMARGS="$DOMAIN --user $DJOINACCOUNT --membership-software=adcli"
if [[ "$OUPATH" ]]; then
    OUPATH=${OUPATH^^}
    if [[ "${OUPATH:0:3}" != "OU=" ]] && [[ "${OUPATH:0:3}" != "CN=" ]]; then
    OUPATH="OU=$OUPATH"
    fi
    REALMARGS+=" --computer-ou=\"$OUPATH\""
fi


#join domain
JOINCOUNTER=0
until /usr/sbin/realm list | eval "$GREPCMD" "$DOMAIN" &>/dev/null; do
    if [[ $JOINCOUNTER -gt 2 ]]; then
        $ECHOCMD "ERROR: Authorization failure."
        [[ "$OLDDOMAIN" ]] && OLDHNAME+=".$OLDDOMAIN"
        /usr/bin/hostnamectl set-hostname "$OLDHNAME"
        exit 1
    fi
    #prompt for password
    read -srp "Password: " DJOINPASSWORD
    $ECHOCMD ""
    $ECHOCMD "$DJOINPASSWORD" | eval /usr/sbin/realm join "$REALMARGS" &>/dev/null || $TRUE
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
if [[ "$AUTHGROUP" ]] && [[ ! $(/usr/sbin/realm list | $GREPCMD "permitted-groups.*$AUTHGROUP")  ]]; then
    /usr/sbin/realm permit --groups "$AUTHGROUP"
fi


#print realm status
eval /usr/sbin/realm list $PIPETONULL


#configure sudo
if [[ "$SUDOGROUP" ]]; then
    #escape spaces in group name
    SUDOGROUP="$($SEDCMD "s/ /\\\\\ /g" <<< "$SUDOGROUP")"
    #remove any preexisting authorization for group
    < /etc/sudoers $SEDCMD "/%$($SEDCMD 's/\\/\\\\/g' <<< "$SUDOGROUP")/Id" | EDITOR='/usr/bin/tee' /usr/sbin/visudo &>/dev/null
    #authorize group
    if $NOPASS; then
        $ECHOCMD "%$SUDOGROUP    ALL=(ALL)    NOPASSWD:    ALL" | EDITOR='/usr/bin/tee -a' /usr/sbin/visudo &>/dev/null
    else
        $ECHOCMD "%$SUDOGROUP    ALL=(ALL)    ALL" | EDITOR='/usr/bin/tee -a' /usr/sbin/visudo &>/dev/null
    fi
fi


#configure ssh to use gssapi and disable root login
$SEDCMD -i "s/$($GREPCMD 'GSSAPIAuthentication' < /etc/ssh/sshd_config)/GSSAPIAuthentication yes/g" /etc/ssh/sshd_config
$SEDCMD -i "s/$($GREPCMD 'GSSAPICleanupCredentials' < /etc/ssh/sshd_config)/GSSAPICleanupCredentials yes/g" /etc/ssh/sshd_config
$SEDCMD -i "s/$($GREPCMD 'PermitRootLogin [yn]' < /etc/ssh/sshd_config)/PermitRootLogin no/g" /etc/ssh/sshd_config


#restart ssh
$SYSTEMCTLCMD restart sshd.service


#purge user kerberos tickets on logout
/usr/bin/touch /etc/bash.bash_logout
if [[ ! $($GREPCMD kdestroy < /etc/bash.bash_logout) ]]; then
    $ECHOCMD kdestroy | /usr/bin/tee /etc/bash.bash_logout &>/dev/null
fi


#remove domain join cronjob and delete script
#/usr/bin/crontab -l | eval $GREPCMD -v 'djoin.sh'  | /usr/bin/crontab - || $TRUE
#/usr/bin/rm -- "$0"


#reboot system
$REBOOT && $SYSTEMCTLCMD reboot


#fin
exit 0
