#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
A script for importing basic sudo command and command group definitions.
"""
# 2017 By Christian Stankowic
# <info at stankowic hyphen development dot net>
# https://github.com/stdevel
#

from optparse import OptionParser, OptionGroup
import logging
import subprocess



LOGGER = logging.getLogger('ipa-sudo-basic-rules.py')
"""
logging: Logger instance
"""
__version__ = "0.2.7"
"""
str: Script version
"""



def run_cmd(cmd=""):
    """
    This function executes a command
    """
    if options.dry_run:
        #print what would be done
        LOGGER.info("I'd like to execute the following command: %s", cmd)
    else:
        #run the command, it's tricky!
        output = subprocess.Popen(
            "LANG=C {0}".format(cmd), shell=True, stdout=subprocess.PIPE
        ).stdout.read()
        LOGGER.debug("Output of '%s' => '%s", cmd, output)



def import_definitions():
    """
    This function imports all sudo definitions by iterating through all the
    defintions and running adequate ipa commands
    """
    cmds = {}
    cmd_groups = {
        "drivers" : "Managing kernel drivers",
        "editors" : "Editing files",
        "filemgmt" : "Managing files",
        "filemgmt-show" : "Displaying files",
        "filemgmt-find" : "Searching files",
        "fileperm" : "Managing file permissions",
        "fileperm-acl" : "Managing ACLs",
        "locate" : "Managing locate database",
        "networking" : "Managing network connections",
        "firewall" : "Managing firewall configuration",
        "time" : "Managing time/date configuration",
        "processes" : "Managing processes",
        "puppet" : "Master of Puppets",
        "selinux" : "Managing SELinux",
        "selinux-files" : "Managing SELinux file contexts",
        "services" : "Managing system services",
        "shells" : "Shells and other bad software",
        "software" : "Managing software",
        "storage-mount" : "Managing storage mounts",
        "storage-part" : "Managing storage partitions",
        "storage-lvm" : "Managing LVM storage",
        "storage-fs" : "Managing file systems",
        "storage-generic" : "Generic storage commands",
        "su" : "Switching user context",
        "usermgmt" : "Managing users and groups",
        "monitoring" : "Managing monitoring",
        "ipa-client" : "Managing IPA clients",
        "ipa-server" : "Managing IPA servers",
        "rhn-server" : "Managing Spacewalk servers",
        "rhn-client" : "Managing Spacewalk clients",
        "katello-server" : "Managing Katello servers",
        "katello-client" : "Managing Katello clients",
        "mysql-server" : "Managing MySQL servers",
        "postfix" : "Managing Postfix servers",
        "disk-quotas" : "Managing disk quotas",
        "nfs-server" : "Managing NFS servers",
        "nfs-client" : "Managing NFS mounts",
        "power" : "Managing power",
        "bugs" : "Managing bug reports",
        "hipster-docker" : "Managing Docker containers",
        "gitlab" : "Managing GitLab and GitLab CI installations",
        "fail2ban" : "Managing fail2ban",
        "system-who" : "Stalking system's users",
        "samba-server" : "Managing Samba servers",
        "ipmi-tools" : "Managing IPMI"
    }

    #command defintions
    cmds.update({"drivers" : [
        "/sbin/modprobe", "/sbin/rmmod"
    ]})
    cmds.update({"editors" : [
        "/usr/bin/sudoedit"
    ]})
    cmds.update({"filemgmt" : [
        "/bin/cp", "/bin/mv", "/usr/bin/rsync", "/bin/rm", "/bin/ls", "/bin/echo",
        "/bin/cat", "/usr/bin/tail", "/bin/df", "/bin/du", "/bin/mkdir", "/bin/rmdir"
    ]})
    cmds.update({"filemgmt-show" : [
        "/bin/vi", "/bin/vim", "/bin/view", "/usr/bin/bzless", "/usr/bin/bzmore",
        "/usr/bin/lzless", "/usr/bin/lzmore", "/usr/bin/xzless", "/usr/bin/xzmore",
        "/usr/bin/zless", "/usr/bin/zmore", "/usr/sbin/vipw", "/bin/more",
        "/usr/bin/less"
    ]})
    cmds.update({"filemgmt-find" : [
        "/bin/find"
    ]})
    cmds.update({"filemgmt-consumption" : [
        "/usr/bin/du", "/bin/df", "/usr/bin/ncdu"
    ]})
    cmds.update({"fileperm" : [
        "/bin/chgrp", "/bin/chmod", "/bin/chown"
    ]})
    cmds.update({"fileperm-acl" : [
        "/usr/bin/chacl", "/usr/bin/gefacl", "/usr/bin/setfacl"
    ]})
    cmds.update({"locate" : [
        "/usr/bin/updatedb"
    ]})
    cmds.update({"networking" : [
        "/sbin/ifconfig", "/sbin/mii-tool", "/usr/bin/net", "/sbin/ifdown",
        "/sbin/ifup", "/bin/netstat"
    ]})
    cmds.update({"firewall" : [
        "/sbin/iptables", "/usr/sbin/lokkit", "/usr/bin/system-config-firewall-tui",
        "/usr/bin/firewall-cmd", "/usr/bin/firewall-offline-cmd"
    ]})
    cmds.update({"time" : [
        "/sbin/hwclock", "/bin/timedatectl", "/usr/sbin/ntpdate"
    ]})
    cmds.update({"processes" : [
        "/bin/kill", "/usr/bin/killall", "/bin/nice", "/usr/bin/renice",
        "/usr/sbin/lsof", "/sbin/fuser"
    ]})
    cmds.update({"puppet" : [
        "/usr/bin/puppet"
    ]})
    cmds.update({"selinux" : [
        "/sbin/ausearch", "/usr/bin/audit2allow", "/usr/bin/audit2why",
        "/usr/sbin/semanage", "/usr/sbin/semodule", "/usr/sbin/setsebool",
        "/usr/sbin/setenforce", "/usr/sbin/load_policy"
    ]})
    cmds.update({"selinux-files" : [
        "/sbin/setfiles", "/sbin/fixfiles", "/usr/bin/chcon", "/sbin/restorecon"
    ]})
    cmds.update({"services" : [
        "/sbin/service", "/bin/systemctl", "/sbin/chkconfig"
    ]})
    cmds.update({"shells" : [
        "/bin/bash", "/bin/csh", "/bin/dash", "/bin/ksh", "/bin/mksh", "/bin/sh",
        "/bin/tcsh", "/bin/zsh", "/usr/bin/scl", "/usr/bin/screen", "/usr/bin/tmux"
    ]})
    cmds.update({"software" : [
        "/bin/rpm", "/usr/bin/up2date", "/usr/bin/yum",
        "/usr/sbin/yum-complete-transaction", "/usr/bin/yumdownloader",
        "/usr/bin/yum-config-manager", "/usr/bin/dnf", "/usr/bin/package-cleanup",
        "/usr/sbin/rpmconf", "/usr/bin/needs-restarting"
    ]})
    cmds.update({"storage-mount" : [
        "/bin/mount", "/bin/umount"
    ]})
    cmds.update({"storage-part" : [
        "/sbin/fdisk", "/sbin/sfdisk", "/sbin/parted", "/sbin/partprobe"
    ]})
    cmds.update({"storage-lvm" : [
        "/sbin/pvchange", "/sbin/pvcreate", "/sbin/pvdisplay", "/sbin/pvmove",
        "/sbin/pvremove", "/sbin/pvresize", "/sbin/pvs", "/sbin/pvscan",
        "/sbin/vgchange", "/sbin/vgcreate", "/sbin/vgdisplay", "/sbin/vgexport",
        "/sbin/vgextend", "/sbin/vgimport", "/sbin/vgreduce", "/sbin/vgremove",
        "/sbin/vgrename", "/sbin/vgs", "/sbin/vgscan", "/sbin/lvchange",
        "/sbin/lvcreate", "/sbin/lvdisplay", "/sbin/lvextend", "/sbin/lvreduce",
        "/sbin/lvremove", "/sbin/lvrename", "/sbin/lvresize", "/sbin/lvscan",
        "/sbin/lvs"
    ]})
    cmds.update({"storage-fs" : [
        "/sbin/mkfs", "/sbin/mkfs.ext3", "/sbin/mkfs.ext4", "/sbin/mkfs.xfs",
        "/sbin/resize2fs", "/sbin/tune2fs", "/sbin/xfs_growfs"
    ]})
    cmds.update({"storage-generic" : [
        "/usr/bin/rescan-scsi-bus.sh", "/usr/bin/scsi-rescan", "/sbin/multipath",
        "/sbin/badblocks", "/sbin/blkid"
    ]})
    cmds.update({"storage-analysis" : [
        "/usr/bin/iostat", "/usr/sbin/iotop"
    ]})
    cmds.update({"su" : [
        "/bin/su", "/sbin/sulogin", "/sbin/sushell", "/sbin/runuser"
    ]})
    cmds.update({"usermgmt" : [
        "/usr/sbin/useradd", "/usr/sbin/userdel", "/usr/sbin/usermod",
        "/usr/sbin/groupadd", "/usr/sbin/groupdel", "/usr/sbin/groupmod",
        "/usr/bin/id", "/usr/bin/gpasswd", "/usr/bin/chage", "/bin/passwd",
        "/usr/bin/passwd", "/usr/bin/chfn", "/usr/bin/chsh"
    ]})
    cmds.update({"monitoring" : [
        "/usr/bin/omd", "/usr/sbin/icinga2", "/usr/bin/icingacli"
    ]})
    cmds.update({"ipa-client" : [
        "/usr/sbin/ipa-client-install", "/usr/sbin/ipa-client-automount",
        "/usr/sbin/ipa-certupdate", "/usr/bin/ipa-getcert",
        "/usr/sbin/ipa-getkeytab", "/usr/sbin/ipa-join", "/usr/sbin/ipa-rmkeytab",
        "/usr/sbin/sss_cache"
    ]})
    cmds.update({"ipa-server" : [
        "/usr/bin/ipa", "/usr/sbin/ipa-ca-install",
        "/usr/sbin/ipa-csreplica-manage", "/usr/sbin/ipa-otptoken-import",
        "/usr/sbin/ipa-restore", "/usr/sbin/ipa-upgradeconfig",
        "/usr/sbin/ipa-adtrust-install", "/usr/sbin/ipactl",
        "/usr/sbin/ipa-kra-install", "/usr/sbin/ipa-replica-conncheck",
        "/usr/sbin/ipa-winsync-migrate", "/usr/sbin/ipa-advise",
        "/usr/sbin/ipa-dns-install", "/usr/sbin/ipa-ldap-updater",
        "/usr/sbin/ipa-replica-install", "/usr/sbin/ipa-server-certinstall",
        "/usr/sbin/ipa-backup", "/usr/sbin/ipa-managed-entries",
        "/usr/sbin/ipa-replica-manage", "/usr/sbin/ipa-server-install",
        "/usr/sbin/ipa-cacert-manage", "/usr/sbin/ipa-compat-manage",
        "/usr/sbin/ipa-nis-manage", "/usr/sbin/ipa-replica-prepare",
        "/usr/sbin/ipa-server-upgrade"
    ]})
    cmds.update({"rhn-server" : [
        "/usr/sbin/rhn-satellite", "/usr/sbin/spacewalk-service",
        "/usr/bin/rhn-satellite-activate", "/usr/bin/rhn-satellite-exporter",
        "/usr/bin/rhn-schema-version", "/usr/bin/spacewalk-cfg-get",
        "/usr/bin/spacewalk-common-channels", "/usr/bin/spacewalk-data-fsck",
        "/usr/bin/spacewalk-debug", "/usr/bin/spacewalk-export",
        "/usr/bin/spacewalk-export-channels", "/usr/bin/spacewalk-hostname-rename",
        "/usr/bin/spacewalk-remove-channel", "/usr/bin/spacewalk-report",
        "/usr/bin/spacewalk-repo-sync", "/usr/bin/spacewalk-schema-upgrade",
        "/usr/bin/spacewalk-selinux-enable", "/usr/bin/spacewalk-setup",
        "/usr/bin/spacewalk-setup-cobbler", "/usr/bin/spacewalk-setup-jabberd",
        "/usr/bin/spacewalk-setup-ipa-authentication"
    ]})
    cmds.update({"rhn-client" : [
        "/usr/sbin/rhn_check", "/usr/sbin/rhnreg_ks", "/usr/bin/rhn_register",
        "/usr/bin/rhn-actions-control", "/usr/bin/rhncfg-client",
        "/usr/sbin/rhn-channel", "/usr/sbin/rhn-profile-sync"
    ]})
    cmds.update({"katello-server" : [
        "/usr/bin/katello-service", "/usr/bin/katello-backup",
        "/usr/bin/katello-restore", "/usr/bin/katello-certs-sign",
        "/usr/bin/katello-certs-gen-rpm", "/usr/sbin/katello-certs-check",
        "/usr/sbin/katello-installer", "/usr/bin/katello-remove",
        "/usr/sbin/katello-selinux-disable", "/usr/sbin/katello-selinux-enable",
        "/usr/sbin/katello-selinux-relabel", "/usr/sbin/foreman-rake"
    ]})
    cmds.update({"katello-client" : [
        "/usr/bin/subscription-manager", "/usr/sbin/subscription-manager",
        "/usr/bin/katello-rhsm-consumer"
    ]})
    cmds.update({"mysql-server" : [
        "/usr/bin/mysqladmin", "/usr/bin/mysql_secure_installation",
        "/usr/bin/mysql_install_db"
    ]})
    cmds.update({"postfix" : [
        "/usr/bin/newaliases", "/usr/sbin/postalias", "/usr/sbin/postconf",
        "/usr/sbin/postfix", "/usr/sbin/postlock", "/usr/sbin/postmap",
        "/usr/sbin/postsuper"
    ]})
    cmds.update({"disk-quotas" : [
        "/sbin/edquota", "/sbin/quotaon", "/sbin/quotaoff", "/sbin/quotacheck",
        "/usr/bin/quota", "/usr/sbin/repquota", "/usr/sbin/setquota",
        "/usr/sbin/convertquota"
    ]})
    cmds.update({"nfs-server" : [
        "/usr/sbin/exportfs"
    ]})
    cmds.update({"nfs-client" : [
        "/sbin/mount.nfs", "/sbin/mount.nfs4", "/sbin/umount.nfs",
        "/sbin/umount.nfs4"
    ]})
    cmds.update({"power" : [
        "/usr/sbin/reboot", "/usr/sbin/poweroff", "/sbin/shutdown", "/usr/sbin/halt"
    ]})
    cmds.update({"bugs" : [
        "/usr/sbin/abrt-auto-reporting", "/usr/sbin/abrt-configuration",
        "/usr/bin/abrt-cli"
    ]})
    cmds.update({"hipster-docker" : [
        "/usr/bin/docker", "/usr/bin/docker-storage-setup"
    ]})
    cmds.update({"gitlab" : [
        "/usr/bin/gitlab-ci-multi-runner"
    ]})
    cmds.update({"fail2ban" : [
        "/usr/bin/fail2ban-client"
    ]})
    cmds.update({"system-who" : [
        "/usr/bin/w", "/usr/bin/who", "/usr/bin/lastlog"
    ]})
    cmds.update({"samba-server" : [
        "/usr/bin/smbpasswd", "/usr/bin/testparm", "/usr/bin/net",
        "/usr/bin/pdbedit", "/usr/bin/profiles", "/usr/bin/smbstatus",
        "/usr/bin/eventlogadm"
    ]})
    cmds.update({"samba-users" : [
        "/usr/bin/smbpasswd"
    ]})
    cmds.update({"ipmi-tools" : [
        "/usr/sbin/ipmi-sensors", "/usr/sbin/ipmi-sensors-config",
        "/usr/sbin/ipmi-sel", "/usr/sbin/ipmimonitoring",
        "/usr/bin/ipmitool"
    ]})

    #print definition version:
    if options.info_only:
        total = [len(v) for v in cmds.values()]
        counter = 0
        for i in total:
            counter += i
        LOGGER.info(
            "This definition has version %s and consists of %i command groups " \
            "and %i commands.", __version__, len(cmd_groups), counter
        )
        exit(0)

    #print definitions
    if options.list_only:
        for group in cmd_groups:
            LOGGER.info(
                "Group '%s' (%s) has the following commands:",
                group, cmd_groups[group]
            )
            LOGGER.info('  ' + ', '.join(cmds[group]))
        exit(0)

    #simulate/import definitions
    for grp in cmd_groups:
        run_cmd("ipa sudocmdgroup-add {0} --desc='{1}'".format(grp, cmd_groups[grp]))
        for cmdl in cmds[grp]:
            run_cmd(
                "ipa sudocmd-add '{0}' && ipa sudocmdgroup-add-member {1} "\
                "--sudocmds='{0}'".format(cmdl, grp)
            )



def parse_options(args=None):
    """
    This function defines and parses options
    """
    desc = "%prog is used to import a basic set of sudo commands and command " \
    "groups into an existing FreeIPA installation. " \
    "Checkout the GitHub page for updates: " \
    "https://github.com/stdevel/freeipa-utils"
    parser = OptionParser(description=desc, version="%prog version {0}".format(__version__))
    #define option groups
    gen_opts = OptionGroup(parser, "Generic options")
    parser.add_option_group(gen_opts)

    #GENERIC OPTIONS
    #-d / --debug
    gen_opts.add_option(
        "-d", "--debug", dest="debug", default=False, action="store_true",
        help="enable debugging outputs (default: no)"
    )
    #-n / --dry-run
    gen_opts.add_option(
        "-n", "--dry-run", dest="dry_run", default=False, action="store_true",
        help="only simulates what the script would do (default: no)"
    )
    #-i / --info-only
    gen_opts.add_option(
        "-i", "--info-only", dest="info_only", default=False, action="store_true",
        help="only print definition version and quits (default: no)"
    )
    #-l / --list-only
    gen_opts.add_option(
        "-l", "--list-only", dest="list_only", default=False, action="store_true",
        help="only prints definitions and quits (default: no)"
    )

    #parse and return options and arguments
    (options, args) = parser.parse_args(args)
    return (options, args)



if __name__ == "__main__":
    (options, args) = parse_options()
    #set logger level
    if options.debug:
        logging.basicConfig(level=logging.DEBUG)
        LOGGER.setLevel(logging.DEBUG)
    else:
        logging.basicConfig()
        LOGGER.setLevel(logging.INFO)

    LOGGER.debug("Options: %s", options)
    LOGGER.debug("Arguments: %s", args)

    import_definitions()
