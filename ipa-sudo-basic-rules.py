#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ipa-sudo-basic-rules.py - a script for importing
# basic sudo command and command group definitions
#
# 2016 By Christian Stankowic
# <info at stankowic hyphen development dot net>
# https://github.com/stdevel
#

from optparse import OptionParser, OptionGroup
import logging
import subprocess



#set logger and version
LOGGER = logging.getLogger('ipa-sudo-basic-rules.py')
vers = "0.1.6"



def run_cmd(cmd=""):
	#run the command, it's tricky!
	if options.dryRun:
		#print what would be done
		LOGGER.info("I'd like to execute the following command: {0}".format(cmd))
	else:
		#execute command
		output = subprocess.Popen("LANG=C {0}".format(cmd), shell=True, stdout=subprocess.PIPE).stdout.read()
		LOGGER.debug("Output of '{0}' => '{1}".format(cmd, output))



def import_definitions():
	#import _all_ the sudo definitions!
	cmds={}
	cmd_groups={"delegating" : "Delegating user access",
		"drivers" : "Managing kernel drivers",
		"editors" : "Editing files",
		"filemgmt" : "Managing files",
		"fileperm" : "Managing file permissions",
		"fileperm-acl" : "Managing ACLs",
		"locate" : "Managing locate database",
		"networking" : "Managing network connections",
		"firewall" : "Managing firewall configuration",
		"time" : "Managing time/date configuration",
		"processes" : "Managing processes",
		"selinux" : "Managing SELinux",
		"services" : "Managing system services",
		"shells" : "Shells and other bad software",
		"software" : "Managing software",
		"storage" : "Managing storage resources",
		"su" : "Switching user context",
		"usermgmt" : "Managing users and groups",
		"monitoring" : "Managing monitoring",
		"ipa-client" : "Managing IPA clients",
		"ipa-server" : "Managing IPA servers",
		"rhn-server" : "Managing Red Hat Satellite",
		"rhn-client" : "Managing Enterprise Linux clients",
		"mysql-server" : "Managing MySQL servers",
		"postfix" : "Managing Postfix servers",
		"disk-quotas" : "Managing disk quotas",
		"nfs-server" : "Managing NFS servers",
		"nfs-client" : "Managing NFS mounts"
	}
	
	#command defintions
	cmds.update({"delegating" : ["/usr/sbin/visudo"]})
	cmds.update({"drivers" : ["/sbin/modprobe", "/sbin/rmmod"]})
	cmds.update({"editors" : ["/bin/rvi", "/bin/rvim", "/bin/rview"]})
	cmds.update({"filemgmt" : ["/bin/cp", "/bin/mv", "/usr/bin/rsync", "/bin/rm", "/bin/ls", "/bin/echo", "/bin/cat", "/usr/bin/less", "/bin/more", "/usr/bin/tail", "/bin/df", "/bin/du", "/bin/mkdir", "/bin/rmdir"]})
	cmds.update({"fileperm" : ["/bin/chgrp", "/bin/chmod", "/bin/chown"]})
	cmds.update({"fileperm-acl" : ["/usr/bin/chacl", "/usr/bin/gefacl", "/usr/bin/setfacl"]})
	cmds.update({"locate" : ["/usr/bin/updatedb"]})
	cmds.update({"networking" : ["/sbin/ifconfig", "/sbin/mii-tool", "/usr/bin/net", "/sbin/ifdown", "/sbin/ifup", "/bin/netstat"]})
	cmds.update({"firewall" : ["/sbin/iptables", "/usr/sbin/lokkit", "/usr/bin/system-config-firewall-tui"]})
	cmds.update({"time" : ["/sbin/hwclock", "/bin/timedatectl", "/usr/sbin/ntpdate"]})
	cmds.update({"processes" : ["/bin/kill", "/usr/bin/killall", "/bin/nice"]})
	cmds.update({"selinux" : ["/sbin/ausearch", "/usr/bin/audit2allow", "/usr/bin/audit2why", "/usr/sbin/semanage", "/usr/sbin/semodule", "/usr/sbin/setsebool", "/usr/sbin/setenforce"]})
	cmds.update({"services" : ["/sbin/service", "/bin/systemctl", "/sbin/chkconfig"]})
	cmds.update({"shells" : ["/bin/bash", "/bin/csh", "/bin/dash", "/bin/ksh", "/bin/mksh", "/bin/sh", "/bin/tcsh", "/bin/zsh", "/usr/bin/scl", "/usr/bin/screen", "/usr/bin/tmux", "/bin/vi", "/bin/vim", "/bin/view", "/bin/find"]})
	cmds.update({"software" : ["/bin/rpm", "/usr/bin/up2date", "/usr/bin/yum", "/usr/bin/dnf", "/usr/bin/package-cleanup", "/usr/sbin/rpmconf"]})
	cmds.update({"storage" : ["/bin/mount", "/bin/umount", "/sbin/fdisk", "/sbin/sfdisk", "/sbin/parted", "/sbin/partprobe", "/sbin/mkfs", "/sbin/mkfs.ext3", "/sbin/mkfs.ext4", "/sbin/mkfs.xfs", "/sbin/resize2fs", "/sbin/tune2fs", "/sbin/xfs_growfs", "/sbin/pvchange", "/sbin/pvcreate", "/sbin/pvdisplay", "/sbin/pvmove", "/sbin/pvremove", "/sbin/pvresize", "/sbin/pvs", "/sbin/pvscan", "/sbin/vgchange", "/sbin/vgcreate", "/sbin/vgdisplay", "/sbin/vgexport", "/sbin/vgextend", "/sbin/vgimport", "/sbin/vgreduce", "/sbin/vgremove", "/sbin/vgrename", "/sbin/vgs", "/sbin/vgscan", "/sbin/lvchange", "/sbin/lvcreate", "/sbin/lvdisplay", "/sbin/lvextend", "/sbin/lvreduce", "/sbin/lvremove", "/sbin/lvrename", "/sbin/lvresize", "/sbin/lvscan", "/sbin/lvs", "/usr/bin/rescan-scsi-bus.sh", "/usr/bin/scsi-rescan", "/sbin/multipath", "/sbin/badblocks"]})
	cmds.update({"su" : ["/bin/su", "/sbin/sulogin", "/sbin/sushell", "/sbin/runuser"]})
	cmds.update({"usermgmt" : ["/usr/sbin/useradd", "/usr/sbin/userdel", "/usr/sbin/usermod", "/usr/sbin/groupadd", "/usr/sbin/groupdel", "/usr/sbin/groupmod", "/usr/bin/id", "/usr/bin/gpasswd", "/usr/bin/chage", "/bin/passwd", "/usr/bin/passwd", "/usr/bin/chfn", "/usr/bin/chsh", "/usr/sbin/vigr", "/usr/sbin/vipw"]})
	cmds.update({"monitoring" : ["/usr/bin/omd", "/usr/sbin/icinga2", "/usr/bin/icingacli"]})
	cmds.update({"ipa-client" : ["/usr/sbin/ipa-client-install", "/usr/sbin/ipa-client-automount", "/usr/sbin/ipa-certupdate", "/usr/bin/ipa-getcert", "/usr/sbin/ipa-getkeytab", "/usr/sbin/ipa-join", "/usr/sbin/ipa-rmkeytab"]})
	cmds.update({"ipa-server" : ["/usr/bin/ipa", "/usr/sbin/ipa-ca-install", "/usr/sbin/ipa-csreplica-manage", "/usr/sbin/ipa-otptoken-import", "/usr/sbin/ipa-restore", "/usr/sbin/ipa-upgradeconfig", "/usr/sbin/ipa-adtrust-install", "/usr/sbin/ipactl", "/usr/sbin/ipa-kra-install", "/usr/sbin/ipa-replica-conncheck", "/usr/sbin/ipa-winsync-migrate", "/usr/sbin/ipa-advise", "/usr/sbin/ipa-dns-install", "/usr/sbin/ipa-ldap-updater", "/usr/sbin/ipa-replica-install", "/usr/sbin/ipa-server-certinstall", "/usr/sbin/ipa-backup", "/usr/sbin/ipa-managed-entries", "/usr/sbin/ipa-replica-manage", "/usr/sbin/ipa-server-install", "/usr/sbin/ipa-cacert-manage", "/usr/sbin/ipa-compat-manage", "/usr/sbin/ipa-nis-manage", "/usr/sbin/ipa-replica-prepare", "/usr/sbin/ipa-server-upgrade"]})
	cmds.update({"rhn-server" : ["/usr/sbin/rhn-satellite", "/usr/sbin/spacewalk-service", "/usr/bin/rhn-satellite-activate", "/usr/bin/rhn-satellite-exporter", "/usr/bin/rhn-schema-version", "/usr/bin/spacewalk-cfg-get", "/usr/bin/spacewalk-common-channels", "/usr/bin/spacewalk-data-fsck", "/usr/bin/spacewalk-debug", "/usr/bin/spacewalk-export", "/usr/bin/spacewalk-export-channels", "/usr/bin/spacewalk-hostname-rename", "/usr/bin/spacewalk-remove-channel", "/usr/bin/spacewalk-report", "/usr/bin/spacewalk-repo-sync", "/usr/bin/spacewalk-schema-upgrade", "/usr/bin/spacewalk-selinux-enable", "/usr/bin/spacewalk-setup", "/usr/bin/spacewalk-setup-cobbler", "/usr/bin/spacewalk-setup-ipa-authentication", "/usr/bin/spacewalk-setup-jabberd"]})
	cmds.update({"rhn-client" : ["/usr/sbin/rhn_check", "/usr/sbin/rhnreg_ks", "/usr/bin/rhn_register", "/usr/bin/rhn-actions-control", "/usr/bin/rhncfg-client", "/usr/sbin/rhn-channel", "/usr/sbin/rhn-profile-sync", "/usr/bin/subscription-manager"]})
	cmds.update({"mysql-server" : ["/usr/bin/mysqladmin", "/usr/bin/mysql_secure_installation", "/usr/bin/mysql_install_db"]})
	cmds.update({"postfix" : ["/usr/bin/newaliases", "/usr/sbin/postalias", "/usr/sbin/postconf", "/usr/sbin/postfix", "/usr/sbin/postlock", "/usr/sbin/postmap", "/usr/sbin/postsuper"]})
	cmds.update({"disk-quotas" : ["/sbin/edquota", "/sbin/quotaon", "/sbin/quotaoff", "/sbin/quotacheck", "/usr/bin/quota", "/usr/sbin/repquota", "/usr/sbin/setquota", "/usr/sbin/convertquota"]})
	cmds.update({"nfs-server" : ["/usr/sbin/exportfs"]})
	cmds.update({"nfs-client" : ["/sbin/mount.nfs", "/sbin/mount.nfs4", "/sbin/umount.nfs", "/sbin/umount.nfs4"]})
	
	#print definition version:
	if options.infoOnly == True:
		total = [len(v) for v in cmds.values()]
		counter=0
		for i in total: counter += i
		LOGGER.info("This definition has version {0} and consists of {1} command groups and {2} commands.".format(vers, len(cmd_groups), counter))
		exit(0)
	
	#print definitions
	if options.listOnly == True:
		for group in cmd_groups:
			LOGGER.info("Group '{0}' ({1}) has the following commands:".format(group, cmd_groups[group]))
			LOGGER.info('  ' + ', '.join(cmds[group]))
		exit(0)
	
	#simulate/import definitions
	for grp in cmd_groups:
		run_cmd("ipa sudocmdgroup-add {0} --desc='{1}'".format(grp, cmd_groups[grp]))
		for cmdl in cmds[grp]:
			run_cmd("ipa sudocmd-add '{0}' && ipa sudocmdgroup-add-member {1} --sudocmds='{0}'".format(cmdl, grp))



def parse_options(args=None):
	#define usage, description, version and load parser
	desc='''%prog is used to import a basic set of sudo commands and command groups into an existing FreeIPA installation.

Checkout the GitHub page for updates: https://github.com/stdevel/freeipa-utils'''
	parser = OptionParser(description=desc, version="%prog version {0}".format(vers))
	#define option groups
	genOpts = OptionGroup(parser, "Generic Options")
	parser.add_option_group(genOpts)
	
	#GENERIC OPTIONS
	#-d / --debug
	genOpts.add_option("-d", "--debug", dest="debug", default=False, action="store_true", help="enable debugging outputs (default: no)")
	#-n / --dry-run
	genOpts.add_option("-n", "--dry-run", dest="dryRun", default=False, action="store_true", help="only simulates what the script would do (default: no)")
	#-i / --info-only
	genOpts.add_option("-i", "--info-only", dest="infoOnly", default=False, action="store_true", help="only print definition version and quits (default: no)")
	#-l / --list-only
	genOpts.add_option("-l", "--list-only", dest="listOnly", default=False, action="store_true", help="only prints definitions and quits (default: no)")
	
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
	
	LOGGER.debug("Options: {0}".format(options))
	LOGGER.debug("Arguments: {0}".format(args))
	
	import_definitions()
