#
# Regular cron jobs for the dansguardian package
#
0 4	* * *	root	[ -x /usr/bin/dansguardian_maintenance ] && /usr/bin/dansguardian_maintenance
