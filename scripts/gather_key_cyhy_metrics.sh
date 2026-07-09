#!/usr/bin/env bash

# A script to gather key Cyber Hygiene metrics from various sources.  Output
# is a header row and a single line of comma-separated values.
#
# Usage:
# gather_key_cyhy_metrics.sh cyhy_db_fqdn cyhy_reporter_fqdn cyhy_mongodb_uri \
#   cyhy_mongodb_username cyhy_mongodb_password
#
# - cyhy_db_fqdn: The fully qualified domain name of the Cyber Hygiene database
# server (e.g. "database.example.gov")
# - cyhy_reporter_fqdn: The fully qualified domain name of the Cyber Hygiene
# reporter server (e.g. "reporter.example.gov")
# - cyhy_mongodb_uri: The MongoDB URI for the Cyber Hygiene database (e.g.
# "mongodb://localhost:27017/cyhy" or "localhost/cyhy")
# - cyhy_mongodb_username: The MongoDB username for the Cyber Hygiene database
# - cyhy_mongodb_password: The MongoDB password for the Cyber Hygiene database
#
# Requires:
# - SSH access to the Cyber Hygiene database and reporter servers
# - mongosh installed; see https://www.mongodb.com/docs/mongodb-shell/install/
# - A MongoDB user with read access to the Cyber Hygiene database

set -o nounset
set -o errexit
set -o pipefail

if [ $# -ne 5 ]; then
  cat << END_OF_LINE
Usage:  ${0##*/} cyhy_db_fqdn cyhy_reporter_fqdn cyhy_mongodb_uri cyhy_mongodb_username cyhy_mongodb_password

cyhy_db_fqdn: The fully qualified domain name of the Cyber Hygiene database server (e.g. "database.example.gov")
cyhy_reporter_fqdn: The fully qualified domain name of the Cyber Hygiene reporter server (e.g. "reporter.example.gov")
cyhy_mongodb_uri: The MongoDB URI for the Cyber Hygiene database (e.g. "mongodb://localhost:27017/cyhy" or "localhost/cyhy")
cyhy_mongodb_username: The MongoDB username for the Cyber Hygiene database
cyhy_mongodb_password: The MongoDB password for the Cyber Hygiene database

END_OF_LINE
  exit 1
fi

cyhy_db_fqdn=$1
cyhy_reporter_fqdn=$2
cyhy_mongodb_uri=$3
cyhy_mongodb_username=$4
cyhy_mongodb_password=$5

today=$(date +%Y-%m-%d)

# COMMANDER MAIN LOOP DURATION METRICS
# NOTE: These metrics are pulled from all existing (non-compressed) commander
# logs, not just the most recent one.
commander_log_pattern="/var/log/cyhy/commander.log*"
# We ignore shellcheck SC2029 ("Note that, unescaped, this expands on the client
# side") warnings here and elsewhere in this script because we do indeed want to
# expand the commands on the remote host, not locally.
# shellcheck disable=SC2029
if ssh "$cyhy_db_fqdn" "ls $commander_log_pattern > /dev/null 2>&1"; then
  # shellcheck disable=SC2029
  commander_duration_text=$(ssh "$cyhy_db_fqdn" "grep --only-matching --perl-regexp 'Last cycle took [\d.]* seconds' $commander_log_pattern")
  commander_duration_mean=$(echo "$commander_duration_text" | awk '{ total += $4; count++ } END { print total/count }')
  # Note: The macOS default "cut" command does not support the long flag names
  # for --delimeter and --fields.
  commander_duration_median=$(echo "$commander_duration_text" | cut -d' ' -f4 | sort --numeric-sort | awk '{ a[i++]=$1; } END { print a[int(i/2)]; }')
  commander_duration_max=$(echo "$commander_duration_text" | cut -d' ' -f4 | sort --numeric-sort | tail --lines 1)
else
  commander_duration_mean="N/A"
  commander_duration_median="N/A"
  commander_duration_max="N/A"
fi

# COMMANDER SCAN BACKLOG METRICS
scan_stages=("NETSCAN1" "NETSCAN2" "PORTSCAN" "VULNSCAN")

# Hosts with non-zero priority
declare -A nonzero_priority_waiting_count
for stage in "${scan_stages[@]}"; do
  nonzero_priority_waiting_count[$stage]=$(mongosh --quiet "$cyhy_mongodb_uri" --username "$cyhy_mongodb_username" --password "$cyhy_mongodb_password" --eval "db.hosts.countDocuments({'status': 'WAITING', 'priority': {\$ne: 0}, 'stage':'$stage'})")
done

# Hosts with zero priority
declare -A zero_priority_waiting_count
for stage in "${scan_stages[@]}"; do
  zero_priority_waiting_count[$stage]=$(mongosh --quiet "$cyhy_mongodb_uri" --username "$cyhy_mongodb_username" --password "$cyhy_mongodb_password" --eval "db.hosts.countDocuments({'status': 'WAITING', 'priority': 0, 'stage':'$stage'})")
done

# WEEKLY REPORTING METRICS
weekly_reporting_log="/var/cyhy/reports/output/snapshots_reports_scorecard_automation.log"
# shellcheck disable=SC2029
if ssh "$cyhy_reporter_fqdn" "[ -f $weekly_reporting_log ]"; then
  # shellcheck disable=SC2029
  weekly_reporting_text=$(ssh "$cyhy_reporter_fqdn" "tail --lines 10 $weekly_reporting_log")
  # Note: The macOS default "cut" command does not support the long flag names
  # for --delimeter and --fields.
  weekly_snapshots_duration_minutes=$(echo "$weekly_reporting_text" | grep 'Time to generate snapshots' | cut -d' ' -f9)
  weekly_reports_duration_minutes=$(echo "$weekly_reporting_text" | grep 'Time to generate reports' | cut -d' ' -f9)
  weekly_total_reporting_duration_minutes=$(echo "$weekly_reporting_text" | grep 'Total time' | cut -d' ' -f7)
else
  weekly_snapshots_duration_minutes="N/A"
  weekly_reports_duration_minutes="N/A"
  weekly_total_reporting_duration_minutes="N/A"
fi

# WEEKLY DATABASE ARCHIVE METRICS
weekly_cyhy_db_archive_duration_minutes=$(ssh "$cyhy_db_fqdn" "archive_log=\$(ls -rt /var/log/cyhy/archive.log-* 2>/dev/null | tail --lines 1); if [ -n \"\$archive_log\" ]; then grep 'successfully completed' \"\$archive_log\" | grep --only-matching '(.*)' | sed 's/[( minutes)]//g'; else echo 'N/A'; fi")

# DAILY CYHY FEED METRICS
daily_cyhy_feed_duration_minutes=$(ssh "$cyhy_db_fqdn" "if [ -f /var/log/cyhy/feeds.log ]; then grep 'Finished data extraction process' /var/log/cyhy/feeds.log | cut --delimiter ' ' --fields 2 | awk -F: '{print (\$1 * 60) + \$2}'; else echo 'N/A'; fi")

# OUTPUT RESULTS
echo "Date,Commander Main Loop Duration Mean (sec),Commander Main Loop Duration Median (sec),Commander Main Loop Duration Max (sec),NETSCAN1 hosts waiting (non-zero priority),NETSCAN2 hosts waiting (non-zero priority),PORTSCAN hosts waiting (non-zero priority),VULNSCAN hosts waiting (non-zero priority),NETSCAN1 hosts waiting (zero priority),NETSCAN2 hosts waiting (zero priority),PORTSCAN hosts waiting (zero priority),VULNSCAN hosts waiting (zero priority),Weekly Snapshots Duration (min),Weekly Reports Duration (min),Weekly Total Reporting Duration (min),Weekly CyHy DB Archive Duration (min),Daily CyHy Feed Duration (min)"
echo "$today,$commander_duration_mean,$commander_duration_median,$commander_duration_max,${nonzero_priority_waiting_count[NETSCAN1]},${nonzero_priority_waiting_count[NETSCAN2]},${nonzero_priority_waiting_count[PORTSCAN]},${nonzero_priority_waiting_count[VULNSCAN]},${zero_priority_waiting_count[NETSCAN1]},${zero_priority_waiting_count[NETSCAN2]},${zero_priority_waiting_count[PORTSCAN]},${zero_priority_waiting_count[VULNSCAN]},$weekly_snapshots_duration_minutes,$weekly_reports_duration_minutes,$weekly_total_reporting_duration_minutes,$weekly_cyhy_db_archive_duration_minutes,$daily_cyhy_feed_duration_minutes"

exit 0
