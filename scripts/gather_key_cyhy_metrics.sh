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
# - mongosh installed
# - A MongoDB user with read access to the Cyber Hygiene database

set -o nounset
set -o errexit
set -o pipefail

if [ $# -eq 5 ]; then
  cyhy_db_fqdn=$1
  cyhy_reporter_fqdn=$2
  cyhy_mongodb_uri=$3
  cyhy_mongodb_username=$4
  cyhy_mongodb_password=$5
else
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

today=$(date +%Y-%m-%d)

# COMMANDER MAIN LOOP DURATION METRICS
# NOTE: These metrics are pulled from all existing (non-compressed) commander
# logs, not just the most recent one.
commander_duration_mean=$(ssh "$cyhy_db_fqdn" "grep --only-matching --perl-regexp 'Last cycle took .* seconds' /var/log/cyhy/commander.log* | awk '{ total += \$4; count++ } END { print total/count }'")
commander_duration_median=$(ssh "$cyhy_db_fqdn" "grep --only-matching --perl-regexp 'Last cycle took .* seconds' /var/log/cyhy/commander.log* | cut --delimiter ' ' --fields 4 | sort --numeric-sort | awk '{ a[i++]=\$1; } END { print a[int(i/2)]; }'")
commander_duration_max=$(ssh "$cyhy_db_fqdn" "grep --only-matching --perl-regexp 'Last cycle took .* seconds' /var/log/cyhy/commander.log* | cut --delimiter ' ' --fields 4 | sort --numeric-sort | tail --lines 1")

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
weekly_snapshots_duration_minutes=$(ssh "$cyhy_reporter_fqdn" "tail --lines 10 /var/cyhy/reports/output/snapshots_reports_scorecard_automation.log | grep 'Time to generate snapshots' | cut --delimiter ' ' --fields 9")
weekly_reports_duration_minutes=$(ssh "$cyhy_reporter_fqdn" "tail --lines 10 /var/cyhy/reports/output/snapshots_reports_scorecard_automation.log | grep 'Time to generate reports' | cut --delimiter ' ' --fields 9")
weekly_total_reporting_duration_minutes=$(ssh "$cyhy_reporter_fqdn" "tail --lines 10 /var/cyhy/reports/output/snapshots_reports_scorecard_automation.log | grep 'Total time' | cut --delimiter ' ' --fields 7")

# WEEKLY DATABASE ARCHIVE METRICS
weekly_cyhy_db_archive_duration_minutes=$(ssh "$cyhy_db_fqdn" "grep 'successfully completed' \$(ls -rt /var/log/cyhy/archive.log-* | tail --lines 1) | grep --only-matching '(.*)' | sed 's/[( minutes)]//g'")

# DAILY CYHY FEED METRICS
daily_cyhy_feed_duration_minutes=$(ssh "$cyhy_db_fqdn" "grep 'Finished data extraction process' /var/log/cyhy/feeds.log | cut --delimiter ' ' --fields 2 | awk -F: '{print (\$1 * 60) + \$2}'")

# OUTPUT RESULTS
echo "Date,Commander Main Loop Duration Mean (sec),Commander Main Loop Duration Median (sec),Commander Main Loop Duration Max (sec),NETSCAN1 hosts waiting (non-zero priority),NETSCAN2 hosts waiting (non-zero priority),PORTSCAN hosts waiting (non-zero priority),VULNSCAN hosts waiting (non-zero priority),NETSCAN1 hosts waiting (zero priority),NETSCAN2 hosts waiting (zero priority),PORTSCAN hosts waiting (zero priority),VULNSCAN hosts waiting (zero priority),Weekly Snapshots Duration (min),Weekly Reports Duration (min),Weekly Total Reporting Duration (min),Weekly CyHy DB Archive Duration (min),Daily CyHy Feed Duration (min)"
echo "$today,$commander_duration_mean,$commander_duration_median,$commander_duration_max,${nonzero_priority_waiting_count[NETSCAN1]},${nonzero_priority_waiting_count[NETSCAN2]},${nonzero_priority_waiting_count[PORTSCAN]},${nonzero_priority_waiting_count[VULNSCAN]},${zero_priority_waiting_count[NETSCAN1]},${zero_priority_waiting_count[NETSCAN2]},${zero_priority_waiting_count[PORTSCAN]},${zero_priority_waiting_count[VULNSCAN]},$weekly_snapshots_duration_minutes,$weekly_reports_duration_minutes,$weekly_total_reporting_duration_minutes,$weekly_cyhy_db_archive_duration_minutes,$daily_cyhy_feed_duration_minutes"

exit 0
