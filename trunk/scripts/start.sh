#!/bin/bash
# create logrotate config for srs log
SRS_LOG_FILE=`grep srs_log_file /usr/local/srs/conf/bruce.conf | awk  '{print $NF}' | cut -d ';' -f 1`
cat > /etc/logrotate.d/srs << EOF
$SRS_LOG_FILE {
    daily
    dateext
    dateformat -%Y-%m-%d.log
    compress
    delaycompress
    missingok
    notifempty
    rotate 30
    sharedscripts
    postrotate
        if [ -f /usr/local/srs/objs/srs.pid ]; then
            kill -USR1 \`cat /usr/local/srs/objs/srs.pid\`
        fi
    endscript
}
EOF

# start cron for logrotate
service cron start

# start srs
/usr/local/srs/objs/srs -c conf/bruce.conf
