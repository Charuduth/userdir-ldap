# crontab for the fallback replicate operation, should be handled by the daemon
@weekly root if [ -x /usr/bin/ud-replicate ]; then /usr/bin/ud-replicate; fi
