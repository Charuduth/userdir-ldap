# crontab for the replicate operation, 15 min cycle.
10,25,40,55 * * * * root if [ -x /usr/bin/ud-replicate ]; then /usr/bin/ud-replicate; fi
