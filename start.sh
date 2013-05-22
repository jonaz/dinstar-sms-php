#!/bin/bash

php smsd.php >> /var/log/dinstar-smsd.log 2>&1 & 
PID=$!
echo $PID > pid
