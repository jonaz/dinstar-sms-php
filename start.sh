#!/bin/bash

php smsd.php >> /var/log/dinstar-smsd.log & 
PID=$!
echo $PID > pid
