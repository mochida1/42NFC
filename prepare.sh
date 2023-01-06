#!/bin/bash

mkdir /etc/ft_beep
date "+%W" > /etc/ft_beep/weeks.cfg
mkdir /var/log/ft_beep
touch /var/log/ft_beep/logfile.log

#crontab