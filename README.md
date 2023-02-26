# 42NFC

# Basic instructions and things to know
* google "systemctl set-default multi-user.target"
* to run a boot: /etc/init.d/w
* binaries are inside /usr/sbin/
* to access via ssh, first present a bocal card. It'll exit the nfc service
* logs are in /var/bin/ft_beep
* template file for writer is /etc/ft_beep/template_mifare1k
* weeks file is /etc/ft_beep/weeks.cfg
* endpoints are in /etc/ft_beep/enpoints.cfg
* to connect via wi-fi use **nmtui**
* service is initialized by systemctl

# todo
* implement support for mifare ultralight
* add support for broker (zeromq/vanilla socket)
* remove interdependencies from source files
* ...maybe report currently weekly time?

# Known issues
* bocal card does not beep. Kinda hard to know if it worked.
* changing ssh port from 22 ends up in unexpected behaviour.
* if after 1 whole year, in the same week of the year as the user last left (after exactly 53 weeks), the user enters again, there will be a discrepancy in this year's weekly hours.
* there's still no redundancy on the card. Removing it while the operation is in process will likely corrupt it's data.
* if someone can somehow make mora than 1000 weekly hours, it'll bug the user log. While it will still show the correct time in seconds, the hours filed will be set to 000