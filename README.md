# 42NFC


# Known issues
* if after 1 whole year, in the same week of the year as the user last left (after exactly 53 weeks), the user enters again, there will be a discrepancy in this year's weekly hours.
* there's still no redundancy on the card. Removing it while the operation is in process will likely corrupt it's data.
* if someone can somehow make mora than 1000 weekly hours, it'll bug the user log. While it will still show the correct time in seconds, the hours filed will be set to 000