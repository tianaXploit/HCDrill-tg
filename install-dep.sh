#!/bin/sh
echo "Make sure to have Node.JS installed and added to your PATH variables."
sleep 5
npm update --save
node HCDrill.js -bt 1884439266:AAEvRon1PiWCK0cagWKkFq89AZzaUYtsP8c -d storage
exit
