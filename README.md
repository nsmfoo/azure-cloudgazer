
## About:

This script allows you to collect external IPs and URL's (webapp) from any Azure subscriptions that you have access to.

The information is saved to files, so you can use the data in other tools if you fancy.

But the script also allows you to scan the resources using the data collected

## Install:

Install azure cli (az)

pip3 install -r requirments.txt

## Usage:

azure_cloudgazer.py [-h] [-ip] [-url] [-scan]

## Examples:

### Collect all external IPs

python3 azure_cloudgazer.py -ip

### Crawls all collected URL and retrives title and error status codes

python3 azure_cloudgazer.py -url -scan

## FAQ:

Q: Why did you not use the python azure-cli module? Instead of wrapping az?!

A: Next question!

