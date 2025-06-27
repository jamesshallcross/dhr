#!/bin/bash

# Domain Health Reporter (dhr)
# Script to check domain info, DNS records, hosting, SSL and redirects

# Check if domain argument provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <domain>"
    echo "Example: $0 example.com"
    echo "Example: $0 https://www.example.com/path"
    exit 1
fi

echo
dns_server=`dig | grep SERVER | cut -d " " -f 2,3 | cut -d "#" -f 1`
printf "Lookups using DNS $dns_server"
echo

# Extract clean domain from various input formats
domain=`echo $1 | awk -F "//" '{print $NF}' | awk -F "www." '{print $NF}' | awk -F "/" '{print $1}'`
echo -e "Domain : $(tput setaf 1)$domain$(tput sgr0) - finding IP & Ownership..."
echo

# Get IP and organization info for root domain
NON_WWW_IP=`dig +short $domain | head -n 1 | xargs | sed -e 's/ /, /g'`
NON_WWW_IP_ORG=`dig +short $domain | head -n 1 | xargs whois | grep 'OrgName\|org-name\|descr' | sort -r | head -n 1 | awk '{print $2,$3,$4,$5}'`
echo -e "IP for root\t: ${NON_WWW_IP}\t: ${NON_WWW_IP_ORG}"

# Get IP and organization info for www subdomain
WWW_IP=`dig +short www.$domain | head -n 1 | xargs | sed -e 's/ /, /g'`
WWW_IP_ORG=`dig +short www.$domain | head -n 1 | xargs whois | grep 'OrgName\|org-name\|descr' | sort -r | head -n 1 | awk '{print $2,$3,$4,$5}'`
echo -e "IP for www\t: ${WWW_IP}\t: ${WWW_IP_ORG}"
echo

# A records for root domain
dig $domain | grep IN | grep -v ";" | grep -v NS | sort -k 5n,5
echo

# A records for www subdomain
dig www.$domain | grep IN | grep -v ";" | grep -v NS
echo

# MX records
dig MX $domain | grep IN | grep -v ";" | grep MX | sort -k 5n,5
dig MX $domain | grep IN | grep -v ";" | grep -v NS | sort -k 5n,5 | cuts -1 | xargs dig | grep IN | grep -v ";" | grep -v NS | grep -v SOA
echo

# NS records
dig NS $domain | grep IN | grep -v ";" | sort -k 5n,5
echo

# TXT records
dig TXT $domain | grep IN | grep -v ";" | grep -v NS | grep -v SOA
echo

# DMARC record
dig TXT _dmarc.$domain | grep IN | grep \"v
echo

# DKIM records (common selectors)
dig TXT bozmail._domainkey.$domain | grep IN | grep \"v
dig TXT boz._domainkey.$domain | grep IN | grep \"v
echo

# Registrar information
whois $domain | grep -m 1 -A1 "Registrar:" | grep -v "Sponsoring" | grep -v "IANA ID" | sed -e 's/^[ \t]*//' 
echo

# Domain expiration
whois $domain | grep Expir | grep -v "Registrar Registration Expiration Date:" | sed -e 's/^[ \t]*//'
echo

# HTTP/HTTPS redirect testing
echo -e "Checking HTTP/HTTPS + root/www for redirects/errors..."
echo
printf 'TIME (s)|REQUEST URL|CODE|REDIRECT URL\n' > /tmp/301.txt
curl -sI http://$domain -w '%{time_total}|%{url_effective}|%{response_code}|%{redirect_url}\n' -o /dev/null >> /tmp/301.txt
curl -sI http://www.$domain -w '%{time_total}|%{url_effective}|%{response_code}|%{redirect_url}\n' -o /dev/null >> /tmp/301.txt
curl -sI https://$domain -w '%{time_total}|%{url_effective}|%{response_code}|%{redirect_url}\n' -o /dev/null >> /tmp/301.txt
curl -sI https://www.$domain -w '%{time_total}|%{url_effective}|%{response_code}|%{redirect_url}\n' -o /dev/null >> /tmp/301.txt
cat /tmp/301.txt | column -t -s '|'
echo
rm /tmp/301.txt
