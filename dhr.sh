#!/bin/bash

# Domain Health Reporter (dhr)
# Script to check domain info, DNS records, hosting, SSL and redirects

# Parse command line arguments
dns_server=""
domain=""

# Loop through all command line arguments until none left
while [[ $# -gt 0 ]]; do
    case $1 in
        -ns)
            # If current argument is -ns, then next argument ($2) is the DNS server
            dns_server="@$2"
            # Skip both the -ns flag and the DNS server value (shift by 2 positions)
            shift 2
            ;;
        *)
            # Any other argument is treated as the domain name
            domain="$1"
            # Move to next argument (shift by 1 position)
            shift
            ;;
    esac
done

# Check if domain argument provided
if [ -z "$domain" ]; then
    echo "Usage: $(basename $0) [-ns dns_server] <domain>"
    echo "Example: $(basename $0) example.com"
    echo "Example: $(basename $0) -ns 1.1.1.1 example.com"
    echo "Example: $(basename $0) -ns 8.8.8.8 https://www.example.com/path"
    exit 1
fi

echo
# Check if dns_server variable is empty (user didn't specify -ns option)
if [ -z "$dns_server" ]; then
    # No custom DNS server specified - get system default DNS info
    dns_info=`dig | grep SERVER | cut -d " " -f 2,3 | cut -d "#" -f 1`
    printf "$(tput setaf 4)Lookups using DNS $dns_info$(tput sgr0)"
else
    # Custom DNS server was specified - display it (strip @ symbol for clean output)
    # ${dns_server#@} removes the "@" prefix we added earlier
    printf "$(tput setaf 4)Lookups using DNS ${dns_server#@}$(tput sgr0)"
fi
echo

# Extract clean domain from various input formats
domain=`echo $domain | awk -F "//" '{print $NF}' | awk -F "www." '{print $NF}' | awk -F "/" '{print $1}'`
echo -e "Domain : $(tput setaf 1)$domain$(tput sgr0) - finding IP & Ownership..."
echo

# Get IP and organization info for root domain and www subdomain
echo "$(tput setaf 6)HOST INFORMATION:$(tput sgr0)"
printf "%-36s %-36s %s\n" "HOST" "IP/CNAME" "ORGANIZATION"

# Root domain
NON_WWW_IP=`dig $dns_server +short $domain | head -n 1`
if [[ $NON_WWW_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    # It's an IP address
    NON_WWW_ORG=`echo $NON_WWW_IP | xargs whois | grep 'OrgName\|org-name\|descr' | sort -r | head -n 1 | awk '{print $2,$3,$4,$5}'`
    printf "%-36s $(tput setaf 2)%-36s$(tput sgr0) $(tput setaf 5)%s$(tput sgr0)\n" "$domain" "$NON_WWW_IP" "$NON_WWW_ORG"
else
    # It's a CNAME or other record
    printf "%-36s $(tput setaf 3)%-36s$(tput sgr0) $(tput setaf 3)%s$(tput sgr0)\n" "$domain" "$NON_WWW_IP" "(CNAME)"
fi

# WWW subdomain  
WWW_RESULT=`dig $dns_server +short www.$domain | head -n 1`
if [[ $WWW_RESULT =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    # It's an IP address
    WWW_ORG=`echo $WWW_RESULT | xargs whois | grep 'OrgName\|org-name\|descr' | sort -r | head -n 1 | awk '{print $2,$3,$4,$5}'`
    printf "%-36s $(tput setaf 2)%-36s$(tput sgr0) $(tput setaf 5)%s$(tput sgr0)\n" "www.$domain" "$WWW_RESULT" "$WWW_ORG"
else
    # It's a CNAME - show the CNAME and follow the chain
    printf "%-36s $(tput setaf 3)%-36s$(tput sgr0) $(tput setaf 3)%s$(tput sgr0)\n" "www.$domain" "$WWW_RESULT" "(CNAME)"
    
    # Follow the CNAME chain until we get an IP address
    current_host="$WWW_RESULT"
    while [[ ! $current_host =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && [[ -n "$current_host" ]]; do
        next_result=`dig $dns_server +short $current_host | head -n 1`
        if [[ $next_result =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            # Found the final IP address
            FINAL_ORG=`echo $next_result | xargs whois | grep 'OrgName\|org-name\|descr' | sort -r | head -n 1 | awk '{print $2,$3,$4,$5}'`
            printf "%-36s $(tput setaf 2)%-36s$(tput sgr0) $(tput setaf 5)%s$(tput sgr0)\n" "  -> $current_host" "$next_result" "$FINAL_ORG"
            break
        elif [[ -n "$next_result" ]] && [[ "$next_result" != "$current_host" ]]; then
            # Another CNAME in the chain
            printf "%-36s $(tput setaf 3)%-36s$(tput sgr0) $(tput setaf 3)%s$(tput sgr0)\n" "  -> $current_host" "$next_result" "(CNAME)"
            current_host="$next_result"
        else
            # Dead end or loop detected
            printf "%-36s $(tput setaf 1)%-36s$(tput sgr0) $(tput setaf 1)%s$(tput sgr0)\n" "  -> $current_host" "No A record found" "(Dead end)"
            break
        fi
    done
fi
echo

# HTTP/HTTPS redirect testing
echo "$(tput setaf 6)HTTP/HTTPS REDIRECT RESULTS:$(tput sgr0)"
printf "%-30s %-5s %-36s %s\n" "REQUEST URL" "CODE" "REDIRECT URL" "TIME (s)"

# Collect curl results in temp file
curl -sI http://$domain -w '%{time_total}|%{url_effective}|%{response_code}|%{redirect_url}\n' -o /dev/null > /tmp/301.txt
curl -sI http://www.$domain -w '%{time_total}|%{url_effective}|%{response_code}|%{redirect_url}\n' -o /dev/null >> /tmp/301.txt
curl -sI https://$domain -w '%{time_total}|%{url_effective}|%{response_code}|%{redirect_url}\n' -o /dev/null >> /tmp/301.txt
curl -sI https://www.$domain -w '%{time_total}|%{url_effective}|%{response_code}|%{redirect_url}\n' -o /dev/null >> /tmp/301.txt

# Format the results in 4 columns
awk -F'|' '{printf "%-30s %-5s %-36s %s\n", $2, $3, $4, $1}' /tmp/301.txt
echo
rm /tmp/301.txt

# A records for root domain
echo "$(tput setaf 6)A RECORDS (root domain):$(tput sgr0)"
dig $dns_server $domain | grep IN | grep -v ";" | grep -v NS | sort -k 5n,5 | awk '{printf "%-36s %-36s %s\n", $1, $2" "$3" "$4, $5}'
echo

# A records for www subdomain
echo "$(tput setaf 6)A RECORDS (www subdomain):$(tput sgr0)"
dig $dns_server www.$domain | grep IN | grep -v ";" | grep -v NS | awk '{printf "%-36s %-36s %s\n", $1, $2" "$3" "$4, $5}'
echo

# MX records
echo "$(tput setaf 6)MX RECORDS:$(tput sgr0)"
dig $dns_server MX $domain | grep IN | grep -v ";" | grep MX | sort -k 5n,5 | awk '{printf "%-36s %-36s %s %s\n", $1, $2" "$3" "$4, $5, $6}'
echo
echo "$(tput setaf 6)MX SERVER IP ADDRESSES:$(tput sgr0)"
dig $dns_server MX $domain | grep IN | grep -v ";" | grep -v NS | sort -k 5n,5 | cuts -1 | xargs dig $dns_server | grep IN | grep -v ";" | grep -v NS | grep -v SOA | awk '{printf "%-36s %-36s %s\n", $1, $2" "$3" "$4, $5}'
echo

# NS records
echo "$(tput setaf 6)NS RECORDS:$(tput sgr0)"
dig $dns_server NS $domain | grep IN | grep -v ";" | sort -k 5n,5 | awk '{printf "%-36s %-36s %s\n", $1, $2" "$3" "$4, $5}'
echo

# TXT records
echo "$(tput setaf 6)TXT RECORDS:$(tput sgr0)"
dig $dns_server TXT $domain | grep IN | grep -v ";" | grep -v NS | grep -v SOA | awk '{printf "%-36s %-36s ", $1, $2" "$3" "$4; for(i=5;i<=NF;i++) printf "%s ", $i; printf "\n"}'
echo

# DMARC record
echo "$(tput setaf 6)DMARC RECORD:$(tput sgr0)"
dig $dns_server TXT _dmarc.$domain | grep IN | grep \"v | awk '{printf "%-36s %-36s ", $1, $2" "$3" "$4; for(i=5;i<=NF;i++) printf "%s ", $i; printf "\n"}'
echo

# DKIM records (common selectors)
echo "$(tput setaf 6)DKIM RECORDS:$(tput sgr0)"
dig $dns_server TXT bozmail._domainkey.$domain | grep IN | grep \"v | awk '{printf "%-36s %-36s ", $1, $2" "$3" "$4; for(i=5;i<=NF;i++) printf "%s ", $i; printf "\n"}'
dig $dns_server TXT boz._domainkey.$domain | grep IN | grep \"v | awk '{printf "%-36s %-36s ", $1, $2" "$3" "$4; for(i=5;i<=NF;i++) printf "%s ", $i; printf "\n"}'
echo

# Registrar information
echo "$(tput setaf 6)REGISTRAR INFORMATION:$(tput sgr0)"
whois $domain | grep -m 1 -A1 "Registrar:" | grep -v "Sponsoring" | grep -v "IANA ID" | sed -e 's/^[ \t]*//' 
echo

# Domain expiration
echo "$(tput setaf 6)DOMAIN EXPIRATION:$(tput sgr0)"
whois $domain | grep Expir | grep -v "Registrar Registration Expiration Date:" | sed -e 's/^[ \t]*//'
echo
