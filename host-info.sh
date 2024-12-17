#!/bin/bash
# host-info.sh - a simple script to look up where an IP address is located
# 2016-12-11: Peter Möller
# 2019-06-26: Changed to host-info.sh and gives vastly more info on a server
# 2024-12-17: Major rewrite (reshuffling) plus cypher information


GeoLookupURL="ipinfo.io"
CountriesFile="Countries.txt"
CDN_file="cdn.txt"
CmdError=false
ShowCertificate=false
ShowServer=false
# (Colors can be found at http://en.wikipedia.org/wiki/ANSI_escape_code, http://graphcomp.com/info/specs/ansi_col.html and other sites)
Reset="\e[0m"
ESC="\e["
RES="0"
BoldFace="1"
ItalicFace="3"
UnderlineFace="4"
SlowBlink="5"
BlackBack="40"
RedBack="41"
YellowBack="43"
BlueBack="44"
WhiteBack="47"
BlackFont="30"
RedFont="31"
GreenFont="32"
YellowFont="33"
BlueFont="34"
CyanFont="36"
WhiteFont="37"
# Reset all colors
BGColor="$RES"
Face="$RES"
FontColor="$RES"
NewLine=$'\n'
# F1 & F2 is the format string for printf
F1="%-20s"
F2="%-60s"
Color=""


help() {
    echo "Usage: $(basename $0) URL, DNS-name or IP-address"
    echo "Enter a URL, a DNS-name or an IP-address to get it resolved"
    echo "-c will show certificate information"
    echo "-s will show information about the server"
    echo
    exit 0
}


# Read the parameters:
while getopts ":hcs" opt
do
    case $opt in
        c )  ShowCertificate=true;;
        s )  ShowServer=true;;
        \?|h ) help;;
    esac
done

# Shift the positional parameters
shift $((OPTIND - 1))

# Access the remaining arguments
Input="$@"       # Input='https://www.youtube.com/watch?v=98eabjjAEz8'

# Ugly cludge: older versions of OpenSSL (at least 0.9.8) can not download certs. 
# Just don't do these tests if we have that version of OpenSSL
OpenSSLToOld="$(openssl version | egrep -o "0.9.8")"   # OpenSSLToOld='0.9.8'



#==============================================================================================================
#   _____ _____ ___  ______ _____    ___________   ______ _   _ _   _ _____ _____ _____ _____ _   _  _____
#  /  ___|_   _/ _ \ | ___ \_   _|  |  _  |  ___|  |  ___| | | | \ | /  __ \_   _|_   _|  _  | \ | |/  ___|
#  \ `--.  | |/ /_\ \| |_/ / | |    | | | | |_     | |_  | | | |  \| | /  \/ | |   | | | | | |  \| |\ `--.
#   `--. \ | ||  _  ||    /  | |    | | | |  _|    |  _| | | | | . ` | |     | |   | | | | | | . ` | `--. \
#  /\__/ / | || | | || |\ \  | |    \ \_/ / |      | |   | |_| | |\  | \__/\ | |  _| |_\ \_/ / |\  |/\__/ /
#  \____/  \_/\_| |_/\_| \_| \_/     \___/\_|      \_|    \___/\_| \_/\____/ \_/  \___/ \___/\_| \_/\____/
#


# Check if we have 'dig' and 'curl'. Exit if they are not available
check_stop() {
    if ! which dig >&/dev/null; then
        CmdError=true
        echo "CRITICAL ERROR: command \"dig\" not found on \$PATH!"
    fi
    if ! which curl >&/dev/null; then
        CmdError=true
        echo "CRITICAL ERROR: command \"curl\" not found on \$PATH!"
    fi
    if [ -z "$Input" ]; then
        CmdError=true
        echo "NO INPUT!!"
    fi
    if $CmdError; then
        echo "Script will now exit."
        exit 1
    fi
}


# Basic setup:
# - create tempdir
# - find out where the script resides
# - get the input (the host to check)
setup_things() {
    # Use the correct time format for Darwin and Linux
    OS="$(uname -s)"
    if [ "$OS" = "Darwin" ]; then
        MTime1d="-mtime -1d"
        PingWait=5000
    elif [ "$OS" = "Linux" ]; then
        MTime1d="-mtime -1"
        PingWait=5
    fi

    # Create TempDir -- used to store the files
    TempDir="/tmp/host-info"
    [ ! -d "$TempDir" ] && mkdir "$TempDir" 2>/dev/null
    
    # Find where the script resides (so updates update the correct version) -- without trailing slash
    DirName="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
    # What is the name of the script? (without any PATH)
    ScriptName="$(basename $0)"
    # If "${DirName}/${ScriptName}" is a link, find the original and correct DirName
    if [ -L "${DirName}/${ScriptName}" ]; then
        DirName="$(ls -ls "${DirName}/${ScriptName}" | cut -d\> -f2 | sed -e 's/^\ //' -e 's;/host-info.sh;;')"
    fi
    
    # Make it shorter by removing everything from a question mark and forwards
    NameToCheck="$(echo "$Input" | sed -e 's/\?.*//')"   # NameToCheck='https://www.youtube.com/watch'
}


# Get the IP address
# (It’s what is being used int eh script)
get_ip_address() {
    if [ -z "${NameToCheck//[0-9.]/}" ]; then
        IP=$NameToCheck
    else
        # Get the DNS part of the URL
        DNS="$(echo "$NameToCheck" | sed -e 's;https*://;;g' -e 's;/.*;;g' -e 's/:[0-9]*//')"   # DNS=www.youtube.com
        # Check to see that the DNS name doesn't contain a wildcard
        if [ -n "$(echo "$DNS" | egrep -o '\*')" ]; then
            echo "Can NOT use a wildcard for input!"
            echo "Will exit now..."
            exit 1
        fi
        # Get the IP address from the DNS name
        IP="$(/usr/bin/dig +search +short $DNS | tail -1)"    # IP=80.239.174.87
        # Exit if the DNS doesn't have an IP-number
        if [ -z "$IP" ]; then
            echo "Problem: \"$DNS\" doesn't have an IP-address!"
            echo "Exiting now..."
            exit 1
        fi
    fi
}


# Find out what port is being used. First eliminate everything but the DNS and an optional port number
get_port_number() {
    PortTemp="$(echo "$NameToCheck" | sed -e 's;https*://;;g' -e 's;/.*;;g')"
    # If there is a colon, get the port number
    [ -n "$(echo "$PortTemp" | egrep -o ":")" ] && Port="$(echo $PortTemp | cut -d: -f2)"
    # If no port given, see if the 'https' is specified. If so, $PortGiven indicates that
    # Note: 'http://' does *NOT* have to mean no TLS!
    if [ -z "$Port" ]; then
        [ -n "$(echo "$NameToCheck" | grep -o "https://")" ] && PortGiven="t" || PortGiven=""
        # Assume port 443
        Port=443
    else
        PortGiven="t"
    fi
}


# Find out where the device is
GeoLocate()
{
    # Where to store the GeoLookup-data
    GeoLocateFile="${TempDir}/${IP}.json"
    
    # Get the geoinfo data, but only if we don't already have it (and it's less than a day old)
    if [ -z "$(find "$GeoLocateFile" ${MTime1d} 2>/dev/null)" ]; then
        curl -s -f -o "$GeoLocateFile" "$GeoLookupURL/$IP"
    fi
    # Exempel:
    # {
    #   "ip": "46.30.211.34",
    #   "hostname": "www.one.com",
    #   "city": "",
    #   "region": "",
    #   "country": "DK",
    #   "loc": "55.7123,12.0564",
    #   "org": "AS51468 One.com A/S"
    # }

    # Gräv ut information ur json-filen:
    #City="$(less $GeoLocateFile | python -c "import json,sys;obj=json.load(sys.stdin);print obj['city'].encode('utf-8');")"
    City="$(grep '"city"' "$GeoLocateFile" 2>/dev/null | awk -F\" '{print $4}')"
    # City=Copenhagen
    #CountryShort="$(less $GeoLocateFile | python -c "import json,sys;obj=json.load(sys.stdin);print obj['country'].encode('utf-8');")"
    CountryShort="$(grep '"country"' "$GeoLocateFile" 2>/dev/null | awk -F\" '{print $4}')"
    # CountryShort=DK
    #Region="$(less $GeoLocateFile | python -c "import json,sys;obj=json.load(sys.stdin);print obj['region'].encode('utf-8');")"
    Region="$(grep '"region"' "$GeoLocateFile" 2>/dev/null | awk -F\" '{print $4}')"
    #Org="$(less $GeoLocateFile | python -c "import json,sys;obj=json.load(sys.stdin);print obj['org'].encode('utf-8');" | cut -d' ' -f2-)"
    Org="$(grep '"org"' "$GeoLocateFile" 2>/dev/null | awk -F\" '{print $4}')"
    # Org='AS1299 Telia Company AB'
    # Get the reverse DNS-name (and remove the last '.')
    Reverse="$(/usr/bin/dig +short -x $IP | sed 's/.$//')"
    # Reverse='ec2-54-246-177-230.eu-west-1.compute.amazonaws.com'
    CDN_raw="$(echo $Org | awk '{print $2}' | sed -e 's/,$//')"
    # CDN_raw='Akamai'
    CDN="$(grep "$CDN_raw" "${DirName}/$CDN_file" | head -1 | cut -f2)"
    # CDN='Akamai'
    # Fix for AWS. This is 'dirty' and I would like to find a better solution!
    if [ -z "$CDN" ]; then
        [ -n "$(echo $Reverse | egrep -o "amazonaws|cloudfront")" ] && CDN="Amazon AWS"
    fi
    ASHandle="$(echo "$Org" | awk '{print $1}')"
    # ASHandle='AS1299'

    # Get the long (real) name of the country
    CountryName="$(grep $CountryShort "${DirName}/${CountriesFile}" | cut -d: -f2)"    # CountryName='Denmark'
}


# Get certificate information (if possible)
SSLInfo()
{
    # Where to store the certificate information
    CertificateFile="${TempDir}/${IP}.certificate"

    # SSLURL must be eithe a DNS-name or an IP-address
    # Use the stored one if its newer than one day
    if [ -z "$(find "$CertificateFile" ${MTime1d} 2>/dev/null)" ]; then
        if [ -n "$DNS" ]; then
            echo | openssl s_client -connect "${DNS}":"$Port" -servername "${DNS}" 2>/dev/null > "$CertificateFile"
            SSLValid=true
        else
            echo | openssl s_client -connect "${IP}":"$Port" 2>/dev/null > "$CertificateFile"
            SSLValid=true
        fi
    else
        SSLValid=true
    fi
    
    # If we don't have a good result, there's no need to continue (won't do it in the printout either)
    if $SSLValid; then
        SSLReturnCode="$(grep "Verify return code:" "$CertificateFile" | cut -d: -f2)"  # SSLReturnCode=' 10 (certificate has expired)'
        if [ $(echo "$SSLReturnCode" | cut -d\( -f1) -eq 0 ]; then
            SSLReturnText="Certificate is valid"
        else
            SSLReturnText="$(echo "$SSLReturnCode" | cut -d\( -f2 | cut -d\) -f1) (code: $(echo "$SSLReturnCode" | cut -d\( -f1 | sed -e 's/\ //g'))"  # SSLReturnText='certificate has expired (code: 10)'
        fi
        SSLDNS="$(less "$CertificateFile" | openssl x509 -noout -text | grep DNS: | sed -e 's/^\ *//' -e 's/DNS://g')"
        SSLNrDNS="$(echo "$SSLDNS" | wc -w | awk '{print $1}')"
        SSLValidFrom="$(less "$CertificateFile" | openssl x509 -noout -startdate | sed -e 's/notBefore=//')"
        SSLValidTo="$(less "$CertificateFile" | openssl x509 -noout -enddate | sed -e 's/notAfter=//')"
        SSLBits="$(less "$CertificateFile" | openssl x509 -noout -text | grep -i "Public-Key:" | cut -d\( -f2 | awk '{print $1}')"
        SSLSignAlgoritm="$(less  "$CertificateFile" | openssl x509 -noout -text | grep -i "Signature Algorithm" | sort -u | cut -d: -f2 | sed 's/^ //')"
        case "$SSLSignAlgoritm" in
            rsaEncryption)                SSLSignAlgoritmText="Rivest, Shamir and Adleman (RSA) encryption (and signing)";;
            md2WithRSAEncryption)         SSLSignAlgoritmText="Message Digest 2 (MD2) checksum with Rivest, Shamir and Adleman (RSA) encryption";;
            md4withRSAEncryption)         SSLSignAlgoritmText="Message Digest 4 (MD4) checksum with Rivest, Shamir and Adleman (RSA) encryption";;
            md5WithRSAEncryption)         SSLSignAlgoritmText="Rivest, Shamir and Adleman (RSA) encryption with Message Digest 5 (MD5) signature";;
            sha1-with-rsa-signature)      SSLSignAlgoritmText="Rivest, Shamir and Adleman (RSA) with Secure Hash Algorithm (SHA-1) signature";;
            rsaOAEPEncryptionSET)         SSLSignAlgoritmText="Rivest, Shamir and Adleman (RSA) Optimal Asymmetric Encryption Padding (OAEP) encryption set";;
            id-RSAES-OAEP)                SSLSignAlgoritmText="Public-key encryption scheme combining Optimal Asymmetric Encryption Padding (OAEP) with the Rivest, Shamir and Adleman Encry...";;
            id-mgf1)                      SSLSignAlgoritmText="Rivest, Shamir and Adleman (RSA) algorithm that uses the Mask Generator Function 1 (MGF1)";;
            id-pSpecified)                SSLSignAlgoritmText="Rivest, Shamir and Adleman (RSA) algorithm (szOID_RSA_PSPECIFIED)";;
            rsassa-pss)                   SSLSignAlgoritmText="Rivest, Shamir, Adleman (RSA) Signature Scheme with Appendix - Probabilistic Signature Scheme (RSASSA-PSS)";;
            sha384WithRSAEncryption)      SSLSignAlgoritmText="Secure Hash Algorithm 384 (SHA384) with Rivest, Shamir and Adleman (RSA) Encryption";;
            sha512WithRSAEncryption)      SSLSignAlgoritmText="Secure Hash Algorithm (SHA) 512 with Rivest, Shamir and Adleman (RSA) encryption";;
            sha256WithRSAEncryption)      SSLSignAlgoritmText="Secure Hash Algorithm 256 (SHA256) with Rivest, Shamir and Adleman (RSA) encryption";;
        esac
        SSLProtocol="$(less "$CertificateFile" | grep "Protocol" | cut -d: -f2 | sed 's/^\ //')"  # SSLProtocol='TLSv1.2'
        # Version    Intro.    Phase out
        # TLS 1.0    1999    Deprecation planned in 2020
        # TLS 1.1    2006    Deprecation planned in 2020
        # TLS 1.2    2008
        # TLS 1.3    2018
        if [ "$SSLProtocol" = "TLSv1" ] || [ "$SSLProtocol" = "TLSv1.1" ]; then
            SSLProtocol="$SSLProtocol (old: deprecated since 2020)"
        fi
        SSLIssuer="$(less "$CertificateFile" | openssl x509 -noout -issuer | sed -e 's/issuer= //')"
        # Is the cert “appropriate”, i.e. does the cert actually cover the name we are looking at? Also look at 
        # wildcard certs (which are assumed to contain wildcard only in the first position)
        if [ -n "$(echo "$SSLDNS" | egrep -o "$DNS")" -o -n "$(echo "$SSLDNS" | egrep -o "\*\.$(echo "$DNS" | cut -d. -f2-)")" ]; then
            SSLAppropriate="t"
        else
            SSLAppropriate=""
        fi
    fi
}


# Get info about host (through 'curl')
HostInfo()
{
    # If we only have an IP-address or DNS-name, then try http and https
    if [ "$NameToCheck" = "$IP" -o "$NameToCheck" = "$DNS" ]; then
        CurlInfoHttps="$(curl --silent --head https://${IP})"
        CurlInfoHttp="$(curl --silent --head http://${IP})"
        # Add those together (we can be in a situation where a server responds on both port '80' and '443' and 
        # the only “sane” (sigh) solution is to deal with both, *ASSUMING* that it's the same server powering both...)
        CurlResponse="$(echo "${CurlInfoHttp}${NewLine}${CurlInfoHttps}" | egrep -i "^HTTP\/|^server:|^via:|^x-powered-by:|^x-generator:" | sort -u)"
    else
        # See if the cert is self signed (exit code '60' from curl)
        if curl --silent --head "$NameToCheck"  >&/dev/null; [ "$?" -eq 60 ]; then
            SSLIssuer="Self signed certificate"
        fi
        CurlResponse="$(curl --silent --insecure --head "${NameToCheck}" | egrep -i "^HTTP\/|^server:|^via:|^x-powered-by:|^x-generator:")"
    fi
    ServerHTTPver="$(echo "$CurlResponse" | grep "^HTTP" | head -1 | awk '{print $1}' | sed -e 's;HTTP/;;' | tr -d '\r')"  # ServerHTTPver=1.1
    ServerServer="$(echo "$CurlResponse" | grep -i "^Server:" | head -1 | cut -d: -f2- | sed -e 's/^\ *//' | tr -d '\r')"  # ServerServer='Apache/2.4.18 (Ubuntu)'
    # Make ServerServer a bit more clear
    case "$ServerServer" in
        gws) ServerServer="gws (Google Web Server)";;
        ghs) ServerServer="ghs (Google Hosting Server)";;
        iis) ServerServer="iis (Microsoft Informartion Server)";;
    esac
    ServerVia="$(echo "$CurlResponse" | grep -i "^Via:" | head -1 | cut -d: -f2- | sed -e 's/^\ *//' | tr -d '\r')"  # ServerVia='1.1 varnish-v4'
    ServerXPoweredBy="$(echo "$CurlResponse" | grep -i "^x-powered-by:" | head -1 | cut -d: -f2- | sed -e 's/^\ *//' | tr -d '\r')"  #
    ServerXGenerator="$(echo "$CurlResponse" | grep -i "^x-generator:" | head -1 | cut -d: -f2- | sed -e 's/^\ *//' | tr -d '\r')"  #
}

# Get the ping time to the host
PingTime()
{
    PingTimeMS="$(ping -c 1 -W $PingWait "$IP" 2>/dev/null | egrep -o "time=[0-9.]* ms" | cut -d= -f2)"
}


# Get the names for the certificate attributes
GetSSLCertAttribExplain()
{
    case "$CertAttribute" in
        CN)     CertAttributeText="Common name";;
        E)      CertAttributeText="Email";;
        T)      CertAttributeText="Locality";;
        ST)     CertAttributeText="State";;
        O)      CertAttributeText="Organization";;
        OU)     CertAttributeText="Org.unit";;
        C)      CertAttributeText="Country";;
        L)        CertAttributeText="Locality";;
        STREET) CertAttributeText="Street addr.";;
        ALL)    CertAttributeText="Complete name";;
    esac
    # Get the full country name
    [ "$CertAttributeText" = "Country" ] && CertAttributeValue="$(grep $CertAttributeValue "${DirName}/${CountriesFile}" | cut -d: -f2)"
}


print_head() {
	printf "${ESC}${BlackBack};${WhiteFont}mHost information for:${Reset}${ESC}${WhiteBack};${BlackFont}m $DNS ${Reset}   ${ESC}${BlackBack};${WhiteFont}mDate & time:${ESC}${WhiteBack};${BlackFont}m $(date +%F", "%R) ${Reset}\n"
	printf "${ESC}${BoldFace};${UnderlineFace}mHost info:${Reset}\n"
}


get_print_host_info() {
	printf "${ESC}${WhiteFont}mGathering geolocation data, please wait...${Reset}"
    GeoLocate
    printf "\033[2K\033[42D"
    
    printf "${F1}${F2}\n" "IP:" "$IP (reverse lookup: \"$(echo ${Reverse:-—})\")"
    if [ -n "$CDN" ]; then
        printf "${F1}${F2}\n" "CDN:" "Site is serverd by the CDN \"$CDN\". Geolocation might not be correct."
        printf "${ESC}${ItalicFace}m${F1}${F2}${Reset}\n" "Country:" "${CountryName:-—}"
        printf "${ESC}${ItalicFace}m${F1}${F2}${Reset}\n" "City:" "${City:-—} (region: ${Region:-—})"
    else
        printf "${F1}${F2}\n" "CDN:" "No CDN detected"
        printf "${F1}${F2}\n" "Country:" "${CountryName:-—}"
        printf "${F1}${F2}\n" "City:" "${City:-—} (region: ${Region:-—})"
    fi
    printf "${F1}${F2}\n" "Org.:" "$Org  (See: \"https://ipinfo.io/$ASHandle\" for more info)"
    
    printf "${ESC}${WhiteFont}mGathering ping data, please wait...${Reset}"
    
    PingTime
    
    printf "\033[2K\033[35D"
    printf "${F1}${F2}\n" "Ping time:" "${PingTimeMS:---no answer--}"
    echo
}


get_print_certificate_info() {
    if [ -z "$OpenSSLToOld" ]; then
        if nc -w 3 -z $IP ${Port:-443} 2>/dev/null; then
            printf "${ESC}${WhiteFont}mGathering SSL data, please wait...${Reset}"
            SSLInfo
            printf "\033[2K\033[34D"
        
            # Only continue if the result is valid
            if $SSLValid; then
                printf "${ESC}${BoldFace};${UnderlineFace}mCertificate info:${Reset}\n"
                printf "${F1}${F2}\n" "Protocol:" "${SSLProtocol} (Note: TLS is not part of the certificate!)"
                [ -z "$PortGiven" ] && printf "${ESC}${ItalicFace}mNo port given: SSL-info based on a guess of port \"443\"!!${Reset}\n"
                if [ "$SSLReturnText" = "Certificate is valid" ]; then 
                    Color="${ESC}${GreenFont}m"
                    printf "${F1}${Color}${F2}${Reset}\n" "Info:" "$SSLReturnText"
                elif [ "$SSLReturnText" = 'certificate has expired (code: 10)' ]; then
                    Color="${ESC}${RedFont}m"
                    printf "${F1}${Color}${F2}${Reset}\n" "Info:" "$SSLReturnText"
                else
                    printf "${F1}${F2}\n" "Info:" "${SSLReturnText}"
                fi
                printf "${F1}${F2}\n" "${SSLNrDNS} registered DNS:" "${SSLDNS:---no extra DNS names--}"
                [ -z "$SSLAppropriate" ] && printf  "${F1}${ESC}${RedFont}m${F2}${Reset}\n" "" "Note: this certificate DOES NOT cover \"$DNS\"!"
                printf "${F1}${F2}\n" "Valid from:" "$SSLValidFrom"
                printf "${F1}${F2}\n" "Valid to:" "$SSLValidTo"
                printf "${F1}${F2}\n" "Bits:" "${SSLBits}"
                printf "${F1}${F2}\n" "Signature algoritm:" "${SSLSignAlgoritm}  (“${SSLSignAlgoritmText:--No explanaination for this algoritm-}”)"
                printf "${F1}${F2}\n" "Issuer:" "${SSLIssuer}"
                if [ ! "$SSLIssuer" = "Self signed certificate" ]; then
                    printf "${ESC}${ItalicFace}mIssuer information dissected for clarity:${Reset}\n"
                    SSLIssuerString="$(echo "$SSLIssuer" | sed -e 's;^/;;' | tr '/' '\n')"
                    # SSLIssuerString='C=NL
                    # ST=Noord-Holland
                    # L=Amsterdam
                    # O=TERENA
                    # CN=TERENA SSL CA 3'
                    echo "$SSLIssuerString" | while IFS== read -r CertAttribute CertAttributeValue
                    do
                        # echo "Short: \"$Short\"; Long: \"$Long\""
                         GetSSLCertAttribExplain
                         printf "${F1}${F2}\n" " - ${CertAttributeText}:" "${CertAttributeValue}"
                    done
                fi
            fi
        else
            echo "No answer to port ${Port:-443} on host $Input!"
            echo "No info about certificate possible to get"
        fi
    else
        echo "OpenSSL is too old (version: $(openssl version 2>/dev/null | sed -e 's/OpenSSL //')) to test certificates. Upgrade OpenSSL or use a more modern OS!"
    fi
    echo
}


get_print_cipher_info() {
    if type -p nmap &>/dev/null; then
        printf "${ESC}${WhiteFont}mGathering cypher infornation, please wait...${Reset}"
        CypherInfo="$(nmap --script ssl-enum-ciphers -p $Port $IP | sed -n '/| ssl-enum-ciphers:/,/.*least strength.*/p' | sed 's/| //; s/|_/  /')"
        # Ex: CypherInfo='ssl-enum-ciphers: 
        #                   TLSv1.2: 
        #                     ciphers: 
        #                       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (ecdh_x25519) - A
        #                       TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (ecdh_x25519) - A
        #                       TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (ecdh_x25519) - A
        #                       TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (ecdh_x25519) - A
        #                       TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (ecdh_x25519) - A
        #                     compressors: 
        #                       NULL
        #                     cipher preference: server
        #                     least strength: A'
        printf "\033[2K\033[44D"

        printf "${ESC}${BoldFace};${UnderlineFace}mCypher info:${Reset}\n"
        echo "$CypherInfo"
    fi
}


get_print_server_info() {
    printf "${ESC}${WhiteFont}mGathering host data, please wait...${Reset}"
    HostInfo
    printf "\033[2K\033[35D"
    if [ -n "$CurlResponse" ]; then
        echo
        printf "${ESC}${BoldFace};${UnderlineFace}mServer info:${Reset}\n"
        [ -z "$ServerServer" ] || printf "${F1}${F2}\n" "Server:" "${ServerServer}"
        [ -z "$ServerHTTPver" ] || printf "${F1}${F2}\n" "HTTP-version:" "${ServerHTTPver}"
        [ -z "$ServerVia" ] || printf "${F1}${F2}\n" "Via:" "${ServerVia}"
        [ -z "$ServerXPoweredBy" ] || printf "${F1}${F2}\n" "X-Powered-By:" "${ServerXPoweredBy}"
        [ -z "$ServerXGenerator" ] || printf "${F1}${F2}\n" "X-Generator:" "${ServerXGenerator}"
    fi
}


#
#   _____ _   _______    ___________   ______ _   _ _   _ _____ _____ _____ _____ _   _  _____
#  |  ___| \ | |  _  \  |  _  |  ___|  |  ___| | | | \ | /  __ \_   _|_   _|  _  | \ | |/  ___|
#  | |__ |  \| | | | |  | | | | |_     | |_  | | | |  \| | /  \/ | |   | | | | | |  \| |\ `--.
#  |  __|| . ` | | | |  | | | |  _|    |  _| | | | | . ` | |     | |   | | | | | | . ` | `--. \
#  | |___| |\  | |/ /   \ \_/ / |      | |   | |_| | |\  | \__/\ | |  _| |_\ \_/ / |\  |/\__/ /
#  \____/\_| \_/___/     \___/\_|      \_|    \___/\_| \_/\____/ \_/  \___/ \___/\_| \_/\____/
#
#==============================================================================================================

check_stop

setup_things

get_ip_address

get_port_number


# Print stuff

print_head

get_print_host_info

if $ShowCertificate; then
    get_print_certificate_info
    get_print_cipher_info
fi

if $ShowServer; then
    get_print_server_info
fi
