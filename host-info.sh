#!/bin/bash
# host-info.sh - a simple script to look up where an IP address is located
# 2016-12-11 / Peter Möller
# 2019-06-26 /Changed to host-info.sh and gives vastly more info on a server
# 
# 
# Tanken är att så småningom kunna få fram även info om vilken registrar ett DNS-namn har

GeoLookupURL="ipinfo.io"
CountriesURL="http://fileadmin.cs.lth.se/intern/Drift/Countries.txt"
CountriesFile="/tmp/.Countries.txt"
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

function help() {
	echo "Usage: $(basename $0) URL, DNS-name or IP-address"
	echo "Enter a URL, a DNS-name or an IP-address to get it resolved"
	echo
	exit 0
}


# Read the parameters:
while getopts ":h" opt
do
	case $opt in
		\?|h ) help;;
	esac
done

if [ ! -x /usr/bin/dig ]; then
	echo "No \"dig\" found (in /usr/bin). Script will exit."
	exit 1
fi

#
NameToCheck=$1
# NameToCheck='https://www.youtube.com/watch?v=98eabjjAEz8'

# tag fram IP-adressen
if [ -z "${NameToCheck//[0-9.]/}" ]; then
	IP=$NameToCheck
else
	# Gräv ut DNS-biten av URL:en
	DNS="$(echo "$NameToCheck" | sed -e 's;https*://;;g' -e 's;/.*;;g' -e 's/:[0-9]*//')"
	# DNS=www.youtube.com
	if [ -n "$(echo "$DNS" | egrep -o '\*')" ]; then
		echo "Can NOT use a wildcard for input!"
		echo "Will exit now..."
		exit 1
	fi
	# Omvandla DNS-namn till IP-nummer:
	IP="$(/usr/bin/dig +search +short $DNS | tail -1)"
	# IP=80.239.174.87
fi

# Find out what port is being used
Port="$(echo "$NameToCheck" | sed -e 's;https*://;;g' -e 's;/.*;;g' | cut -d: -f2 | grep -o "[0-9]*")"
# If no port given, see if the 'https' is specified. If so, $PortGiven indicates that
# Note: 'http://' does *NOT* have to mean no TLS!
if [ -z "$Port" ]; then
	if [ -n "$(echo "$NameToCheck" | grep -o "https://")" ]; then
		PortGiven="t"
		Port=443
	else
		PortGiven=""
		Port=443
	fi
else
	PortGiven="t"
fi


OutFile="/tmp/${IP}.json"


# Find out where the device is
function GeoLocate()
{
	# Hämta geolookupen
	curl -s -f -o "$OutFile" "$GeoLookupURL/$IP"
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
	#City="$(less $OutFile | python -c "import json,sys;obj=json.load(sys.stdin);print obj['city'].encode('utf-8');")"
	City="$(grep '"city"' "$OutFile" 2>/dev/null | awk -F\" '{print $4}')"
	# City=Copenhagen
	#CountryShort="$(less $OutFile | python -c "import json,sys;obj=json.load(sys.stdin);print obj['country'].encode('utf-8');")"
	CountryShort="$(grep '"country"' "$OutFile" 2>/dev/null | awk -F\" '{print $4}')"
	# CountryShort=DK
	#Region="$(less $OutFile | python -c "import json,sys;obj=json.load(sys.stdin);print obj['region'].encode('utf-8');")"
	Region="$(grep '"region"' "$OutFile" 2>/dev/null | awk -F\" '{print $4}')"
	#Org="$(less $OutFile | python -c "import json,sys;obj=json.load(sys.stdin);print obj['org'].encode('utf-8');" | cut -d' ' -f2-)"
	Org="$(grep '"org"' "$OutFile" 2>/dev/null | awk -F\" '{print $4}')"
	# Org='Telia Company AB'

	# Hämta Landslistan om den inte finns
	[[ -f "$CountriesFile" ]] || curl -s -f -o "$CountriesFile" "$CountriesURL" 2>/dev/null
	# Gräv fram det långa landsnamnet
	CountryName="$(grep $CountryShort $CountriesFile | cut -d: -f2)"
	# CountryName=Denmark

	#Tag fram reversen och skala bort den avslutande punkten:
	Reverse="$(/usr/bin/dig +short -x $IP | sed 's/.$//')"
}

# Get certificate information (if possible)
function SSLInfo()
{
	# SSLURL must be eithe a DNS-name or an IP-address *without* anything before or after!
	SSLURL=$1
	SSLResult="$(echo | openssl s_client -connect "${SSLURL}":"$Port" 2>/dev/null)"
	SSLValid="$?"
	SSLReturnCode="$(echo "${SSLResult}" | grep "Verify return code:" | cut -d: -f2)"  # SSLReturnCode=' 10 (certificate has expired)'
	if [ $(echo "$SSLReturnCode" | cut -d\( -f1) -eq 0 ]; then
		SSLReturnText="Certificate is valid"
	else
		SSLReturnText="$(echo "$SSLReturnCode" | cut -d\( -f2 | cut -d\) -f1) (code: $(echo "$SSLReturnCode" | cut -d\( -f1 | sed -e 's/\ //g'))"  # SSLReturnText='certificate has expired (code: 10)'
	fi
	SSLDNS="$(echo "${SSLResult}" | openssl x509 -noout -text | grep DNS: | sed -e 's/^\ *//' -e 's/DNS://g')"
	#SSLDates="$(echo "${SSLResult}" | openssl x509 -noout -dates | sed -e 's/notBefore=/Valid from: /' -e 's/notAfter=/Valid till: /')"
	SSLValidFrom="$(echo "${SSLResult}" | openssl x509 -noout -startdate | sed -e 's/notBefore=//')"
	SSLValidTo="$(echo "${SSLResult}" | openssl x509 -noout -enddate | sed -e 's/notAfter=//')"
	SSLProtocol="$(echo "${SSLResult}" | grep "Protocol" | cut -d: -f2 | sed 's/^\ //')"  # SSLProtocol='TLSv1.2'
	# Version	Intro.	Phase out
	# TLS 1.0	1999	Deprecation planned in 2020
	# TLS 1.1	2006	Deprecation planned in 2020
	# TLS 1.2	2008
	# TLS 1.3	2018
	[ "$SSLProtocol" = "TLSv1" -o "$SSLProtocol" = "TLSv1.1" ] && SSLProtocol="$SSLProtocol (old: will be deprecated in 2020)"
	SSLIssuer="$(echo "${SSLResult}" | openssl x509 -noout -issuer | sed -e 's/issuer= //')"
	# Is the cert “appropriate”, i.e. does the cert actually cover the name we are looking at?
	if [ -n "$(echo "$SSLDNS" | egrep -o "$DNS")" -o -n "$(echo "$SSLDNS" | egrep -o "\*\.$(echo "$DNS" | cut -d. -f2-)")" ]; then
		SSLAppropriate="t"
	else
		SSLAppropriate=""
	fi
}

# Get info about host (through 'curl')
function HostInfo()
{
	if [ "$NameToCheck" = "$IP" -o "$NameToCheck" = "$DNS" ]; then
		CurlInfoHttps="$(curl --silent --head https://${IP})"
		CurlInfoHttp="$(curl --silent --head http://${IP})"
	else
		# Frist see if the cert is self signed
		if curl --silent --head "$NameToCheck"  >&/dev/null; [ "$?" -eq 60 ]; then
			SSLIssuer="Self signed certificate"
		fi
		CurlResponse="$(curl --silent --insecure --head "$NameToCheck" | egrep -i "^HTTP\/|^server:|^via:|^x-powered-by:|^x-generator:")"
		ServerHTTPver="$(echo "$CurlResponse" | grep "^HTTP" | awk '{print $1}' | sed -e 's;HTTP/;;')"  # ServerHTTPver=1.1
		ServerServer="$(echo "$CurlResponse" | grep -i "^Server:" | cut -d: -f2- | sed -e 's/^\ *//')"  # ServerServer='Apache/2.4.18 (Ubuntu)'
		ServerVia="$(echo "$CurlResponse" | grep -i "^Via:" | cut -d: -f2- | sed -e 's/^\ *//')"  # ServerVia='1.1 varnish-v4'
		ServerXPoweredBy="$(echo "$CurlResponse" | grep -i "^x-powered-by:" | cut -d: -f2- | sed -e 's/^\ *//')"  #
		ServerXGenerator="$(echo "$CurlResponse" | grep -i "^x-generator:" | cut -d: -f2- | sed -e 's/^\ *//')"  #
	fi
}


##################################################

# START OF ACTUAL WORK

GeoLocate
SSLInfo "$IP"
HostInfo


# Print it:
printf "${ESC}${BlackBack};${WhiteFont}mGeolookup information for:${Reset}${ESC}${WhiteBack};${BlackFont}m $DNS ${Reset}   ${ESC}${BlackBack};${WhiteFont}mDate & time:${ESC}${WhiteBack};${BlackFont}m $(date +%F", "%R) ${Reset}\n"
echo "     IP: $IP (reverse lookup: \"$(echo ${Reverse:-—})\")"
echo "Country: ${CountryName:-—}"
echo "   City: ${City:-—} (region: ${Region:-—})"
echo "   Org.: $Org"
echo
if [ $SSLValid -eq 0 ]; then
	printf "${ESC}${BoldFace}mCertificate info:${Reset}\n"
	[ -z "$PortGiven" ] && printf "${ESC}${ItalicFace}mNo port given: SSL-info based on a guess of port \"443\"!!${Reset}\n"
	if [ "$SSLReturnText" = "Certificate is valid" ]; then 
		printf "${ESC}${GreenFont}mInfo:           Certificate is valid${Reset}\n"
	else
		echo "Info:           ${SSLReturnText}"
	fi
	printf "Registered DNS: ${SSLDNS:---no extra DNS names--}"
	[ -z "$SSLAppropriate" ] && printf "   ${ESC}${RedFont}mNote: this certificate DOES NOT cover \"$DNS\"!${Reset}\n" || printf "\n"
	echo "Valid from:     $SSLValidFrom"
	echo "Valid to:       $SSLValidTo"
	echo "Protocol:       ${SSLProtocol}"
	echo "Issuer:         ${SSLIssuer}"
fi
if [ -n "$CurlResponse" ]; then
	echo
	printf "${ESC}${BoldFace}mServer info:${Reset}\n"
	[ -z "$ServerServer" ] || echo "Server:         ${ServerServer}"
	[ -z "$ServerHTTPver" ] || echo "HTTP-version:   ${ServerHTTPver}"
	[ -z "$ServerVia" ] || echo "Via:            ${ServerVia}"
	[ -z "$ServerXPoweredBy" ] || echo "X-Powered-By:   ${ServerXPoweredBy}"
	[ -z "$ServerXGenerator" ] || echo "X-Generator:    ${ServerXGenerator}"
fi