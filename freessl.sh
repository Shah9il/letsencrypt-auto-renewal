#!/bin/sh
SCRIPT_FILE_NAME=freessl.sh
VERSION_DATE='10/10/2020 0119';

scrptLoc=$(pwd);
SCRIPT_RUN_DATE=($(date +"%F %s"))

#----------------------DOMAIN CONFIGURATION STARTS----------------------#
#Set full domain in DOMAIN_NAME parameter
DOMAIN_NAME="billing.optimistix.work"
#Set DAYS_BEFORE_RENEWAL in days for the script to attempt before actual renewal date
DAYS_BEFORE_RENEWAL=1
#Configure web server
WEBAPP_DIR='mirza'
WEBSERVER_SERVICE_FILE='tomcat'
WEBSERVER='jakarta-tomcat-7.0.61'
WEBSERVER_PATH='/usr/local/jakarta-tomcat-7.0.61'
WEBSERVER_LOG_FILE=$WEBSERVER_PATH/logs/catalina.out
# WEBSERVER_CONF_FILE=$WEBSERVER_PATH/conf/server.xml
WEBSERVER_RESTART_WAIT_SECOND=60
#----------------------DOMAIN CONFIGURATION ENDS------------------------#

#TODO TEST: 
#1) set domain without SSL certificate

#No Colors
NC='\033[0m'              # Text Reset/No Color
# Regular Colors
Black='\033[0;30m'        # Black
Red='\033[0;31m'          # Red
Green='\033[0;32m'        # Green
Yellow='\033[0;33m'       # Yellow
Blue='\033[0;34m'         # Blue
Purple='\033[0;35m'       # Purple
Cyan='\033[0;36m'         # Cyan
White='\033[0;37m'        # White
# Bold
BBlack='\033[1;30m'       # Black
BRed='\033[1;31m'         # Red
BGreen='\033[1;32m'       # Green
BYellow='\033[1;33m'      # Yellow
BBlue='\033[1;34m'        # Blue
BPurple='\033[1;35m'      # Purple
BCyan='\033[1;36m'        # Cyan
BWhite='\033[1;37m'       # White
# Underline
UBlack='\033[4;30m'       # Black
URed='\033[4;31m'         # Red
UGreen='\033[4;32m'       # Green
UYellow='\033[4;33m'      # Yellow
UBlue='\033[4;34m'        # Blue
UPurple='\033[4;35m'      # Purple
UCyan='\033[4;36m'        # Cyan
UWhite='\033[4;37m'       # White
# Background
On_Black='\033[40m'       # Black
On_Red='\033[41m'         # Red
On_Green='\033[42m'       # Green
On_Yellow='\033[43m'      # Yellow
On_Blue='\033[44m'        # Blue
On_Purple='\033[45m'      # Purple
On_Cyan='\033[46m'        # Cyan
On_White='\033[47m'       # White
# High Intensity
IBlack='\033[0;90m'       # Black
IRed='\033[0;91m'         # Red
IGreen='\033[0;92m'       # Green
IYellow='\033[0;93m'      # Yellow
IBlue='\033[0;94m'        # Blue
IPurple='\033[0;95m'      # Purple
ICyan='\033[0;96m'        # Cyan
IWhite='\033[0;97m'       # White
# Bold High Intensity
BIBlack='\033[1;90m'      # Black
BIRed='\033[1;91m'        # Red
BIGreen='\033[1;92m'      # Green
BIYellow='\033[1;93m'     # Yellow
BIBlue='\033[1;94m'       # Blue
BIPurple='\033[1;95m'     # Purple
BICyan='\033[1;96m'       # Cyan
BIWhite='\033[1;97m'      # White
# High Intensity backgrounds
On_IBlack='\033[0;100m'   # Black
On_IRed='\033[0;101m'     # Red
On_IGreen='\033[0;102m'   # Green
On_IYellow='\033[0;103m'  # Yellow
On_IBlue='\033[0;104m'    # Blue
On_IPurple='\033[0;105m'  # Purple
On_ICyan='\033[0;106m'    # Cyan
On_IWhite='\033[0;107m'   # White
spaceVal='  '

LETSENCRYPT_PATH='/etc/letsencrypt'
FREE_SSL="$LETSENCRYPT_PATH/FREE_SSL"
FREE_SSL_LOG='/var/log/FREE_SSL'
mkdir -p $FREE_SSL $FREE_SSL_LOG;
cd $FREE_SSL

CONFIG_FILE="$DOMAIN_NAME.conf"
# SSL_DATA_DUMP_JSON="$DOMAIN_NAME.json"

CRT_PATH="$LETSENCRYPT_PATH/live/$DOMAIN_NAME"
WEBROOT_PATH="$WEBSERVER_PATH/webapps/$WEBAPP_DIR"

TEMP_VALIDITY_CHECK="$FREE_SSL/temp_validity"

DATE_NOT_AFTER=($(grep DATE_NOT_AFTER $FREE_SSL/$DOMAIN_NAME.conf | gawk -F: '{print $2}'))
DATE_NOT_BEFORE=($(grep DATE_NOT_BEFORE $FREE_SSL/$DOMAIN_NAME.conf | gawk -F: '{print $2}'))
DATE_NEXT_RENEWAL=($(grep DATE_NEXT_RENEWAL $FREE_SSL/$DOMAIN_NAME.conf | gawk -F: '{print $2}'))
SSL_CRT_PASS=$(grep SSL_CRT_PASS $FREE_SSL/$DOMAIN_NAME.conf | gawk -F: '{print $2}')
DATE_BUNDLEPFX_MODIFY=()

CERT_PEM_FILE=cert.pem
CHAIN_PEM_FILE=chain.pem
FULLCHAIN_PEM_FILE=fullchain.pem
PRIVKEY_PEM_FILE=privkey.pem
BUNDLE_PFX_FILE=bundle.pfx

LOG_DATE="date +%F_%T.%3N"
SCRIPT_LOG_FILE="$FREE_SSL_LOG/freessl.log-"${SCRIPT_RUN_DATE[0]}-${SCRIPT_RUN_DATE[1]}
>$SCRIPT_LOG_FILE

#Color Code: BLUE - Processing, RED - Failure, GREEN - Success

function fn_next_date_conf(){
	cd $FREE_SSL
	openssl x509 -noout -dates -in $CRT_PATH/$CERT_PEM_FILE > $TEMP_VALIDITY_CHECK
	certNotBfr=($(date -d "$(cat $TEMP_VALIDITY_CHECK | grep notBefore | gawk -F'=' '{print $2}')" +"%F %s"))
	certNotAftr=($(date -d "$(cat $TEMP_VALIDITY_CHECK | grep notAfter | gawk -F'=' '{print $2}')" +"%F %s"))	

	if  [ ${certNotAftr[1]} -gt ${DATE_NOT_AFTER[1]} ];then
		echo -e "$($LOG_DATE): ${BBlue}Going to update configuration file...${NC}" >> $SCRIPT_LOG_FILE;
		nextRenewalDate=($(date -d @$((${certNotAftr[1]} - 86400 * $DAYS_BEFORE_RENEWAL)) +"%F %s"))

		echo -e "$($LOG_DATE): ${BGreen}${certNotBfr[@]} ${certNotAftr[@]} $nextRenewalDate ${NC}" >> $SCRIPT_LOG_FILE;

		mv $CONFIG_FILE $CONFIG_FILE-${SCRIPT_RUN_DATE[1]}
		echo "DOMAIN:$DOMAIN_NAME" > $CONFIG_FILE
		echo "DATE_NOT_AFTER:${certNotAftr[@]}" >> $CONFIG_FILE
		echo "DATE_NOT_BEFORE:${certNotBfr[@]}" >> $CONFIG_FILE
		echo "DATE_NEXT_RENEWAL:${nextRenewalDate[@]}" >> $CONFIG_FILE
		echo "SSL_CRT_PASS:$SSL_CRT_PASS" >> $CONFIG_FILE
		
		fn_restartWebServer
		
	elif [[ -z ${certNotAftr[1]} ]];then
		echo -e "$($LOG_DATE): ${Red}NO SSL Certificate found for ${BRed}$DOMAIN_NAME ${NC}" >> $SCRIPT_LOG_FILE;
	elif [ ${certNotAftr[1]} -eq ${DATE_NOT_AFTER[1]} ];then
		echo -e "$($LOG_DATE): ${BGreen}Expiry at $CERT_PEM_FILE: ${certNotAftr[0]} and $CONFIG_FILE: ${DATE_NOT_AFTER[0]} are same. No changes actions required...${NC}" >> $SCRIPT_LOG_FILE;
	else
		echo -e "$($LOG_DATE): ${BRed}fn_next_date_conf dead end... ${NC}" >> $SCRIPT_LOG_FILE;
	fi
}

#TODO: Check below command to get expiry date
#openssl x509 -noout -dates -in /etc/letsencrypt/live/billing.optimistix.work/cert.pem

function fn_bundle_pfx_gen(){
	# echo -e "${DATE_BUNDLEPFX_MODIFY[@]} printing for information"
	if [ -z ${DATE_BUNDLEPFX_MODIFY[@]} ] || [ ${SCRIPT_RUN_DATE[1]} -ge ${DATE_NEXT_RENEWAL[1]} ];then
		# echo -e "$($LOG_DATE): ${BRed}bundle.pfx not found or updated...${NC}";
		echo -e "$($LOG_DATE): ${BBlue}Generating bundle.pfx...${NC}" >> $SCRIPT_LOG_FILE;
		cd $CRT_PATH/
		openssl pkcs12 -export -out $BUNDLE_PFX_FILE -inkey $PRIVKEY_PEM_FILE -in $CERT_PEM_FILE -certfile $CHAIN_PEM_FILE -password pass:$SSL_CRT_PASS
		echo -e "$($LOG_DATE): ${BGreen}bundle.pfx generation done...${NC}" >> $SCRIPT_LOG_FILE;
	elif [ ${SCRIPT_RUN_DATE[1]} -eq ${DATE_NEXT_RENEWAL[1]} ];then
		echo -e "$($LOG_DATE): ${BGreen}bundle.pfx is up to date...${NC}" >> $SCRIPT_LOG_FILE;
		echo -e "$($LOG_DATE): ${BBlue}Skipping bundle.pfx generation...${NC}" >> $SCRIPT_LOG_FILE;
	fi
}

function fn_renewal(){
	cd $FREE_SSL
	if [ ${SCRIPT_RUN_DATE[1]} -ge ${DATE_NEXT_RENEWAL[1]} ];then
		echo -e "$($LOG_DATE): ${BRed}${SCRIPT_RUN_DATE[0]} is greater than ${DATE_NEXT_RENEWAL[0]}...${NC}" >> $SCRIPT_LOG_FILE;
		echo -e "$($LOG_DATE): ${BBlue}Attempting to renew SSL certificates...${NC}" >> $SCRIPT_LOG_FILE;

		cd $LETSENCRYPT_PATH
		./certbot-auto renew
		# ./certbot-auto certonly --webroot -w $WEBROOT_PATH -d $DOMAIN_NAME
	else
		echo -e "$($LOG_DATE): ${BGreen}Renewal is due for $((((${DATE_NEXT_RENEWAL[1]}-${SCRIPT_RUN_DATE[1]}))/86400)) days and Next Renewal Date: ${DATE_NEXT_RENEWAL[0]} ${NC}" >> $SCRIPT_LOG_FILE;
	fi
}

function fn_restartWebServer(){
	bash_service=`which service`
	if [ -z $bash_service ];then 
		bash_service="service";
	fi

	declare -i tomcatStopFlag=0
	declare -i tomcatStartFlag=0
	echo -e "$($LOG_DATE): ${BBlue}Stopping Tomcat......${NC}" >> $SCRIPT_LOG_FILE
	`$bash_service tomcat stop > /dev/null 2>&1`
	sleep 5
	`$bash_service tomcat stop > /dev/null 2>&1`
	sleep 5
	declare -i process_id=`/bin/ps -fu $USER| grep "$WEBSERVER" | grep -v "grep" | awk '{print $2}'`

	if [ -z $process_id ];then
		process_id=`pgrep -f "$WEBSERVER"`
	fi

	if [ $process_id -gt 0 ];then
		echo -e "$($LOG_DATE): ${BRed}Tomcat Still running. Trying to shutdown again...   ${NC}\n" >> $SCRIPT_LOG_FILE
		`$bash_service tomcat stop > /dev/null 2>&1`
		sleep 10
		`kill -9 $process_id > /dev/null 2>&1`
		`pkill -f "$WEBSERVER" > /dev/null 2>&1`
		`rm -rf "$servicePath/work/Catalina" > /dev/null 2>&1`
	fi

	process_id=`/bin/ps -fu $USER| grep "$WEBSERVER" | grep -v "grep" | awk '{print $2}'`
	if [ -z $process_id ];then
		process_id=`pgrep -f "$WEBSERVER"`
	fi

	if [ $process_id -lt 1 ];then
		echo -e "$($LOG_DATE): ${BGreen}Tomcat Stopped....  ${NC}\n" >> $SCRIPT_LOG_FILE
		tomcatStopFlag=1
		`mv $WEBSERVER_LOG_FILE $WEBSERVER_LOG_FILE$(date +%s) > /dev/null 2>&1`
	else
		echo -e "$($LOG_DATE): ${BRed}Tomcat Process Hanged or Unknown. Please Restart Tomcat Manually......  ${NC}\n" >> $SCRIPT_LOG_FILE
		tomcatStopFlag=3
		sleep 3
	fi
	if [ $tomcatStopFlag -eq 1 ];then
		echo -e "$($LOG_DATE): ${BBlue}Starting Tomcat ....${NC}" >> $SCRIPT_LOG_FILE
		`$bash_service tomcat start > /dev/null 2>&1`
		sleep 2
		declare -i waiter=1
		while [ $waiter -lt 11 ];do
			wTime=$(( waiter*$WEBSERVER_RESTART_WAIT_SECOND ))
			if grep -q 'Server startup in' $WEBSERVER_LOG_FILE > /dev/null 2>&1; then
				tomcatStartFlag=1
				echo -ne "$($LOG_DATE):${BGreen} Tomcat started after $wTime sec.${NC}"'\r' >> $SCRIPT_LOG_FILE
				break
			else
				tomcatStartFlag=0
				if [ $waiter -eq 10 ];then
					echo -e "$($LOG_DATE): ${BBlue}Sending notification... ${NC}" >> $SCRIPT_LOG_FILE
					#TODO: Send Mail
					# fn_sendMail
					break;
				else 
					sleep $WEBSERVER_RESTART_WAIT_SECOND
				fi
			fi
			waiter=$waiter+1
		done
	fi

	declare -i process_id=`/bin/ps -fu $USER| grep "$WEBSERVER" | grep -v "grep" | awk '{print $2}'`
	if [ -z $process_id ];then
		process_id=`pgrep -f "$WEBSERVER"`
	fi
	if [ $tomcatStartFlag -eq 1 ];then
		echo -e "\n$($LOG_DATE):${BGreen} Tomcat Started Successfully   ${NC}\n" >> $SCRIPT_LOG_FILE
	elif [ $tomcatStartFlag -eq 0 ] && [ $tomcatStopFlag -eq 1 ];then
		echo -e "\n$($LOG_DATE):${BRed} Tomcat did not start Still now! Please check status of tomcat manually!!!  ${NC}\n" >> $SCRIPT_LOG_FILE				   
	fi
}

function fn_sendMail(){
	echo "Feature not added yet! " >> $SCRIPT_LOG_FILE;
}

cd $CRT_PATH && crtPathXst=1 || crtPathXst=0
if [ $crtPathXst -eq 1 ];then
	echo -e "$($LOG_DATE): ${BBlue}Going to check SSL certificates...${NC}" >> $SCRIPT_LOG_FILE;

	ls $BUNDLE_PFX_FILE >>/dev/null 2>&1 && bundlePFXFile=1 || bundlePFXFile=0
	ls $CERT_PEM_FILE >>/dev/null 2>&1 && certFile=1 || certFile=0
	ls $CHAIN_PEM_FILE >>/dev/null 2>&1 && chainFile=1 || chainFile=0
	ls $FULLCHAIN_PEM_FILE >>/dev/null 2>&1 && fullchainFile=1 || fullchainFile=0
	ls $PRIVKEY_PEM_FILE >>/dev/null 2>&1 && privkeyFile=1 || privkeyFile=0

	#TODO TEST: add crt resource checking
	# echo "cert: $certFile chain: $chainFile fullchain: $fullchainFile privkey: $privkeyFile bundle: $bundlePFXFile";
	
	if [ $certFile -eq 1 ] && [ $chainFile -eq 1 ] && [ $fullchainFile -eq 1 ] && [ $privkeyFile -eq 1 ];then
		echo -e "$($LOG_DATE): ${BGreen}Found all cert files...${NC}" >> $SCRIPT_LOG_FILE;
		fn_renewal
		
		if [ $bundlePFXFile -eq 1 ];then
			echo -e "$($LOG_DATE): ${BGreen}Found bundle.pfx files...${NC}" >> $SCRIPT_LOG_FILE;
			DATE_BUNDLEPFX_MODIFY=($(date -r $CRT_PATH/bundle.pfx +"%F %s"));
		else
			echo -e "$($LOG_DATE): ${BRed}Missing bundle.pfx files...${NC}" >> $SCRIPT_LOG_FILE;
			fn_bundle_pfx_gen;
		fi
		
		echo -e "$($LOG_DATE): ${BBlue}Running fn_next_date_conf...${NC}" >> $SCRIPT_LOG_FILE;
		fn_next_date_conf
		
		# fn_restartWebServer
	else
		echo -e "$($LOG_DATE): ${BRed}Some / All cert files are missing...${NC}" >> $SCRIPT_LOG_FILE;
		#TODO: Send Mail
		# fn_sendMail
	fi
else
	echo -e "$($LOG_DATE): ${BRed}$CRT_PATH removed or SSL not installed${NC}" >> $SCRIPT_LOG_FILE;
	#TODO: Send Mail: $CRT_PATH removed or SSL not installed
	# fn_sendMail
fi

#0 10 * * 5 cd /etc/letsencrypt/ && ./certbot-auto renew && service tomcat restart