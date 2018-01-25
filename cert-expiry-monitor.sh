
#!/bin/sh
############################################################
#  Program: cert_expiry_monitor.sh
#  Author : Rebecca Robinson
#  Purpose: Monitor certificate files and listening ports on
#           the current system for certificate expiration.
############################################################

## BEGIN SCRIPT
usage()
{
    cat << EOF
usage: $0 OPTIONS
OPTIONS can be:
    -h      Show this message
    -f      Specify a single file
    -p      Specify a single port
    -t      Send Alert email To
    -r      Run / Execute
    -v      Verbose (boolean)

Examples:
  Change Alarm email address for testing
    ./cert-expiry-monitor.sh -t me@mydomain.com

  Check single port
    ./cert-expiry-monitor.sh -p 443

  Check single file
    ./cert-expiry-monitor.sh -f /path/to/my/cert/ssl.crt

  Execute using defaults and find all certs listening ports
    ./cert-expiry-monitor.sh -r

Error Messages:
   1 - Warning  - Error attempting to build cache
   2 - Warning  - Error attempting to rotate logs
   3 - Major    - Error attempting to get the date difference between today and expiry.
   4 - Major    - Error checking port for certificate expiry
   5 - Major    - Error checking file for certificate expiry
   6 - Major    - Error sending alert
   7 - Major    - Error writing to log file
   8 - Critical - Critical script fault preventing operation

EOF
}
# Show usage when there are no arguments.
if test -z "$1"
then
    usage
    exit
fi
VERBOSE=
FILENAME=
PORT=
RUN=
LOGFILE="/var/log/certchecks.log"
ALERTEMAIL="monitoring@example.org"

WARNDAYS=90
MINDAYS=60
MAJDAYS=45
CRITDAYS=30
CLEAR=0
INTERMEDIATE=1
WARNING=2
MINOR=3
MAJOR=4
CRITICAL=5
error1="echo 'Message: Error while attempting to build cache'; echo 'Statistic: 1' ; exit 1"
error2="echo 'Message: Error while attempting to rotate logs'; echo 'Statistic: 2' ; exit 2"
error3="echo 'Message: Error while attempting to calculate the days until expiry'; echo 'Statistic: 3' ; exit 3"
error4="echo 'Message: Error while attempting to check port for cert expiry'; echo 'Statistic: 4' ; exit 4"
error5="echo 'Message: Error while attempting to check file for cert expiry'; echo 'Statistic: 5' ; exit 5"
error6="echo 'Message: Error while attempting to send alert'; echo 'Statistic: 6' ; exit 6"
error7="echo 'Message: Error while attempting to write to log file'; echo 'Statistic: 7' ; exit 7"

# Check options passed in.
while getopts "h r v e:f:p:t:" OPTION
do
    case $OPTION in
        h)
            usage
            exit 1
            ;;
        e)
            ### Hidden flag used for overriding the expiration date for alarm testing.
            MYEXPIRES=$OPTARG
            manual="Manual alarm threshold of $MYEXPIRES set."
            echo "Manual alarm threshold of $MYEXPIRES set."
            ;;
        f)
            ### Flag used for specifying a single file for testing.
            FILENAME=$OPTARG
            ;;
        p)
            ### Flag used for specifying a single port for testing.
            PORT=$OPTARG
            ;;
        r)
            RUN=1
            ;;
        t)
            MYALERTEMAIL=$OPTARG
            echo "## Email override set to $MYALERTEMAIL"
            if [ -n "$MYALERTEMAIL" ]; then ALERTEMAIL=$MYALERTEMAIL ; fi
            unset MYALERTEMAIL
            ;;
        v)
            VERBOSE=1
            ;;
        ?)
            usage
            exit
            ;;
    esac
done
# Do something with the arguments...
## BEGIN FUNCTIONS
function send_alarm () {
  local myfrom=$1
  local mytype=$2
  local mymessage=$3
  local myitem=$4
  local myexpires=$5
  local mynodename=$6
  local mynodeip=$7
  local myseverity=$8
  local myalertemail=$9
  case $mytype in
    'file')
        myname="
        Cert file location: $myitem
        "
      ;;
    'port')
        myname="
        Cert port: $myitem
        "
      ;;
    *)
        echo "I don't know what to do with $myitem!"
      ;;
  esac
  # Build message
  echo "
    Alert message:  SSL certificate Expiration
    $myname
    Cert expires in x days:  $myexpires
    Node:  $mynodename
    Node IP:  $mynodeip
    Message:  $mymessage
    Severity: $myseverity
  " | mail -s 'SSL certificate expiration alert' -r $myfrom $myalertemail

  if [[ "$VERBOSE" -eq "1" ]]
  then
    echo "
    'Alert message:  SSL certificate Expiration
    $myname
    Cert expires in x days:  $myexpires
    Node:  $mynodename
    Node IP:  $mynodeip
    Message:  $mymessage
    Severity: $myseverity
    '| mail -s 'SSL certificate expiration alert' -r $myfrom $myalertemail"
  fi
}

function write_log () {
  local mylogfile=$1
  local mytype=$2
  local mymessage=$3
  local myitem=$4
  local myexpires=$5
  local myname=$6
  local myseverity=$7
  ##  Rotate Logs
  if [ -f "$mylogfile" ]
  then
    if [[ "$VERBOSE" -eq "1" ]]; then echo "Rotating logfile $mylogfile..."    ; fi
    mv $mylogfile $mylogfile.$(date +%Y%m%d)
    if [[ "$VERBOSE" -eq "1" ]]; then echo "Clearing logfiles older than 5 days..."    ; fi
    find $mylogfile* -mtime +5 -exec rm {} \;
  fi
  if [[ "$VERBOSE" -eq "1" ]]; then echo "$(date) $myname -- Severity: $myseverity Type: $mytype Item: $myitem Expires: $myexpires days -- $mymessage    will be sent to $mylogfile"     ; fi
  echo "$(date) $myname -- Severity: $myseverity Type: $mytype Item: $myitem Expires: $myexpires days -- $mymessage" >> $mylogfile
}

function rotate_log () {
  local mylogfile=$1

  ##  Rotate Logs
  if [ -f "$mylogfile" ]
  then
    if [[ "$VERBOSE" -eq "1" ]]; then echo "Rotating logfile $mylogfile..."    ; fi
    mv $mylogfile $mylogfile.$(date +%Y%m%d)
    if [[ "$VERBOSE" -eq "1" ]]; then echo "Clearing logfiles older than 5 days..."    ; fi
    find $mylogfile* -mtime +5 -exec rm {} \;
  fi
}

function get_files () {
  local mycertcache='/var/log/mycertfiles'
  local mycertexts=( 'crt' 'cer' 'pem' )
  ##  Rotate Logs
  if [ -f "$mycertcache" ]
  then
    if [[ "$VERBOSE" -eq "1" ]]; then echo "Rotating certcache $mycertcache..." ; fi
    mv $mycertcache $mycertcache.$(date +%Y%m%d)
    if [[ "$VERBOSE" -eq "1" ]]; then echo "Clearing certcache older than 5 days..." ; fi
    find $mycertcache* -mtime +5 -exec rm {} \;
  fi
  for x in $( echo ${mycertexts[*]} )
  do
    locate *.$x >> $mycertcache
  done
}

function get_ports () {
  local myportcache='/var/log/mylisteningports'
  ##  Rotate Logs
  if [ -f "$myportcache" ]
  then
    if [[ "$VERBOSE" -eq "1" ]]; then echo "Rotating portcache $mycertcache..." ; fi
    mv $myportcache $myportcache.$(date +%Y%m%d)
    if [[ "$VERBOSE" -eq "1" ]]; then echo "Clearing portcache older than 5 days..." ; fi
    find $myportcache* -mtime +5 -exec rm {} \;
  fi
  # Get ipv4 ports
  if [[ "$VERBOSE" -eq "1" ]]; then echo "Finding ipv4 listening ports..." ; fi
  netstat -lnpt | grep -v Active | grep -v Proto | grep -v tcp6 | awk '{print $4}' | cut -d ':' -f2 >> $myportcache
  # Get ipv6 ports
  if [[ "$VERBOSE" -eq "1" ]]; then echo "Finding ipv6 listening ports..." ; fi
  netstat -lnpt | grep -v Active | grep -v Proto | grep tcp6 | awk '{print $4}' | cut -d ':' -f4 >> $myportcache
  # Filter ports to be uniq and sorted

  if [[ "$VERBOSE" -eq "1" ]]; then echo "Sorting and filtering unique ports..." ; fi
  mv $myportcache $myportcache.tmp
  sort $myportcache.tmp | uniq > $myportcache
  rm -f $myportcache.tmp
}

function datediff () {
  ## Function to check the number of days from today to expiration of certificate.
  if [[ "$VERBOSE" -eq "1" ]]; then echo "Calculating number of days until expiration..." ; fi
  local d1=$(date -d "$1" +%s)
  local d2=$(date -d "$(date)" +%s)
  days=$(( (d1 - d2) / 86400 ))
}

function check_file () {
  ## Check for certificate expiry of a file.
  if [[ "$VERBOSE" -eq "1" ]]; then echo " Checking file $1 for certificate expiration date..." ; fi
  expiring=$(openssl x509 -enddate -noout -in $1 2>/dev/null | grep notAfter | cut -d '=' -f2)
}

function check_port () {
  ## Check for certificate expiry of a port.
  ### Check to see if there is a peer certificate on this port.

  if [[ "$VERBOSE" -eq "1" ]]; then echo " Checking to see if port $1 has a certificate..." ; fi
  local mycertvalid=$(echo | openssl s_client -connect 127.0.0.1:$1 2>1)
  ### If there is a cert on the port, then check for the expiry of the certificate.
  iscert=$(echo "$mycertvalid" | grep 'no peer certificate available')
  if [ -z "$iscert" ]
  then
    if [[ "$VERBOSE" -eq "1" ]]; then echo "  Getting certificate expiration date for port $1..." ; fi
    expiring=$( echo | openssl s_client -connect 127.0.0.1:$1 2>1 | openssl x509 -noout -enddate 2>/dev/null | grep notAfter | cut -d'=' -f2)
  fi
}

## END FUNCTIONS
## BEGIN SCRIPT
### Build cache

if [[ "$VERBOSE" -eq "1" ]]; then echo "Building certificate file cache..." ; fi
get_files #|| $error1

if [[ "$VERBOSE" -eq "1" ]]; then echo "Building listening port cache..." ; fi
get_ports #|| $error1

if [[ "$VERBOSE" -eq "1" ]]; then echo "Rotating log files..." ; fi
rotate_log $LOGFILE #|| $error2

me=$(hostname)
mydomain=$(hostname -d)
myip=$(ip a | grep 10.25 | awk '{print $2}' | cut -d'/' -f1)

### Check to see if single argument is passed, typically for testing.
if [[ "$VERBOSE" -eq "1" ]]; then echo "Testing for single specified port..." ; fi
if [ -z "$PORT" ]
then
  if [[ "$VERBOSE" -eq "1" ]]; then echo " Looping through ports to test for certificates..." ; fi
  ### Loop through port cache and test ports
  for port in $(grep '[^[:blank:]]' <  /var/log/mylisteningports);
  do
    if [[ "$VERBOSE" -eq "1" ]]; then echo "  Checking port $port..." ; fi
    unset expiredays
    check_port $port ##|| { $error4 }
    unset days
    if [[ "$VERBOSE" -eq "1" ]]; then echo "   Testing for returned expiration date..." ; fi
    if [ -n "$expiring" ]
    then
      if [[ "$VERBOSE" -eq "1" ]]; then echo "   Certificate expires on $expiring..." ; fi
      datediff "$expiring" #||  $error3
      if [[ "$VERBOSE" -eq "1" ]]; then echo "   The certificate for port $port expires in $days days..." ; fi
      if [ -n "$MYEXPIRES" ]; then days="$MYEXPIRES";fi
      if [[ "$VERBOSE" -eq "1" ]]; then echo "   Evaluating against alarm thresholds..." ; fi
      # Checking against thresholds
      port_alarm_message=" 'port' 'This is a PORT expiry alarm test for PORT $PORT that will expire in $days days!  $manual' '$PORT' '$days' '$me' '$myip'"
      if (( "$WARNDAYS" >= "$days" && "$days" < "$MINDAYS" )); then
        if [[ "$VERBOSE" -eq "1" ]]; then echo "    The port $port is in a warning state due to certificate expiring in $days days..." ; fi
        send_alarm "$me@$mydomain" $port_alarm_message "$WARNING" "$ALERTEMAIL" #|| $error6
        write_log "$LOGFILE" $port_alarm_message "$WARNING" #||  $error7
      elif (( "$MINDAYS" >= "$days" && "$days" < "$MAJDAYS" )); then
        if [[ "$VERBOSE" -eq "1" ]]; then echo "    The port $port is in a Minor alarm state due to certificate expiring in $days days..." ; fi
        send_alarm "$me@$mydomain" $port_alarm_message "$MINOR" "$ALERTEMAIL" #|| $error6
        write_log "$LOGFILE" $port_alarm_message "$MINOR" #||  $error7
      elif (( "$MAJDAYS" >= "$days" && "$days" < "$CRITDAYS" )); then
        if [[ "$VERBOSE" -eq "1" ]]; then echo "    The port $port is in a Major alarm state due to certificate expiring in $days days..." ; fi
        send_alarm "$me@$mydomain" $port_alarm_message "$MAJOR" "$ALERTEMAIL" #|| $error6
        write_log "$LOGFILE" $port_alarm_message "$MAJOR" #||  $error7
      elif (( "$CRITDAYS" >= "$days" )); then
        if [[ "$VERBOSE" -eq "1" ]]; then echo "    The port $port is in a Critical alarm state due to certificate expiring in $days days..." ; fi
        send_alarm "$me@$mydomain" $port_alarm_message "$CRITICAL" "$ALERTEMAIL" #|| $error6
        write_log "$LOGFILE" $port_alarm_message "$CRITICAL" #||  $error7
      fi
    else
      if [[ "$VERBOSE" -eq "1" ]]; then echo "   Port $port does not have a certificate..." ; fi
    fi
  done
else
    if [[ "$VERBOSE" -eq "1" ]]; then echo "Single port flag selected..." ; fi
    unset expiredays
    if [[ "$VERBOSE" -eq "1" ]]; then echo "  Checking port $PORT..." ; fi
    check_port $PORT #||  $error4
    unset days
    if [[ "$VERBOSE" -eq "1" ]]; then echo "   Testing for returned expiration date..." ; fi
    if [ -n "$expiring" ]
    then
      if [[ "$VERBOSE" -eq "1" ]]; then echo "   Certificate expires on $expiring..." ; fi
      datediff "$expiring" #||  $error3
      if [[ "$VERBOSE" -eq "1" ]]; then echo "   The certificate for port $PORT expires in $days days..." ; fi
      if [ -n "$MYEXPIRES" ]; then days="$MYEXPIRES";fi
      if [[ "$VERBOSE" -eq "1" ]]; then echo "   Evaluating against alarm thresholds..." ; fi
      # Checking against thresholds
      port_alarm_message=" 'port' 'This is a PORT expiry alarm test for PORT $PORT that will expire in $days days!  $manual' '$PORT' '$days' '$me' '$myip'"
      if (( "$WARNDAYS" >= "$days" && "$days" < "$MINDAYS" )); then
        if [[ "$VERBOSE" -eq "1" ]]; then echo "    The port $port is in a warning state due to certificate expiring in $days days..." ; fi
        send_alarm "$me@$mydomain" $port_alarm_message "$WARNING" "$ALERTEMAIL" #|| $error6
        write_log "$LOGFILE" $port_alarm_message "$WARNING" #||  $error7
      elif (( "$MINDAYS" >= "$days" && "$days" < "$MAJDAYS" )); then
        if [[ "$VERBOSE" -eq "1" ]]; then echo "    The port $port is in a Minor alarm state due to certificate expiring in $days days..." ; fi
        send_alarm "$me@$mydomain" $port_alarm_message "$MINOR" "$ALERTEMAIL" #|| $error6
        write_log "$LOGFILE" $port_alarm_message "$MINOR" #||  $error7
      elif (( "$MAJDAYS" >= "$days" && "$days" < "$CRITDAYS" )); then
        if [[ "$VERBOSE" -eq "1" ]]; then echo "    The port $port is in a Major alarm state due to certificate expiring in $days days..." ; fi
        send_alarm "$me@$mydomain" $port_alarm_message "$MAJOR" "$ALERTEMAIL" #|| $error6
        write_log "$LOGFILE" $port_alarm_message "$MAJOR" #||  $error7
      elif (( "$CRITDAYS" >= "$days" )); then
        if [[ "$VERBOSE" -eq "1" ]]; then echo "    The port $port is in a Critical alarm state due to certificate expiring in $days days..." ; fi
        send_alarm "$me@$mydomain" $port_alarm_message "$CRITICAL" "$ALERTEMAIL" #|| $error6
        write_log "$LOGFILE" $port_alarm_message "$CRITICAL" #||  $error7
      fi
    else
      if [[ "$VERBOSE" -eq "1" ]]; then echo "   Port $PORT does not have a certificate..." ; fi
    fi
fi

### Check to see if single argument is passed, typically for testing.
if [[ "$VERBOSE" -eq "1" ]]; then echo "Testing for single specified file..." ; fi
if [ -z "$FILENAME" ]
then
  if [[ "$VERBOSE" -eq "1" ]]; then echo "  Looping through files to get certificate expiration date..." ; fi
  ### Loop through file cache and test files.
  for x in $( grep -v "/opt/puppetlabs/puppet/share/installer/vendor/ruby/2.1.0/gems/eventmachine-1.2.1/tests/client.crt" /var/log/mycertfiles )
  do
    if [[ "$VERBOSE" -eq "1" ]]; then echo "  Checking file $file..." ; fi
    check_file $file || $error5
    if [[ "$VERBOSE" -eq "1" ]]; then echo "   Testing for returned expiration date..." ; fi
    unset days
    if [ -n "$expiring" ]
    then
      if [[ "$VERBOSE" -eq "1" ]]; then echo "   File $FILENAME expires on $expiring..." ; fi
      datediff "$expiring" #|| $error3
      if [[ "$VERBOSE" -eq "1" ]]; then echo "   File $FILENAME expires in $days days..." ; fi
      # Checking against thresholds
      file_alarm_message=" 'file' 'This is a file expiry alarm test for file $FILENAME that will expire in $days days!'  '$manual' '$FILENAME' '$days' '$me' '$myip'"
      if (( "$WARNDAYS" >= "$days" && "$days" < "$MINDAYS" ))
      then
        if [[ "$VERBOSE" -eq "1" ]]; then echo "    The file $FILENAME is in a warning state due to certificate expiring in $days days..." ; fi
        send_alarm "$me@$mydomain" $file_alarm_message "$WARNING" "$ALERTEMAIL" #|| $error6
        write_log "$LOGFILE" $file_alarm_message "$WARNING" #|| $error7
      elif (( "$MINDAYS" >= "$days" && "$days" < "$MAJDAYS" ))
      then
        if [[ "$VERBOSE" -eq "1" ]]; then echo "    The file $FILENAME is in a Minor alarm state due to certificate expiring in $days days..." ; fi
        send_alarm "$me@$mydomain" $file_alarm_message "$MINOR" "$ALERTEMAIL" #|| $error6
        write_log "$LOGFILE" $file_alarm_message "$MINOR" #|| $error7
      elif (( "$MAJDAYS" >= "$days" && "$days" < "$CRITDAYS" ))
      then
        if [[ "$VERBOSE" -eq "1" ]]; then echo "    The file $FILENAME is in a Major alarm state due to certificate expiring in $days days..." ; fi
        send_alarm "$me@$mydomain" $file_alarm_message "$MAJOR" "$ALERTEMAIL" #|| $error6
        write_log "$LOGFILE" $file_alarm_message "$MAJOR" #|| $error7
      elif (( "$CRITDAYS" >= "$days" ))
      then
        if [[ "$VERBOSE" -eq "1" ]]; then echo "    The file $FILENAME is in a Critical alarm state due to certificate expiring in $days days..." ; fi
        send_alarm "$me@$mydomain" $file_alarm_message "$CRITICAL" "$ALERTEMAIL" #|| $error6
        write_log "$LOGFILE" $file_alarm_message "$CRITICAL" #|| $error7
      fi
    else
      if [[ "$VERBOSE" -eq "1" ]]; then echo "   File $FILENAME does not have a certificate..." ; fi
    fi
    if [ -n "$MYEXPIRES" ]; then days="$MYEXPIRES";fi


  done
else
  if [[ "$VERBOSE" -eq "1" ]]; then echo "  Checking file $FILENAME..." ; fi
  check_file $FILENAME #|| $error5
  unset days
  if [[ "$VERBOSE" -eq "1" ]]; then echo "   Testing for returned expiration date..." ; fi
  if [ -n "$expiring" ]
  then
    if [[ "$VERBOSE" -eq "1" ]]; then echo "   File $FILENAME expires on $expiring..." ; fi
    datediff "$expiring" #|| $error3
    if [[ "$VERBOSE" -eq "1" ]]; then echo "   File $FILENAME expires in $days days..." ; fi
      if [[ "$VERBOSE" -eq "1" ]]; then echo "   File $FILENAME expires in $days days..." ; fi
      # Checking against thresholds
      file_alarm_message=" 'file' 'This is a file expiry alarm test for file $FILENAME that will expire in $days days!'  '$manual' '$FILENAME' '$days' '$me' '$myip'"
      if (( "$WARNDAYS" >= "$days" && "$days" < "$MINDAYS" ))
      then
        if [[ "$VERBOSE" -eq "1" ]]; then echo "    The file $FILENAME is in a warning state due to certificate expiring in $days days..." ; fi
        send_alarm "$me@$mydomain" $file_alarm_message "$WARNING" "$ALERTEMAIL" #|| $error6
        write_log "$LOGFILE" $file_alarm_message "$WARNING" #|| $error7
      elif (( "$MINDAYS" >= "$days" && "$days" < "$MAJDAYS" ))
      then
        if [[ "$VERBOSE" -eq "1" ]]; then echo "    The file $FILENAME is in a Minor alarm state due to certificate expiring in $days days..." ; fi
        send_alarm "$me@$mydomain" $file_alarm_message "$MINOR" "$ALERTEMAIL" #|| $error6
        write_log "$LOGFILE" $file_alarm_message "$MINOR" #|| $error7
      elif (( "$MAJDAYS" >= "$days" && "$days" < "$CRITDAYS" ))
      then
        if [[ "$VERBOSE" -eq "1" ]]; then echo "    The file $FILENAME is in a Major alarm state due to certificate expiring in $days days..." ; fi
        send_alarm "$me@$mydomain" $file_alarm_message "$MAJOR" "$ALERTEMAIL" #|| $error6
        write_log "$LOGFILE" $file_alarm_message "$MAJOR" #|| $error7
      elif (( "$CRITDAYS" >= "$days" ))
      then
        if [[ "$VERBOSE" -eq "1" ]]; then echo "    The file $FILENAME is in a Critical alarm state due to certificate expiring in $days days..." ; fi
        send_alarm "$me@$mydomain" $file_alarm_message "$CRITICAL" "$ALERTEMAIL" #|| $error6
        write_log "$LOGFILE" $file_alarm_message "$CRITICAL" #|| $error7
      fi
  else
    if [[ "$VERBOSE" -eq "1" ]]; then echo "   File $FILENAME does not have a certificate..." ; fi
  fi

fi

### Add successful exit
echo "Message: Completed Successfully"
echo "Statistic: 0"


## END SCRIPT
