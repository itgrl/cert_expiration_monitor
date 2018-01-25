Purpose:  Monitor for certificate expiration of files and listening ports.


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


