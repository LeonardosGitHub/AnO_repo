when RULE_INIT {
    set static::explicitHTTPS_debug 0; # if this is set to 1 additional conditional logging will be enabled.
    set static::categoriesToBlock {"Botnets" "Cloud Provider Networks" "Denial of Service" "Illegal Websites" "Infected Sources" "Phishing" "Proxy" "Scanners" "Spam Sources" "Web Attacks" "Windows Exploits"}
}
when CLIENT_ACCEPTED {
    set hslhttps [HSL::open -proto TCP -pool Shared/telemetry_pool2]
    set hsl_httpsclientAccept "logType=\"httpsLog\",eventTimestamp=\"[clock format [clock seconds] -format "%a, %d %h %Y %T GMT" -gmt 1]\",bigipHostname=\"$static::tcl_platform(machine)\",clientIp=\"[IP::remote_addr clientside]\",clientPort=\"[TCP::client_port]\",virtualName=\"[virtual name]\",bytesToClient=\"[IP::stats bytes out]\",bytesToProxy=\"[IP::stats bytes in]\""
    set opt28 [TCP::option get 28]
    if {[info exists opt28]} {
        binary scan $opt28 cH8H12 ver addr uuidbin
        if {[info exists uuidbin]} {
            scan $addr "%2x%2x%2x%2x" ip1 ip2 ip3 ip4
            set v2_sourceAddress "$ip1.$ip2.$ip3.$ip4"
            scan $uuidbin "%4s%4s%4s" uu1 uu2 uu3
            set custProxyHeader "$uu1:$uu2:$uu3"
            if { $static::explicitHTTPS_debug } {log local0.debug "opt28 client address from proxy protocol: $v2_sourceAddress; UUID: $custProxyHeader"}
        }
        else {
            scan $addr "%2x%2x%2x%2x" ip1 ip2 ip3 ip4
            set v2_sourceAddress "$ip1.$ip2.$ip3.$ip4"
            set custProxyHeader ""
            #if { $static::explicitHTTPS_debug } { log local0.debug "v2_sourceAddress: $v2_sourceAddress"}
        }
    }
}
when CLIENTSSL_HANDSHAKE {
    set  hsl_httpsclientsslhandshake "CLIENTSSL_HANDSHAKE: sslCipherName=\"[SSL::cipher name]\",sslCipherBits=\"[SSL::cipher bits]\",sslCipherVersion=\"[SSL::cipher version]\",sslCertValid=\"[X509::verify_cert_error_string [SSL::verify_result]]\""
    set ext_count [SSL::extensions count]
    #if { $static::explicitHTTPS_debug } { log local0.debug "ClientSSL_Handshake"}
}
when HTTP_REQUEST {
    if { $static::explicitHTTPS_debug } {log local0.debug "[HTTP::host] HTTPS: $v2_sourceAddress"}
    set 403response 0
    set xffProto ""
    set sharedTraffic "shared"
    #Set XFF header
    if {[info exists v2_sourceAddress]} {
        HTTP::header insert X-Forwarded-For $v2_sourceAddress
    }
    else {
        HTTP::header insert X-Forwarded-For ""
    }
    if {[TCP::local_port] == 443} {
        HTTP::header insert X-Forwarded-Proto https
        set xffProto https
    }
    #Set optional seal header
    set custHTTPSHeader [HTTP::header value "proxyUUID"]
    set hsl_httpshttpRequest "url=\"https://[HTTP::host][HTTP::uri]\",serverIP=\"[IP::local_addr]\",serverPort=\"[TCP::local_port]\",httpMethod=\"[HTTP::method]\",httpVersion=\"[HTTP::version]\",httpUri=\"[HTTP::uri]\",httpQuery=\"[HTTP::query]\",headerHost=\"[HTTP::host]\",headerXff=\"[HTTP::header X-Forwarded-For]\",headerContentType=\"[HTTP::header Content-Type]\",headerReferer=\"[HTTP::header Referer]\",headerUserAgent=\"[HTTP::header User-Agent]\",headerXfProto=\"$xffProto\""
    #Use custom header if not use IP address
    if {$custProxyHeader != ""} {
       set sourceClient $custProxyHeader
       set customHeader 1
    }
    elseif {$custHTTPSHeader != ""} {
       set sourceClient $custProxyHeader
       set customHeader 1
    }
    else {
       set sourceClient $v2_sourceAddress
       set customHeader 0
    }
    if { ([HTTP::uri] contains "jndi:ldap") || ([HTTP::uri] contains "jndi%3Aldap") } {
        set 403response 1
        HSL::send $hslhttps "Apache Log4j vulnerability prevention fix."
    }

    if {[info exists sourceClient]} {
        if {$customHeader == 1}{
            set srcDatagroup [class match -value $sourceClient equals Shared/proxyFilterHeaderToDatagroup]
        }
        else {
            if { $static::explicitHTTPS_debug } {log local0.info "source variable HTTPS: $sourceClient"}
            set srcDatagroup [class match -value $sourceClient equals Shared/srcipToDatagroup]
        }
        #if { $static::explicitHTTPS_debug } {log local0.debug "[HTTP::host] source variable HTTPS: $sourceClient, customHeader = $customHeader source dataGroup: $srcDatagroup"}
        if {[info exists srcDatagroup]} {
            if { ([HTTP::uri] contains "jndi:ldap") || ([HTTP::uri] contains "jndi%3Aldap") } {
                set 403response 1
                HSL::send $hslhttps "Apache Log4j vulnerability prevention fix."
            }
            else {
                if { $srcDatagroup ne "" } {
                    set hostName [getfield [string tolower [HTTP::host]] ":" 1]
                    set get_uri_datagroup  [class match -value [string tolower [HTTP::host]] equals Shared/$srcDatagroup]
                    #if { $static::explicitHTTPS_debug } {log local0.info "[HTTP::host] uri datagroup: $get_uri_datagroup"}
                    if {[info exists get_uri_datagroup]} {
                        if {[class match "noh" equals Shared/$srcDatagroup ]} {
                            if {[class match -value "method" equals Shared/$srcDatagroup] contains [HTTP::method] } {
                                log local0. "method match"
                                #if {[HTTP::method] == "GET"} {}
                                if { $static::explicitHTTPS_debug } {log local0.debug "noh traffic provisionally allowed as request is GET method"}
                                set hsl_httpswhitelistHost "whitelistHost=\"ACCEPTED\""
                                set hsl_httpswhitelistURI "whitelistURI=\"ALLOWED\""
                                if {[class match -value "ipi" equals Shared/$srcDatagroup] contains "true"} {
                                    log local0. "IPI matched true"
                                    set ipi_match [IP::reputation [LB::server addr]]
                                    log local0. "IPI category match: $ipi_match"
                                    foreach match $ipi_match {
                                        if {[lsearch -exact $static::categoriesToBlock $match] >= 0} {
                                            set 403response 1
                                            if { $static::explicitHTTPS_debug } {log local0.debug "noh traffic denied due to IP intelligence. Destination IP address, [LB::server addr], which has been categorized as: ($ipi_match), request was rejected"}
                                            HSL::send $hslhttps "noh traffic denied due to IP intelligence. Destination IP address, [LB::server addr], which has been categorized as: ($ipi_match), request was rejected"
                                            break
                                        }
                                    }
                                }
                            }
                        }
                        elseif {[class match [string tolower [HTTP::host]] equals Shared/$srcDatagroup] && [class match [string tolower [HTTP::uri]] starts_with Shared/$get_uri_datagroup]} {
                            #if { $static::explicitHTTPS_debug } {log local0.debug "[HTTP::host] Matched whiteList"}
                            set hsl_httpswhitelistHost "whitelistHost=\"ACCEPTED\""
                            set hsl_httpswhitelistURI "whitelistURI=\"ALLOWED\""
                            #HTTP::header insert X-Real-IP [IP::remote_addr clientside]
                        }
                        else {
                            set dotIndex [string first "." $hostName 0]
                            set starHostName [string replace $hostName 0 $dotIndex "#."]
                            log local0.info "REPLACED.: $starHostName"
                            set get_uri_datagroup  [class match -value [string tolower $starHostName] equals Shared/$srcDatagroup]
                            if {[class match [string tolower $starHostName] equals Shared/$srcDatagroup] && [class match [string tolower [HTTP::uri]] starts_with Shared/$get_uri_datagroup]} {
                                #if { $static::explicitHTTPS_debug } {log local0.debug "[HTTP::host] Matched whiteList"}
                                set hsl_httpswhitelistHost "whitelistHost=\"ACCEPTED\""
                                set hsl_httpswhitelistURI "whitelistURI=\"ALLOWED\""
                                #HTTP::header insert X-Real-IP [IP::remote_addr clientside]
                            }
                            else {
                                HSL::send $hslhttps "Failed to match Host with URI"
                                set 403response 1
                            }
                        }
                    }
                    else {
                        HSL::send $hslhttps "Unable to map hostname datagroup to URI data group"
                        set 403response 1
                    }
                }
                else {
                    log local0.info "checking in shared datagroup.."
                    set sharedTrafficDatagroup [class match -value $sharedTraffic equals Shared/sharedDatagroup]
                    if {[info exists sharedTrafficDatagroup]} {
                        if { $sharedTrafficDatagroup ne "" } {
                            set hostName [getfield [string tolower [HTTP::host]] ":" 1]
                            set get_uri_datagroup  [class match -value [string tolower [HTTP::host]] equals Shared/$sharedTrafficDatagroup]
                            #if { $static::explicitHTTPS_debug } {log local0.info "[HTTP::host] uri datagroup: $get_uri_datagroup"}
                            if {[info exists get_uri_datagroup]} {
                                if {[class match [string tolower [HTTP::host]] equals Shared/$sharedTrafficDatagroup] && [class match [string tolower [HTTP::uri]] starts_with Shared/$get_uri_datagroup]} {
                                    #if { $static::explicitHTTPS_debug } {log local0.debug "[HTTP::host] Matched whiteList"}
                                    set hsl_httpswhitelistHost "whitelistHost=\"ACCEPTED\""
                                    set hsl_httpswhitelistURI "whitelistURI=\"ALLOWED\""
                                    #HTTP::header insert X-Real-IP [IP::remote_addr clientside]
                                }
                                else {
                                    set dotIndex [string first "." $hostName 0]
                                    set starHostName [string replace $hostName 0 $dotIndex "#."]
                                    log local0.info "REPLACED.: $starHostName"
                                    set get_uri_datagroup  [class match -value [string tolower $starHostName] equals Shared/$sharedTrafficDatagroup]
                                    if {[class match [string tolower $starHostName] equals Shared/$sharedTrafficDatagroup] && [class match [string tolower [HTTP::uri]] starts_with Shared/$get_uri_datagroup]} {
                                        #if { $static::explicitHTTPS_debug } {log local0.debug "[HTTP::host] Matched whiteList"}
                                        set hsl_httpswhitelistHost "whitelistHost=\"ACCEPTED\""
                                        set hsl_httpswhitelistURI "whitelistURI=\"ALLOWED\""
                                        #HTTP::header insert X-Real-IP [IP::remote_addr clientside]
                                    }
                                    else {
                                        HSL::send $hslhttps "Failed to match Host with URI in shared datagroup"
                                        set 403response 1
                                    }
                                }
                            }
                            else {
                                HSL::send $hslhttps "Unable to map hostname datagroup to URI shared data group"
                                set 403response 1
                            }
                        }
                        else {
                            HSL::send $hslhttps "Shared data group policy doesn't exist"
                            set 403response 1
                        }
                    }
                    else {
                        HSL::send $hslhttps "Shared data group policy is incorrect"
                        set 403response 1
                    }
                }
            }
        }
        else {
            HSL::send $hslhttps "Source IP data group policy doesn't exist"
            set 403response 1
        }
    }
    else {
        HSL::send $hslhttps "Unable to set variable, sourceClient. TCP option 28 header was missing or unable to decode"
        set 403response 1
    }
    if {$403response == 1} {
        set hsl_httpswhitelistURI "whitelistURI=\"NOT_EVALUATED\""
        set hsl_httpswhitelistHost "whitelistHost=\"DENIED\""
        set hsl_httpshttpResponse "httpStatus=\"403\""
        HTTP::close
        HTTP::respond 403
        HSL::send $hslhttps "$hsl_httpsclientAccept,$hsl_httpsclientsslhandshake,$hsl_httpshttpRequest,$hsl_httpshttpResponse,$hsl_httpswhitelistHost,$hsl_httpswhitelistURI"
        if { $static::explicitHTTPS_debug } { log local0.debug "$hsl_httpsclientAccept,$hsl_httpsclientsslhandshake,$hsl_httpshttpRequest,$hsl_httpshttpResponse,$hsl_httpswhitelistHost,$hsl_httpswhitelistURI"}
    }
}
when HTTP_RESPONSE {
    set contentLengthCheck 0
    if {[class match "noh" equals Shared/$srcDatagroup ]} {
        set contentLengthmin [class match -value "contentLenMin" equals Shared/$srcDatagroup ]
        set contentLengthmax [class match -value "contentLenMax" equals Shared/$srcDatagroup ]
        if {not([HTTP::header "Content-Length"] >= $contentLengthmin and [HTTP::header "Content-Length"] <= $contentLengthmax)} {
            set contentLengthCheck 1
            if { $static::explicitHTTPS_debug } { log local0.debug "Content-Length header was equal to 0 or out of specified range or not present - failed"}
            log local0.debug "Content-Length header was equal to 0 or out of specified range or not present - failed"
        }
    }
    if {$403response == 0 and $contentLengthCheck == 0} {
        set hsl_httpshttpResponse "httpStatus=\"[HTTP::status]\""
        HSL::send $hslhttps "$hsl_httpsclientAccept,$hsl_httpsclientsslhandshake,$hsl_httpshttpRequest,$hsl_httpshttpResponse,$hsl_httpswhitelistHost,$hsl_httpswhitelistURI"
        if { $static::explicitHTTPS_debug } { log local0.debug "$hsl_httpsclientAccept,$hsl_httpsclientsslhandshake,$hsl_httpshttpRequest,$hsl_httpshttpResponse,$hsl_httpswhitelistHost,$hsl_httpswhitelistURI"}
    }
    else {
        set hsl_httpswhitelistURI "whitelistURI=\"NOT_EVALUATED\""
        set hsl_httpswhitelistHost "whitelistHost=\"DENIED\""
        set hsl_httpshttpResponse "httpStatus=\"403\""
        HTTP::respond 403
        HSL::send $hslhttps "$hsl_httpsclientAccept,$hsl_httpsclientsslhandshake,$hsl_httpshttpRequest,$hsl_httpshttpResponse,$hsl_httpswhitelistHost,$hsl_httpswhitelistURI"
        if { $static::explicitHTTPS_debug } { log local0.debug "$hsl_httpsclientAccept,$hsl_httpsclientsslhandshake,$hsl_httpshttpRequest,$hsl_httpshttpResponse,$hsl_httpswhitelistHost,$hsl_httpswhitelistURI"}
    }
}