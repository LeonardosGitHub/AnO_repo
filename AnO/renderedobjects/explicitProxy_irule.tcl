when RULE_INIT {
    set static::allowProxyV1 0
    set static::allowProxyV2 1
    set static::allowNoProxy 0
    set static::explicitProxy_debug 1; # if this is set to 1 additional conditional logging will be enabled.
}

when CLIENT_ACCEPTED {
    set hslproxy [HSL::open -proto TCP -pool Shared/telemetry_pool]
    set hsl_proxyclientAccept "logType=\"proxyLog\",eventTimestamp=\"[clock format [clock seconds] -format "%a, %d %h %Y %T GMT" -gmt 1]\",bigipHostname=\"$static::tcl_platform(machine)\",clientIp=\"[IP::remote_addr clientside]\",clientPort=\"[TCP::client_port]\",proxyIp=\"[IP::local_addr clientside]\",proxyPort=\"[TCP::local_port clientside]\",virtualName=\"[virtual name]\",bytesToClient=\"[IP::stats bytes out]\",bytesToProxy=\"[IP::stats bytes in]\""
    TCP::collect
}
when SERVER_INIT {
    if {[info exists v2_sourceAddress]}{
        scan $v2_sourceAddress {%d.%d.%d.%d.} a b c d
        if {$custHttpHeader != ""} {
            scan $custHttpHeader {%[^:]:%[^:]:%s} 6a 6b 6c
            TCP::option set 28 [binary format cccccH12 {1} $a $b $c $d $6a$6b$6c] all
        }
        else {
            TCP::option set 28 [binary format ccccc {1} $a $b $c $d] all
        }
    }
}
when CLIENT_DATA {
    binary scan [TCP::payload 12] H* v2_protocol_sig
    if {$static::allowProxyV1 && [TCP::payload 0 5] eq "PROXY"} {
        set proxy_string [TCP::payload]
        set proxy_string_length [expr {[string first "\r" [TCP::payload]] + 2}]
        scan $proxy_string {PROXY TCP%s%s%s%s%s} tcpver srcaddr dstaddr srcport dstport
        if { $static::explicitProxy_debug } {log local0.debug "Proxy Protocol v1 conn from [IP::client_addr]:[TCP::client_port] for an IPv$tcpver stream from Src: $srcaddr:$srcport to Dst: $dstaddr:$dstport"}
        TCP::payload replace 0 $proxy_string_length ""
    } elseif {$static::allowProxyV2 && $v2_protocol_sig eq "0d0a0d0a000d0a515549540a"}{
        binary scan [TCP::payload] @12H* v2_proxyheaderremainder
        binary scan [TCP::payload] @12H2H* v2_verCommand v2_remainder
        if {$v2_verCommand == 21}{
            binary scan [TCP::payload] @13H2 v2_addressFamilyTransportProtocol
            if {$v2_addressFamilyTransportProtocol == 11} {
                binary scan [TCP::payload] @16ccccccccSS v2_sourceAddress1 v2_sourceAddress2 v2_sourceAddress3 v2_sourceAddress4 v2_destAddress1 v2_destAddress2 v2_destAddress3 v2_destAddress4 v2_sourcePort1 v2_destPort1
                set v2_sourceAddress "[expr {$v2_sourceAddress1 & 0xff}].[expr {$v2_sourceAddress2 & 0xff}].[expr {$v2_sourceAddress3 & 0xff}].[expr {$v2_sourceAddress4 & 0xff}]"
                set v2_destAddress "[expr {$v2_destAddress1 & 0xff}].[expr {$v2_destAddress2 & 0xff}].[expr {$v2_destAddress3 & 0xff}].[expr {$v2_destAddress4 & 0xff}]"
                set v2_sourcePort [expr {$v2_sourcePort1 & 0xffff}]
                set v2_destPort [expr {$v2_destPort1 & 0xffff}]
                if { $static::explicitProxy_debug } { log "Proxy Protocol v2 conn from [IP::client_addr]:[TCP::client_port] for an IPv4 Stream from Src: $v2_sourceAddress:$v2_sourcePort to Dst: $v2_destAddress:$v2_destPort"}
    			binary scan [TCP::payload] @14S address_size
    			set skip_bytes [expr 16 + $address_size]
                TCP::payload replace 0 $skip_bytes ""
            } elseif {$v2_addressFamilyTransportProtocol == 21} {
                binary scan [TCP::payload] @16H4H4H4H4H4H4H4H4 v2_v6sourceAddress1 v2_v6sourceAddress2 v2_v6sourceAddress3 v2_v6sourceAddress4 v2_v6sourceAddress5 v2_v6sourceAddress6 v2_v6sourceAddress7 v2_v6sourceAddress8
                binary scan [TCP::payload] @32H4H4H4H4H4H4H4H4 v2_v6destAddress1 v2_v6destAddress2 v2_v6destAddress3 v2_v6destAddress4 v2_v6destAddress5 v2_v6destAddress6 v2_v6destAddress7 v2_v6destAddress8
                binary scan [TCP::payload] @48SS v2_v6sourcePort1 v2_v6destPort1
                set v2_v6sourcePort [expr {$v2_v6sourcePort1 & 0xffff}]
                set v2_v6destPort [expr {$v2_v6destPort1 & 0xffff}]
                set v2_v6sourceAddress "$v2_v6sourceAddress1:$v2_v6sourceAddress2:$v2_v6sourceAddress3:$v2_v6sourceAddress4:$v2_v6sourceAddress5:$v2_v6sourceAddress6:$v2_v6sourceAddress7:$v2_v6sourceAddress8"
                set v2_v6destAddress "$v2_v6destAddress1:$v2_v6destAddress2:$v2_v6destAddress3:$v2_v6destAddress4:$v2_v6destAddress5:$v2_v6destAddress6:$v2_v6destAddress7:$v2_v6destAddress8"
                if { $static::explicitProxy_debug } { log "Proxy Protocol v2 conn from from [IP::client_addr]:[TCP::client_port] for an IPv6 Stream from Src: $v2_v6sourceAddress:$v2_v6sourcePort to Dst: $v2_v6destAddress:$v2_v6destPort"}
    			binary scan [TCP::payload] @14S address_size
    			set skip_bytes [expr 16 + $address_size]
                TCP::payload replace 0 $skip_bytes ""
            } else {
                if { $static::explicitProxy_debug } {log local0.crit "v2_proxy conn from [IP::client_addr]:[TCP::client_port] - possible unknown/malformed transportProtocol or addressFamily"}
                reject
            }
        } elseif {$v2_verCommand == 20}{
            if { $static::explicitProxy_debug } { log "Proxy Protocol v2 and LOCAL command from [IP::client_addr]:[TCP::client_port]; skipping"}
			binary scan [TCP::payload] @14S address_size
			set skip_bytes [expr 16 + $address_size]
            TCP::payload replace 0 $skip_bytes ""
            binary scan [TCP::payload] H* local_remainder
        } else {
            if { $static::explicitProxy_debug } {log local0.crit "Proxy Protocol Protocol Signature Detected from [IP::client_addr]:[TCP::client_port] but protocol version and command not legal; connection reset"}
            reject
        }
    } elseif {$static::allowNoProxy} {
        if { $static::explicitProxy_debug } { log local0.crit "Connection from [IP::client_addr]:[TCP::client_port] allowed despite lack of PROXY protocol header"}
    } else {
        reject
        log local0.crit "Connection rejected from [IP::client_addr]:[TCP::client_port] due to lack of PROXY protocol header"
        if { $static::explicitProxy_debug } {log local0.debug "TCP payload: [TCP::payload]"}
    }
    TCP::release
}
when HTTP_PROXY_REQUEST {
    set 403response 0
    set sharedTraffic "shared"
    if {[HTTP::host] == ""} {
        HTTP::header replace Host [HTTP::uri]
        }
    set hsl_proxyhttpProxyReq "url=\"[getfield [HTTP::host] ":" 1]\",portReqByClient=\"[URI::port [HTTP::uri]]\",httpHost=\"[HTTP::uri]\",httpMethod=\"[HTTP::method]\",httpVersion=\"[HTTP::version]\""
    set hostPort [getfield [HTTP::host] ":" 2]
    set custHttpHeader [HTTP::header value "proxyUUID"]
    if {[string trim $hostPort] != ""} {
        # Port is part of the HOST header, no action is needed
    } else {
        set hostPort 443
        # This is being done to handle a scenario related to form3 where in the CONNECT phase the
        # HOST does not have the port information provided as required by the RFC: https://tools.ietf.org/html/rfc7231#section-4.3.6
        if { $static::explicitProxy_debug } { log local0.warning "Host port is null. Setting it to 443 for host: [getfield [string tolower [HTTP::host]] ":" 1]"}
    }
    #Use custom header if not use IP address
    if { $custHttpHeader != ""} {
       set sourceClient $custHttpHeader
       set customHeader 1
    }
    else {
       set sourceClient $v2_sourceAddress
       set customHeader 0
    }

    # 1. Check if sourceClient exists
    # 2. Check if customHeader exists, if yes set the srcDatagroup
    # 3. If no, then check if the hostname exists in Shared/explicitPxy_bypass
    # 4. If no, then check if the hostname exists in the Shared/shared_datagroup
    # 5. If no, then check if the sourceClient exists in the shared cidr datagroup (srcipToDatagroup)

    if {[info exists sourceClient]} {

        set whitelistHostAccepted "whitelistHost=\"ACCEPTED\""

        if { $static::explicitProxy_debug } {log local0.debug "source variable HTTPS: $sourceClient"}

        if {$customHeader == 1} {
            set srcDatagroup [class match -value $sourceClient equals Shared/proxyFilterHeaderToDatagroup]
        } else {
            set srcDatagroup [class match -value $sourceClient equals Shared/srcipToDatagroup]
        }

        if { ([HTTP::uri] contains "jndi:ldap") || ([HTTP::uri] contains "jndi%3Aldap") } {

            set 403response 1
            set hsl_proxywhitelistHost "whitelistHost=\"DENIED due to LDAP request\""
            HSL::send $hslproxy "Apache Log4j vulnerability prevention fix."
        } else {
            if { $static::explicitProxy_debug } {log local0.info "checking in explicitPxy_bypass and shared datagroups"}

            set hostName [getfield [string tolower [HTTP::host]] ":" 1]
            set dotIndex [string first "." $hostName 0]
            set starHostName [string replace $hostName 0 $dotIndex "#."]
            log local0.info "REPLACED: $starHostName"

            set sharedTrafficDatagroup [class match -value $sharedTraffic equals Shared/sharedDatagroup]

            if {[class match $hostName equals Shared/explicitPxy_bypass ]} {
                set hsl_proxywhitelistHost $whitelistHostAccepted
                set hsl_proxywhitelistHost "explicitPxy_bypass=\"True\""
            } elseif {[catch $sharedTrafficDatagroup] && ($hostPort == 443 or $hostPort > 1024) && ([class match $hostName equals Shared/$sharedTrafficDatagroup ] || [class match $starHostName equals Shared/$sharedTrafficDatagroup ])} {
                set hsl_proxywhitelistHost $whitelistHostAccepted
            } elseif {[catch $srcDatagroup] && ($hostPort == 443 or $hostPort > 1024)} {

                if {[class match [getfield [string tolower [HTTP::host]] ":" 1] equals Shared/$srcDatagroup ]} {
                    set hsl_proxywhitelistHost $whitelistHostAccepted
                } elseif {[class match $starHostName equals Shared/$srcDatagroup ]} {
                    set hsl_proxywhitelistHost $whitelistHostAccepted
                } else {
                    set 403response 1
                    HSL::send $hslproxy "A mapping of source IP to datagroup was not found, responding with 403"
                }
            } else {
                set 403response 1
            }

        }
    } else {
        set 403response 1
        HSL::send $hslproxy "The Proxy v2 iRule did not produce a source IP, unable to allow traffic, responding with 403"
    }
    if {$403response == 1} {
        if { $static::explicitProxy_debug } { log local0.info "Hostname: [ getfield [HTTP::host] ":" 1]"}
        if { $static::explicitProxy_debug } {log local0. "Port: [ getfield [HTTP::host] ":" 2]"}
        if { $static::explicitProxy_debug } { log local0. "$hsl_proxyclientAccept : $hsl_proxyhttpProxyReq"}
        HTTP::close
        HTTP::respond 403
        set hsl_proxywhitelistHost "whitelistHost=\"DENIED\""
    }
    HSL::send $hslproxy "$hsl_proxyclientAccept,$hsl_proxyhttpProxyReq,$hsl_proxywhitelistHost"
    #if { $static::explicitProxy_debug } { log local0. "$hsl_proxyclientAccept,$hsl_proxyhttpProxyReq,$hsl_proxywhitelistHost"}
}