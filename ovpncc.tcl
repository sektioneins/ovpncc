##

set alias_map {
	parameter echo
	ip-remote-hint preresolve
	server-poll-timeout connect-timeout
	udp-mtu link-mtu
	ncp-ciphers data-ciphers
	show-groups show-curves
	}

set connection_options {local connect-retry connect-timeout float link-mtu tun-mtu tun-mtu-max tun-mtu-extra max-packet-size fragment mtu-disc port lport rport bind nobind proto http-proxy http-proxy-user-pass http-proxy-option socks-proxy explicit-exit-notify mssfix key-direction remote tls-auth tls-crypt tls-crypt-v2}

set multi_options {remote ignore-unknown-option setenv echo cd plugin connection socket-flags client-nat route route-ipv6 redirect-gateway push push-reset push-remove iroute iroute-ipv6 ifconfig-push ifconfig-ipv6-push dns dhcp-option x509-track}

##

## read file and parse config
proc load_config {fn} {
	return [parse_config [read_file $fn] $fn]
}

## parse config from input data and return a list of dicts for each relevant line
proc parse_config {data {cfgfn ""} {lineno 0}} {
	set result {}
	set lines [split $data "\n"] 
	set blockname ""
	set blockdata {}
	set blockstartlineno 0
	foreach line $lines {
		incr lineno
		if {$blockname ne ""} {
			if {[string trim $line] eq "</$blockname>"} {
				lappend result [list key $blockname value $blockdata line "<$blockname>" lineno $blockstartlineno lineno $lineno cfgfn $cfgfn inlineblock 1]
				set blockname ""
				set blockdata {}
				continue
			}
			append blockdata $line \n
			continue
		}
		set line [string trim $line]

		## empty lines and comments
		if {$line eq ""} { continue }
		if {[regexp -- {^[#;]} $line]} { continue }

		if {[regexp -- {^<(.*?)>$} $line -> blockname]} {
			continue
		} elseif {![regexp -- {^(.*?)(?:\s+(.*))?$} $line -> key value]} {
			puts stderr "WARNING: unknown syntax on line $lineno: $line"
			set ::check_errors 1
			continue
		}

		## parse parameters + backslash substitution
		set p {}
		while {$value ne ""} {
			set value [string trim $value]
			if {[regexp -- {^#} $value]} {
				break
			}
			if {[regexp -- {^"((?:[^"\\]*(?:\\.)?)*)"(.*)$} $value -> p1 value] ||
				[regexp -- {^'((?:[^'\\]*(?:\\.)?)*)'(.*)$} $value -> p1 value] ||
				[regexp -- {^(.*?)(?:\s+(.*))?$} $value -> p1 value]} {
				set p1 [regsub -all -- {\\(.)} $p1 {\1}]
				lappend p $p1
				continue
			}
		}
		set value $p

		lappend result [list key $key value $value line $line lineno $lineno cfgfn $cfgfn inlineblock 0]
	}
	if {$blockname ne ""} {
		puts stderr "WARNING: missing close tag for block <$blockname> on line $blockstartlineno"
		set ::check_errors 1
	}
	return $result
}

proc add_ovpn_argv_result {opt params} {
	upvar result result
	if {$opt eq ""} { return }
	lappend result [list key $opt value $params line "--$opt [join $params]" lineno 0 cfgfn {[CMD-LINE]} inlineblock 0]
}
proc parse_ovpn_argv {argv} {
	set result {}
	set opt ""
	set params {}
	foreach arg $argv {
		if {[string range $arg 0 1] eq "--"} {
			add_ovpn_argv_result $opt $params
			set opt [string range $arg 2 end]
			set params {}
			continue
		}
		if {$opt eq ""} {
			puts stderr "invalid openvpn option '$arg' - missing '--'"
			exit 1
		}
		lappend params $arg
	}
	add_ovpn_argv_result $opt $params
	return $result
}

##

proc check_file {fn} {
	set cfgdata [load_config $fn]
	return [check_config $cfgdata]
}

## add to result list - internal function to be used within check_config
proc addresult {severity msg desc {entry {}}} {
	if {$entry eq "-"} {
		set entry {key "" value "" line "" lineno "" cfgfn ""}
	} elseif {$entry eq {}} {
		unset entry
		upvar entry entry
	}
	upvar result result
	lappend result [list severity $severity msg $msg desc $desc {*}$entry]
}

proc resolve_plugin_path {fn} {
	if {$fn eq ""} { return }
	if {[string match {/*} $fn]} { return $fn }
	if {[string match {./*} $fn]} { return $fn }
	return [file join $::params(plugin_libdir) $fn]
}

## check file and parent dir permissons for writable group/others
proc check_file_permissions_gow {fn what {rw 0}} {
	upvar entry entry result result
	if {![file readable $fn]} {
		addresult error "$what not readable" "The specified $what '$fn' does not exist or is not readable."
	} else {
		if {!$rw && ([file_mode $fn] & 0022)} {
			addresult critical "incorrect file permissions" "$what is writable by group or others. Please change file permissions."
		}
		if {$rw && ([file_mode $fn] & 0066)} {
			addresult critical "incorrect file permissions" "$what can be read or written by group or others. Please change file permissions."
		}
		if {[check_parent_dir_mode $fn 0022]} {
			addresult critical "incorrect dir permissions" "Parent directory of $what is writable by group or others."
		}
	}
}

proc map_alias {key} {
	global alias_map
	if {[dict exists $alias_map $key]} { return [dict get $alias_map $key] }
	return $key
}

## perform security check on parsed config
proc check_config {cfgdata {context global}} {
	global cfg
	set result {}

	if {$context eq "connection"} {
		incr cfg(cid)
	}

	foreach entry $cfgdata {		
		## set variables from dict: key, value, line, lineno, ...
		foreach {k v} $entry { set $k $v }
		lassign $value p1 p2 p3 p4 p5

		set key [map_alias $key]

		set cfgkey $key
		if {$context eq "connection"} {
			if {[in_list $::connection_options $key -exact]} {
				set cfgkey "connection-$cfg(cid)-$key"
			} else {
				addresult notice "global option inside connection block" "The option may be allowed inside a connection block, but is actually set globally."
			}
		}
		if {[in_list $::multi_options $key -exact]} {
			lappend cfg($cfgkey) $entry
		} else {
			if {[info exists cfg($cfgkey)]} {
				addresult notice "duplicate option" "This option overrides a previous option: [dict get $cfg($key) cfgfn] line [dict get $cfg($key) lineno]"
			}
			set cfg($cfgkey) $entry
		}

		switch -glob -- $key {
			config {
				lappend result {*}[check_file $p1]
				check_file_permissions_gow $p1 "config file"
			}
			management {
				if {$p2 eq "unix"} {
					if {$p3 eq ""} {
						addresult warning "missing password protection" "Securing the management interface with a password file is recommended."
					}
					if {[file exists $p1] && [file_mode $p1] & 0002} {
						addresult warning "file permissions / socket writable by others" "The management socket should not be writable by others. Please change file permissions."
					}
				} else {
					if {$p3 eq ""} {
						addresult critical "missing password protection" "Not securing a TCP based managament interface with a password file is insecure."
					}
					if {$p1 ne "127.0.0.1"} {
						addresult notice "non-local management interface" "The management interface is listening on an IP other than 127.0.0.1"
					}
				}
				if {$p2 ne ""} {
					if {![file readable $p2]} {
						addresult error "pw-file unreadable" "The specified password file does not exist or is not readable."
					} else {
						if {[file_mode $p2] & 0006} {
							addresult critical "file permissions / pw-file accessible by others" "A password file protecting the management interface must not be accessible (read or write) by others. Please change file permissions."
						}
						if {[check_parent_dir_mode $p2 0022]} {
							addresult critical "writable pw-file parent dir" "The pw-file dir or one of its parent directories is writable for group or others, which may lead to system compromise e.g. using symlinks. Please check and fix permissions accordingly."
						}
					}
				}
			}
			plugin {
				set plugin_file [resolve_plugin_path $p1]
				check_file_permissions_gow $plugin_file "plugin"
			}
			iproute -
			ipchange -
			up -
			down -
			route-up -
			route-pre-down -
			auth-user-pass-verify -
			client-connect -
			client-crresponse -
			client-disconnect -
			learn-address -
			tls-verify -
			tls-crypt-v2-verify {
				set cmd $p1
				## strip optional cmd arguments
				regexp -- {^((?:\\.|[^\\])+)\s} $cmd -> cmd
				check_file_permissions_gow $cmd "$key cmd"
			}
			connection {
				set connection_block [parse_config $value $cfgfn $lineno]
				if {$::check_errors} {
					addresult error "invalid connection block" "Error parsing connection block"
				} else {
					lappend result {*}[check_config $connection_block connection]
				}
				set ::check_errors 0
			}
			ignore-unknown-option {
				lappend cfg($key) {*}$value
			}
			setenv {
				if {$p1 eq "opt" && $p2 ne ""} {
					lappend cfg(ignore-unknown-option) $p2
				}
			}
			gremlin {
				addresult notice "debug option enabled" "This option should only be used for debugging."
			}
			cd {
				cd $value
			}
			writepid -
			log -
			log-append -
			memstats -
			status -
			ifconfig-pool-persist -
			replay-persist {
				set dir [file dirname $p1]
				if {![file isdirectory $dir]} {
					addresult error "invalid directory" "directory '$dir' does not exist"
				} elseif {[check_parent_dir_mode $p1 0022]} {
					addresult critical "writable $key parent dir" "The $key dir or one of its parent directories is writable for group or others, which may lead to system compromise e.g. using symlinks. Please check and fix permissions accordingly."
				}
			}
			script-security {
				if {$p1 ne "" && [string is integer $p1] && $p1 > 1} {
					addresult info "permissive script-security" "script-security is set to $p1, which is more than the default (1), allowing the use of user-defined scripts."
				}
			}
			connect-freq -
			connect-freq-initial {
				if {[string is integer $p1] && [string is integer $p2] && $p1/$p2 > 500} {
					addresult notice "high connect-freq" "The maximum number of connections per second is set rather high."
				}
			}
			max-clients {
				if {[string is integer $p1] $p1 > 1000} {
					addresult notice "high max-clients" "The maximum number of concurrent clients is set rather high."
				}
			}
			max-routes-per-client {
				## default 256
				if {[string is integer $p1] $p1 > 512} {
					addresult notice "high routes-per-client" "The maximum number of internal routes per client is set rather high. This may be overridden in a ccd file."
				}
			}
			client-cert-not-required -
			verify-client-cert {
				if {$key eq "client-cert-not-required" || $p1 ne "require"} {
					addresult notice "inactive client certificate validation" "The entire security of your VPN's authentication is based on --auth-user-pass-verify. Please consider using client certificates in addition."
				}
			}
			auth-user-pass-optional {
				addresult info "providing user/pass is optional" "The authentication script or plugin must validate a user by other means, likely certificate fields."
			}
			auth-gen-token {
				if {[$p1 eq ""] || $p1 == 0} {
					addresult warning "token never expires" "Once authenticated, the auth token generated by the server never expires. This value should be set no a reasonable value, e.g. 86400 (1 day) or 43200 (1/2 day)"
				}
			}
			ca -
			cert -
			dh -
			extra-certs -
			key -
			pkcs12 -
			secret -
			crl-verify -
			http-proxy-user-pass -
			tls-auth -
			auth-gen-token-secret -
			peer-fingerprint -
			tls-crypt -
			tls-crypt-v2 -
			verify-hash -
			askpass {
				if {!$inlineblock && $p1 ne ""} {
					check_file_permissions_gow $p1 $key 1
				}
			}
			tmp-dir {
				if {![file isdirectory $p1]} {
					addresult error "$key not found" "The $key '$p1' does not exist."
				} elseif {[check_parent_dir_mode "$p1/x" 0006]} {
					addresult critical "incorrect dir permissions" "dir or parent dir can be read or written by others. Please fix permissions."
				}
			}
			capath -
			tls-export-cert {
				if {![file isdirectory $p1]} {
					addresult error "$key not found" "The $key '$p1' does not exist."
				} elseif {[check_parent_dir_mode "$p1/x" 0022]} {
					addresult critical "incorrect dir permissions" "dir or parent dir can be written by group or others. Please fix permissions."
				}
			}
			client-config-dir {
				if {![file isdirectory $p1]} {
					addresult error "client-config-dir not found" "The client-config-dir '$p1' does not exist."
				} else {
					if {[check_parent_dir_mode "$p1/x" 0006]} {
					addresult critical "incorrect dir permissions" "dir or parent dir can be read or written by others. Please fix permissions."
					}
					foreach fn [glob -types {f l} -- $p1] {
						if {[check_mode $fn] & 0022} {
							addresult critical "incorrect file permissions" "'$fn' is writable by group or others. Please change file permissions."
						}
						if {![file readable $fn]} {
							addresult error "cannot read ccd file" "Connecting with ccd file '$fn' will fail."
						} else {
							set ccdcfg [load_config $fn]
							if {$::check_errors} {
								addresult error "invalid connection block" "Error parsing connection block"
							} else {
								lappend result {*}[check_ccd $connection_block]
							}
							set ::check_errors 0
						}
					}
				}
			}
			port-share {
				if {$p3 ne "" && [file isdirectory $p3]} {
					if {[check_parent_dir_mode "$p3/x" 0002]} {
						addresult critical "incorrect dir permissions" "dir or parent dir can be written by others. Please fix permissions."
					}
				}
			}
			push -
			push-reset -
			push-remove -
			iroute -
			iroute-ipv6 -
			ifconfig-push -
			ifconfig-ipv6-push -
			vlan-pvid -
			disable {
				addresult error "ccd config in other context" "This option should only be used in within a client-config-dir file. This is likely a configuration mistake."
			}
			auth-token {
				addresult error "push option in other context" "This option is supposed to be pushed using client-connect/plugin only."
			}
			auth-user-pass {
				if {$p1 ne "" && [file exists $p1]} {
					if {[check_mode $p1] & 0044} {
						addresult warning "bad password file permissions" "The $key file is readable by group or others. Please fix permissions."
					}
				}
			}
			auth {
				if {$p1 eq "none"} {
					addresult critical "HMAC authentication disabled" "This should always remain enabled."
				}
			}
			cipher {
				addresult notice "deprecated option" "This option should only be used for compatibility with older versions. Use 'data-ciphers' (or 'ncp-ciphers' before OpenVPN 2.5) instead."
				if {$p1 eq "none"} {
					addresult critical "encryption disabled" "This should always remain enabled."
				}
			}
			data-ciphers {
				set ciphers [regexp -all -inline -- {[^:?]+} $p1]
				set deprecated_ciphers [lsearch -all -inline -regexp $ciphers {^(BF-|CAST5-|DES|IDEA|RC2)}]
				if {[llength $deprecated_ciphers]} {
					addresult critical "deprecated ciphers in use" "The following ciphers are enabled and should not be used anymore: [join $deprecated_ciphers {:}]"
				}
			}
			use-prediction-resistance {
				addresult info "using prediction resistance" "Reseeding the RNG often may result in less kernel entropy."
			}
			msg-channel -
			win-sys -
			ip-win32 -
			show-adapters -
			show-net -
			show-net-up -
			tap-sleep -
			dhcp-renew -
			dhcp-pre-release -
			dhcp-release -
			dhcp-internal -
			register-dns -
			block-outside-dns -
			rdns-internal -
			show-valid-subnets -
			pause-exit -
			service -
			allow-nonadmin -
			comp-noadapt {
				## windows-only options
				if {![string match -nocase {windows*} $::tcl_platform(os)]} {
					addresult notice "incompatible option" "Use of Windows-only option detected on non-Windows system."
				}
			}
			allow-compression -
			comp-lzo -
			compress {
				if {$key eq "compress" && ![in_list {migrate stub stub-v2} $p1 -exact] ||
					[in_list {allow-compression comp-lzo} $key -exact] && $p1 ne "no"} {
					addresult critical "compression enabled" "VPN tunnels which use compression are susceptible to the VORALCE attack vector."
				}
			}
			tls-version-min {
				lassign [split $p1 .] vmajor vminor
				if {$vmajor < 1 || $vmajor == 1 && $vminor < 2} {
					addresult warning "old TLS version configured" "Please upgrade SSL library and change to at least TLS 1.2"
				}
			}
			tls-version-max {
				addresult notice "maximum TLS version set" "This option is set to the highest supported version by default. No need to change things here."
			}
			tls-cipher -
			tls-ciphersuites {
				## there should probably be a check for weak TLS ciphers here, but the
				## pre-selection listed with --show-tls already looks pretty solid on
				## my system
			}
			tls-cert-profile {
				if {$p1 eq "legacy" || $p1 eq "insecure"} {
					addresult notice "almost deprecated $key" "Please consider using cert profile 'preferred' or 'suiteb'."
				}
			}
			hand-window {
				if {$p1 ne "" && [string is integer $p1] && $p1 > 60} {
					addresult notice "TLS handshake window rather long" "The TLS handshake should be complete within 60 seconds"
				}
			}
			tran-window {
				if {$p1 ne "" && [string is integer $p1] && $p1 > 3600} {
					addresult notice "TLS transition window big" "The TLS transition window should to exceed 3600 unless there is a good reason"
				}
			}
			show-ciphers -
			show-digests -
			show-tls -
			show-engines -
			show-curves -
			genkey -
			test-crypto -
			show-pkcs11-ids -
			rmtun -
			mktun -
			help -
			version {
				## found standalone option in config file
				## could have been passed via command line -> do nothing
			}
			show-gateway -
			echo -
			management-* -
			mode -
			dev -
			dev-type -
			windows-driver -
			disable-dco -
			dev-node -
			lladdr -
			topology -
			tun-ipv6 -
			ifconfig -
			ifconfig-ipv6 -
			ifconfig-noexec -
			ifconfig-nowarn -
			local -
			remote-random -
			http-proxy-override -
			remote -
			resolv-retry -
			preresolve -
			connect-retry -
			connect-timeout -
			connect-retry-max -
			float -
			chroot -
			setcon -
			down-pre -
			up-delay -
			up-restart -
			syslog -
			daemon -
			suppress-timestamps -
			machine-readable-output -
			mlock -
			multihome -
			verb -
			mute -
			errors-to-stderr -
			status-version -
			remap-usr1 -
			link-mtu -
			tun-mtu -
			tun-mtu-max -
			tun-mtu-extra -
			max-packet-size -
			mtu-dynamic -
			fragment -
			mtu-disc -
			mtu-test -
			nice -
			rcvbuf -
			sndbuf -
			mark -
			socket-flags -
			bind-dev - 
			txqueuelen -
			shaper -
			port -
			lport -
			rport -
			bind -
			nobind -
			fast-io -
			inactive -
			session-timeout -
			proto -
			proto-force -
			http-proxy -
			http-proxy-* -
			socks-proxy -
			keepalive -
			ping -
			ping-exit -
			ping-restart -
			ping-timer-rem -
			explicit-exit-notify -
			persist-* -
			client-nat -
			route -
			route-ipv6 -
			max-routes -
			route-gateway -
			route-ipv6-gateway -
			route-metric -
			route-delay -
			route-noexec -
			route-nopull -
			pull-filter -
			allow-pull-fqdn -
			redirect-gateway -
			redirect-private -
			block-ipv6 -
			remote-random-hostname -
			compat-mode -
			setenv-safe -
			mssfix -
			disable-occ -
			server -
			server-ipv6 -
			server-bridge -
			ifconfig-pool -
			ifconfig-ipv6-pool -
			hash-size -
			username-as-common-name -
			opt-verify -
			bcast-buffers -
			tcp-queue-limit -
			client-to-client -
			duplicate-cn -
			ifconfig-push-constraint -
			tcp-nodelay -
			stale-routes-check -
			client -
			pull -
			push-continuation -
			auth-retry -
			static-challenge -
			dns -
			dhcp-option -
			route-method -
			user -
			group -
			passtos -
			key-direction -
			ncp-disable -
			protocol-flags -
			prng -
			no-replay -
			replay-window -
			mute-replay-warnings -
			engine -
			providers -
			ecdh-curve -
			tls-server -
			tls-client -
			verify-hash -
			peer-fingerprint -
			auth-nocache -
			auth-token-user -
			single-session -
			push-peer-info -
			tls-exit -
			tls-groups -
			compat-names -
			no-name-remapping -
			verify-x509-name -
			ns-cert-type -
			remote-cert-ku -
			remote-cert-eku -
			remote-cert-ku -
			remote-cert-tls -
			tls-timeout -
			reneg-bytes -
			reneg-pkts -
			reneg-sec -
			x509-track -
			x509-username-field -
			pkcs11-providers -
			pkcs11-protected-authentication -
			pkcs11-private-mode -
			pkcs11-cert-private -
			pkcs11-pin-cache -
			pkcs11-id -
			pkcs11-id-management -
			peer-id -
			keying-material-exporter -
			allow-recursive-routing -
			vlan-tagging -
			vlan-accept -
			vlan-pvid {
				## nothing to do here
			}

			default {
				if {![info exists cfg(ignore-unknown-option)] || ![in_list $cfg(ignore-unknown-option) $key -exact]} {
					addresult warning "unknown option '$key'" "This may be a typo in the configuration or it may be an unsupported feature of an old, new or custom OpenVPN version"
				}
			}

		}
	}

	return $result
}

proc check_ccd {cfgdata} {
	set result {}
	global cfg

	foreach entry $cfgdata {		
		## set variables from dict: key, value, line, lineno, ...
		foreach {k v} $entry { set $k $v }
		lassign $value p1 p2 p3 p4 p5

		set key [map_alias $key]

		switch -glob -- $key {
			allow-compression -
			comp-lzo -
			compress {
				## compression options within ccd files may or may not be allowed. better check anyway.
				if {$key eq "compress" && ![in_list {migrate stub stub-v2} $p1 -exact] ||
					[in_list {allow-compression comp-lzo} $key -exact] && $p1 ne "no"} {
					addresult critical "compression enabled" "VPN tunnels which use compression are susceptible to the VORALCE attack vector."
				}
			}
			max-routes-per-client -
			session-timeout -
			push -
			push-reset -
			push-remove -
			iroute -
			iroute-ipv6 -
			ifconfig-push -
			ifconfig-ipv6-push -
			vlan-pvid -
			disable {
				## seems ok. do nothing.
			}
			default {
				if {![info exists cfg(ignore-unknown-option)] || ![in_list $cfg(ignore-unknown-option) $key -exact]} {
					addresult warning "unexpected ccd option '$key'" "This may be a typo in the configuration or it may be an unsupported feature of an old, new or custom OpenVPN version"
				}
			}

		}
	}

	return $result
}

## perform extra checks after collecting all the config data
proc check_extra {} {
	if ($::params(nx)) { return }
	global cfg
	global result

	set server 1
	if {[info exists cfg(client)] || [info exists cfg(remote)] || [info exists cfg(cid)]} { set server 0 }

	if {$server} {
		if {![info exists cfg(connect-freq)]} {
			addresult info "connect-freq unset" "Consider setting 'connect-freq' as DoS protection." -
		}
		if {![info exists cfg(max-clients)]} {
			addresult info "max-clients unset" "Consider setting 'max-clients' as DoS protection." -
		}
		if {[info exists cfg(auth-user-pass-verify)]} {
			lassign [dict get $cfg(auth-user-pass-verify) value] p1 p2
			set tmpdir ""
			if {[info exists cfg(tmp-dir)]} {
				set tmpdir $cfg(tmp-dir)
			} elseif {[info exists ::env(TMPDIR)]} {
				set tmpdir $::env(TMPDIR)
			}
			if {$p2 eq "via-file" && $tmpdir ne "/dev/shm"} {
				addresult info "insecure password storage" "Consider using /dev/shm as file path" $cfg(auth-user-pass-verify)
			}
		}
		if {[info exists cfg(client-config-dir)] && ![info exists cfg(ccd-exclusive)]} {
			addresult info "missing ccd file ignored" "Consider setting ccd-exclusive to ensure a ccd file exists for each user." -
		}
		if {![string match -nocase {windows*} $::tcl_platform(os)]} {
			if {![info exists cfg(chroot)]} {
				addresult info "missing chroot" "Consider using chroot for filesystem jailing." -
			}
		}
	}

	if {![info exists cfg(tls-auth)]} {
		addresult info "missing tls-auth" "Consider adding tls-auth HMAC signature to protect against DoS, port scanning and TLS implementation problems." -
	}

	if {![info exists cfg(user)] || [lindex [dict get $cfg(user) value] 0] eq "root" || ![info exists cfg(group)]} {
		addresult info "missing user or group" "Consider adding user/group to drop privileges." -
	}

}

##

print_banner

set options {
	{plugin_libdir.arg "/usr/lib/openvpn/plugins" "plugin search path"}
	{csv.arg "" "save results to CSV file"}
	{noout "do not print results"}
	{nc "no color output on tty"}
	{nx.secret "do not perform extra checks/recommendations"}
}

set usage ": $argv0 \[options] -- \[openvpn-options] \noptions:"
try {
	array set params [::cmdline::getoptions argv $options $usage]
} on error {result} {
	puts $result
	puts "example usage:"
	puts "  $argv0 -- --config /etc/openvpn/server.conf"
	puts ""
	exit 1
}

init_color_output

if {[llength $argv] == 0} {
	puts stderr "no openvpn config file or option provided. please use --config <file>"
	exit 1
}

## SCAN

set ::check_errors 0
array set ::cfg {}
set ::result [check_config [parse_ovpn_argv $argv]]
check_extra


## OUTPUT

if {$check_errors} {
	putx "NOTE: There were errors during processing. Please check your configuration file for syntax errors."
}

if {!$params(noout)} {
	puts "\n## RESULTS ##\n"
	if {[llength $result] == 0} {
		putx "no results."
	} else {
		set resultno 0
		foreach severity {critical warning notice info} {
			foreach entry [lsearch -all -inline -index 1 -exact $result $severity] {
				foreach k {msg desc key value cfgfn line lineno} {
					set $k [dict get $entry $k]
				}
				# 
				incr resultno
				puts "[c bold]($resultno)[c reset] \[[c $severity][string toupper $severity][c default]\] [c bold]$msg[c reset]"
				if {$cfgfn ne ""} {
					putx "[c italic]#> $cfgfn LINE $lineno: $line[c reset]" 4
				}
				putx $desc 4
				puts ""
			}
		}
	}
}

## CSV output
csv_output $params(csv) $result

puts "done."
if {$check_errors} { exit 1 }
