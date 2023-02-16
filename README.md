OpenVPN Security Config Checker
================================

About
-----
OVPNCC checks your openvpn server or client configuration file for security improvements. This is usually done on the live system running openvpn in order to check for file permissions and OS specific features.

Compatibility
-------------
OVPNCC was written with **OpenVPN 2.6** as a reference, but should work mostly fine with older 2.x versions. Please leave a Github issue if you encounter any problems.

Requirements
------------

* working openvpn configuration
* Tcl version 8.6 (or later)
* tcllib

Example usage
-------------

CLI help:
```
------------------------------------------------------------------------------
OpenVPN Security Config Checker v0.1dev1
  (c) 2023 SektionEins GmbH / Ben Fuhrmannek - https://sektioneins.de/
  https://github.com/sektioneins/ovpncc
running on Darwin 22.2.0 x86_64 with Tcl 8.6 with TTY
started at 2023-02-16 14:15:44
------------------------------------------------------------------------------
ovpncc : ./ovpncc [options] -- [openvpn-options]
options:
 -plugin_libdir value plugin search path </usr/lib/openvpn/plugins>
 -csv value           save results to CSV file <>
 -noout               do not print results
 -nc                  no color output on tty
 --                   Forcibly stop option processing
 -help                Print this message
 -?                   Print this message

example usage:
  ./ovpncc -- --config /etc/openvpn/server.conf
```

Simple client config check on MacOS/Tunnelblick:
```
$ ./ovpncc -- --config ~/Library/openvpn/vpntest.tblk/Contents/Resources/config.ovpn
------------------------------------------------------------------------------
OpenVPN Security Config Checker v0.1dev1
  (c) 2023 SektionEins GmbH / Ben Fuhrmannek - https://sektioneins.de/
  https://github.com/sektioneins/ovpncc
running on Darwin 22.2.0 x86_64 with Tcl 8.6 with TTY
started at 2023-02-16 14:19:46
------------------------------------------------------------------------------

## RESULTS ##

(1) [INFO] missing tls-auth
    Consider adding tls-auth HMAC signature to protect against DoS, port
    scanning and TLS implementation problems.

(2) [INFO] missing user or group
    Consider adding user/group to drop privileges.

done.
```
