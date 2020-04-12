## dhcpchecker
# Work in progress
Checks for dhcpv4 offers using desiderate MAC address

Usage:

Single mac test

```dhcpchecker single-mac --ifname <interface_name> --mac <mac_to_test> --expected-ip <excpected_ip>```

Multiple mac test

```dhcpchecker multiple-mac --ifname <interface_name> --config-file <config_file>```

A sample config file can be obtained with:

```dhcpchecker sample-config```


# Pcap is required

On Centos 8: dnf --enablerepo=PowerTools install libpcap-devel

# If running inside virtual machine on oVirt install the macspoof hook