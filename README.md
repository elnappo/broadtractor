# Broadtractor
**Broad**cast Ex**tractor** is a small proof of concept code to demonstrate how to extract
information's from broadcast data.

>Make sure you have permission from the network owners before running this tool. Make sure
>you check with your local laws before running this tool. Unauthorized eavesdropping can
>land you in trouble if you don't follow the rules and law. This tool is only intended to
>be a proof of concept demonstration tool for authorized security testing.
> -- <cite>UCSniff Disclaimer</cite>

## Get it running
    # on macOS only, install libdnet
    brew install libdnet

    pip3 install dnslib netaddr kamene
    python3 broadtractor.py -v -i eth0

## Sample verbose output
    INFO: Found Canon BJNP, IP: 192.168.136.124 MAC: ad:52:59:f2:8b:5a
    INFO: Found Dropbox LanSync, IP: 192.168.124.152 MAC: 8c:c7:32:fa:bf:33
    INFO: Found Spotify User, IP: 192.168.148.284 MAC: aa:da:ea:6c:18:bc
    INFO: Found LLMNR, IP: fe80::ee2e:7fff:feb1:e3f9 MAC: ec:2e:7f:b1:e3:f9 Hostname: foxdtnmw
    INFO: Found LLMNR, IP: 192.168.162.244 MAC: ec:2e:7f:b1:e3:f9 Hostname: foxdtnmw
    INFO: Found BROWSER, IP: 192.168.169.119 MAC: 4c:e9:34:b1:01:06 Hostname:
    INFO: Found mDNS, IP: 192.168.67.195 MAC: 7a:2b:75:4f:c7:c5 Hostname: Johns-MacBook-Air
    INFO: Found mDNS, IP: fe80::782b:75ff:fe4f:c7c5 MAC: 7a:2b:75:4f:c7:c5 Hostname: Johns-MacBook-Air

## Contributors
* [@elnappo](https://github.com/elnappo)
* [@MKV21](https://github.com/MKV21)
