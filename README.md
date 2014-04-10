# Heartbleed OpenVPN test script

## Description

This is a test script to test OpenVPN server for CVE-2014-0160 vulnerability. The script tries to connect to the server, while doing so it will send a modified heartbeat request.

## Installation

Its a python script which needs Python 2, check your Distro of choice. To use it, simply clone it from Github
`git clone https://github.com/falstaff84/heartbleed_test_openvpn.git`

## Usage

Call the script with the target server as argument. In case the server is vulnerable, you will receive a message similar to this:

```
$ ./heartbleed_test_openvpn.py my.server.com
my.server.com|VULNERABLE

0000 18 03 01 10 13 02 10 00 48 65 61 72 74 62 6C 65 ........Heartble
0010 65 64 20 74 65 73 74 20 70 61 79 6C 6F 61 64 E2 ed test payload.
0020 0B 9E 38 34 EC 3D 66 2B 9C D5 63 00 00 68 C0 14 ..84.=f+..c..h..
0030 C0 0A 22 C0 C0 21 00 39 00 38 00 88 00 87 C0 0F ...".!.9.8......
0040 C0 05 00 35 00 84 C0 21 C4 08 1C 1C C0 1B 00 16 ...5............
0050 00 13 C0 0D C0 03 00 0A C0 13 C0 09 C0 1F C0 1E ................
0060 00 00 00 32                                     ...2
```

The script currently supports ***UDP*** only. It connects to the default port 1194, but this can be changed using the command line option `--port`.

