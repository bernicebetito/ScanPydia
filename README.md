# ScanPydia
_A Network Scanning Tool for Advanced and Offensive Security (NSSECU2)._\
Date Accomplished: December 15, 2020

## Uses
ScanPydia is able to do ICMP Echo Request and TCP Scans including TCP Connect Scan, TCP SYN (Half-Open) Scan, Xmas Scan, FIN Scan, Null Scan, and Ack Scan. Another feature included in ScanPydia is computing for the total time that the program executed.

## Pre-requisites
1. Python / Python3
  * Programming language used.
  * To download in **Linux**: `sudo apt-get install python3`
  * To download in **Windows**: [Python for Windows](https://www.python.org/downloads/windows/)
2. Curl
  * Command that allows the transfer (upload / download) of data using command line interface.
  * To download in **Linux**: `sudo apt-get install curl`
  * To download in **Windows**: [Curl for Windows](https://curl.se/windows/)
3. Pip
  * Tool which helps in installing packages written in Python.
  * To download in **Linux**: `sudo apt-get install pip`
  * To download in **Windows**: [Pip for Windows](https://pip.pypa.io/en/stable/installation/)
4. Scapy
  * Packet tool and library written in Python.
  * To download in **Linux**: `sudo pip install scapy`
  * To download in **Windows**: `pip install scapy`

## Download
* To download in Linux:
``` sudo curl -O https://raw.githubusercontent.com/bernicebetito/ScanPydia/main/ScanPydia.py ```
* To download in Windows:
``` curl -O https://raw.githubusercontent.com/bernicebetito/ScanPydia/main/ScanPydia.py ```

Once downloaded, ScanPydia is ready to be used. To see a full list of available commands, go to the file location and run:
- For Linux: `sudo python3 ScanPydia.py`
- For Windows: `python ScanPydia.py`

## Syntax
In Linux, the syntax for using ScanPydia is:
```
sudo python3 ScanPydia.py -<?> <positional arguments>
```

Similarly, the syntax for using ScanPydia in Windows is:
```
python ScanPydia.py -<?> <positional arguments>
```

To see the full list of available options and positional arguments, run `python ScanPydia.py` for Windows and `sudo python3 ScanPydia.py` for Linux.
