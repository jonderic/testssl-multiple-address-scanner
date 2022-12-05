# testssl-multiple-address-scanner
A Python script that automates multiple address scanning using testssl.

# Requirements
-	Linux OS
-	testssl
-	Python
-	ssl_multiple_scan.py (script file)
-	CSV files
    -	iplist.csv
    -	weak_ciphersuites.csv

# Usage
1.	First, run ```python --version``` on Terminal to make sure Python is installed. If not, run
```sudo apt-get install python```

2.	Next, check to see that testssl is installed on your Linux OS. If you do not have testssl yet, run
```git clone --depth 1 https://github.com/drwetter/testssl.sh.git```

3.	Copy ssl_multiple.scan.py, iplist.csv and weak_ciphersuites.csv into the same directory as testssl.sh in the testssl folder.

4.	For usage of the iplist.csv, each scan takes in one address per row:
    -	avoid any leading characters before the domain/IP address (http://, https://)
    
    ![example1](https://user-images.githubusercontent.com/75235391/205538286-2ecb1901-bbab-4478-9e0a-da243563960a.png) :x:
    
    -	no forward slash after the domain/IP address
    
    ![example2](https://user-images.githubusercontent.com/75235391/205537109-8b9ec975-bd4f-4853-a1a1-9ea6f9d936dd.png) :x:

5.	To begin using the script, navigate to the testssl folder and run ```python ssl_multiple_scan.py``` on Terminal.

6.	Upon finishing scanning of the address(es), each address should generate 2 new files with the same name in the same directory: 1 CSV file and 1 HTML file.

7.	The HTML file will display the full scan results, highlighting in red and flagging out insecure protocol(s) in use, as well as the weak ciphersuites used for TLS 1.2 and 1.3.

8.	For the CSV file, the results are cleaned up to only display insecure protocol(s) in use, as well as the weak ciphersuites used for TLS 1.2 and 1.3.

