import csv
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import subprocess
import os
import pandas as pd

weak_ciphersuites=[] #empty list to store weak ciphersuites

#read weak ciphersuites from csv and store into empty list, to be used for matching later and flagging
with open('weak_ciphersuites.csv') as csvfile:
    reader = csv.reader(csvfile, delimiter=',')
    for row in reader: # each row is a list
        weak_ciphersuites.append(row[0])

#MAIN SCAN
print("SSL/TLS Multiple Address Scanning")
iplist="iplist.csv"
with open(iplist) as csv_file:
    csv_reader = csv.reader(csv_file, delimiter=',')
    for row in csv_reader:
        #begins scanning, outputs html file
        subprocess.call(['./testssl.sh','-E','--quiet','--protocols','--mapping=no-openssl','--htmlfile',row[0]+'_scan.html','--csvfile',row[0]+'_scan.csv',row[0]])
        htmlfile=open(row[0]+'_scan.html', 'r')
        linelist=htmlfile.readlines()
        htmlfile.close()
        os.remove(row[0]+'_scan.html')
        htmlfile2=open(row[0]+'_scan.html','w')
        for line in linelist:
            if any(e in line for e in weak_ciphersuites):
                markedline = '<mark style="background: #FF0000">' + line + '</mark>'
                changedline = line.replace(line, markedline)
                htmlfile2.write(changedline)
            else:
                htmlfile2.write(line)
        
        f = pd.read_csv(row[0]+'_scan.csv', encoding= 'unicode_escape')
        #removes tested (secure) protocol rows via specified strings
        f = f[(f.iloc[:, 3]!="INFO") & (f.iloc[:, 4]!="http/1.1") & (f.iloc[:, 4]!="No 128 cipher limit bug") & (f.iloc[:, 4]!="not offered") & (f.iloc[:, 4]!="not offered (OK)") & (f.iloc[:, 4]!="offered") & (f.iloc[:, 4]!="offered with final") & (f.iloc[:, 4]!="offered with h2, http/1.1, http/1.0 (advertised)") & (f.iloc[:, 4]!="h2")]

        #keeps specified columns id and finding
        keep_col = ['id','finding']
        f = f[keep_col]

        # #removes ciphersuite rows for TLS 1 and TLS 1.1
        f=f[~f.id.str.startswith('cipher-tls1_x') & ~f.id.str.startswith('cipher-tls1_1_x')]

        f.loc[f['finding'].str.startswith("offered (deprecated)"), 'finding'] = "aaaaaaa xxxxx deprecated"

        #renames id column
        f.loc[f['id'].str.startswith("TLS1_1"), 'id'] = "TLS 1.1"
        f.loc[f['id'].str.startswith("TLS1_2"), 'id'] = "TLS 1.2"
        f.loc[f['id'].str.startswith("TLS1_3"), 'id'] = "TLS 1.3"
        f.loc[f['id'].str.startswith("TLS1"), 'id'] = "TLS 1"
        f.loc[f['id'].str.startswith("cipher-tls1_2_x"), 'id'] = "TLS 1.2"
        f.loc[f['id'].str.startswith("cipher-tls1_3_x"), 'id'] = "TLS 1.3"

        #removes TLS string in front of ciphersuite
        f['finding'] = f['finding'].str[7:]
        #splits to multiple columns, keeps ciphersuites
        f['finding']= f['finding'].str.split(' +',expand=True)[2]

        # #keeps weak ciphersuites
        f = f[f['finding'].isin(weak_ciphersuites)]

        f.to_csv(row[0]+'_scan.csv', index=False)
        
htmlfile2.close()