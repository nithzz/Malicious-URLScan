import json
import requests
import urllib

import pyfiglet
import os
banner = pyfiglet.figlet_format("Malicious URL Scanner ~ ipqualityscore")


class IPQS:
    key = 'RSXvbq3d9ZdZevgVhso1M1T5zYopwPIx'
    def malicious_url_scanner_api(self, url: str, vars: dict = {}) -> dict:
        url = 'https://www.ipqualityscore.com/api/json/url/%s/%s' % (self.key, urllib.parse.quote_plus(url))
        x = requests.get(url, params = vars)
        print(x.text)
        return (json.loads(x.text))
    
def prRed(skk):
    print("\033[91m {} \033".format(skk))
    return
def prCyan(skk):
    print("\033[96m {} \033".format(skk))
    return
def prGreen(skk):
    print("\033[92m {} \033".format(skk))
    return
def prYellow(skk):
    print("\033[93m {} \033".format(skk))	
    return

def urlScan(URL):
    #Adjustable strictness level from 0 to 2. 0 is the least strict and recommended for most use cases. Higher strictness levels can increase false-positives.
    strictness = 0

    #custom feilds
    additional_params = {
        'strictness' : strictness
    }

    ipqs = IPQS()
    result = ipqs.malicious_url_scanner_api(URL, additional_params)
    

    if 'success' in result and result['success'] == True:
        print("Unsafe: ",result['unsafe'])
        print("Domain: ",result['domain'])
        print("IP address: ",result['ip_address'])
        print("Domain rank: ",result['domain_rank'])
        print("Category: ",result['category'])
        print("Spamming: ",result['spamming'])
        print("Malware: ",result['malware'])
        print("Phishing: ",result['phishing'])
        print("Suspicious: ",result['suspicious'])
        print("Risk score: ",result['risk_score'],"\n\n")
        #print(result)

        #Identify suspicious URLs regardless of Risk Score
        
        if result['suspicious'] == True:
        # flag suspicious URL
            print("suspicious URL\n") 
        
        #We'd like to block all malicious URLs suspected of being used for phishing or malware
        
        if result['phishing'] == True or result['malware'] == True or result['risk_score'] > 85:
            # flag high risk URLs likely to be malicious
            print("URL seems to be malicious (phishing or malware)\n")

if __name__ == "__main__":

    cmd = os.system("cls")
    print(banner)
    prCyan("[+] 1) Enter the URL")
    prCyan("[+] 2) Enter the file name containing URLs")

    prGreen("[-] Enter your choice")
    ch = int(input(""))
    
    if ch == 1:
        
        """
        URL to scan - URL Encoded in cURL function below.
        """
        prYellow("Enter the URL: ")
        URL = input()
        #URL = 'https://streampasstv.pro/nhl-tv/'
        urlScan(URL)
    elif ch== 2:
        fileName = input("Enter the file name: ")
        f = open(fileName,"r")
        for i in f.readlines():
            i.rstrip("\n")
            print(i)
            urlScan(i)
        
        
        
    

    
