import argparse
import subprocess
import json
import time
import os
from datetime import datetime, timedelta
import nmap
import urllib.request
from urllib.error import HTTPError
import urllib.response
from bs4 import BeautifulSoup
from time import sleep

parser = argparse.ArgumentParser(description='Collect external information and scan')
parser.add_argument('-ip',action='store_true', help='Collect external IP addresses')
parser.add_argument('-url',action='store_true', help='Collect external URLs')
parser.add_argument('-scan',action='store_true', help='Scan, just like the name implies (requires -ip or -url')
parser.add_argument('-waf',action='store_true', help='Check if the site if protected by the Azure WAF (requires -url')
parser.add_argument('-ports', type=str, dest='ports', help='Add port/ports that you like to have scanned, replaced the built-in list (requires -ip and -scan)')

args = parser.parse_args()
print("""                                                                                                                                          
                                          #                                     
                                       ###                                        
                                    #####    ###                                
                                 #######    (####                                
                              ########/    /######(                             
                           ##########     .#########                            
                        (###########      ###########*                          
                      #############      ##############                         
                     #############      ################                        
                   ##############      ###################                      
                  #############(      #####################                     
                /#############.       #######################                   
               ##############           ######################                  
             .##############              #####################/                
            ###############                 #####################               
           ###############                    ####################              
         ###############(                       ####################            
        ###############,                          (##################           
      (###############                              /##################         
                                                     .##################        
                                       ,(################################(      
                         ,(################################################    
                         Azure cloudgazer - @nsmfoo  (Mikael Keri)       
""")

# List subscriptions
def azure_account ():  
    d = []
    subscriptions = json.loads(subprocess.check_output('az account list', shell=True, stderr=subprocess.DEVNULL).decode('utf-8'))
    for i in subscriptions:
        d.append(i['id'])   
    return d

def azure_ip (ip_file):
    f = open(ip_file, "w")
    ids = azure_account()
    amount = len(ids)
    number = 1
    ip_ext = []
    for id in ids:
        print("Searching: " + str(number) + "/" + str(amount) +  " ID: " + id) 
        set_sub = subprocess.getoutput("az account set --subscription " + id)
        ext_ips = json.loads(subprocess.getoutput("az graph query -q \"Resources | where type contains 'publicIPAddresses' and isnotempty(properties.ipAddress)| project properties.ipAddress\" -o json"))
        for pi in ext_ips:
            ip_ext.append(pi['properties_ipAddress'])
        number += 1  
        time.sleep(2)  
   
    # Sort output and remove dups
    list_set = set(ip_ext)
    unique_list = (list(list_set))
    f.write('\n'.join(unique_list))
    print("All done! " +  ip_file + " written to disk")
    f.close()

def azure_url(url_file, frontdoor):
    f = open(url_file, "w")
    ids = azure_account()
    amount = len(ids)
    number = 1
    url_ext = []
    for id in ids:
        try: 
            print("Searching: " + str(number) + "/" + str(amount) +  " ID: " + id) 
            number += 1  
            set_sub = subprocess.getoutput("az account set --subscription " + id)
            ext_url = json.loads(subprocess.getoutput("az webapp list --query \"[].{hostName: defaultHostName, state: state}\" -o json"))
            ext_url.extend(json.loads(subprocess.getoutput("az staticwebapp list --query \"[].{hostName: defaultHostname, state: state}\" -o json")))
            if frontdoor:
                ext_url.extend(json.loads(subprocess.getoutput("az network front-door list --query \"[].frontendEndpoints[].{hostName: hostName, state: resourceState}\" -o json")))
            for pi in ext_url:
                url_ext.append(pi['hostName'])
            time.sleep(2)  
        except Exception:
            continue

    for var in url_ext:
        print(var)  
     
    # Sort output and remove dups
    list_set = set(url_ext)
    unique_list = (list(list_set))
    f.write('\n'.join(unique_list))
    print("All done! " +  url_file + " written to disk")
    f.close()    

def azure_nmap():
    o = open(ip_scan_file, "w")
    azure_ip_in = open(ip_file, 'r').read().split('\n')
    azure_ip_in_nice = list(filter(None, azure_ip_in))
    count = 1
    nm = nmap.PortScanner() 
    o.write("IP|Port|Service|Product" + "\n")
    for ips in azure_ip_in_nice:
        print("* Scanning: " + str(count) + "/" + str(len(azure_ip_in_nice)))
        count += 1
        nm.scan(ips, ports)
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    if 'open' in nm[host][proto][port]['state']:
                                name = (nm[host][proto][port]['name'])
                                product = (nm[host][proto][port]['product'])
                                print("IP: " + str(ips) + " Port: " + str(port) + " Service: " + name + " Product: " + product)
                                o.write(str(ips) + "|" + str(port) + "|" + name + "|" + product + "\n")
        sleep(2)

def azure_crawling():
    o = open(url_scan_file, "w")
    azure_url_in = open(url_file, 'r').read().split('\n')
    azure_url_in_nice = list(filter(None, azure_url_in))
    count = 1
    req_type = ['http://','https://']
    for url in azure_url_in_nice:
       print("* Scanning: " + str(count) + "/" + str(len(azure_url_in_nice))) 
       count += 1 
       for req in req_type: 
            try: 
                x = urllib.request.urlopen(req + url, timeout = 10)
                xx = x.read()
                soup = BeautifulSoup(xx, 'html.parser')   
                print("Schema: " + req + " URL: " + url + " Status: OK Title: " + soup.title.get_text()) 
                o.write("Schema: " + req + " URL: " + url + " Status: OK  Title: " + soup.title.get_text() + "\n")
            except urllib.error.HTTPError as e:
                print("Schema: " + req + " URL: " + url + " Error: " + str(e)) 
                o.write("Schema: " + req + " URL: " + url + " Error: " + str(e) + "\n")  
            except Exception as e:
               print("Schema: " + req + " URL: " + url + " Error: " + str(e))  
               o.write("Schema: " + req + " URL: " + url + " Error: " + str(e) + "\n")
               continue
    time.sleep(3)
    o.close()

def azure_waf_crawling():
    o = open(waf_scan_file, "w")
    azure_url_in = open(url_file, 'r').read().split('\n')
    azure_url_in_nice = list(filter(None, azure_url_in))
    count = 1
    req_type = ['http://','https://']
    for url in azure_url_in_nice:
       print("* Scanning: " + str(count) + "/" + str(len(azure_url_in_nice))) 
       count += 1 
       # Yes I know ...
       bad_url = url + '?id=<script>alert(1)</script>'
       for req in req_type: 
            subdomain = url.split(".") 
            try: 
                x = urllib.request.urlopen(req + bad_url, timeout = 10)
                print('Not blocked :/ URL: ' + url)  
            except urllib.error.HTTPError as e:
                omph = e.getheaders()
                if 'x-ms-forbidden-ip' in str(omph):
                 print("Schema: " + req + " URL: " + url + " Blocked by WAF")  
                 o.write("Schema: " + req + " URL: " + url + " Blocked by WAF" + "\n")  
            except Exception as e:
                print("URL: " + bad_url + " Error: " + str(e))  
                continue
    time.sleep(2) 
    o.close()    

# Misc settings
# IP log file
ip_file = "azure_ip.lst"
ip_scan_file = "azure_ip_scan_result.lst"
# URL log file
url_file = "azure_url.lst"
url_scan_file = "azure_url_scan_result.lst"
waf_scan_file = "azure_waf_scan_result.lst"
# Ports
ports = '21-22,25,80,111,443,1433,3389,6443,8080,61616'
# Front Door
fd = True

# Logged in 
logged_in = subprocess.getoutput("az account list-locations")
if 'Please run' in logged_in:
    print("*** Not logged in, please run 'az login' ***")
    exit() 
else:
    print("* Logged in, ready to start!")

# AZ Extentions
az_extentions = json.loads(subprocess.getoutput("az extension list --query \"[].name\" -o json"))

# Check if front door extention is installed
if 'front-door' not in az_extentions:
    print("*** Front Door extention missing, please run 'az extension add --name front-door' to enable front door collection ***")
    fd = False

# Check if resource graph extention is installed
if 'resource-graph' not in az_extentions:
    print("*** Resource Graph extention missing, please run 'az extension add --name resource-graph' to enable ip collection ***")
    args.ip = False


if args.ip:
    # Check if file exist
    if os.path.isfile(ip_file):
    # If it exist, check age of the file. No need to burn magic cloud money ..
        age = datetime.now() - timedelta(days=7)
        filetime = datetime.fromtimestamp(os.path.getctime(ip_file))
        if filetime < age:
            print("* IP file needs to be update ..") 
            azure_ip(ip_file)         
        else:
            print("* IP file is fresh, will not update (and you can't make me)") 
    else:
        print("* First run! Populating IP file")
        azure_ip(ip_file)

if args.url:
    # Check if file exist
    if os.path.isfile(url_file):
    # If it exist, check age of the file. No need to burn magic cloud money ..
        age = datetime.now() - timedelta(days=7)
        filetime = datetime.fromtimestamp(os.path.getctime(url_file))
        if filetime < age:
            print("* URL file needs to be update ..") 
            azure_url(url_file, fd)         
        else:
            print("* URL file is fresh, will not update (and you can't make me)") 
    else:
        print("* First run! Populating URL file")
        azure_url(url_file, fd)

if args.scan:
    # Scanning
    if args.ip:
        if args.ports:
           ports = args.ports
        print("* Let's go NMAP scanning! We will go soft, so go and grab some coffee")
        azure_nmap()
    # Crawling
    if args.url:
         print("* Let's go URL Crawling! We will go soft, so go and grab some coffee")
         azure_crawling()
    # WAF check
    if args.waf:
         print("* Let's go WAF Checking! We will go soft, so go and grab some coffee")
         azure_waf_crawling()     
