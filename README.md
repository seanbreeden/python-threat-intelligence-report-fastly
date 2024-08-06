                          ▄   ▀██                       
     ▄▄▄ ▄▄▄   ▄▄▄▄ ▄▄▄ ▄██▄   ██ ▄▄     ▄▄▄   ▄▄ ▄▄▄   
      ██▀  ██   ▀█▄  █   ██    ██▀ ██  ▄█  ▀█▄  ██  ██  
      ██    █    ▀█▄█    ██    ██  ██  ██   ██  ██  ██  
      ██▄▄▄▀      ▀█     ▀█▄▀ ▄██▄ ██▄  ▀█▄▄█▀ ▄██▄ ██▄ 
      ██       ▄▄ █                                     
     ▀▀▀▀       ▀▀                                      
     
         🅣🅗🅡🅔🅐🅣 🅘🅝🅣🅔🅛🅛🅘🅖🅔🅝🅒🅔 🅡🅔🅟🅞🅡🅣
     
     ▀██▀▀▀▀█     █      ▄█▀▀▀▄█  █▀▀██▀▀█ ▀██▀      ▀██▀ ▀█▀
      ██  ▄      ███     ██▄▄  ▀     ██     ██         ██ █  
      ██▀▀█     █  ██     ▀▀███▄     ██     ██          ██   
      ██       ▄▀▀▀▀█▄  ▄     ▀██    ██     ██          ██   
     ▄██▄     ▄█▄  ▄██▄ █▀▄▄▄▄█▀    ▄██▄   ▄██▄▄▄▄▄█   ▄██▄  
                                                             
      ██                                        ▄                   
     ▄▄▄  ▄▄ ▄▄ ▄▄   ▄▄▄ ▄▄▄    ▄▄▄   ▄▄▄ ▄▄  ▄██▄    ▄▄▄▄  ▄▄▄ ▄▄  
      ██   ██ ██ ██   ██▀  ██ ▄█  ▀█▄  ██▀ ▀▀  ██   ▄█▄▄▄██  ██▀ ▀▀ 
      ██   ██ ██ ██   ██    █ ██   ██  ██      ██   ██       ██     
     ▄██▄ ▄██ ██ ██▄  ██▄▄▄▀   ▀█▄▄█▀ ▄██▄     ▀█▄▀  ▀█▄▄▄▀ ▄██▄    
                      ██                                            
                     ▀▀▀▀                                          
                                                        
<strong>Author: </strong> Sean Breeden<br>
<strong>Language: </strong> Python 3.9<br>
<strong>Version: </strong> 1.0<br>

# Description
This Python script crawls a list of Threat Intelligent Report IP lists and adds them in bulk to a Fastly blocklist.

# Dependencies
     pip3 install requests beautifulsoup4

# Usage
     python threat-intelligence-report-fastly-importer.py config.ini ip_addresses.txt threat-site-urls.txt

# config.ini
     [fastly]
     api_key = YOUR_FASTLY_API_KEY
     service_id = YOUR_FASTLY_SERVICE_ID
     version = YOUR_FASTLY_VERSION
     blocklist_name = FASTLY_BLOCKLIST_NAME

# ip_addresses.txt
     185.234.216.59
     212.83.185.105
     194.44.38.51
     194.143.136.122
     113.160.133.8

# threat-site-urls.txt
     https://snort-org-site.s3.amazonaws.com/production/document_files/files/000/032/663/original/ip-filter.blf?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAU7AK5ITMMOXGB2W5%2F20240804%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20240804T222010Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=b8e4448b0aa06f761b83378ad19df0d1ea63b0c52f0770296dd9f5d8ab1f07a3
     https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt
     https://www.dan.me.uk/torlist/
     https://lists.blocklist.de/lists/all.txt
     https://rules.emergingthreats.net/blockrules/compromised-ips.txt
     https://blocklist.greensnow.co/greensnow.txt
     https://myip.ms/files/blacklist/general/latest_blacklist.txt
     
