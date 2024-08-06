# threat-intelligence-report-fastly-importer.py
# Author: Sean Breeden
# License: GNU GENERAL PUBLIC LICENSE 3.0
# 2024-08-04
import requests
from bs4 import BeautifulSoup
import os
import re
import sys
import argparse
import configparser

# Get the current blocklist from Fastly
def get_current_blocklist(api_key, service_id, version, blocklist_name):
    url = f'https://api.fastly.com/service/{service_id}/version/{version}/snippet'
    headers = {
        'Fastly-Key': api_key,
        'Accept': 'application/json'
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        snippets = response.json()
        blocklist_content = ''
        for snippet in snippets:
            if snippet['name'] == blocklist_name:
                blocklist_content += snippet['content']
        return set(extract_ip_addresses(blocklist_content))
    else:
        print(f'Failed to get the blocklist. Status code: {response.status_code}, Response: {response.text}')
        return set()

# Add the IP address to the Fastly blocklist
def add_ip_to_blocklist(api_key, service_id, version, blocklist_name, ip_address):
    url = f'https://api.fastly.com/service/{service_id}/version/{version}/snippet'
    headers = {
        'Fastly-Key': api_key,
        'Content-Type': 'application/json'
    }
    payload = {
        "name": blocklist_name,
        "dynamic": 1,
        "type": "recv",
        "content": f"if (client.ip == {ip_address}) {{ error 403; }}\n"
    }
    response = requests.post(url, headers=headers, json=payload)
    
    if response.status_code == 200:
        print(f'Successfully added {ip_address} to blocklist.')
    else:
        print(f'Failed to add {ip_address} to blocklist. Status code: {response.status_code}, Response: {response.text}')

# Spider the url and extract IP addresses
def spider_website(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        text = soup.get_text()
        ip_addresses = extract_ip_addresses(text)
        return ip_addresses
    except requests.RequestException as e:
        print(f'Failed to spider {url}. Error: {e}')
        return []

# Extract IP addresses from text
def extract_ip_addresses(text):
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    return ip_pattern.findall(text)

# Get list of URLs from text file
def read_urls(file_path):
    with open(file_path, 'r') as file:
        urls = [line.strip() for line in file.readlines()]
    return urls

# Get list of IP addresses from text file
def read_ip_addresses(file_path):
    with open(file_path, 'r') as file:
        ip_addresses = [line.strip() for line in file.readlines()]
    return ip_addresses

# Main
def main(config_file, ip_file, url_file):
    # Get config
    config = configparser.ConfigParser()
    config.read(config_file)
    
    api_key = config['fastly']['api_key']
    service_id = config['fastly']['service_id']
    version = config['fastly']['version']
    blocklist_name = config['fastly']['blocklist_name']
    
    urls = read_urls(url_file)
    
    ip_addresses_list = set()
    # Iterate through URLs and spider them
    for url in urls:
        ip_addresses_list = spider_website(url)
        ip_addresses_list.update(ip_addresses)

    # Update main IP addresses list
    ip_addresses_list.update(read_ip_addresses(ip_file))

    # Get the current blocklist from Fastly
    current_blocklist = get_current_blocklist(api_key, service_id, version, blocklist_name)

    # Iterate through all IP addresses
    for ip_address in ip_addresses_list:
        # Make sure the IP address has not already been added
        if ip_address not in current_blocklist:
            # Add IP to the Fastly blocklist
            add_ip_to_blocklist(api_key, service_id, version, blocklist_name, ip_address)
        else:
            print(f'{ip_address} is already in the blocklist. Skipping.')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Add IP addresses to the Fastly blocklist.')
    parser.add_argument('config_file', type=str, help='Full path to the configuration file (config.ini).')
    parser.add_argument('ip_file', type=str, help='Full path to the file containing IP addresses to block (one per line).')
    parser.add_argument('url_file', type=str, help='Full path to the file containing URLs to crawl (one per line).')
    
    args = parser.parse_args()
    main(args.config_file, args.ip_file, args.url_file)
