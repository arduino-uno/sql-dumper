#!/usr/bin/env python3
# Lab: Check & test the proxies ( both 'http' or 'https' )
# Lab-Link: https://github.com/frank-leitner/portswigger-websecurity-academy
# Difficulty: PRACTITIONER

import requests

proxies = {
  "http": "http://157.10.3.10:8080",
  "https": "https://157.10.3.10:8080",
}

url = "https://ipinfo.io/what-is-my-ip"
session = requests.Session()

response = session.get(url, verify=False, proxies=proxies)
text_resp = response.text

print(text_resp)