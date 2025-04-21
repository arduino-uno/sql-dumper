# SQL Dumper
<center>
<img src="./img/hackaday-security.png" alt="image-logo" width="300"/>
</center>
Lab: SQL injection UNION attack, determining the number of columns returned by the query</br>
Lab-Link: https://github.com/frank-leitner/portswigger-websecurity-academy</br>
Difficulty: PRACTITIONER</br>  
Python script: [sqldumper.py](sqldumper.py)</br>

## Examples

### Example #1: Checking the proxies (both http & https)

```bash
    sudo python3 checkproxy.py
```

![Checking proxies](img/screenshot1.png)

### Example #2: SQL injection test

```bash
    sudo python3 sqldumper.py http://testphp.vulnweb.com/artists.php?artist=-1
```

![Attacking successful](img/screenshot.png)
