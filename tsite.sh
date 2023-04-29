#!/bin/bash
############################################################################
# TeTeOS.Net Website Manager
#
# by TeTeOS.Net. (teteos.net)
# Copyright (c) 2023.
############################################################################

# ========================================================================
# Before Executing
# ========================================================================

#
# Check who is executing.
#

if [ ! `whoami` = 'root' ]; then
	echo "Error: Only administrators allowed."
	exit 1
fi

#
# Register PiluX (Based OS) variables
#
PILUX_OS_NAME=`cat /teteosnet/OS/Name`

# ========================================================================
# Functions
# ========================================================================

# === === Check domain string
checkdomain(){

      # 2: ok
      # 3: domain is null.
      # 4: domain is long.
      # 5: domain is reserved.
      # 6: domain start with dot.
      # 7: domain end with dot.
      # 8: domain start with dot http:, https:, www. .
      # 9: domain have invalid character.
      if [[ $1 = "" ]]; then
            checkdomain_result=3;
      elif (( DomainLen > 253 )); then
            checkdomain_result=4;
      elif [[ $1 = "000-default" ]]; then
            checkdomain_result=5;
      elif [[ $1 = "default" ]]; then
            checkdomain_result=5;
      elif [[ $1 == .* ]]; then
            checkdomain_result=6;
      elif [[ $1 == *. ]]; then
            checkdomain_result=7;
      elif [[ $1 == http:* || $1 == https:* || $1 == www.* ]]; then
            checkdomain_result=8;
      elif ! [[ "$1" =~ ^[a-zA-Z0-9\.\i\-]*$ ]]; then
            checkdomain_result=9;
      else
            checkdomain_result=2
      fi
}

# ========================================================================
# - add
# ========================================================================

# add
if [[ $1 = "add" ]]; then

      # === === Check domain name
      checkdomain $2
      case $checkdomain_result in

            3) # domain is null.
            echo "[!] Domain name is null."
            exit 1
            ;;

            4) # domain is long.
            echo "[!] Domain name is long."
            exit 1
            ;;

            5) # domain is reserved.
            echo "[!] Domain name is reserved for system." 
            exit 1
            ;;

            6) # domain starts with dot.
            echo "[!] Domain name starts with dot."
            exit 1
            ;;

            7) # domain ends with dot.
            echo "[!] Domain name ends with dot."
            exit 1
            ;;

            8) # domain start with dot http:, https:, www. .
            echo "[!] Domain name starts with http:, https: or www."
            exit 1
            ;;

            9) # domain have invalid character.
            echo "[!] Domain name have invalid character(s)"
            exit 1
            ;;

      esac

      # === === Check site is exist?
      if [[ -f "/etc/nginx/sites-available/$2" ]]; then
            echo "[!] Domain already added."
            exit 1
      fi

      # === === Add site now!

      # Create site file
      echo "server {" > /etc/nginx/sites-available/$2
      if ! [ -f "/etc/nginx/sites-available/$2" ]; then
            echo "[!] Failed to creating site file."
            echo "May be:"
            echo " - Permission/Write error"
            echo " - Disk is full"
            echo " - Domain name not valid"
            exit 1
      fi
      echo "    listen 80;" >> /etc/nginx/sites-available/$2
      echo "    server_name $2 *.$2;" >> /etc/nginx/sites-available/$2
      echo "    root /var/www/$2/public_html/;" >> /etc/nginx/sites-available/$2
      echo "" >> /etc/nginx/sites-available/$2
      echo "    index index.html index.htm index.php;" >> /etc/nginx/sites-available/$2
      echo "" >> /etc/nginx/sites-available/$2
      echo "    location / {" >> /etc/nginx/sites-available/$2
      echo "        try_files \$uri \$uri/ =404;" >> /etc/nginx/sites-available/$2
      echo "    }" >> /etc/nginx/sites-available/$2
      echo "" >> /etc/nginx/sites-available/$2
      echo "    location ~ \.php$ {" >> /etc/nginx/sites-available/$2
      echo "        include snippets/fastcgi-php.conf;" >> /etc/nginx/sites-available/$2
      echo "        fastcgi_pass unix:/var/run/php/php8.2-fpm.sock;" >> /etc/nginx/sites-available/$2
      echo "     }" >> /etc/nginx/sites-available/$2
      echo "" >> /etc/nginx/sites-available/$2
      echo "    location ~ /\.ht {" >> /etc/nginx/sites-available/$2
      echo "        deny all;" >> /etc/nginx/sites-available/$2
      echo "    }" >> /etc/nginx/sites-available/$2
      echo "" >> /etc/nginx/sites-available/$2
      echo "}" >> /etc/nginx/sites-available/$2
      chmod 644 /etc/nginx/sites-available/$2

      # Check site folder
      site_folder_found=0
      if [ -d "/var/www/$2/public_html" ]; then
            site_folder_found=1
      else
            # Create site folder with index.php
            mkdir -p /var/www/$2/public_html/
            if [ -f "/var/www/000-default/public_html/index.php" ]; then
                  cp /var/www/000-default/public_html/index.php /var/www/$2/public_html/index.php &>/dev/null
            elif [ -f "/var/www/default/public_html/index.php" ]; then
                  cp /var/www/default/public_html/index.php /var/www/$2/public_html/index.php &>/dev/null
            else
                  echo "<html>" > /var/www/$2/public_html/index.php
                  echo "  <head>" >> /var/www/$2/public_html/index.php
                  echo "    <title>Nginx Server with PiluX OS</title>" >> /var/www/$2/public_html/index.php
                  echo "  </head>" >> /var/www/$2/public_html/index.php
                  echo "  <body style=\"font-family: Arial; background:black; color: white;\">" >> /var/www/$2/public_html/index.php
                  echo "    <p style=\"text-align:center\"><span style=\"font-size:28px\"><br><br>Congratulations! Your website is working!</span></p>" >> /var/www/$2/public_html/index.php
                  echo "    <p style=\"text-align:center\"><span style=\"color:#8e44ad\"><span style=\"font-size:20px\">PiluXA 💕 Nginx </span></span></p>" >> /var/www/$2/public_html/index.php
                  echo "  </body>" >> /var/www/$2/public_html/index.php
                  echo "</html>" >> /var/www/$2/public_html/index.php
            fi
      fi

      # === === Localwork mode
      if [[ $3 = "localwork" ]]; then

            # === === Enable now.
            ln -s /etc/nginx/sites-available/$2 "/etc/nginx/sites-enabled/$2" && sleep 0.01

            # === === Check is enabled?
            if [[ -f "/etc/nginx/sites-enabled/$2" ]]; then
                  echo "[✔] Site enabled successfuly."
                  systemctl restart nginx.service &>/dev/null
                  #exit 0 # Do not exit before adding to /etc/hosts!
            else
                  echo "[!] Site cannot enabled. (May be permission error)"
                  #exit 1
            fi

            # === === Add to /etc/hosts now
            if ! grep -q "$2" /etc/hosts
            then
                  sed -i "s/127.0.0.1 localhost/127.0.0.1 localhost\n127.0.0.1 $2/g" /etc/hosts
                  if ! grep -q "$2" /etc/hosts
                  then
                        echo "[!] Site cannot added to hosts file. (May be permission error)"
                        #exit 1
                  else
                        echo "[✔] Site added to hosts file successfuly."
                        resolvectl flush-caches &>/dev/null
                        #exit 0
                  fi
            #else
                  #echo "[!] Domain found in /etc/hosts. (May be already added)"
                  #exit 1
            fi
      fi

      # === === Finish!
      if [[ $site_folder_found = 1 ]]; then
            echo "[i] Site files found: /var/www/$2/"
      fi

      if ! [[ $3 = "localwork" ]]; then
            if [[ $0 = "/teteosnet/Bin/tsite" ]]; then
                  echo "[i] Note: Site is not enabled. Enable command: tsite enable $2"
            else
                  echo "[i] Note: Site is not enabled. Enable command: $0 enable $2"
            fi
      fi
      echo "[✔] Site added successfuly."
      exit 0


# ========================================================================
# - del
# ========================================================================

# del
elif [[ $1 = "del" ]]; then

      # === === Check domain name
      checkdomain $2
      if ! [[ $checkdomain_result = 2 ]]; then
            echo "[!] Site not exist."
            exit 1
      fi

      # === === Check site is exist?
      if ! [[ -f "/etc/nginx/sites-available/$2" ]]; then
            if [[ $3 = "all" ]]; then
                  if [[ -d "/var/www/$2/" ]]; then
                        rm -rf /var/www/$2/
                        echo "[✔] Site deleted successfuly."
                        exit 0
                  else
                        echo "[!] Site not exist."
                        exit 1
                  fi
            else
                  echo "[!] Site not exist."
                  exit 1
            fi

      fi

      # === === Delete now.
      rm /etc/nginx/sites-available/$2 &>/dev/null
      rm /etc/nginx/sites-enabled/$2 &>/dev/null
      if grep -q "$2" /etc/hosts
	then
		sed -i "/$2/d" /etc/hosts
	fi

      # === === Check is deleted?
      if ! [[ -f "/etc/nginx/sites-available/$2" ]]; then
            if [[ $3 = "all" ]]; then
                  rm -rf /var/www/$2/
            fi
            systemctl restart nginx.service &>/dev/null
            echo "[✔] Site deleted successfuly."
            exit 0
      else
            echo "[!] Site cannot deleted. (May be permission error)"
            exit 1
      fi

# ========================================================================
# - list
# ========================================================================

# list
elif [[ $1 = "list" ]]; then
     
     # ls /etc/nginx/sites-available
      SiteCount=`ls /etc/nginx/sites-available | sed -z 's/000-default\n//g' | sed -z 's/default\n//g' | wc -l`
      if (( $SiteCount > 0 )); then
            ls /etc/nginx/sites-available | sed -z 's/000-default\n//g' | sed -z 's/default\n//g'
      else
            echo "[i] No sites found."
      fi
      exit 0


# ========================================================================
# - piluxbin
# ========================================================================
elif [[ $1 = "piluxbin" ]]; then
     
      cp $0 /teteosnet/Bin/tsite
      if ! [ -f /teteosnet/Bin/tsite ]; then
            echo "[!] Cannot added this script to this PiluX system. (May be permission error)"
            exit 1
      fi

      echo "[✔] Script added to your $PILUX_OS_NAME as command."
      exit 0


# ========================================================================
# - restart
# ========================================================================
elif [[ $1 = "restart" ]]; then
      systemctl restart nginx.service &>/dev/null

# ========================================================================
# - enable
# ========================================================================

# enable
elif [[ $1 = "enable" ]]; then

      # === === Check domain name
      checkdomain $2
      if ! [[ $checkdomain_result = 2 ]]; then
            echo "[!] Site not exist."
            exit 1
      fi

      # === === Check site is exist?
      if ! [[ -f "/etc/nginx/sites-available/$2" ]]; then
            echo "[!] Site not exist."
            exit 1
      fi

      # === === Check site is enabled?
      if [[ -f "/etc/nginx/sites-enabled/$2" ]]; then
            echo "[!] Site is already enabled."
            exit 1
      fi

      # === === Enable now.
      ln -s /etc/nginx/sites-available/$2 "/etc/nginx/sites-enabled/$2" && sleep 0.01

      # === === Check is enabled?
      if [[ -f "/etc/nginx/sites-enabled/$2" ]]; then
            echo "[✔] Site enabled successfuly."
            systemctl restart nginx.service &>/dev/null
            exit 0
      else
            echo "[!] Site cannot enabled. (May be permission error)"
            exit 1
      fi



# ========================================================================
# - disable
# ========================================================================

# disable
elif [[ $1 = "disable" ]]; then

      # === === Check domain name
      checkdomain $2
      if ! [[ $checkdomain_result = 2 ]]; then
            echo "[!] Site not exist."
            exit 1
      fi

      # === === Check site is exist?
      if ! [[ -f "/etc/nginx/sites-available/$2" ]]; then
            echo "[!] Site not exist."
            exit 1
      fi

      # === === Check site is enabled?
      if ! [[ -f "/etc/nginx/sites-enabled/$2" ]]; then
            echo "[!] Site is already disabled."
            exit 1
      fi

      # === === Disable now.
      unlink /etc/nginx/sites-enabled/$2 && sleep 0.01

      # === === Check is disabled?
      if ! [[ -f "/etc/nginx/sites-enabled/$2" ]]; then
            echo "[✔] Site disabled successfuly."
            systemctl restart nginx.service &>/dev/null
            exit 0
      else
            echo "[!] Site cannot enabled. (May be permission error)"
            exit 1
      fi


# ========================================================================
# - local-add
# ========================================================================

# local-add
elif [[ $1 = "local-add" ]]; then

      # === === Check domain name
      checkdomain $2
      if ! [[ $checkdomain_result = 2 ]]; then
            echo "[!] Site not exist."
            exit 1
      fi

      # === === Check site is exist?
      if ! [[ -f "/etc/nginx/sites-available/$2" ]]; then
            echo "[!] Site not exist."
            exit 1
      fi

      # === === Add now
      if ! grep -q "$2" /etc/hosts
	then
		sed -i "s/127.0.0.1 localhost/127.0.0.1 localhost\n127.0.0.1 $2/g" /etc/hosts
            if ! grep -q "$2" /etc/hosts
	      then
                  echo "[!] Site cannot added to hosts file. (May be permission error)"
                  exit 1
            else

                  echo "[✔] Site added to hosts file successfuly."
                  resolvectl flush-caches &>/dev/null
                  exit 1
            fi
      else
            echo "[!] Domain found in /etc/hosts. (May be already added)"
            exit 1
	fi


# ========================================================================
# - local-del
# ========================================================================

# local-del
elif [[ $1 = "local-del" ]]; then

      # === === Check domain name
      checkdomain $2
      if ! [[ $checkdomain_result = 2 ]]; then
            echo "[!] Site not exist."
            exit 1
      fi

      # === === Check site is exist?
      if ! [[ -f "/etc/nginx/sites-available/$2" ]]; then
            echo "[!] Site not exist."
            exit 1
      fi

      # === === Del now
      if grep -q "$2" /etc/hosts
	then
		sed -i "/$2/d" /etc/hosts && sleep 0.01
            if grep -q "$2" /etc/hosts
	      then
                  echo "[!] Site cannot deleted in hosts file. (May be permission error)"
                  exit 1
            else

                  echo "[✔] Site deleted in hosts file successfuly."
                  exit 1
            fi
      else
            echo "[!] Domain not found in /etc/hosts. (May be already deleted)"
            exit 1
	fi
# ========================================================================
# - sign-self
# ========================================================================

# sign-self
elif [[ $1 = "sign-self" || $1 = "self-sign" ]]; then
      
      echo "[i] Generating self-signed key and certificate pair with OpenSSL (365 day, rsa:2048)..."
      echo "[i] - Location: /etc/ssl/private/nginx-selfsigned.key & /etc/ssl/certs/nginx-selfsigned.crt"
      
      openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/nginx-selfsigned.key -out /etc/ssl/certs/nginx-selfsigned.crt
      openssl x509 -x509toreq -in /etc/ssl/certs/nginx-selfsigned.crt -signkey /etc/ssl/private/nginx-selfsigned.key -out /etc/ssl/certs/nginx-selfsigned.csr &>/dev/null

      if ! [[ -f "/etc/ssl/private/nginx-selfsigned.key" && -f "/etc/ssl/certs/nginx-selfsigned.crt" ]]; then
            echo "[!] Cannot generated self-sign key."
            exit 1
      fi
      echo "[i] Generating DH parameters..."
      echo "[i] - Location: /etc/nginx/dhparam.pem"
      openssl dhparam -dsaparam -out /etc/nginx/dhparam.pem 4096 &>/dev/null
      if ! [[ -f "/etc/nginx/dhparam.pem" ]]; then
            echo "[!] Cannot generated self-sign key."
            exit 1
      fi

      echo "[i] Creating self-signed.conf and ssl-params.conf..."
      echo "ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;">/etc/nginx/snippets/self-signed.conf
      echo "ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;">>/etc/nginx/snippets/self-signed.conf
      echo "ssl_protocols TLSv1.3;">/etc/nginx/snippets/ssl-params.conf
      echo "ssl_prefer_server_ciphers on;">>/etc/nginx/snippets/ssl-params.conf
      echo "ssl_dhparam /etc/nginx/dhparam.pem;">>/etc/nginx/snippets/ssl-params.conf
      echo "ssl_ciphers EECDH+AESGCM:EDH+AESGCM;">>/etc/nginx/snippets/ssl-params.conf
      echo "ssl_ecdh_curve secp384r1;">>/etc/nginx/snippets/ssl-params.conf
      echo "ssl_session_timeout  10m;">>/etc/nginx/snippets/ssl-params.conf
      echo "ssl_session_cache shared:SSL:10m;">>/etc/nginx/snippets/ssl-params.conf
      echo "ssl_session_tickets off;">>/etc/nginx/snippets/ssl-params.conf
      echo "ssl_stapling on;">>/etc/nginx/snippets/ssl-params.conf
      echo "ssl_stapling_verify on;">>/etc/nginx/snippets/ssl-params.conf
      echo "resolver 1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 valid=300s;">>/etc/nginx/snippets/ssl-params.conf
      echo "resolver_timeout 5s;">>/etc/nginx/snippets/ssl-params.conf
      echo "# Disable strict transport security for now. You can uncomment the following">>/etc/nginx/snippets/ssl-params.conf
      echo "# line if you understand the implications.">>/etc/nginx/snippets/ssl-params.conf
      echo "#add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\";">>/etc/nginx/snippets/ssl-params.conf
      echo "add_header X-Frame-Options DENY;">>/etc/nginx/snippets/ssl-params.conf
      echo "add_header X-Content-Type-Options nosniff;">>/etc/nginx/snippets/ssl-params.conf
      echo "add_header X-XSS-Protection \"1; mode=block\";">>/etc/nginx/snippets/ssl-params.conf
      if ! [[ -f "/etc/nginx/snippets/ssl-params.conf" && -f "/etc/nginx/snippets/self-signed.conf" ]]; then
            echo "[!] Cannot generated self-sign key."
            exit 1
      fi

      echo "[i] Setting Firewall rules..."
      ufw allow 'Nginx Full' &>/dev/null
      ufw delete allow 'Nginx HTTP' &>/dev/null

      echo "[✔] Generating self-signed key successfuly."
      exit 0

# ========================================================================
# - sign-self
# ========================================================================

# sign-self
elif [[ $1 = "sign-self-renew" || $1 = "self-sign-renew" ]]; then

      if ! [ -f "/etc/ssl/certs/nginx-selfsigned.crt" ]; then
            echo "[!] nginx-selfsigned.crt not found."
            exit 1
      fi

      CRT_OLD_MD5=`md5sum /etc/ssl/certs/nginx-selfsigned.crt`
      cp /etc/ssl/certs/nginx-selfsigned.crt /etc/ssl/certs/nginx-selfsigned.backup.crt &>/dev/null
      cp /etc/ssl/certs/nginx-selfsigned.csr /etc/ssl/certs/nginx-selfsigned.backup.csr &>/dev/null
      if ! [ -f "/etc/ssl/certs/nginx-selfsigned.backup.crt" ]; then
            echo "[!] Backup failed for nginx-selfsigned.crt (May be permission error.)"
            exit 1
      fi
      openssl x509 -x509toreq -in /etc/ssl/certs/nginx-selfsigned.crt -signkey /etc/ssl/private/nginx-selfsigned.key -out /etc/ssl/certs/nginx-selfsigned.csr &>/dev/null
      if ! [ -f "/etc/ssl/certs/nginx-selfsigned.csr" ]; then
            echo "[!] Failed to renew Self-Sign SSL. File cannot created. (May be permission error.)"
            exit 1
      fi
      openssl x509 -req -days 365 -in /etc/ssl/certs/nginx-selfsigned.csr -signkey /etc/ssl/private/nginx-selfsigned.key -out /etc/ssl/certs/nginx-selfsigned.crt &>/dev/null
      CRT_NEW_MD5=`md5sum /etc/ssl/certs/nginx-selfsigned.crt`

      if [[ $CRT_NEW_MD5 = $CRT_OLD_MD5 ]]; then
            echo "[!] Failed to renew Self-Sign SSL."
            rm /etc/ssl/certs/nginx-selfsigned.crt || mv /etc/ssl/certs/nginx-selfsigned.backup.crt /etc/ssl/certs/nginx-selfsigned.crt ||
            rm /etc/ssl/certs/nginx-selfsigned.csr || mv /etc/ssl/certs/nginx-selfsigned.backup.csr /etc/ssl/certs/nginx-selfsigned.csr ||
            exit 1
      fi

      echo "[✔] Renewing self-signed key successfuly."
      systemctl restart nginx.service &>/dev/null
      exit 0


# ================================
# ========================================================================
# - ssl-on
# ==================================================================

# ssl-on
elif [[ $1 = "ssl-on" ]]; then

      # === === Check domain name
      checkdomain $2
      if ! [[ $checkdomain_result = 2 ]]; then
            echo "[!] Site not exist."
            exit 1
      fi

      # === === Check site is exist?
      if ! [[ -f "/etc/nginx/sites-available/$2" ]]; then
            echo "[!] Site not exist."
            exit 1
      fi

      # === === SSL mode on now.

      if ! grep -q "listen 443 ssl" /etc/nginx/sites-available/$2
      then
            
            # Write
            if [[ -f "/etc/nginx/snippets/self-signed.conf" && -f "/etc/nginx/snippets/ssl-params.conf" ]]; then
                  sed -i "s/server {/server {\n    listen 443 ssl;\n    include snippets\/self-signed.conf;\n    include snippets\/ssl-params.conf;/g" /etc/nginx/sites-available/$2
            else
                  sed -i "s/server {/server {\n    listen 443 ssl;/g" /etc/nginx/sites-available/$2
            fi

            # Check is success?
            if ! grep -q "listen 443 ssl" /etc/nginx/sites-available/$2
            then
                  echo "[!] SSL cannot added to site. (May be permission error)"
                  exit 0
            else
                  echo "[✔] SSL added to site successfuly."
                  systemctl restart nginx.service &>/dev/null
                  exit 1
            fi

      else
            echo "[!] SSL is already on in this site."
            exit 1
      fi

# ========================================================================
# - ssl-off
# ========================================================================

# ssl-off
elif [[ $1 = "ssl-off" ]]; then

      # === === Check domain name
      checkdomain $2
      if ! [[ $checkdomain_result = 2 ]]; then
            echo "[!] Site not exist."
            exit 1
      fi

      # === === Check site is exist?
      if ! [[ -f "/etc/nginx/sites-available/$2" ]]; then
            echo "[!] Site not exist."
            exit 1
      fi

      # === === SSL mode off now.
      if grep -q "listen 443 ssl" /etc/nginx/sites-available/$2
      then
            
            # Write
            sed -i "/listen 443 ssl/d" /etc/nginx/sites-available/$2
            sed -i "/listen 443 ssl/d" /etc/nginx/sites-available/$2
            sed -i "/include snippets\/self-signed.conf/d" /etc/nginx/sites-available/$2
            sed -i "/include snippets\/ssl-params.conf/d" /etc/nginx/sites-available/$2

            # Check is success?
            if grep -q "listen 443 ssl" /etc/nginx/sites-available/$2
            then
                  echo "[!] SSL cannot removed to site. (May be permission error)"
                  exit 0
            else
                  echo "[✔] SSL removed in site successfuly."
                  systemctl restart nginx.service &>/dev/null
                  exit 0
            fi
      else
            echo "[!] SSL is already off in this site."
            exit 1
      fi

# ========================================================================
# - help, unknown command
# ========================================================================


else
      # Allow show help page without root user.
      echo "TeTeOS.Net Website Manager"
      echo "A tool for manage nginx in PiluX Webserver Edition"
      echo "Version beta"
      echo ""
      echo "Usage:"
      echo " - Site managing:"
      echo "      list                           list sites available"
      echo "      add [domain name]              add a site"
      echo "                                     (create /var/www/[domain name]/public_html/)"
      echo "      add [domain name] localwork    add a site, enable and add to hosts file"
      echo "                                     (create /var/www/[domain name]/public_html/)"
      echo "      del [domain name]              delete a site"
      echo "      del [domain name] all          delete a site (with /var/www/ files!)"
      echo "      enable [domain name]           enable a site"
      echo "      disable [domain name]          disable a site"
      echo ""
      echo " - Server managing: "
      echo "      restart                        restart services"
      echo "      local-add                      add site to hosts file with \"localhost\" ip"
      echo "      local-del                      del site to hosts file with \"localhost\" ip"
      if [ -f /teteosnet/OS/Name ]; then
            if ! [[ $0 = "/teteosnet/Bin/tsite" || $0 = "tsite" ]]; then
      echo "      piluxbin                       add script to this $PILUX_OS_NAME. (install command)"
            fi
      fi
      echo ""
      echo " - SSL: "
      echo "      sign-self                      create and config nginx self-sign ssl"
      echo "      sign-self-renew                renew signed ssl (365 day)"
      echo "      ssl-on [domain name]           enable SSL for a site (self-sign)"
      echo "      ssl-off [domain name]          disable SSL for a site (self-sign)"

      echo ""
      exit 0
fi
