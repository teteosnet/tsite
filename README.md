# tsite

A tool for manage nginx in Linux/PiluX

Installation for Linux distros (Not yet!)

```
 git clone https://github.com/hasanmerkit/tsite.git
```
 Or
```
 wget https://pilux.teteos.net/tools/tsite.sh
```

Installation for PiluX based OS
```
 tsite
```

Usage:

```
  - Site managing:
      list                           list sites available
      add [domain name]              add a site
                                     (create /var/www/[domain name]/public_html/)
      add [domain name] localwork    add a site, enable and add to hosts file
                                     (create /var/www/[domain name]/public_html/)
      del [domain name]              delete a site
      del [domain name] all          delete a site
                                     (with /var/www/ files!)
      enable [domain name]           enable a site
      disable [domain name]          disable a site

 - Server managing: 
      restart                        restart services
      local-add                      add site to hosts file with "localhost" ip
      local-del                      del site to hosts file with "localhost" ip

 - SSL: 
      sign-self                      create and config nginx self-sign ssl
      sign-self-renew                renew signed ssl (365 day)
      ssl-on [domain name]           enable SSL for a site (self-sign)
      ssl-off [domain name]          disable SSL for a site (self-sign)
```

Example:

```
  tsite add example.com # add example.com to your nginx
  tsite add example.com localwork # add example.com to your nginx, hosts file and enable
  tsite del example.com all # del example.com in your nginx ->WITH /VAR/WWW/ DATA<-
  tsite local-add example.com # add example.com to hosts file with 127.0.0.1 ip.
  tsite sign-self # create self-sign ssl for your nginx
```
