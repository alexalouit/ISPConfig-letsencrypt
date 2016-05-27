ISPConfig Let's Encrypt
=========================

Don't use this plugin with ISPConfig 3.1 (or newer), this plugin is natively included.

# REQUIREMENTS

Let's Encrypt installed

ISPConfig (select version in branche)

Apache or Nginx


# INSTALLATION (as root)

```
git clone https://github.com/alexalouit/ISPConfig-letsencrypt.git
cd ISPConfig-letsencrypt
php -q install.php
```

After install, a new checkbox will be available in editing website, just check it.

Adjust server in ```/etc/letsencrypt/cli.ini```if isn't ``https://acme-v01.api.letsencrypt.org/directory```


## MANUAL INSTALLATION

- make your own backup!

- go to dir
```
cd ISPConfig-letsencrypt
```

- create Let's Encrypt configuration
```
cp ./cli.ini /etc/letsencrypt/cli.ini
```

- patch ISPConfig (merge all files from ./src to /usr/local/ispconfig)
```
rsync -av ./src/ /usr/local/ispconfig/
```

- prepare apache
```
cp ./apache.letsencrypt.conf /etc/apache2/conf-available/letsencrypt.conf
a2enmod headers
a2enconf letsencrypt
service apache2 reload
```

- prepare nginx
```
patch /etc/nginx/nginx.conf < ./nginx.conf.patch
service nginx reload
```

- create a cron for automatic renewal:
```
crontab -e
30 02 * * * /root/.local/share/letsencrypt/bin/letsencrypt renew >> /var/log/ispconfig/cron.log
```

- sql queries:
```
ALTER TABLE `web_domain` ADD `ssl_letsencrypt` enum('n','y') NOT NULL DEFAULT 'n';
```


## TROUBLESHOOTING

update Let's Encrypt
```
cd /root/letsencrypt
git fetch
./letsencrypt-auto
```

see Let's Encrypt log
```
cat /var/log/letsencrypt/letsencrypt.log
```

see ISPConfig log
```
cat /var/log/ispconfig/ispconfig.log
cat /var/log/ispconfig/cron.log
```

remove certs
```
rm -r /etc/letsencrypt/archive/$domain/
rm -r /etc/letsencrypt/live/$domain/
rm -r /etc/letsencrypt/renewal/$domain.conf
```

re-generate cert: uncheck SSL & Let's Encrypt, save, recheck and save
