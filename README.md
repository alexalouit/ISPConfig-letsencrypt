ISPConfig Let's Encrypt
=========================


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
30 02 * * * /root/.local/share/letsencrypt/bin/letsencrypt-renewer >> /var/log/ispconfig/cron.log; done
```

- sql queries:
```
ALTER TABLE `web_domain` ADD `ssl_letsencrypt` enum('n','y') NOT NULL DEFAULT 'n';
```
