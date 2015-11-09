ISPConfig Let's Encrypt
=========================


# REQUIRREMENTS

Let's Encrypt installed
ISPConfig 3.0.5.4p8 or newer
Apache or Nginx


# INSTALLATION (as root)

```
git clone https://github.com/alexalouit/ISPConfig-letsencrypt.git
cd ISPConfig-letsencrypt
php -q install.php
```

Then, go to file /etc/letsencrypt/cli.ini:
Uncomment email field, and add a valid email address.

After install, a new checkbox will be available in editing website, just check it.


## MANUAL INSTALLATION

- patch or create Let's Encrypt configuration
```
cp ./cli.ini /etc/letsencrypt/cli.ini");
 or
patch /etc/letsencrypt/cli.ini < ./cli.ini.patch
```

- patch ISPConfig
```
cp ispconfig.patch /usr/local/ispconfig/ispconfig.patch
cd /usr/local/ispconfig
patch -p3 < ./ispconfig.patch
rm ./ispconfig.patch
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
30 02 * * * /root/.local/share/letsencrypt/bin/letsencrypt-renewer >> /var/log/ispconfig/cron.log; done
```

- sql queries:
```
ALTER TABLE `web_domain` ADD `ssl_letsencrypt` enum('n','y') NOT NULL DEFAULT 'n';
```