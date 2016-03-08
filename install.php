<?php
/*
Let's Encrypt for ISPConfig
Copyright (c) 2015, Alexandre Alouit <alexandre.alouit@gmail.com>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

$backup_dir = "/var/backup/";
$backup_file = date("Ymdhis")."-ISPConfig-letsencrypt.tar.gz";
$backup_file2 = date("Ymdhis")."-cronjob.txt";

if(!file_exists("/usr/local/ispconfig/server/lib/config.inc.php") OR !file_exists("/usr/local/ispconfig/server/lib/mysql_clientdb.conf")) {
	echo "ERROR: Unable to load the ISPConfig defaut configuration files.\n";
	exit;
}

require_once "/usr/local/ispconfig/server/lib/config.inc.php";
require_once "/usr/local/ispconfig/server/lib/mysql_clientdb.conf";

if($conf["app_version"] != "3.0.5.4p8") {
	echo "ERROR: This version is unsupported.\n";
	exit;
}

if(!file_exists($backup_dir)) {
	echo "Backup directory not found.\n";
	mkdir($backup_dir, 0700);
}

if(!file_exists($backup_dir)) {
	echo "ERROR: Create it, and relaunch me!\n";
	exit;
}

if(getcwd() != realpath(dirname(__FILE__))) {
	echo "ERROR: Run me in current installer directory!\n";
	exit;
}

echo "Create backup on " . $backup_dir . " directory\n";

exec("/bin/tar -czf " . $backup_dir . $backup_file . " /usr/local/ispconfig");

if(!file_exists($backup_dir . $backup_file )) {
	echo "ERROR: There was a problem with the backup file.\n";
	exit;
}

echo "Backup finished\n";

if(!is_dir("/etc/letsencrypt")) {
	echo "ERROR: Let's Encrypt directory ( /etc/letsencrypt/ ) is missing, install it corectly!\n";
	exit;
}

if(!is_file("/root/.local/share/letsencrypt/bin/letsencrypt")) {
	echo "ERROR: Let's Encrypt ( /root/.local/share/letsencrypt/bin/letsencrypt ) is missing, install it corectly!\n";
	exit;
}


if(is_file("/etc/letsencrypt/cli.ini")) {
	echo "Let's Encrypt configuration file exist, backup up and remove.\n";
	exec("cp /etc/letsencrypt/cli.ini " . $backup_dir . date("Ymdhis") . "-letsencrypt.cli.ini");
	exec("rm /etc/letsencrypt/cli.ini");

}
echo "Copy Let's Encrypt configuration.\n";
exec("cp ./cli.ini /etc/letsencrypt/cli.ini");

if(!$buffer = mysql_connect($clientdb_host, $clientdb_user, $clientdb_password)) {
	echo "ERROR: There was a problem with the MySQL connection.\n";
	exit;
}

echo "Start MySQL update..\n";
mysql_db_query($conf['db_database'], "ALTER TABLE `web_domain` ADD `ssl_letsencrypt` enum('n','y') NOT NULL DEFAULT 'n';", $buffer);

if(is_file("/etc/apache2/apache2.conf")) {
	echo "Configure Apache and reload it.\n";
	if(is_dir("/etc/apache2/conf-available")) {
		if(is_file("/etc/apache2/conf-available/letsencrypt.conf")) {
			exec("rm /etc/apache2/conf-available/letsencrypt.conf");
		}
		exec("cp ./apache.letsencrypt.conf /etc/apache2/conf-available/letsencrypt.conf");
	}
	if(is_dir("/etc/apache2/conf.d")) {
		if(is_file("/etc/apache2/conf.d/letsencrypt.conf")) {
			exec("rm /etc/apache2/conf.d/letsencrypt.conf");
		}
		exec("cp ./apache.letsencrypt.conf /etc/apache2/conf.d/letsencrypt.conf");
	}
	exec("a2enmod headers");
	exec("a2enconf letsencrypt");
	exec("service apache2 reload");
}

if(is_file("/etc/nginx/nginx.conf")) {
	echo "Backup Nginx file to " . $backup_dir . ".\n";
	exec("cp /etc/nginx/nginx.conf " . $backup_dir . date("Ymdhis") . "-nginx.conf");
	echo "Patch Nginx and reload it.\n";
	exec("patch /etc/nginx/nginx.conf < ./nginx.conf.patch");
	exec("service nginx reload");
}

echo "Create backup cronjob on " . $backup_dir . " directory\n";
exec("crontab -l >> " . $backup_dir . $backup_file2);
if(!file_exists($backup_dir . $backup_file2 )) {
	echo "ERROR: There was a problem with the cronjob backup file.\n";
	exit;
}

exec("crontab -l", $output);

if(!in_array("30 02 * * * /root/.local/share/letsencrypt/bin/letsencrypt renew >> /var/log/ispconfig/cron.log; done", $output)) {
	echo "Add a cronjob for renewal certs\n";

	$output[] = "30 02 * * * /root/.local/share/letsencrypt/bin/letsencrypt renew >> /var/log/ispconfig/cron.log; done";

	exec("touch ./crontab.tmp");
	if(!is_file("./crontab.tmp")) {
		echo "ERROR: Unable to create temporary crontab file.\n";
		exit;
	}

	foreach($output as $line) {
		exec("echo '" . $line . "' >> ./crontab.tmp");
	}

/*
	exec("cat ./crontab.tmp", $crontab);

	$diff = array_diff($output, $crontab);
	if(empty($diff)) {
		exec("crontab ./crontab.tmp");
		exec("rm ./crontab.tmp");
	} else {
		echo "ERROR: There was a problem with the cronjob temporary file.\n";
		exit;
	}
*/
exec("crontab ./crontab.tmp");
exec("rm ./crontab.tmp");
} else {
		echo "Renewer already present in crontab.\n";
}

echo "And finally, update ISPConfig.\n";

if(!is_file("/usr/bin/rsync")) {
	echo "ERROR: Unable to find rsync binary, install it or merge ./src to /usr/local/ispconfig manually.\n";
	exit;
}

exec("rsync -av ./src/ /usr/local/ispconfig");

echo "Done my job. Enjoy!\n";
exit;
?>
