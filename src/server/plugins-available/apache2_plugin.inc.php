<?php

/*
Copyright (c) 2007 - 2012, Till Brehm, projektfarm Gmbh
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.
    * Neither the name of ISPConfig nor the names of its contributors
      may be used to endorse or promote products derived from this software without
      specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

class apache2_plugin {

	var $plugin_name = 'apache2_plugin';
	var $class_name = 'apache2_plugin';

	// private variables
	var $action = '';
	var $ssl_certificate_changed = false;

	//* This function is called during ispconfig installation to determine
	//  if a symlink shall be created for this plugin.
	function onInstall() {
		global $conf;

		if($conf['services']['web'] == true) {
			return true;
		} else {
			return false;
		}

	}


	/*
	 	This function is called when the plugin is loaded
	*/

	function onLoad() {
		global $app;

		/*
		Register for the events
		*/
		$app->plugins->registerEvent('web_domain_insert', $this->plugin_name, 'ssl');
		$app->plugins->registerEvent('web_domain_update', $this->plugin_name, 'ssl');
		$app->plugins->registerEvent('web_domain_delete', $this->plugin_name, 'ssl');

		$app->plugins->registerEvent('web_domain_insert', $this->plugin_name, 'insert');
		$app->plugins->registerEvent('web_domain_update', $this->plugin_name, 'update');
		$app->plugins->registerEvent('web_domain_delete', $this->plugin_name, 'delete');

		$app->plugins->registerEvent('server_ip_insert', $this->plugin_name, 'server_ip');
		$app->plugins->registerEvent('server_ip_update', $this->plugin_name, 'server_ip');
		$app->plugins->registerEvent('server_ip_delete', $this->plugin_name, 'server_ip');

		$app->plugins->registerEvent('webdav_user_insert', $this->plugin_name, 'webdav');
		$app->plugins->registerEvent('webdav_user_update', $this->plugin_name, 'webdav');
		$app->plugins->registerEvent('webdav_user_delete', $this->plugin_name, 'webdav');

		$app->plugins->registerEvent('client_delete', $this->plugin_name, 'client_delete');

		$app->plugins->registerEvent('web_folder_user_insert', $this->plugin_name, 'web_folder_user');
		$app->plugins->registerEvent('web_folder_user_update', $this->plugin_name, 'web_folder_user');
		$app->plugins->registerEvent('web_folder_user_delete', $this->plugin_name, 'web_folder_user');

		$app->plugins->registerEvent('web_folder_update', $this->plugin_name, 'web_folder_update');
		$app->plugins->registerEvent('web_folder_delete', $this->plugin_name, 'web_folder_delete');

		$app->plugins->registerEvent('ftp_user_delete', $this->plugin_name, 'ftp_user_delete');

	}

	// Handle the creation of SSL certificates
	function ssl($event_name, $data) {
		global $app, $conf;

		$app->uses('system');

		// load the server configuration options
		$app->uses('getconf');
		$web_config = $app->getconf->get_server_config($conf['server_id'], 'web');
		if ($web_config['CA_path']!='' && !file_exists($web_config['CA_path'].'/openssl.cnf'))
			$app->log("CA path error, file does not exist:".$web_config['CA_path'].'/openssl.cnf', LOGLEVEL_ERROR);

		//* Only vhosts can have a ssl cert
		if($data["new"]["type"] != "vhost" && $data["new"]["type"] != "vhostsubdomain") return;

		// if(!is_dir($data['new']['document_root'].'/ssl')) exec('mkdir -p '.$data['new']['document_root'].'/ssl');
		if(!is_dir($data['new']['document_root'].'/ssl')) $app->system->mkdirpath($data['new']['document_root'].'/ssl');

		$ssl_dir = $data['new']['document_root'].'/ssl';
		$domain = $data['new']['ssl_domain'];
		$key_file = $ssl_dir.'/'.$domain.'.key.org';
		$key_file2 = $ssl_dir.'/'.$domain.'.key';
		$csr_file = $ssl_dir.'/'.$domain.'.csr';
		$crt_file = $ssl_dir.'/'.$domain.'.crt';

		//* Create a SSL Certificate, but only if this is not a mirror server.
		if($data['new']['ssl_action'] == 'create' && $conf['mirror_server_id'] == 0) {

			$this->ssl_certificate_changed = true;

			//* Rename files if they exist
			if(file_exists($key_file)){
				$app->system->rename($key_file, $key_file.'.bak');
				$app->system->chmod($key_file.'.bak', 0400);
			}
			if(file_exists($key_file2)){
				$app->system->rename($key_file2, $key_file2.'.bak');
				$app->system->chmod($key_file2.'.bak', 0400);
			}
			if(file_exists($csr_file)) $app->system->rename($csr_file, $csr_file.'.bak');
			if(file_exists($crt_file)) $app->system->rename($crt_file, $crt_file.'.bak');

			$rand_file = $ssl_dir.'/random_file';
			$rand_data = md5(uniqid(microtime(), 1));
			for($i=0; $i<1000; $i++) {
				$rand_data .= md5(uniqid(microtime(), 1));
				$rand_data .= md5(uniqid(microtime(), 1));
				$rand_data .= md5(uniqid(microtime(), 1));
				$rand_data .= md5(uniqid(microtime(), 1));
			}
			$app->system->file_put_contents($rand_file, $rand_data);

			$ssl_password = substr(md5(uniqid(microtime(), 1)), 0, 15);

			$ssl_cnf = "        RANDFILE               = $rand_file

        [ req ]
        default_bits           = 2048
		default_md             = sha256
        default_keyfile        = keyfile.pem
        distinguished_name     = req_distinguished_name
        attributes             = req_attributes
        prompt                 = no
        output_password        = $ssl_password

        [ req_distinguished_name ]
        C                      = ".trim($data['new']['ssl_country'])."
        ST                     = ".trim($data['new']['ssl_state'])."
        L                      = ".trim($data['new']['ssl_locality'])."
        O                      = ".trim($data['new']['ssl_organisation'])."
        OU                     = ".trim($data['new']['ssl_organisation_unit'])."
        CN                     = $domain
        emailAddress           = webmaster@".$data['new']['domain']."

        [ req_attributes ]
        challengePassword              = A challenge password";

			$ssl_cnf_file = $ssl_dir.'/openssl.conf';
			$app->system->file_put_contents($ssl_cnf_file, $ssl_cnf);

			$rand_file = escapeshellcmd($rand_file);
			$key_file = escapeshellcmd($key_file);
			$openssl_cmd_key_file = $key_file;
			if(substr($domain, 0, 2) == '*.' && strpos($key_file, '/ssl/\*.') !== false) $key_file = str_replace('/ssl/\*.', '/ssl/*.', $key_file); // wildcard certificate
			$key_file2 = escapeshellcmd($key_file2);
			$openssl_cmd_key_file2 = $key_file2;
			if(substr($domain, 0, 2) == '*.' && strpos($key_file2, '/ssl/\*.') !== false) $key_file2 = str_replace('/ssl/\*.', '/ssl/*.', $key_file2); // wildcard certificate
			$ssl_days = 3650;
			$csr_file = escapeshellcmd($csr_file);
			$openssl_cmd_csr_file = $csr_file;
			if(substr($domain, 0, 2) == '*.' && strpos($csr_file, '/ssl/\*.') !== false) $csr_file = str_replace('/ssl/\*.', '/ssl/*.', $csr_file); // wildcard certificate
			$config_file = escapeshellcmd($ssl_cnf_file);
			$crt_file = escapeshellcmd($crt_file);
			$openssl_cmd_crt_file = $crt_file;
			if(substr($domain, 0, 2) == '*.' && strpos($crt_file, '/ssl/\*.') !== false) $crt_file = str_replace('/ssl/\*.', '/ssl/*.', $crt_file); // wildcard certificate

			if(is_file($ssl_cnf_file) && !is_link($ssl_cnf_file)) {

				exec("openssl genrsa -des3 -rand $rand_file -passout pass:$ssl_password -out $openssl_cmd_key_file 2048");
				exec("openssl req -new -sha256 -passin pass:$ssl_password -passout pass:$ssl_password -key $openssl_cmd_key_file -out $openssl_cmd_csr_file -days $ssl_days -config $config_file");
				exec("openssl rsa -passin pass:$ssl_password -in $openssl_cmd_key_file -out $openssl_cmd_key_file2");

				if(file_exists($web_config['CA_path'].'/openssl.cnf'))
				{
					exec("openssl ca -batch -out $openssl_cmd_crt_file -config ".$web_config['CA_path']."/openssl.cnf -passin pass:".$web_config['CA_pass']." -in $openssl_cmd_csr_file");
					$app->log("Creating CA-signed SSL Cert for: $domain", LOGLEVEL_DEBUG);
					if (filesize($crt_file)==0 || !file_exists($crt_file)) $app->log("CA-Certificate signing failed.  openssl ca -out $openssl_cmd_crt_file -config ".$web_config['CA_path']."/openssl.cnf -passin pass:".$web_config['CA_pass']." -in $openssl_cmd_csr_file", LOGLEVEL_ERROR);
				};
				if (@filesize($crt_file)==0 || !file_exists($crt_file)){
					exec("openssl req -x509 -passin pass:$ssl_password -passout pass:$ssl_password -key $openssl_cmd_key_file -in $openssl_cmd_csr_file -out $openssl_cmd_crt_file -days $ssl_days -config $config_file ");
					$app->log("Creating self-signed SSL Cert for: $domain", LOGLEVEL_DEBUG);
				};

			}

			$app->system->chmod($key_file, 0400);
			$app->system->chmod($key_file2, 0400);
			@$app->system->unlink($config_file);
			@$app->system->unlink($rand_file);
			$ssl_request = $app->db->quote($app->system->file_get_contents($csr_file));
			$ssl_cert = $app->db->quote($app->system->file_get_contents($crt_file));
			$ssl_key2 = $app->db->quote($app->system->file_get_contents($key_file2));
			/* Update the DB of the (local) Server */
			$app->db->query("UPDATE web_domain SET ssl_request = '$ssl_request', ssl_cert = '$ssl_cert', ssl_key = '$ssl_key2' WHERE domain = '".$data['new']['domain']."'");
			$app->db->query("UPDATE web_domain SET ssl_action = '' WHERE domain = '".$data['new']['domain']."'");
			/* Update also the master-DB of the Server-Farm */
			$app->dbmaster->query("UPDATE web_domain SET ssl_request = '$ssl_request', ssl_cert = '$ssl_cert', ssl_key = '$ssl_key2' WHERE domain = '".$data['new']['domain']."'");
			$app->dbmaster->query("UPDATE web_domain SET ssl_action = '' WHERE domain = '".$data['new']['domain']."'");
		}

		//* Save a SSL certificate to disk
		if($data["new"]["ssl_action"] == 'save') {
			$this->ssl_certificate_changed = true;
			$ssl_dir = $data["new"]["document_root"]."/ssl";
			$domain = ($data["new"]["ssl_domain"] != '')?$data["new"]["ssl_domain"]:$data["new"]["domain"];
			$key_file = $ssl_dir.'/'.$domain.'.key.org';
			$key_file2 = $ssl_dir.'/'.$domain.'.key';
			$csr_file = $ssl_dir.'/'.$domain.".csr";
			$crt_file = $ssl_dir.'/'.$domain.".crt";
			$bundle_file = $ssl_dir.'/'.$domain.".bundle";

			//* Backup files
			if(file_exists($key_file)){
				$app->system->copy($key_file, $key_file.'~');
				$app->system->chmod($key_file.'~', 0400);
			}
			if(file_exists($key_file2)){
				$app->system->copy($key_file2, $key_file2.'~');
				$app->system->chmod($key_file2.'~', 0400);
			}
			if(file_exists($csr_file)) $app->system->copy($csr_file, $csr_file.'~');
			if(file_exists($crt_file)) $app->system->copy($crt_file, $crt_file.'~');
			if(file_exists($bundle_file)) $app->system->copy($bundle_file, $bundle_file.'~');

			//* Write new ssl files
			if(trim($data["new"]["ssl_request"]) != '') $app->system->file_put_contents($csr_file, $data["new"]["ssl_request"]);
			if(trim($data["new"]["ssl_cert"]) != '') $app->system->file_put_contents($crt_file, $data["new"]["ssl_cert"]);
			if(trim($data["new"]["ssl_bundle"]) != '') $app->system->file_put_contents($bundle_file, $data["new"]["ssl_bundle"]);

			//* Write the key file, if field is empty then import the key into the db
			if(trim($data["new"]["ssl_key"]) != '') {
				$app->system->file_put_contents($key_file2, $data["new"]["ssl_key"]);
				$app->system->chmod($key_file2, 0400);
			} else {
				$ssl_key2 = $app->db->quote($app->system->file_get_contents($key_file2));
				/* Update the DB of the (local) Server */
				$app->db->query("UPDATE web_domain SET ssl_key = '$ssl_key2' WHERE domain = '".$data['new']['domain']."'");
				/* Update also the master-DB of the Server-Farm */
				$app->dbmaster->query("UPDATE web_domain SET ssl_key = '$ssl_key2' WHERE domain = '".$data['new']['domain']."'");
			}

			/* Update the DB of the (local) Server */
			$app->db->query("UPDATE web_domain SET ssl_action = '' WHERE domain = '".$data['new']['domain']."'");

			/* Update also the master-DB of the Server-Farm */
			$app->dbmaster->query("UPDATE web_domain SET ssl_action = '' WHERE domain = '".$data['new']['domain']."'");
			$app->log('Saving SSL Cert for: '.$domain, LOGLEVEL_DEBUG);
		}

		//* Delete a SSL certificate
		if($data['new']['ssl_action'] == 'del') {
			$ssl_dir = $data['new']['document_root'].'/ssl';
			$domain = ($data["new"]["ssl_domain"] != '')?$data["new"]["ssl_domain"]:$data["new"]["domain"];
			$csr_file = $ssl_dir.'/'.$domain.'.csr';
			$crt_file = $ssl_dir.'/'.$domain.'.crt';
			$bundle_file = $ssl_dir.'/'.$domain.'.bundle';
			if(file_exists($web_config['CA_path'].'/openssl.cnf') && !is_link($web_config['CA_path'].'/openssl.cnf'))
			{
				exec("openssl ca -batch -config ".$web_config['CA_path']."/openssl.cnf -passin pass:".$web_config['CA_pass']." -revoke ".escapeshellcmd($crt_file));
				$app->log("Revoking CA-signed SSL Cert for: $domain", LOGLEVEL_DEBUG);
			};
			$app->system->unlink($csr_file);
			$app->system->unlink($crt_file);
			$app->system->unlink($bundle_file);
			/* Update the DB of the (local) Server */
			$app->db->query("UPDATE web_domain SET ssl_request = '', ssl_cert = '' WHERE domain = '".$data['new']['domain']."'");
			$app->db->query("UPDATE web_domain SET ssl_action = '' WHERE domain = '".$data['new']['domain']."'");
			/* Update also the master-DB of the Server-Farm */
			$app->dbmaster->query("UPDATE web_domain SET ssl_request = '', ssl_cert = '' WHERE domain = '".$data['new']['domain']."'");
			$app->dbmaster->query("UPDATE web_domain SET ssl_action = '' WHERE domain = '".$data['new']['domain']."'");
			$app->log('Deleting SSL Cert for: '.$domain, LOGLEVEL_DEBUG);
		}

	}


	function insert($event_name, $data) {
		global $app, $conf;

		$this->action = 'insert';
		// just run the update function
		$this->update($event_name, $data);


	}


	function update($event_name, $data) {
		global $app, $conf;

		if($this->action != 'insert') $this->action = 'update';

		if($data['new']['type'] != 'vhost' && $data['new']['type'] != 'vhostsubdomain' && $data['new']['parent_domain_id'] > 0) {

			$old_parent_domain_id = intval($data['old']['parent_domain_id']);
			$new_parent_domain_id = intval($data['new']['parent_domain_id']);

			// If the parent_domain_id has been changed, we will have to update the old site as well.
			if($this->action == 'update' && $data['new']['parent_domain_id'] != $data['old']['parent_domain_id']) {
				$tmp = $app->db->queryOneRecord('SELECT * FROM web_domain WHERE domain_id = '.$old_parent_domain_id." AND active = 'y'");
				$data['new'] = $tmp;
				$data['old'] = $tmp;
				$this->action = 'update';
				$this->update($event_name, $data);
			}

			// This is not a vhost, so we need to update the parent record instead.
			$tmp = $app->db->queryOneRecord('SELECT * FROM web_domain WHERE domain_id = '.$new_parent_domain_id." AND active = 'y'");
			$data['new'] = $tmp;
			$data['old'] = $tmp;
			$this->action = 'update';
		}

		// load the server configuration options
		$app->uses('getconf');
		$web_config = $app->getconf->get_server_config($conf['server_id'], 'web');

		//* Check if this is a chrooted setup
		if($web_config['website_basedir'] != '' && @is_file($web_config['website_basedir'].'/etc/passwd')) {
			$apache_chrooted = true;
			$app->log('Info: Apache is chrooted.', LOGLEVEL_DEBUG);
		} else {
			$apache_chrooted = false;
		}

		if($data['new']['document_root'] == '') {
			if($data['new']['type'] == 'vhost' || $data['new']['type'] == 'vhostsubdomain') $app->log('document_root not set', LOGLEVEL_WARN);
			return 0;
		}
		if($app->system->is_allowed_user($data['new']['system_user'], $app->system->is_user($data['new']['system_user']), true) == false
			|| $app->system->is_allowed_group($data['new']['system_group'], $app->system->is_group($data['new']['system_group']), true) == false) {
			$app->log('Websites cannot be owned by the root user or group. User: '.$data['new']['system_user'].' Group: '.$data['new']['system_group'], LOGLEVEL_WARN);
			return 0;
		}
		if(trim($data['new']['domain']) == '') {
			$app->log('domain is empty', LOGLEVEL_WARN);
			return 0;
		}

		$web_folder = 'web';
		$log_folder = 'log';
		$old_web_folder = 'web';
		$old_log_folder = 'log';
		if($data['new']['type'] == 'vhostsubdomain') {
			// new one
			$tmp = $app->db->queryOneRecord('SELECT `domain` FROM web_domain WHERE domain_id = '.intval($data['new']['parent_domain_id']));
			$subdomain_host = preg_replace('/^(.*)\.' . preg_quote($tmp['domain'], '/') . '$/', '$1', $data['new']['domain']);
			if($subdomain_host == '') $subdomain_host = 'web'.$data['new']['domain_id'];
			$web_folder = $data['new']['web_folder'];
			$log_folder .= '/' . $subdomain_host;
			unset($tmp);
			
			if(isset($data['old']['parent_domain_id'])) {
				// old one
				$tmp = $app->db->queryOneRecord('SELECT `domain` FROM web_domain WHERE domain_id = '.intval($data['old']['parent_domain_id']));
				$subdomain_host = preg_replace('/^(.*)\.' . preg_quote($tmp['domain'], '/') . '$/', '$1', $data['old']['domain']);
				if($subdomain_host == '') $subdomain_host = 'web'.$data['old']['domain_id'];
				$old_web_folder = $data['old']['web_folder'];
				$old_log_folder .= '/' . $subdomain_host;
				unset($tmp);
			}
		}

		// Create group and user, if not exist
		$app->uses('system');

		if($web_config['connect_userid_to_webid'] == 'y') {
			//* Calculate the uid and gid
			$connect_userid_to_webid_start = ($web_config['connect_userid_to_webid_start'] < 1000)?1000:intval($web_config['connect_userid_to_webid_start']);
			$fixed_uid_gid = intval($connect_userid_to_webid_start + $data['new']['domain_id']);
			$fixed_uid_param = '--uid '.$fixed_uid_gid;
			$fixed_gid_param = '--gid '.$fixed_uid_gid;

			//* Check if a ispconfigend user and group exists and create them
			if(!$app->system->is_group('ispconfigend')) {
				exec('groupadd --gid '.($connect_userid_to_webid_start + 10000).' ispconfigend');
			}
			if(!$app->system->is_user('ispconfigend')) {
				exec('useradd -g ispconfigend -d /usr/local/ispconfig --uid '.($connect_userid_to_webid_start + 10000).' ispconfigend');
			}
		} else {
			$fixed_uid_param = '';
			$fixed_gid_param = '';
		}

		$groupname = escapeshellcmd($data['new']['system_group']);
		if($data['new']['system_group'] != '' && !$app->system->is_group($data['new']['system_group'])) {
			exec('groupadd '.$fixed_gid_param.' '.$groupname);
			if($apache_chrooted) $this->_exec('chroot '.escapeshellcmd($web_config['website_basedir']).' groupadd '.$groupname);
			$app->log('Adding the group: '.$groupname, LOGLEVEL_DEBUG);
		}

		$username = escapeshellcmd($data['new']['system_user']);
		if($data['new']['system_user'] != '' && !$app->system->is_user($data['new']['system_user'])) {
			if($web_config['add_web_users_to_sshusers_group'] == 'y') {
				exec('useradd -d '.escapeshellcmd($data['new']['document_root'])." -g $groupname $fixed_uid_param -G sshusers $username -s /bin/false");
				if($apache_chrooted) $this->_exec('chroot '.escapeshellcmd($web_config['website_basedir']).' useradd -d '.escapeshellcmd($data['new']['document_root'])." -g $groupname $fixed_uid_param -G sshusers $username -s /bin/false");
			} else {
				exec('useradd -d '.escapeshellcmd($data['new']['document_root'])." -g $groupname $fixed_uid_param $username -s /bin/false");
				if($apache_chrooted) $this->_exec('chroot '.escapeshellcmd($web_config['website_basedir']).' useradd -d '.escapeshellcmd($data['new']['document_root'])." -g $groupname $fixed_uid_param $username -s /bin/false");
			}
			$app->log('Adding the user: '.$username, LOGLEVEL_DEBUG);
		}

		//* If the client of the site has been changed, we have a change of the document root
		if($this->action == 'update' && $data['new']['document_root'] != $data['old']['document_root']) {

			//* Get the old client ID
			$old_client = $app->dbmaster->queryOneRecord('SELECT client_id FROM sys_group WHERE sys_group.groupid = '.intval($data['old']['sys_groupid']));
			$old_client_id = intval($old_client['client_id']);
			unset($old_client);

			//* Remove the old symlinks
			$tmp_symlinks_array = explode(':', $web_config['website_symlinks']);
			if(is_array($tmp_symlinks_array)) {
				foreach($tmp_symlinks_array as $tmp_symlink) {
					$tmp_symlink = str_replace('[client_id]', $old_client_id, $tmp_symlink);
					$tmp_symlink = str_replace('[website_domain]', $data['old']['domain'], $tmp_symlink);
					// Remove trailing slash
					if(substr($tmp_symlink, -1, 1) == '/') $tmp_symlink = substr($tmp_symlink, 0, -1);
					// create the symlinks, if not exist
					if(is_link($tmp_symlink)) {
						exec('rm -f '.escapeshellcmd($tmp_symlink));
						$app->log('Removed symlink: rm -f '.$tmp_symlink, LOGLEVEL_DEBUG);
					}
				}
			}

			//* Remove protection of old folders
			$app->system->web_folder_protection($data['old']['document_root'], false);

			if($data["new"]["type"] != "vhostsubdomain") {
				//* Move the site data
				$tmp_docroot = explode('/', $data['new']['document_root']);
				unset($tmp_docroot[count($tmp_docroot)-1]);
				$new_dir = implode('/', $tmp_docroot);

				$tmp_docroot = explode('/', $data['old']['document_root']);
				unset($tmp_docroot[count($tmp_docroot)-1]);
				$old_dir = implode('/', $tmp_docroot);

				//* Check if there is already some data in the new docroot and rename it as we need a clean path to move the existing site to the new path
				if(@is_dir($data['new']['document_root'])) {
					$app->system->web_folder_protection($data['new']['document_root'], false);
					$app->system->rename($data['new']['document_root'], $data['new']['document_root'].'_bak_'.date('Y_m_d_H_i_s'));
					$app->log('Renaming existing directory in new docroot location. mv '.$data['new']['document_root'].' '.$data['new']['document_root'].'_bak_'.date('Y_m_d_H_i_s'), LOGLEVEL_DEBUG);
				}
				
				//* Unmount the old log directory bfore we move the log dir
				exec('umount '.escapeshellcmd($old_dir.'/log'));

				//* Create new base directory, if it does not exist yet
				if(!is_dir($new_dir)) $app->system->mkdirpath($new_dir);
				$app->system->web_folder_protection($data['old']['document_root'], false);
				exec('mv '.escapeshellarg($data['old']['document_root']).' '.escapeshellarg($new_dir));
				//$app->system->rename($data['old']['document_root'],$new_dir);
				$app->log('Moving site to new document root: mv '.$data['old']['document_root'].' '.$new_dir, LOGLEVEL_DEBUG);

				// Handle the change in php_open_basedir
				$data['new']['php_open_basedir'] = str_replace($data['old']['document_root'], $data['new']['document_root'], $data['old']['php_open_basedir']);

				//* Change the owner of the website files to the new website owner
				exec('chown --recursive --from='.escapeshellcmd($data['old']['system_user']).':'.escapeshellcmd($data['old']['system_group']).' '.escapeshellcmd($data['new']['system_user']).':'.escapeshellcmd($data['new']['system_group']).' '.$new_dir);

				//* Change the home directory and group of the website user
				$command = 'killall -u '.escapeshellcmd($data['new']['system_user']).' ; usermod';
				$command .= ' --home '.escapeshellcmd($data['new']['document_root']);
				$command .= ' --gid '.escapeshellcmd($data['new']['system_group']);
				$command .= ' '.escapeshellcmd($data['new']['system_user']).' 2>/dev/null';
				exec($command);
			}

			if($apache_chrooted) $this->_exec('chroot '.escapeshellcmd($web_config['website_basedir']).' '.$command);

			//* Change the log mount
			/*
			$fstab_line = '/var/log/ispconfig/httpd/'.$data['old']['domain'].' '.$data['old']['document_root'].'/'.$old_log_folder.'    none    bind';
			$app->system->removeLine('/etc/fstab', $fstab_line);
			$fstab_line = '/var/log/ispconfig/httpd/'.$data['old']['domain'].' '.$data['old']['document_root'].'/'.$old_log_folder.'    none    bind,nobootwait';
			$app->system->removeLine('/etc/fstab', $fstab_line);
			$fstab_line = '/var/log/ispconfig/httpd/'.$data['old']['domain'].' '.$data['old']['document_root'].'/'.$old_log_folder.'    none    bind,nobootwait';
			$app->system->removeLine('/etc/fstab', $fstab_line);
			*/
			
			$fstab_line_old = '/var/log/ispconfig/httpd/'.$data['old']['domain'].' '.$data['old']['document_root'].'/'.$old_log_folder.'    none    bind';
			
			if($web_config['network_filesystem'] == 'y') {
				$fstab_line = '/var/log/ispconfig/httpd/'.$data['new']['domain'].' '.$data['new']['document_root'].'/'.$log_folder.'    none    bind,nobootwait,_netdev    0 0';
				$app->system->replaceLine('/etc/fstab', $fstab_line_old, $fstab_line, 0, 1);
			} else {
				$fstab_line = '/var/log/ispconfig/httpd/'.$data['new']['domain'].' '.$data['new']['document_root'].'/'.$log_folder.'    none    bind,nobootwait    0 0';
				$app->system->replaceLine('/etc/fstab', $fstab_line_old, $fstab_line, 0, 1);
			}
			
			exec('mount --bind '.escapeshellarg('/var/log/ispconfig/httpd/'.$data['new']['domain']).' '.escapeshellarg($data['new']['document_root'].'/'.$log_folder));
			
		}

		//print_r($data);

		// Check if the directories are there and create them if necessary.
		$app->system->web_folder_protection($data['new']['document_root'], false);

		if(!is_dir($data['new']['document_root'].'/' . $web_folder)) $app->system->mkdirpath($data['new']['document_root'].'/' . $web_folder);
		if(!is_dir($data['new']['document_root'].'/' . $web_folder . '/error') and $data['new']['errordocs']) $app->system->mkdirpath($data['new']['document_root'].'/' . $web_folder . '/error');
		//if(!is_dir($data['new']['document_root'].'/'.$log_folder)) exec('mkdir -p '.$data['new']['document_root'].'/'.$log_folder);
		if(!is_dir($data['new']['document_root'].'/ssl')) $app->system->mkdirpath($data['new']['document_root'].'/ssl');
		if(!is_dir($data['new']['document_root'].'/cgi-bin')) $app->system->mkdirpath($data['new']['document_root'].'/cgi-bin');
		if(!is_dir($data['new']['document_root'].'/tmp')) $app->system->mkdirpath($data['new']['document_root'].'/tmp');
		if(!is_dir($data['new']['document_root'].'/webdav')) $app->system->mkdirpath($data['new']['document_root'].'/webdav');

		//* Create the new private directory
		if(!is_dir($data['new']['document_root'].'/private')) {
			$app->system->mkdirpath($data['new']['document_root'].'/private');
			$app->system->chmod($data['new']['document_root'].'/private', 0710);
			$app->system->chown($data['new']['document_root'].'/private', $username);
			$app->system->chgrp($data['new']['document_root'].'/private', $groupname);
		}


		// Remove the symlink for the site, if site is renamed
		if($this->action == 'update' && $data['old']['domain'] != '' && $data['new']['domain'] != $data['old']['domain']) {
			if(is_dir('/var/log/ispconfig/httpd/'.$data['old']['domain'])) exec('rm -rf /var/log/ispconfig/httpd/'.$data['old']['domain']);
			if(is_link($data['old']['document_root'].'/'.$old_log_folder)) $app->system->unlink($data['old']['document_root'].'/'.$old_log_folder);

			//* remove old log mount
			$fstab_line = '/var/log/ispconfig/httpd/'.$data['old']['domain'].' '.$data['old']['document_root'].'/'.$old_log_folder.'    none    bind';
			$app->system->removeLine('/etc/fstab', $fstab_line);

			//* Unmount log directory
			exec('umount '.escapeshellarg($data['old']['document_root'].'/'.$old_log_folder));
		}

		//* Create the log dir if nescessary and mount it
		if(!is_dir($data['new']['document_root'].'/'.$log_folder) || !is_dir('/var/log/ispconfig/httpd/'.$data['new']['domain']) || is_link($data['new']['document_root'].'/'.$log_folder)) {
			if(is_link($data['new']['document_root'].'/'.$log_folder)) unlink($data['new']['document_root'].'/'.$log_folder);
			if(!is_dir('/var/log/ispconfig/httpd/'.$data['new']['domain'])) exec('mkdir -p /var/log/ispconfig/httpd/'.$data['new']['domain']);
			$app->system->mkdirpath($data['new']['document_root'].'/'.$log_folder);
			$app->system->chown($data['new']['document_root'].'/'.$log_folder, 'root');
			$app->system->chgrp($data['new']['document_root'].'/'.$log_folder, 'root');
			$app->system->chmod($data['new']['document_root'].'/'.$log_folder, 0755);
			exec('mount --bind '.escapeshellarg('/var/log/ispconfig/httpd/'.$data['new']['domain']).' '.escapeshellarg($data['new']['document_root'].'/'.$log_folder));
			//* add mountpoint to fstab
			$fstab_line = '/var/log/ispconfig/httpd/'.$data['new']['domain'].' '.$data['new']['document_root'].'/'.$log_folder.'    none    bind,nobootwait,_netdev    0 0';
			$app->system->replaceLine('/etc/fstab', $fstab_line, $fstab_line, 1, 1);
		}

		$app->system->web_folder_protection($data['new']['document_root'], true);

		// Get the client ID
		$client = $app->dbmaster->queryOneRecord('SELECT client_id FROM sys_group WHERE sys_group.groupid = '.intval($data['new']['sys_groupid']));
		$client_id = intval($client['client_id']);
		unset($client);

		// Remove old symlinks, if site is renamed
		if($this->action == 'update' && $data['old']['domain'] != '' && $data['new']['domain'] != $data['old']['domain']) {
			$tmp_symlinks_array = explode(':', $web_config['website_symlinks']);
			if(is_array($tmp_symlinks_array)) {
				foreach($tmp_symlinks_array as $tmp_symlink) {
					$tmp_symlink = str_replace('[client_id]', $client_id, $tmp_symlink);
					$tmp_symlink = str_replace('[website_domain]', $data['old']['domain'], $tmp_symlink);
					// Remove trailing slash
					if(substr($tmp_symlink, -1, 1) == '/') $tmp_symlink = substr($tmp_symlink, 0, -1);
					// remove the symlinks, if not exist
					if(is_link($tmp_symlink)) {
						exec('rm -f '.escapeshellcmd($tmp_symlink));
						$app->log('Removed symlink: rm -f '.$tmp_symlink, LOGLEVEL_DEBUG);
					}
				}
			}
		}

		// Create the symlinks for the sites
		$tmp_symlinks_array = explode(':', $web_config['website_symlinks']);
		if(is_array($tmp_symlinks_array)) {
			foreach($tmp_symlinks_array as $tmp_symlink) {
				$tmp_symlink = str_replace('[client_id]', $client_id, $tmp_symlink);
				$tmp_symlink = str_replace('[website_domain]', $data['new']['domain'], $tmp_symlink);
				// Remove trailing slash
				if(substr($tmp_symlink, -1, 1) == '/') $tmp_symlink = substr($tmp_symlink, 0, -1);
				//* Remove symlink if target folder has been changed.
				if($data['old']['document_root'] != '' && $data['old']['document_root'] != $data['new']['document_root'] && is_link($tmp_symlink)) {
					$app->system->unlink($tmp_symlink);
				}
				// create the symlinks, if not exist
				if(!is_link($tmp_symlink)) {
					//     exec("ln -s ".escapeshellcmd($data["new"]["document_root"])."/ ".escapeshellcmd($tmp_symlink));
					if ($web_config["website_symlinks_rel"] == 'y') {
						$this->create_relative_link(escapeshellcmd($data["new"]["document_root"]), escapeshellcmd($tmp_symlink));
					} else {
						exec("ln -s ".escapeshellcmd($data["new"]["document_root"])."/ ".escapeshellcmd($tmp_symlink));
					}

					$app->log('Creating symlink: ln -s '.$data['new']['document_root'].'/ '.$tmp_symlink, LOGLEVEL_DEBUG);
				}
			}
		}



		// Install the Standard or Custom Error, Index and other related files
		// /usr/local/ispconfig/server/conf is for the standard files
		// /usr/local/ispconfig/server/conf-custom is for the custom files
		// setting a local var here

		// normally $conf['templates'] = "/usr/local/ispconfig/server/conf";
		if($this->action == 'insert' && ($data['new']['type'] == 'vhost' || $data['new']['type'] == 'vhostsubdomain')) {

			// Copy the error pages
			if($data['new']['errordocs']) {
				$error_page_path = escapeshellcmd($data['new']['document_root']).'/' . $web_folder . '/error/';
				if (file_exists($conf['rootpath'] . '/conf-custom/error/'.substr(escapeshellcmd($conf['language']), 0, 2))) {
					exec('cp ' . $conf['rootpath'] . '/conf-custom/error/'.substr(escapeshellcmd($conf['language']), 0, 2).'/* '.$error_page_path);
				}
				else {
					if (file_exists($conf['rootpath'] . '/conf-custom/error/400.html')) {
						exec('cp '. $conf['rootpath'] . '/conf-custom/error/*.html '.$error_page_path);
					}
					else {
						exec('cp ' . $conf['rootpath'] . '/conf/error/'.substr(escapeshellcmd($conf['language']), 0, 2).'/* '.$error_page_path);
					}
				}
				exec('chmod -R a+r '.$error_page_path);
			}

			if (file_exists($conf['rootpath'] . '/conf-custom/index/standard_index.html_'.substr(escapeshellcmd($conf['language']), 0, 2))) {
				exec('cp ' . $conf['rootpath'] . '/conf-custom/index/standard_index.html_'.substr(escapeshellcmd($conf['language']), 0, 2).' '.escapeshellcmd($data['new']['document_root']).'/' . $web_folder . '/index.html');

				if(is_file($conf['rootpath'] . '/conf-custom/index/favicon.ico')) {
					exec('cp ' . $conf['rootpath'] . '/conf-custom/index/favicon.ico '.escapeshellcmd($data['new']['document_root']).'/' . $web_folder . '/');
				}
				if(is_file($conf['rootpath'] . '/conf-custom/index/robots.txt')) {
					exec('cp ' . $conf['rootpath'] . '/conf-custom/index/robots.txt '.escapeshellcmd($data['new']['document_root']).'/' . $web_folder . '/');
				}
				if(is_file($conf['rootpath'] . '/conf-custom/index/.htaccess')) {
					exec('cp ' . $conf['rootpath'] . '/conf-custom/index/.htaccess '.escapeshellcmd($data['new']['document_root']).'/' . $web_folder . '/');
				}
			}
			else {
				if (file_exists($conf['rootpath'] . '/conf-custom/index/standard_index.html')) {
					exec('cp ' . $conf['rootpath'] . '/conf-custom/index/standard_index.html '.escapeshellcmd($data['new']['document_root']).'/' . $web_folder . '/index.html');
				}
				else {
					exec('cp ' . $conf['rootpath'] . '/conf/index/standard_index.html_'.substr(escapeshellcmd($conf['language']), 0, 2).' '.escapeshellcmd($data['new']['document_root']).'/' . $web_folder . '/index.html');
					if(is_file($conf['rootpath'] . '/conf/index/favicon.ico')) exec('cp ' . $conf['rootpath'] . '/conf/index/favicon.ico '.escapeshellcmd($data['new']['document_root']).'/' . $web_folder . '/');
					if(is_file($conf['rootpath'] . '/conf/index/robots.txt')) exec('cp ' . $conf['rootpath'] . '/conf/index/robots.txt '.escapeshellcmd($data['new']['document_root']).'/' . $web_folder . '/');
					if(is_file($conf['rootpath'] . '/conf/index/.htaccess')) exec('cp ' . $conf['rootpath'] . '/conf/index/.htaccess '.escapeshellcmd($data['new']['document_root']).'/' . $web_folder . '/');
				}
			}
			exec('chmod -R a+r '.escapeshellcmd($data['new']['document_root']).'/' . $web_folder . '/');

			//** Copy the error documents on update when the error document checkbox has been activated and was deactivated before
		} elseif ($this->action == 'update' && ($data['new']['type'] == 'vhost' || $data['new']['type'] == 'vhostsubdomain') && $data['old']['errordocs'] == 0 && $data['new']['errordocs'] == 1) {

			$error_page_path = escapeshellcmd($data['new']['document_root']).'/' . $web_folder . '/error/';
			if (file_exists($conf['rootpath'] . '/conf-custom/error/'.substr(escapeshellcmd($conf['language']), 0, 2))) {
				exec('cp ' . $conf['rootpath'] . '/conf-custom/error/'.substr(escapeshellcmd($conf['language']), 0, 2).'/* '.$error_page_path);
			}
			else {
				if (file_exists($conf['rootpath'] . '/conf-custom/error/400.html')) {
					exec('cp ' . $conf['rootpath'] . '/conf-custom/error/*.html '.$error_page_path);
				}
				else {
					exec('cp ' . $conf['rootpath'] . '/conf/error/'.substr(escapeshellcmd($conf['language']), 0, 2).'/* '.$error_page_path);
				}
			}
			exec('chmod -R a+r '.$error_page_path);
			exec('chown -R '.$data['new']['system_user'].':'.$data['new']['system_group'].' '.$error_page_path);
		}  // end copy error docs

		// Set the quota for the user, but only for vhosts, not vhostsubdomains
		if($username != '' && $app->system->is_user($username) && $data['new']['type'] == 'vhost') {
			if($data['new']['hd_quota'] > 0) {
				$blocks_soft = $data['new']['hd_quota'] * 1024;
				$blocks_hard = $blocks_soft + 1024;
			} else {
				$blocks_soft = $blocks_hard = 0;
			}
			exec("setquota -u $username $blocks_soft $blocks_hard 0 0 -a &> /dev/null");
			exec('setquota -T -u '.$username.' 604800 604800 -a &> /dev/null');
		}

		if($this->action == 'insert' || $data["new"]["system_user"] != $data["old"]["system_user"]) {
			// Chown and chmod the directories below the document root
			$this->_exec('chown -R '.$username.':'.$groupname.' '.escapeshellcmd($data['new']['document_root']).'/' . $web_folder);
			// The document root itself has to be owned by root in normal level and by the web owner in security level 20
			if($web_config['security_level'] == 20) {
				$this->_exec('chown '.$username.':'.$groupname.' '.escapeshellcmd($data['new']['document_root']).'/' . $web_folder);
			} else {
				$this->_exec('chown root:root '.escapeshellcmd($data['new']['document_root']).'/' . $web_folder);
			}
		}

		//* add the Apache user to the client group if this is a vhost and security level is set to high, no matter if this is an insert or update and regardless of set_folder_permissions_on_update
		if($data['new']['type'] == 'vhost' && $web_config['security_level'] == 20) $app->system->add_user_to_group($groupname, escapeshellcmd($web_config['user']));

		//* If the security level is set to high
		if(($this->action == 'insert' && $data['new']['type'] == 'vhost') or ($web_config['set_folder_permissions_on_update'] == 'y' && $data['new']['type'] == 'vhost')) {

			$app->system->web_folder_protection($data['new']['document_root'], false);

			//* Check if we have the new private folder and create it if nescessary
			if(!is_dir($data['new']['document_root'].'/private')) $app->system->mkdir($data['new']['document_root'].'/private');

			if($web_config['security_level'] == 20) {

				$app->system->chmod($data['new']['document_root'], 0755);
				$app->system->chmod($data['new']['document_root'].'/web', 0711);
				$app->system->chmod($data['new']['document_root'].'/webdav', 0710);
				$app->system->chmod($data['new']['document_root'].'/private', 0710);
				$app->system->chmod($data['new']['document_root'].'/ssl', 0755);

				// make tmp directory writable for Apache and the website users
				$app->system->chmod($data['new']['document_root'].'/tmp', 0770);

				// Set Log directory to 755 to make the logs accessible by the FTP user
				if(realpath($data['new']['document_root'].'/'.$log_folder . '/error.log') == '/var/log/ispconfig/httpd/'.$data['new']['domain'].'/error.log') {
					$app->system->chmod($data['new']['document_root'].'/'.$log_folder, 0755);
				}

				if($web_config['add_web_users_to_sshusers_group'] == 'y') {
					$command = 'usermod';
					$command .= ' --groups sshusers';
					$command .= ' '.escapeshellcmd($data['new']['system_user']).' 2>/dev/null';
					$this->_exec($command);
				}

				//* if we have a chrooted Apache environment
				if($apache_chrooted) {
					$this->_exec('chroot '.escapeshellcmd($web_config['website_basedir']).' '.$command);

					//* add the apache user to the client group in the chroot environment
					$tmp_groupfile = $app->system->server_conf['group_datei'];
					$app->system->server_conf['group_datei'] = $web_config['website_basedir'].'/etc/group';
					$app->system->add_user_to_group($groupname, escapeshellcmd($web_config['user']));
					$app->system->server_conf['group_datei'] = $tmp_groupfile;
					unset($tmp_groupfile);
				}

				//* Chown all default directories
				$app->system->chown($data['new']['document_root'], 'root');
				$app->system->chgrp($data['new']['document_root'], 'root');
				$app->system->chown($data['new']['document_root'].'/cgi-bin', $username);
				$app->system->chgrp($data['new']['document_root'].'/cgi-bin', $groupname);
				if(realpath($data['new']['document_root'].'/'.$log_folder . '/error.log') == '/var/log/ispconfig/httpd/'.$data['new']['domain'].'/error.log') {
					$app->system->chown($data['new']['document_root'].'/'.$log_folder, 'root', false);
					$app->system->chgrp($data['new']['document_root'].'/'.$log_folder, $groupname, false);
				}
				$app->system->chown($data['new']['document_root'].'/ssl', 'root');
				$app->system->chgrp($data['new']['document_root'].'/ssl', 'root');
				$app->system->chown($data['new']['document_root'].'/tmp', $username);
				$app->system->chgrp($data['new']['document_root'].'/tmp', $groupname);
				$app->system->chown($data['new']['document_root'].'/web', $username);
				$app->system->chgrp($data['new']['document_root'].'/web', $groupname);
				$app->system->chown($data['new']['document_root'].'/web/error', $username);
				$app->system->chgrp($data['new']['document_root'].'/web/error', $groupname);
				$app->system->chown($data['new']['document_root'].'/web/stats', $username);
				$app->system->chgrp($data['new']['document_root'].'/web/stats', $groupname);
				$app->system->chown($data['new']['document_root'].'/webdav', $username);
				$app->system->chgrp($data['new']['document_root'].'/webdav', $groupname);
				$app->system->chown($data['new']['document_root'].'/private', $username);
				$app->system->chgrp($data['new']['document_root'].'/private', $groupname);

				// If the security Level is set to medium
			} else {

				$app->system->chmod($data['new']['document_root'], 0755);
				$app->system->chmod($data['new']['document_root'].'/web', 0755);
				$app->system->chmod($data['new']['document_root'].'/webdav', 0755);
				$app->system->chmod($data['new']['document_root'].'/ssl', 0755);
				$app->system->chmod($data['new']['document_root'].'/cgi-bin', 0755);

				// make temp directory writable for Apache and the website users
				$app->system->chmod($data['new']['document_root'].'/tmp', 0770);

				// Set Log directory to 755 to make the logs accessible by the FTP user
				if(realpath($data['new']['document_root'].'/'.$log_folder . '/error.log') == '/var/log/ispconfig/httpd/'.$data['new']['domain'].'/error.log') {
					$app->system->chmod($data['new']['document_root'].'/'.$log_folder, 0755);
				}

				$app->system->chown($data['new']['document_root'], 'root');
				$app->system->chgrp($data['new']['document_root'], 'root');
				$app->system->chown($data['new']['document_root'].'/cgi-bin', $username);
				$app->system->chgrp($data['new']['document_root'].'/cgi-bin', $groupname);
				if(realpath($data['new']['document_root'].'/'.$log_folder . '/error.log') == '/var/log/ispconfig/httpd/'.$data['new']['domain'].'/error.log') {
					$app->system->chown($data['new']['document_root'].'/'.$log_folder, 'root', false);
					$app->system->chgrp($data['new']['document_root'].'/'.$log_folder, $groupname, false);
				}

				$app->system->chown($data['new']['document_root'].'/ssl', 'root');
				$app->system->chgrp($data['new']['document_root'].'/ssl', 'root');
				$app->system->chown($data['new']['document_root'].'/tmp', $username);
				$app->system->chgrp($data['new']['document_root'].'/tmp', $groupname);
				$app->system->chown($data['new']['document_root'].'/web', $username);
				$app->system->chgrp($data['new']['document_root'].'/web', $groupname);
				$app->system->chown($data['new']['document_root'].'/web/error', $username);
				$app->system->chgrp($data['new']['document_root'].'/web/error', $groupname);
				$app->system->chown($data['new']['document_root'].'/web/stats', $username);
				$app->system->chgrp($data['new']['document_root'].'/web/stats', $groupname);
				$app->system->chown($data['new']['document_root'].'/webdav', $username);
				$app->system->chgrp($data['new']['document_root'].'/webdav', $groupname);
			}
		} elseif(($this->action == 'insert' && $data['new']['type'] == 'vhostsubdomain') or ($web_config['set_folder_permissions_on_update'] == 'y' && $data['new']['type'] == 'vhostsubdomain')) {
			if($web_config['security_level'] == 20) {
				$app->system->chmod($data['new']['document_root'].'/' . $web_folder, 0710);
				$app->system->chown($data['new']['document_root'].'/' . $web_folder, $username);
				$app->system->chgrp($data['new']['document_root'].'/' . $web_folder, $groupname);
				$app->system->chown($data['new']['document_root'].'/' . $web_folder . '/error', $username);
				$app->system->chgrp($data['new']['document_root'].'/' . $web_folder . '/error', $groupname);
				$app->system->chown($data['new']['document_root'].'/' . $web_folder . '/stats', $username);
				$app->system->chgrp($data['new']['document_root'].'/' . $web_folder . '/stats', $groupname);
			} else {
				$app->system->chmod($data['new']['document_root'].'/' . $web_folder, 0755);
				$app->system->chown($data['new']['document_root'].'/' . $web_folder, $username);
				$app->system->chgrp($data['new']['document_root'].'/' . $web_folder, $groupname);
				$app->system->chown($data['new']['document_root'].'/' . $web_folder . '/error', $username);
				$app->system->chgrp($data['new']['document_root'].'/' . $web_folder . '/error', $groupname);
				$app->system->chown($data['new']['document_root'].'/' . $web_folder . '/stats', $username);
				$app->system->chgrp($data['new']['document_root'].'/' . $web_folder . '/stats', $groupname);
			}
		}

		//* Protect web folders
		$app->system->web_folder_protection($data['new']['document_root'], true);

		if($data['new']['type'] == 'vhost') {
			// Change the ownership of the error log to the root user
			if(!@is_file('/var/log/ispconfig/httpd/'.$data['new']['domain'].'/error.log')) exec('touch '.escapeshellcmd('/var/log/ispconfig/httpd/'.$data['new']['domain'].'/error.log'));
			$app->system->chown('/var/log/ispconfig/httpd/'.$data['new']['domain'].'/error.log', 'root');
			$app->system->chgrp('/var/log/ispconfig/httpd/'.$data['new']['domain'].'/error.log', 'root');
		}

		//* Write the custom php.ini file, if custom_php_ini fieled is not empty
		$custom_php_ini_dir = $web_config['website_basedir'].'/conf/'.$data['new']['system_user'];
		if($data['new']['type'] == 'vhostsubdomain') $custom_php_ini_dir .= '_' . $web_folder;
		if(!is_dir($web_config['website_basedir'].'/conf')) $app->system->mkdir($web_config['website_basedir'].'/conf');

		//* add open_basedir restriction to custom php.ini content, required for suphp only
		if(!stristr($data['new']['custom_php_ini'], 'open_basedir') && $data['new']['php'] == 'suphp') {
			$data['new']['custom_php_ini'] .= "\nopen_basedir = '".$data['new']['php_open_basedir']."'\n";
		}

		$fastcgi_config = $app->getconf->get_server_config($conf['server_id'], 'fastcgi');

		if(trim($data['new']['fastcgi_php_version']) != ''){
			list($custom_fastcgi_php_name, $custom_fastcgi_php_executable, $custom_fastcgi_php_ini_dir) = explode(':', trim($data['new']['fastcgi_php_version']));
			if(is_file($custom_fastcgi_php_ini_dir)) $custom_fastcgi_php_ini_dir = dirname($custom_fastcgi_php_ini_dir);
			if(substr($custom_fastcgi_php_ini_dir, -1) == '/') $custom_fastcgi_php_ini_dir = substr($custom_fastcgi_php_ini_dir, 0, -1);
		}

		//* Create custom php.ini
		if(trim($data['new']['custom_php_ini']) != '') {
			$has_custom_php_ini = true;
			if(!is_dir($custom_php_ini_dir)) $app->system->mkdirpath($custom_php_ini_dir);
			$php_ini_content = '';
			if($data['new']['php'] == 'mod') {
				$master_php_ini_path = $web_config['php_ini_path_apache'];
			} else {
				if($data["new"]['php'] == 'fast-cgi') {
					if(trim($data['new']['fastcgi_php_version']) != '' && file_exists($custom_fastcgi_php_ini_dir)){
						$master_php_ini_path = $custom_fastcgi_php_ini_dir;
					} elseif(file_exists($fastcgi_config["fastcgi_phpini_path"])){
						$master_php_ini_path = $fastcgi_config["fastcgi_phpini_path"];
					} else {
						$master_php_ini_path = $web_config['php_ini_path_cgi'];
					}
				} else {
					$master_php_ini_path = $web_config['php_ini_path_cgi'];
				}
			}

			//* Add php.ini to the path in case that the master_php_ini_path is a directory
			if($master_php_ini_path != '' && is_dir($master_php_ini_path) && is_file($master_php_ini_path.'/php.ini')) {
				if(substr($master_php_ini_path, -1) == '/') $master_php_ini_path = substr($master_php_ini_path, 0, -1);
				$master_php_ini_path .= '/php.ini';
			}

			if($master_php_ini_path != '' && substr($master_php_ini_path, -7) == 'php.ini' && is_file($master_php_ini_path)) {
				$php_ini_content .= $app->system->file_get_contents($master_php_ini_path)."\n";
			}
			$php_ini_content .= str_replace("\r", '', trim($data['new']['custom_php_ini']));
			$app->system->file_put_contents($custom_php_ini_dir.'/php.ini', $php_ini_content);
		} else {
			$has_custom_php_ini = false;
			if(is_file($custom_php_ini_dir.'/php.ini')) $app->system->unlink($custom_php_ini_dir.'/php.ini');
		}


		//* Create the vhost config file
		$app->load('tpl');

		$tpl = new tpl();
		$tpl->newTemplate('vhost.conf.master');

		$vhost_data = $data['new'];
		//unset($vhost_data['ip_address']);
		$vhost_data['web_document_root'] = $data['new']['document_root'].'/' . $web_folder;
		$vhost_data['web_document_root_www'] = $web_config['website_basedir'].'/'.$data['new']['domain'].'/' . $web_folder;
		$vhost_data['web_basedir'] = $web_config['website_basedir'];
		$vhost_data['security_level'] = $web_config['security_level'];
		$vhost_data['allow_override'] = ($data['new']['allow_override'] == '')?'All':$data['new']['allow_override'];
		$vhost_data['php_open_basedir'] = ($data['new']['php_open_basedir'] == '')?$data['new']['document_root']:$data['new']['php_open_basedir'];
		$vhost_data['ssl_domain'] = $data['new']['ssl_domain'];
		$vhost_data['has_custom_php_ini'] = $has_custom_php_ini;
		$vhost_data['custom_php_ini_dir'] = escapeshellcmd($custom_php_ini_dir);

		// Custom Apache directives
		// Make sure we only have Unix linebreaks
		$vhost_data['apache_directives'] = str_replace("\r\n", "\n", $vhost_data['apache_directives']);
		$vhost_data['apache_directives'] = str_replace("\r", "\n", $vhost_data['apache_directives']);
		$trans = array('{DOCROOT}' => $vhost_data['web_document_root_www']);
		$vhost_data['apache_directives'] = strtr($vhost_data['apache_directives'], $trans);

		// Check if a SSL cert exists
		$ssl_dir = $data['new']['document_root'].'/ssl';
		$domain = $data['new']['domain'];
		$key_file = $ssl_dir.'/'.$domain.'.key';
		$crt_file = $ssl_dir.'/'.$domain.'.crt';
		$bundle_file = $ssl_dir.'/'.$domain.'.bundle';

		/*
		if($domain!='' && $data['new']['ssl'] == 'y' && @is_file($crt_file) && @is_file($key_file) && (@filesize($crt_file)>0)  && (@filesize($key_file)>0)) {
			$vhost_data['ssl_enabled'] = 1;
			$app->log('Enable SSL for: '.$domain,LOGLEVEL_DEBUG);
		} else {
			$vhost_data['ssl_enabled'] = 0;
			$app->log('SSL Disabled. '.$domain,LOGLEVEL_DEBUG);
		}
		*/

		//* Generate Let's Encrypt SSL certificat
		if($data['new']['ssl'] == 'y' && $data['new']['ssl_letsencrypt'] == 'y' && ( // ssl and let's encrypt is active
			($data['old']['ssl'] == 'n' OR $data['old']['ssl_letsencrypt'] == 'n') // we have new let's encrypt configuration
			OR ($data['old']['domain'] != $data['new']['domain']) // we have domain update
			OR ($data['old']['subdomain'] != $data['new']['subdomain']) // we have new or update on "auto" subdomain
			OR ($data['new']['type'] == 'subdomain') // we have new or update on subdomain
			OR ($data['old']['type'] == 'alias' OR $data['new']['type'] == 'alias') // we have new or update on alias domain
		)) {
				$data['new']['ssl_domain'] = $domain;
				$vhost_data['ssl_domain'] = $domain;

				// default values
				$temp_domains = array();
				$lddomain = $domain;
				$subdomains = null;
				$aliasdomains = null;

				//* be sure to have good domain
				if($data['new']['subdomain'] == "www" OR $data['new']['subdomain'] == "*") {
					$temp_domains[] = "www." . $domain;
				}

				//* then, add subdomain if we have
				$subdomains = $app->db->queryAllRecords('SELECT domain FROM web_domain WHERE parent_domain_id = '.intval($data['new']['domain_id'])." AND active = 'y' AND type = 'subdomain'");
				if(is_array($subdomains)) {
					foreach($subdomains as $subdomain) {
						$temp_domains[] = $subdomain['domain'];
					}
				}

				//* then, add alias domain if we have
				$aliasdomains = $app->db->queryAllRecords('SELECT domain,subdomain FROM web_domain WHERE parent_domain_id = '.intval($data['new']['domain_id'])." AND active = 'y' AND type = 'alias'");
				if(is_array($aliasdomains)) {
					foreach($aliasdomains as $aliasdomain) {
						$temp_domains[] = $aliasdomain['domain'];
						if(isset($aliasdomain['subdomain']) && ! empty($aliasdomain['subdomain'])) {
							$temp_domains[] = $aliasdomain['subdomain'] . "." . $aliasdomain['domain'];
						}
					}
				}

				// prevent duplicate
				$temp_domains = array_unique($temp_domains);

				// generate cli format
				foreach($temp_domains as $temp_domain) {
					$lddomain .= (string) " --domains " . $temp_domain;
				}

				// useless data
				unset($subdomains);
				unset($temp_domains);

				$crt_tmp_file = "/etc/letsencrypt/live/".$domain."/cert.pem";
				$key_tmp_file = "/etc/letsencrypt/live/".$domain."/privkey.pem";
				$bundle_tmp_file = "/etc/letsencrypt/live/".$domain."/chain.pem";
				$webroot = $data['new']['document_root']."/web";

				//* check if we have already a Let's Encrypt cert
				if(!file_exists($crt_tmp_file) && !file_exists($key_tmp_file)) {
					$app->log("Create Let's Encrypt SSL Cert for: $domain", LOGLEVEL_DEBUG);

					if(is_dir($webroot . "/.well-known/")) {
						$app->log("Remove old challenge directory", LOGLEVEL_DEBUG);
						$this->_exec("rm -rf " . $webroot . "/.well-known/");
					}

					$app->log("Create challenge directory", LOGLEVEL_DEBUG);
					$app->system->mkdirpath($webroot . "/.well-known/");
					$app->system->chown($webroot . "/.well-known/", $data['new']['system_user']);
					$app->system->chgrp($webroot . "/.well-known/", $data['new']['system_group']);
					$app->system->mkdirpath($webroot . "/.well-known/acme-challenge");
					$app->system->chown($webroot . "/.well-known/acme-challenge/", $data['new']['system_user']);
					$app->system->chgrp($webroot . "/.well-known/acme-challenge/", $data['new']['system_group']);
					$app->system->chmod($webroot . "/.well-known/acme-challenge", "g+s");

					$this->_exec("/root/.local/share/letsencrypt/bin/letsencrypt auth -a webroot --email postmaster@$domain --domains $lddomain --webroot-path $webroot");
				};

				//* check is been correctly created
				if(file_exists($crt_tmp_file) OR file_exists($key_tmp_file)) {
					$date = date("YmdHis");
					if(is_file($key_file)) {
						$app->system->copy($key_file, $key_file.'.old'.$date);
						$app->system->chmod($key_file.'.old.'.$date, 0400);
						$app->system->unlink($key_file);
					}

					if ($web_config["website_symlinks_rel"] == 'y') {
						$this->create_relative_link(escapeshellcmd($key_tmp_file), escapeshellcmd($key_file));
					} else {
						exec("ln -s ".escapeshellcmd($key_tmp_file)." ".escapeshellcmd($key_file));
					}

					if(is_file($crt_file)) {
						$app->system->copy($crt_file, $crt_file.'.old.'.$date);
						$app->system->chmod($crt_file.'.old.'.$date, 0400);
						$app->system->unlink($crt_file);
					}

					if($web_config["website_symlinks_rel"] == 'y') {
						$this->create_relative_link(escapeshellcmd($crt_tmp_file), escapeshellcmd($crt_file));
					} else {
						exec("ln -s ".escapeshellcmd($crt_tmp_file)." ".escapeshellcmd($crt_file));
					}

					if(is_file($bundle_file)) {
						$app->system->copy($bundle_file, $bundle_file.'.old.'.$date);
						$app->system->chmod($bundle_file.'.old.'.$date, 0400);
						$app->system->unlink($bundle_file);
					}

					if($web_config["website_symlinks_rel"] == 'y') {
						$this->create_relative_link(escapeshellcmd($bundle_tmp_file), escapeshellcmd($bundle_file));
					} else {
						exec("ln -s ".escapeshellcmd($bundle_tmp_file)." ".escapeshellcmd($bundle_file));
					}

					/* we don't need to store it.
					/* Update the DB of the (local) Server */
					$app->db->query("UPDATE web_domain SET ssl_request = '', ssl_cert = '$ssl_cert', ssl_key = '$ssl_key' WHERE domain = '".$data['new']['domain']."'");
					$app->db->query("UPDATE web_domain SET ssl_action = '' WHERE domain = '".$data['new']['domain']."'");
					/* Update also the master-DB of the Server-Farm */
					$app->dbmaster->query("UPDATE web_domain SET ssl_request = '', ssl_cert = '$ssl_cert', ssl_key = '$ssl_key' WHERE domain = '".$data['new']['domain']."'");
					$app->dbmaster->query("UPDATE web_domain SET ssl_action = '' WHERE domain = '".$data['new']['domain']."'");
				}
			};

		if(@is_file($bundle_file)) $vhost_data['has_bundle_cert'] = 1;

		//$vhost_data['document_root'] = $data['new']['document_root'].'/' . $web_folder;

		// Set SEO Redirect
		if($data['new']['seo_redirect'] != ''){
			$vhost_data['seo_redirect_enabled'] = 1;
			$tmp_seo_redirects = $this->get_seo_redirects($data['new']);
			if(is_array($tmp_seo_redirects) && !empty($tmp_seo_redirects)){
				foreach($tmp_seo_redirects as $key => $val){
					$vhost_data[$key] = $val;
				}
			} else {
				$vhost_data['seo_redirect_enabled'] = 0;
			}
		} else {
			$vhost_data['seo_redirect_enabled'] = 0;
		}

		$tpl->setVar($vhost_data);
		$tpl->setVar('apache_version', $app->system->getapacheversion());

		// Rewrite rules
		$rewrite_rules = array();
		if($data['new']['redirect_type'] != '' && $data['new']['redirect_path'] != '') {
			if(substr($data['new']['redirect_path'], -1) != '/' && !preg_match('/^(https?|\[scheme\]):\/\//', $data['new']['redirect_path'])) $data['new']['redirect_path'] .= '/';
			if(substr($data['new']['redirect_path'], 0, 8) == '[scheme]'){
				$rewrite_target = 'http'.substr($data['new']['redirect_path'], 8);
				$rewrite_target_ssl = 'https'.substr($data['new']['redirect_path'], 8);
			} else {
				$rewrite_target = $data['new']['redirect_path'];
				$rewrite_target_ssl = $data['new']['redirect_path'];
			}
			/* Disabled path extension
			if($data['new']['redirect_type'] == 'no' && substr($data['new']['redirect_path'],0,4) != 'http') {
				$data['new']['redirect_path'] = $data['new']['document_root'].'/web'.realpath($data['new']['redirect_path']).'/';
			}
			*/

			switch($data['new']['subdomain']) {
			case 'www':
				$rewrite_rules[] = array( 'rewrite_domain'  => '^'.$this->_rewrite_quote($data['new']['domain']),
					'rewrite_type'   => ($data['new']['redirect_type'] == 'no')?'':'['.$data['new']['redirect_type'].']',
					'rewrite_target'  => $rewrite_target,
					'rewrite_target_ssl' => $rewrite_target_ssl,
					'rewrite_is_url'    => ($this->_is_url($rewrite_target) ? 'y' : 'n'),
					'rewrite_add_path' => (substr($rewrite_target, -1) == '/' ? 'y' : 'n'));
				$rewrite_rules[] = array( 'rewrite_domain'  => '^' . $this->_rewrite_quote('www.'.$data['new']['domain']),
					'rewrite_type'   => ($data['new']['redirect_type'] == 'no')?'':'['.$data['new']['redirect_type'].']',
					'rewrite_target'  => $rewrite_target,
					'rewrite_target_ssl' => $rewrite_target_ssl,
					'rewrite_is_url'    => ($this->_is_url($rewrite_target) ? 'y' : 'n'),
					'rewrite_add_path' => (substr($rewrite_target, -1) == '/' ? 'y' : 'n'));
				break;
			case '*':
				$rewrite_rules[] = array( 'rewrite_domain'  => '(^|\.)'.$this->_rewrite_quote($data['new']['domain']),
					'rewrite_type'   => ($data['new']['redirect_type'] == 'no')?'':'['.$data['new']['redirect_type'].']',
					'rewrite_target'  => $rewrite_target,
					'rewrite_target_ssl' => $rewrite_target_ssl,
					'rewrite_is_url'    => ($this->_is_url($rewrite_target) ? 'y' : 'n'),
					'rewrite_add_path' => (substr($rewrite_target, -1) == '/' ? 'y' : 'n'));
				break;
			default:
				$rewrite_rules[] = array( 'rewrite_domain'  => '^'.$this->_rewrite_quote($data['new']['domain']),
					'rewrite_type'   => ($data['new']['redirect_type'] == 'no')?'':'['.$data['new']['redirect_type'].']',
					'rewrite_target'  => $rewrite_target,
					'rewrite_target_ssl' => $rewrite_target_ssl,
					'rewrite_is_url'    => ($this->_is_url($rewrite_target) ? 'y' : 'n'),
					'rewrite_add_path' => (substr($rewrite_target, -1) == '/' ? 'y' : 'n'));
			}
		}

		$server_alias = array();

		// get autoalias
		$auto_alias = $web_config['website_autoalias'];
		if($auto_alias != '') {
			// get the client username
			$client = $app->db->queryOneRecord("SELECT `username` FROM `client` WHERE `client_id` = '" . intval($client_id) . "'");
			$aa_search = array('[client_id]', '[website_id]', '[client_username]', '[website_domain]');
			$aa_replace = array($client_id, $data['new']['domain_id'], $client['username'], $data['new']['domain']);
			$auto_alias = str_replace($aa_search, $aa_replace, $auto_alias);
			unset($client);
			unset($aa_search);
			unset($aa_replace);
			$server_alias[] .= $auto_alias.' ';
		}

		// get alias domains (co-domains and subdomains)
		$aliases = $app->db->queryAllRecords('SELECT * FROM web_domain WHERE parent_domain_id = '.$data['new']['domain_id']." AND active = 'y' AND type != 'vhostsubdomain'");
		$alias_seo_redirects = array();
		switch($data['new']['subdomain']) {
		case 'www':
			$server_alias[] .= 'www.'.$data['new']['domain'].' ';
			break;
		case '*':
			$server_alias[] .= '*.'.$data['new']['domain'].' ';
			break;
		}
		if(is_array($aliases)) {
			foreach($aliases as $alias) {
				switch($alias['subdomain']) {
				case 'www':
					$server_alias[] .= 'www.'.$alias['domain'].' '.$alias['domain'].' ';
					break;
				case '*':
					$server_alias[] .= '*.'.$alias['domain'].' '.$alias['domain'].' ';
					break;
				default:
					$server_alias[] .= $alias['domain'].' ';
					break;
				}
				$app->log('Add server alias: '.$alias['domain'], LOGLEVEL_DEBUG);

				// Add SEO redirects for alias domains
				if($alias['seo_redirect'] != '' && $data['new']['seo_redirect'] != '*_to_www_domain_tld' && $data['new']['seo_redirect'] != '*_to_domain_tld' && ($alias['type'] == 'alias' || ($alias['type'] == 'subdomain' && $data['new']['seo_redirect'] != '*_domain_tld_to_www_domain_tld' && $data['new']['seo_redirect'] != '*_domain_tld_to_domain_tld'))){
					$tmp_seo_redirects = $this->get_seo_redirects($alias, 'alias_');
					if(is_array($tmp_seo_redirects) && !empty($tmp_seo_redirects)){
						$alias_seo_redirects[] = $tmp_seo_redirects;
					}
				}

				// Rewriting
				if($alias['redirect_type'] != '' && $alias['redirect_path'] != '') {
					if(substr($alias['redirect_path'], -1) != '/' && !preg_match('/^(https?|\[scheme\]):\/\//', $alias['redirect_path'])) $alias['redirect_path'] .= '/';
					if(substr($alias['redirect_path'], 0, 8) == '[scheme]'){
						$rewrite_target = 'http'.substr($alias['redirect_path'], 8);
						$rewrite_target_ssl = 'https'.substr($alias['redirect_path'], 8);
					} else {
						$rewrite_target = $alias['redirect_path'];
						$rewrite_target_ssl = $alias['redirect_path'];
					}
					/* Disabled the path extension
					if($data['new']['redirect_type'] == 'no' && substr($data['new']['redirect_path'],0,4) != 'http') {
						$data['new']['redirect_path'] = $data['new']['document_root'].'/web'.realpath($data['new']['redirect_path']).'/';
					}
					*/

					switch($alias['subdomain']) {
					case 'www':
						$rewrite_rules[] = array( 'rewrite_domain'  => '^'.$this->_rewrite_quote($alias['domain']),
							'rewrite_type'   => ($alias['redirect_type'] == 'no')?'':'['.$alias['redirect_type'].']',
							'rewrite_target'  => $rewrite_target,
							'rewrite_target_ssl' => $rewrite_target_ssl,
							'rewrite_is_url'    => ($this->_is_url($rewrite_target) ? 'y' : 'n'),
							'rewrite_add_path' => (substr($rewrite_target, -1) == '/' ? 'y' : 'n'));
						$rewrite_rules[] = array( 'rewrite_domain'  => '^' . $this->_rewrite_quote('www.'.$alias['domain']),
							'rewrite_type'   => ($alias['redirect_type'] == 'no')?'':'['.$alias['redirect_type'].']',
							'rewrite_target'  => $rewrite_target,
							'rewrite_target_ssl' => $rewrite_target_ssl,
							'rewrite_is_url'    => ($this->_is_url($rewrite_target) ? 'y' : 'n'),
							'rewrite_add_path' => (substr($rewrite_target, -1) == '/' ? 'y' : 'n'));
						break;
					case '*':
						$rewrite_rules[] = array( 'rewrite_domain'  => '(^|\.)'.$this->_rewrite_quote($alias['domain']),
							'rewrite_type'   => ($alias['redirect_type'] == 'no')?'':'['.$alias['redirect_type'].']',
							'rewrite_target'  => $rewrite_target,
							'rewrite_target_ssl' => $rewrite_target_ssl,
							'rewrite_is_url'    => ($this->_is_url($rewrite_target) ? 'y' : 'n'),
							'rewrite_add_path' => (substr($rewrite_target, -1) == '/' ? 'y' : 'n'));
						break;
					default:
						if(substr($alias['domain'], 0, 2) === '*.') $domain_rule = '(^|\.)'.$this->_rewrite_quote(substr($alias['domain'], 2));
						else $domain_rule = '^'.$this->_rewrite_quote($alias['domain']);
						$rewrite_rules[] = array( 'rewrite_domain'  => $domain_rule,
							'rewrite_type'   => ($alias['redirect_type'] == 'no')?'':'['.$alias['redirect_type'].']',
							'rewrite_target'  => $rewrite_target,
							'rewrite_target_ssl' => $rewrite_target_ssl,
							'rewrite_is_url'    => ($this->_is_url($rewrite_target) ? 'y' : 'n'),
							'rewrite_add_path' => (substr($rewrite_target, -1) == '/' ? 'y' : 'n'));
					}
				}
			}
		}

		//* If we have some alias records
		if(count($server_alias) > 0) {
			$server_alias_str = '';
			$n = 0;

			// begin a new ServerAlias line after 30 alias domains
			foreach($server_alias as $tmp_alias) {
				if($n % 30 == 0) $server_alias_str .= "\n    ServerAlias ";
				$server_alias_str .= $tmp_alias;
			}
			unset($tmp_alias);

			$tpl->setVar('alias', trim($server_alias_str));
		} else {
			$tpl->setVar('alias', '');
		}

		if(count($rewrite_rules) > 0 || $vhost_data['seo_redirect_enabled'] > 0 || count($alias_seo_redirects) > 0) {
			$tpl->setVar('rewrite_enabled', 1);
		} else {
			$tpl->setVar('rewrite_enabled', 0);
		}

		//$tpl->setLoop('redirects',$rewrite_rules);

		/**
		 * install fast-cgi starter script and add script aliasd config
		 * first we create the script directory if not already created, then copy over the starter script
		 * settings are copied over from the server ini config for now
		 * TODO: Create form for fastcgi configs per site.
		 */


		if ($data['new']['php'] == 'fast-cgi') {

			$fastcgi_starter_path = str_replace('[system_user]', $data['new']['system_user'], $fastcgi_config['fastcgi_starter_path']);
			$fastcgi_starter_path = str_replace('[client_id]', $client_id, $fastcgi_starter_path);

			if (!is_dir($fastcgi_starter_path)) {
				$app->system->mkdirpath($fastcgi_starter_path);
				//exec('chown '.$data['new']['system_user'].':'.$data['new']['system_group'].' '.escapeshellcmd($fastcgi_starter_path));


				$app->log('Creating fastcgi starter script directory: '.$fastcgi_starter_path, LOGLEVEL_DEBUG);
			}

			//exec('chown -R '.$data['new']['system_user'].':'.$data['new']['system_group'].' '.escapeshellcmd($fastcgi_starter_path));
			$app->system->chown($fastcgi_starter_path, $data['new']['system_user']);
			$app->system->chgrp($fastcgi_starter_path, $data['new']['system_group']);

			$fcgi_tpl = new tpl();
			$fcgi_tpl->newTemplate('php-fcgi-starter.master');
			$fcgi_tpl->setVar('apache_version', $app->system->getapacheversion());

			// Support for multiple PHP versions (FastCGI)
			if(trim($data['new']['fastcgi_php_version']) != ''){
				$default_fastcgi_php = false;
				if(substr($custom_fastcgi_php_ini_dir, -1) != '/') $custom_fastcgi_php_ini_dir .= '/';
			} else {
				$default_fastcgi_php = true;
			}

			if($has_custom_php_ini) {
				$fcgi_tpl->setVar('php_ini_path', escapeshellcmd($custom_php_ini_dir));
			} else {
				if($default_fastcgi_php){
					$fcgi_tpl->setVar('php_ini_path', escapeshellcmd($fastcgi_config['fastcgi_phpini_path']));
				} else {
					$fcgi_tpl->setVar('php_ini_path', escapeshellcmd($custom_fastcgi_php_ini_dir));
				}
			}
			$fcgi_tpl->setVar('document_root', escapeshellcmd($data['new']['document_root']));
			$fcgi_tpl->setVar('php_fcgi_children', escapeshellcmd($fastcgi_config['fastcgi_children']));
			$fcgi_tpl->setVar('php_fcgi_max_requests', escapeshellcmd($fastcgi_config['fastcgi_max_requests']));
			if($default_fastcgi_php){
				$fcgi_tpl->setVar('php_fcgi_bin', escapeshellcmd($fastcgi_config['fastcgi_bin']));
			} else {
				$fcgi_tpl->setVar('php_fcgi_bin', escapeshellcmd($custom_fastcgi_php_executable));
			}
			$fcgi_tpl->setVar('security_level', intval($web_config['security_level']));
			$fcgi_tpl->setVar('domain', escapeshellcmd($data['new']['domain']));

			$php_open_basedir = ($data['new']['php_open_basedir'] == '')?$data['new']['document_root']:$data['new']['php_open_basedir'];
			$fcgi_tpl->setVar('open_basedir', escapeshellcmd($php_open_basedir));

			$fcgi_starter_script = escapeshellcmd($fastcgi_starter_path.$fastcgi_config['fastcgi_starter_script'].($data['new']['type'] == 'vhostsubdomain' ? '_web' . $data['new']['domain_id'] : ''));
			$app->system->file_put_contents($fcgi_starter_script, $fcgi_tpl->grab());
			unset($fcgi_tpl);

			$app->log('Creating fastcgi starter script: '.$fcgi_starter_script, LOGLEVEL_DEBUG);

			$app->system->chmod($fcgi_starter_script, 0755);
			$app->system->chown($fcgi_starter_script, $data['new']['system_user']);
			$app->system->chgrp($fcgi_starter_script, $data['new']['system_group']);

			$tpl->setVar('fastcgi_alias', $fastcgi_config['fastcgi_alias']);
			$tpl->setVar('fastcgi_starter_path', $fastcgi_starter_path);
			$tpl->setVar('fastcgi_starter_script', $fastcgi_config['fastcgi_starter_script'].($data['new']['type'] == 'vhostsubdomain' ? '_web' . $data['new']['domain_id'] : ''));
			$tpl->setVar('fastcgi_config_syntax', $fastcgi_config['fastcgi_config_syntax']);
			$tpl->setVar('fastcgi_max_requests', $fastcgi_config['fastcgi_max_requests']);

		} else {
			//remove the php fastgi starter script if available
			$fastcgi_starter_script = $fastcgi_config['fastcgi_starter_script'].($data['old']['type'] == 'vhostsubdomain' ? '_web' . $data['old']['domain_id'] : '');
			if ($data['old']['php'] == 'fast-cgi') {
				$fastcgi_starter_path = str_replace('[system_user]', $data['old']['system_user'], $fastcgi_config['fastcgi_starter_path']);
				$fastcgi_starter_path = str_replace('[client_id]', $client_id, $fastcgi_starter_path);
				if($data['old']['type'] == 'vhost') {
					if(is_file($fastcgi_starter_script)) @unlink($fastcgi_starter_script);
					if (is_dir($fastcgi_starter_path)) @rmdir($fastcgi_starter_path);
				} else {
					if(is_file($fastcgi_starter_script)) @unlink($fastcgi_starter_script);
				}
			}
		}



		/**
		 * PHP-FPM
		 */
		// Support for multiple PHP versions
		if($data['new']['php'] == 'php-fpm'){
			if(trim($data['new']['fastcgi_php_version']) != ''){
				$default_php_fpm = false;
				list($custom_php_fpm_name, $custom_php_fpm_init_script, $custom_php_fpm_ini_dir, $custom_php_fpm_pool_dir) = explode(':', trim($data['new']['fastcgi_php_version']));
				if(substr($custom_php_fpm_ini_dir, -1) != '/') $custom_php_fpm_ini_dir .= '/';
			} else {
				$default_php_fpm = true;
			}
		} else {
			if(trim($data['old']['fastcgi_php_version']) != '' && $data['old']['php'] == 'php-fpm'){
				$default_php_fpm = false;
				list($custom_php_fpm_name, $custom_php_fpm_init_script, $custom_php_fpm_ini_dir, $custom_php_fpm_pool_dir) = explode(':', trim($data['old']['fastcgi_php_version']));
				if(substr($custom_php_fpm_ini_dir, -1) != '/') $custom_php_fpm_ini_dir .= '/';
			} else {
				$default_php_fpm = true;
			}
		}

		if($default_php_fpm){
			$pool_dir = escapeshellcmd($web_config['php_fpm_pool_dir']);
		} else {
			$pool_dir = $custom_php_fpm_pool_dir;
		}
		if(substr($pool_dir, -1) != '/') $pool_dir .= '/';
		$pool_name = 'web'.$data['new']['domain_id'];
		$socket_dir = escapeshellcmd($web_config['php_fpm_socket_dir']);
		if(substr($socket_dir, -1) != '/') $socket_dir .= '/';
		
		$apache_modules = $app->system->getapachemodules();
		
		// Use sockets, but not with apache 2.4 on centos (mod_proxy_fcgi) as socket support is buggy in that version
		if($data['new']['php_fpm_use_socket'] == 'y' && in_array('fastcgi_module',$apache_modules)){
			$use_tcp = 0;
			$use_socket = 1;
		} else {
			$use_tcp = 1;
			$use_socket = 0;
		}
		$tpl->setVar('use_tcp', $use_tcp);
		$tpl->setVar('use_socket', $use_socket);
		$fpm_socket = $socket_dir.$pool_name.'.sock';
		$tpl->setVar('fpm_socket', $fpm_socket);
		$tpl->setVar('fpm_port', $web_config['php_fpm_start_port'] + $data['new']['domain_id'] - 1);

		/**
		 * install cgi starter script and add script alias to config.
		 * This is needed to allow cgi with suexec (to do so, we need a bin in the document-path!)
		 * first we create the script directory if not already created, then copy over the starter script.
		 * TODO: we have to fetch the data from the server-settings.
		 */
		if ($data['new']['php'] == 'cgi') {
			//$cgi_config = $app->getconf->get_server_config($conf['server_id'], 'cgi');

			$cgi_config['cgi_starter_path'] = $web_config['website_basedir'].'/php-cgi-scripts/[system_user]/';
			$cgi_config['cgi_starter_script'] = 'php-cgi-starter'.($data['new']['type'] == 'vhostsubdomain' ? '_web' . $data['new']['domain_id'] : '');
			$cgi_config['cgi_bin'] = '/usr/bin/php-cgi';

			$cgi_starter_path = str_replace('[system_user]', $data['new']['system_user'], $cgi_config['cgi_starter_path']);
			$cgi_starter_path = str_replace('[client_id]', $client_id, $cgi_starter_path);

			if (!is_dir($cgi_starter_path)) {
				$app->system->mkdirpath($cgi_starter_path);
				$app->system->chown($cgi_starter_path, $data['new']['system_user']);
				$app->system->chgrp($cgi_starter_path, $data['new']['system_group']);
				$app->system->chmod($cgi_starter_path, 0755);

				$app->log('Creating cgi starter script directory: '.$cgi_starter_path, LOGLEVEL_DEBUG);
			}

			$cgi_tpl = new tpl();
			$cgi_tpl->newTemplate('php-cgi-starter.master');
			$cgi_tpl->setVar('apache_version', $app->system->getapacheversion());

			// This works because PHP "rewrites" a symlink to the physical path
			$php_open_basedir = ($data['new']['php_open_basedir'] == '')?$data['new']['document_root']:$data['new']['php_open_basedir'];
			$cgi_tpl->setVar('open_basedir', escapeshellcmd($php_open_basedir));
			$cgi_tpl->setVar('document_root', escapeshellcmd($data['new']['document_root']));

			// This will NOT work!
			//$cgi_tpl->setVar('open_basedir', '/var/www/' . $data['new']['domain']);
			$cgi_tpl->setVar('php_cgi_bin', $cgi_config['cgi_bin']);
			$cgi_tpl->setVar('security_level', $web_config['security_level']);

			$cgi_tpl->setVar('has_custom_php_ini', $has_custom_php_ini);
			if($has_custom_php_ini) {
				$cgi_tpl->setVar('php_ini_path', escapeshellcmd($custom_php_ini_dir));
			} else {
				$cgi_tpl->setVar('php_ini_path', escapeshellcmd($fastcgi_config['fastcgi_phpini_path']));
			}

			$cgi_starter_script = escapeshellcmd($cgi_starter_path.$cgi_config['cgi_starter_script'].($data['new']['type'] == 'vhostsubdomain' ? '_web' . $data['new']['domain_id'] : ''));
			$app->system->file_put_contents($cgi_starter_script, $cgi_tpl->grab());
			unset($cgi_tpl);

			$app->log('Creating cgi starter script: '.$cgi_starter_script, LOGLEVEL_DEBUG);


			$app->system->chmod($cgi_starter_script, 0755);
			$app->system->chown($cgi_starter_script, $data['new']['system_user']);
			$app->system->chgrp($cgi_starter_script, $data['new']['system_group']);

			$tpl->setVar('cgi_starter_path', $cgi_starter_path);
			$tpl->setVar('cgi_starter_script', $cgi_config['cgi_starter_script'].($data['new']['type'] == 'vhostsubdomain' ? '_web' . $data['new']['domain_id'] : ''));

		}

		$vhost_file = escapeshellcmd($web_config['vhost_conf_dir'].'/'.$data['new']['domain'].'.vhost');
		//* Make a backup copy of vhost file
		if(file_exists($vhost_file)) $app->system->copy($vhost_file, $vhost_file.'~');

		//* create empty vhost array
		$vhosts = array();

		//* Add vhost for ipv4 IP
		$tmp_vhost_arr = array('ip_address' => $data['new']['ip_address'], 'ssl_enabled' => 0, 'port' => 80);
		if(count($rewrite_rules) > 0)  $tmp_vhost_arr = $tmp_vhost_arr + array('redirects' => $rewrite_rules);
		if(count($alias_seo_redirects) > 0) $tmp_vhost_arr = $tmp_vhost_arr + array('alias_seo_redirects' => $alias_seo_redirects);
		$vhosts[] = $tmp_vhost_arr;
		unset($tmp_vhost_arr);

		//* Add vhost for ipv4 IP with SSL
		$ssl_dir = $data['new']['document_root'].'/ssl';
		$domain = $data['new']['ssl_domain'];
		$key_file = $ssl_dir.'/'.$domain.'.key';
		$crt_file = $ssl_dir.'/'.$domain.'.crt';

		if($data['new']['ssl_domain'] != '' && $data['new']['ssl'] == 'y' && @is_file($crt_file) && @is_file($key_file) && (@filesize($crt_file)>0)  && (@filesize($key_file)>0)) {
			$tmp_vhost_arr = array('ip_address' => $data['new']['ip_address'], 'ssl_enabled' => 1, 'port' => '443');
			if(count($rewrite_rules) > 0)  $tmp_vhost_arr = $tmp_vhost_arr + array('redirects' => $rewrite_rules);
			$ipv4_ssl_alias_seo_redirects = $alias_seo_redirects;
			if(is_array($ipv4_ssl_alias_seo_redirects) && !empty($ipv4_ssl_alias_seo_redirects)){
				for($i=0;$i<count($ipv4_ssl_alias_seo_redirects);$i++){
					$ipv4_ssl_alias_seo_redirects[$i]['ssl_enabled'] = 1;
				}
			}
			if(count($ipv4_ssl_alias_seo_redirects) > 0) $tmp_vhost_arr = $tmp_vhost_arr + array('alias_seo_redirects' => $ipv4_ssl_alias_seo_redirects);
			$vhosts[] = $tmp_vhost_arr;
			unset($tmp_vhost_arr, $ipv4_ssl_alias_seo_redirects);
			$app->log('Enable SSL for: '.$domain, LOGLEVEL_DEBUG);
		}

		//* Add vhost for IPv6 IP
		if($data['new']['ipv6_address'] != '') {
			if ($conf['serverconfig']['web']['vhost_rewrite_v6'] == 'y') {
				if (isset($conf['serverconfig']['server']['v6_prefix']) && $conf['serverconfig']['server']['v6_prefix'] <> '') {
					$explode_v6prefix=explode(':', $conf['serverconfig']['server']['v6_prefix']);
					$explode_v6=explode(':', $data['new']['ipv6_address']);

					for ( $i = 0; $i <= count($explode_v6prefix)-3; $i++ ) {
						$explode_v6[$i] = $explode_v6prefix[$i];
					}
					$data['new']['ipv6_address'] = implode(':', $explode_v6);
				}
			}

			$tmp_vhost_arr = array('ip_address' => '['.$data['new']['ipv6_address'].']', 'ssl_enabled' => 0, 'port' => 80);
			if(count($rewrite_rules) > 0)  $tmp_vhost_arr = $tmp_vhost_arr + array('redirects' => $rewrite_rules);
			if(count($alias_seo_redirects) > 0) $tmp_vhost_arr = $tmp_vhost_arr + array('alias_seo_redirects' => $alias_seo_redirects);
			$vhosts[] = $tmp_vhost_arr;
			unset($tmp_vhost_arr);

			//* Add vhost for ipv6 IP with SSL
			if($data['new']['ssl_domain'] != '' && $data['new']['ssl'] == 'y' && @is_file($crt_file) && @is_file($key_file) && (@filesize($crt_file)>0)  && (@filesize($key_file)>0)) {
				$tmp_vhost_arr = array('ip_address' => '['.$data['new']['ipv6_address'].']', 'ssl_enabled' => 1, 'port' => '443');
				if(count($rewrite_rules) > 0)  $tmp_vhost_arr = $tmp_vhost_arr + array('redirects' => $rewrite_rules);
				$ipv6_ssl_alias_seo_redirects = $alias_seo_redirects;
				if(is_array($ipv6_ssl_alias_seo_redirects) && !empty($ipv6_ssl_alias_seo_redirects)){
					for($i=0;$i<count($ipv6_ssl_alias_seo_redirects);$i++){
						$ipv6_ssl_alias_seo_redirects[$i]['ssl_enabled'] = 1;
					}
				}
				if(count($ipv6_ssl_alias_seo_redirects) > 0) $tmp_vhost_arr = $tmp_vhost_arr + array('alias_seo_redirects' => $ipv6_ssl_alias_seo_redirects);
				$vhosts[] = $tmp_vhost_arr;
				unset($tmp_vhost_arr, $ipv6_ssl_alias_seo_redirects);
				$app->log('Enable SSL for IPv6: '.$domain, LOGLEVEL_DEBUG);
			}
		}

		//* Set the vhost loop
		$tpl->setLoop('vhosts', $vhosts);

		//* Write vhost file
		$app->system->file_put_contents($vhost_file, $tpl->grab());
		$app->log('Writing the vhost file: '.$vhost_file, LOGLEVEL_DEBUG);
		unset($tpl);

		/*
		 * maybe we have some webdav - user. If so, add them...
		*/
		$this->_patchVhostWebdav($vhost_file, $data['new']['document_root'] . '/webdav');

		//* Set the symlink to enable the vhost
		//* First we check if there is a old type of symlink and remove it
		$vhost_symlink = escapeshellcmd($web_config['vhost_conf_enabled_dir'].'/'.$data['new']['domain'].'.vhost');
		if(is_link($vhost_symlink)) $app->system->unlink($vhost_symlink);

		//* Remove old or changed symlinks
		if($data['new']['subdomain'] != $data['old']['subdomain'] or $data['new']['active'] == 'n') {
			$vhost_symlink = escapeshellcmd($web_config['vhost_conf_enabled_dir'].'/900-'.$data['new']['domain'].'.vhost');
			if(is_link($vhost_symlink)) {
				$app->system->unlink($vhost_symlink);
				$app->log('Removing symlink: '.$vhost_symlink.'->'.$vhost_file, LOGLEVEL_DEBUG);
			}
			$vhost_symlink = escapeshellcmd($web_config['vhost_conf_enabled_dir'].'/100-'.$data['new']['domain'].'.vhost');
			if(is_link($vhost_symlink)) {
				$app->system->unlink($vhost_symlink);
				$app->log('Removing symlink: '.$vhost_symlink.'->'.$vhost_file, LOGLEVEL_DEBUG);
			}
		}

		//* New symlink
		if($data['new']['subdomain'] == '*') {
			$vhost_symlink = escapeshellcmd($web_config['vhost_conf_enabled_dir'].'/900-'.$data['new']['domain'].'.vhost');
		} else {
			$vhost_symlink = escapeshellcmd($web_config['vhost_conf_enabled_dir'].'/100-'.$data['new']['domain'].'.vhost');
		}
		if($data['new']['active'] == 'y' && !is_link($vhost_symlink)) {
			symlink($vhost_file, $vhost_symlink);
			$app->log('Creating symlink: '.$vhost_symlink.'->'.$vhost_file, LOGLEVEL_DEBUG);
		}

		// remove old symlink and vhost file, if domain name of the site has changed
		if($this->action == 'update' && $data['old']['domain'] != '' && $data['new']['domain'] != $data['old']['domain']) {
			$vhost_symlink = escapeshellcmd($web_config['vhost_conf_enabled_dir'].'/900-'.$data['old']['domain'].'.vhost');
			if(is_link($vhost_symlink)) {
				$app->system->unlink($vhost_symlink);
				$app->log('Removing symlink: '.$vhost_symlink.'->'.$vhost_file, LOGLEVEL_DEBUG);
			}
			$vhost_symlink = escapeshellcmd($web_config['vhost_conf_enabled_dir'].'/100-'.$data['old']['domain'].'.vhost');
			if(is_link($vhost_symlink)) {
				$app->system->unlink($vhost_symlink);
				$app->log('Removing symlink: '.$vhost_symlink.'->'.$vhost_file, LOGLEVEL_DEBUG);
			}
			$vhost_symlink = escapeshellcmd($web_config['vhost_conf_enabled_dir'].'/'.$data['old']['domain'].'.vhost');
			if(is_link($vhost_symlink)) {
				$app->system->unlink($vhost_symlink);
				$app->log('Removing symlink: '.$vhost_symlink.'->'.$vhost_file, LOGLEVEL_DEBUG);
			}
			$vhost_file = escapeshellcmd($web_config['vhost_conf_dir'].'/'.$data['old']['domain'].'.vhost');
			$app->system->unlink($vhost_file);
			$app->log('Removing file: '.$vhost_file, LOGLEVEL_DEBUG);
		}

		//* Create .htaccess and .htpasswd file for website statistics
		//if(!is_file($data['new']['document_root'].'/' . $web_folder . '/stats/.htaccess') or $data['old']['document_root'] != $data['new']['document_root']) {
		if(!is_dir($data['new']['document_root'].'/' . $web_folder . '/stats')) $app->system->mkdir($data['new']['document_root'].'/' . $web_folder . '/stats');
		$ht_file = "AuthType Basic\nAuthName \"Members Only\"\nAuthUserFile ".$data['new']['document_root']."/web/stats/.htpasswd_stats\nrequire valid-user";
		$app->system->file_put_contents($data['new']['document_root'].'/' . $web_folder . '/stats/.htaccess', $ht_file);
		$app->system->chmod($data['new']['document_root'].'/' . $web_folder . '/stats/.htaccess', 0755);
		unset($ht_file);
		//}

		if(!is_file($data['new']['document_root'].'/web/stats/.htpasswd_stats') || $data['new']['stats_password'] != $data['old']['stats_password']) {
			if(trim($data['new']['stats_password']) != '') {
				$htp_file = 'admin:'.trim($data['new']['stats_password']);
				$app->system->web_folder_protection($data['new']['document_root'], false);
				$app->system->file_put_contents($data['new']['document_root'].'/web/stats/.htpasswd_stats', $htp_file);
				$app->system->web_folder_protection($data['new']['document_root'], true);
				$app->system->chmod($data['new']['document_root'].'/web/stats/.htpasswd_stats', 0755);
				unset($htp_file);
			}
		}

		//* Create awstats configuration
		if($data['new']['stats_type'] == 'awstats' && ($data['new']['type'] == 'vhost' || $data['new']['type'] == 'vhostsubdomain')) {
			$this->awstats_update($data, $web_config);
		}

		$this->php_fpm_pool_update($data, $web_config, $pool_dir, $pool_name, $socket_dir);

		if($web_config['check_apache_config'] == 'y') {
			//* Test if apache starts with the new configuration file
			$apache_online_status_before_restart = $this->_checkTcp('localhost', 80);
			$app->log('Apache status is: '.($apache_online_status_before_restart === true? 'running' : 'down'), LOGLEVEL_DEBUG);

			$retval = $app->services->restartService('httpd', 'restart'); // $retval['retval'] is 0 on success and > 0 on failure
			$app->log('Apache restart return value is: '.$retval['retval'], LOGLEVEL_DEBUG);

			// wait a few seconds, before we test the apache status again
			$apache_online_status_after_restart = false;
			sleep(2);
			for($i = 0; $i < 5; $i++) {
				$apache_online_status_after_restart = $this->_checkTcp('localhost', 80);
				if($apache_online_status_after_restart) break;
				sleep(1);
			}
			//* Check if apache restarted successfully if it was online before
			$app->log('Apache online status after restart is: '.($apache_online_status_after_restart === true? 'running' : 'down'), LOGLEVEL_DEBUG);
			if($apache_online_status_before_restart && !$apache_online_status_after_restart || $retval['retval'] > 0) {
				$app->log('Apache did not restart after the configuration change for website '.$data['new']['domain'].'. Reverting the configuration. Saved non-working config as '.$vhost_file.'.err', LOGLEVEL_WARN);
				if(is_array($retval['output']) && !empty($retval['output'])){
					$app->log('Reason for Apache restart failure: '.implode("\n", $retval['output']), LOGLEVEL_WARN);
					$app->dbmaster->datalogError(implode("\n", $retval['output']));
				} else {
					// if no output is given, check again
					$webserver_binary = '';
					exec('which apache2ctl', $webserver_check_output, $webserver_check_retval);
					if($webserver_check_retval == 0){
						$webserver_binary = 'apache2ctl';
					} else {
						unset($webserver_check_output, $webserver_check_retval);
						exec('which apache2', $webserver_check_output, $webserver_check_retval);
						if($webserver_check_retval == 0){
							$webserver_binary = 'apache2';
						} else {
							unset($webserver_check_output, $webserver_check_retval);
							exec('which httpd2', $webserver_check_output, $webserver_check_retval);
							if($webserver_check_retval == 0){
								$webserver_binary = 'httpd2';
							} else {
								unset($webserver_check_output, $webserver_check_retval);
								exec('which httpd', $webserver_check_output, $webserver_check_retval);
								if($webserver_check_retval == 0){
									$webserver_binary = 'httpd';
								} else {
									unset($webserver_check_output, $webserver_check_retval);
									exec('which apache', $webserver_check_output, $webserver_check_retval);
									if($webserver_check_retval == 0){
										$webserver_binary = 'apache';
									}
								}
							}
						}
					}
					if($webserver_binary != ''){
						exec($webserver_binary.' -t 2>&1', $tmp_output, $tmp_retval);
						if($tmp_retval > 0 && is_array($tmp_output) && !empty($tmp_output)){
							$app->log('Reason for Apache restart failure: '.implode("\n", $tmp_output), LOGLEVEL_WARN);
							$app->dbmaster->datalogError(implode("\n", $tmp_output));
						}
						unset($tmp_output, $tmp_retval);
					}
				}
				$app->system->copy($vhost_file, $vhost_file.'.err');
				if(is_file($vhost_file.'~')) {
					//* Copy back the last backup file
					$app->system->copy($vhost_file.'~', $vhost_file);
				} else {
					//* There is no backup file, so we create a empty vhost file with a warning message inside
					$app->system->file_put_contents($vhost_file, "# Apache did not start after modifying this vhost file.\n# Please check file $vhost_file.err for syntax errors.");
				}
				if($this->ssl_certificate_changed === true) {

					$ssl_dir = $data['new']['document_root'].'/ssl';
					$domain = $data['new']['ssl_domain'];
					$key_file = $ssl_dir.'/'.$domain.'.key.org';
					$key_file2 = $ssl_dir.'/'.$domain.'.key';
					$csr_file = $ssl_dir.'/'.$domain.'.csr';
					$crt_file = $ssl_dir.'/'.$domain.'.crt';
					$bundle_file = $ssl_dir.'/'.$domain.'.bundle';

					//* Backup the files that might have caused the error
					if(is_file($key_file)){
						$app->system->copy($key_file, $key_file.'.err');
						$app->system->chmod($key_file.'.err', 0400);
					}
					if(is_file($key_file2)){
						$app->system->copy($key_file2, $key_file2.'.err');
						$app->system->chmod($key_file2.'.err', 0400);
					}
					if(is_file($csr_file)) $app->system->copy($csr_file, $csr_file.'.err');
					if(is_file($crt_file)) $app->system->copy($crt_file, $crt_file.'.err');
					if(is_file($bundle_file)) $app->system->copy($bundle_file, $bundle_file.'.err');

					//* Restore the ~ backup files
					if(is_file($key_file.'~')) $app->system->copy($key_file.'~', $key_file);
					if(is_file($key_file2.'~')) $app->system->copy($key_file2.'~', $key_file2);
					if(is_file($crt_file.'~')) $app->system->copy($crt_file.'~', $crt_file);
					if(is_file($csr_file.'~')) $app->system->copy($csr_file.'~', $csr_file);
					if(is_file($bundle_file.'~')) $app->system->copy($bundle_file.'~', $bundle_file);

					$app->log('Apache did not restart after the configuration change for website '.$data['new']['domain'].' Reverting the SSL configuration. Saved non-working SSL files with .err extension.', LOGLEVEL_WARN);
				}

				$app->services->restartService('httpd', 'restart');
			}
		} else {
			//* We do not check the apache config after changes (is faster)
			if($apache_chrooted) {
				$app->services->restartServiceDelayed('httpd', 'restart');
			} else {
				// request a httpd reload when all records have been processed
				$app->services->restartServiceDelayed('httpd', 'reload');
			}
		}

		//* The vhost is written and apache has been restarted, so we
		// can reset the ssl changed var to false and cleanup some files
		$this->ssl_certificate_changed = false;

		$ssl_dir = $data['new']['document_root'].'/ssl';
		$domain = $data['new']['ssl_domain'];
		$key_file = $ssl_dir.'/'.$domain.'.key.org';
		$key_file2 = $ssl_dir.'/'.$domain.'.key';
		$csr_file = $ssl_dir.'/'.$domain.'.csr';
		$crt_file = $ssl_dir.'/'.$domain.'.crt';
		$bundle_file = $ssl_dir.'/'.$domain.'.bundle';

		if(@is_file($key_file.'~')) $app->system->unlink($key_file.'~');
		if(@is_file($key2_file.'~')) $app->system->unlink($key2_file.'~');
		if(@is_file($crt_file.'~')) $app->system->unlink($crt_file.'~');
		if(@is_file($csr_file.'~')) $app->system->unlink($csr_file.'~');
		if(@is_file($bundle_file.'~')) $app->system->unlink($bundle_file.'~');

		// Remove the backup copy of the config file.
		if(@is_file($vhost_file.'~')) $app->system->unlink($vhost_file.'~');

		//* Unset action to clean it for next processed vhost.
		$this->action = '';
	}

	function delete($event_name, $data) {
		global $app, $conf;

		// load the server configuration options
		$app->uses('getconf');
		$app->uses('system');
		$web_config = $app->getconf->get_server_config($conf['server_id'], 'web');
		$fastcgi_config = $app->getconf->get_server_config($conf['server_id'], 'fastcgi');

		if($data['old']['type'] == 'vhost' || $data['old']['type'] == 'vhostsubdomain') $app->system->web_folder_protection($data['old']['document_root'], false);

		//* Check if this is a chrooted setup
		if($web_config['website_basedir'] != '' && @is_file($web_config['website_basedir'].'/etc/passwd')) {
			$apache_chrooted = true;
		} else {
			$apache_chrooted = false;
		}

		//* Remove the mounts
		$log_folder = 'log';
		$web_folder = '';
		if($data['old']['type'] == 'vhostsubdomain') {
			$tmp = $app->db->queryOneRecord('SELECT `domain`,`document_root` FROM web_domain WHERE domain_id = '.intval($data['old']['parent_domain_id']));
			if($tmp['domain'] != ''){
				$subdomain_host = preg_replace('/^(.*)\.' . preg_quote($tmp['domain'], '/') . '$/', '$1', $data['old']['domain']);
			} else {
				// get log folder from /etc/fstab
				/*
				$bind_mounts = $app->system->file_get_contents('/etc/fstab');
				$bind_mount_lines = explode("\n", $bind_mounts);
				if(is_array($bind_mount_lines) && !empty($bind_mount_lines)){
					foreach($bind_mount_lines as $bind_mount_line){
						$bind_mount_line = preg_replace('/\s+/', ' ', $bind_mount_line);
						$bind_mount_parts = explode(' ', $bind_mount_line);
						if(is_array($bind_mount_parts) && !empty($bind_mount_parts)){
							if($bind_mount_parts[0] == '/var/log/ispconfig/httpd/'.$data['old']['domain'] && $bind_mount_parts[2] == 'none' && strpos($bind_mount_parts[3], 'bind') !== false){
								$subdomain_host = str_replace($data['old']['document_root'].'/log/', '', $bind_mount_parts[1]);
							}
						}
					}
				}
				*/
				// we are deleting the parent domain, so we can delete everything in the log directory
				$subdomain_hosts = array();
				$files = array_diff(scandir($data['old']['document_root'].'/'.$log_folder), array('.', '..'));
				if(is_array($files) && !empty($files)){
					foreach($files as $file){
						if(is_dir($data['old']['document_root'].'/'.$log_folder.'/'.$file)){
							$subdomain_hosts[] = $file;
						}
					}
				}
			}
			if(is_array($subdomain_hosts) && !empty($subdomain_hosts)){
				$log_folders = array();
				foreach($subdomain_hosts as $subdomain_host){
					$log_folders[] = $log_folder.'/'.$subdomain_host;
				}
			} else {
				if($subdomain_host == '') $subdomain_host = 'web'.$data['old']['domain_id'];
				$log_folder .= '/' . $subdomain_host;
			}
			$web_folder = $data['old']['web_folder'];
			unset($tmp);
			unset($subdomain_hosts);
		}

		if($data['old']['type'] == 'vhost' || $data['old']['type'] == 'vhostsubdomain'){
			if(is_array($log_folders) && !empty($log_folders)){
				foreach($log_folders as $log_folder){
					//if($app->system->is_mounted($data['old']['document_root'].'/'.$log_folder)) exec('umount '.escapeshellarg($data['old']['document_root'].'/'.$log_folder));
					exec('umount '.escapeshellarg($data['old']['document_root'].'/'.$log_folder).' 2>/dev/null');
				}
			} else {
				//if($app->system->is_mounted($data['old']['document_root'].'/'.$log_folder)) exec('umount '.escapeshellarg($data['old']['document_root'].'/'.$log_folder));
				exec('umount '.escapeshellarg($data['old']['document_root'].'/'.$log_folder).' 2>/dev/null');
			}
		}

		//* remove mountpoint from fstab
		if(is_array($log_folders) && !empty($log_folders)){
			foreach($log_folders as $log_folder){
				$fstab_line = '/var/log/ispconfig/httpd/'.$data['old']['domain'].' '.$data['old']['document_root'].'/'.$log_folder.'    none    bind';
				$app->system->removeLine('/etc/fstab', $fstab_line);
			}
		} else {
			$fstab_line = '/var/log/ispconfig/httpd/'.$data['old']['domain'].' '.$data['old']['document_root'].'/'.$log_folder.'    none    bind';
			$app->system->removeLine('/etc/fstab', $fstab_line);
		}
		unset($log_folders);

		if($data['old']['type'] != 'vhost' && $data['old']['type'] != 'vhostsubdomain' && $data['old']['parent_domain_id'] > 0) {
			//* This is a alias domain or subdomain, so we have to update the website instead
			$parent_domain_id = intval($data['old']['parent_domain_id']);
			$tmp = $app->db->queryOneRecord('SELECT * FROM web_domain WHERE domain_id = '.$parent_domain_id." AND active = 'y'");
			$data['new'] = $tmp;
			$data['old'] = $tmp;
			$this->action = 'update';
			// just run the update function
			$this->update($event_name, $data);

		} else {
			//* This is a website
			// Deleting the vhost file, symlink and the data directory
			$vhost_file = escapeshellcmd($web_config['vhost_conf_dir'].'/'.$data['old']['domain'].'.vhost');

			$vhost_symlink = escapeshellcmd($web_config['vhost_conf_enabled_dir'].'/'.$data['old']['domain'].'.vhost');
			if(is_link($vhost_symlink)){
				$app->system->unlink($vhost_symlink);
				$app->log('Removing symlink: '.$vhost_symlink.'->'.$vhost_file, LOGLEVEL_DEBUG);
			}
			$vhost_symlink = escapeshellcmd($web_config['vhost_conf_enabled_dir'].'/900-'.$data['old']['domain'].'.vhost');
			if(is_link($vhost_symlink)){
				$app->system->unlink($vhost_symlink);
				$app->log('Removing symlink: '.$vhost_symlink.'->'.$vhost_file, LOGLEVEL_DEBUG);
			}
			$vhost_symlink = escapeshellcmd($web_config['vhost_conf_enabled_dir'].'/100-'.$data['old']['domain'].'.vhost');
			if(is_link($vhost_symlink)){
				$app->system->unlink($vhost_symlink);
				$app->log('Removing symlink: '.$vhost_symlink.'->'.$vhost_file, LOGLEVEL_DEBUG);
			}

			$app->system->unlink($vhost_file);
			$app->log('Removing vhost file: '.$vhost_file, LOGLEVEL_DEBUG);

			if($data['old']['type'] == 'vhost' || $data['old']['type'] == 'vhostsubdomain') {
				$docroot = escapeshellcmd($data['old']['document_root']);
				if($docroot != '' && !stristr($docroot, '..')) {
					if($data['old']['type'] == 'vhost') {
						// this is a vhost - we delete everything in here.
						exec('rm -rf '.$docroot);
					} elseif(!stristr($data['old']['web_folder'], '..')) {
						// this is a vhost subdomain
						// IMPORTANT: do some folder checks before we delete this!
						$do_delete = true;
						$delete_folder = preg_replace('/[\/]{2,}/', '/', $web_folder); // replace / occuring multiple times
						if(substr($delete_folder, 0, 1) === '/') $delete_folder = substr($delete_folder, 1);
						if(substr($delete_folder, -1) === '/') $delete_folder = substr($delete_folder, 0, -1);

						$path_elements = explode('/', $delete_folder);

						if($path_elements[0] == 'web' || $path_elements[0] === '') {
							// paths beginning with /web should NEVER EVER be deleted, empty paths should NEVER occur - but for safety reasons we check it here!
							// we use strict check as otherwise directories named '0' may not be deleted
							$do_delete = false;
						} else {
							// read all vhost subdomains with same parent domain
							$used_paths = array();
							$tmp = $app->db->queryAllRecords("SELECT `web_folder` FROM web_domain WHERE type = 'vhostsubdomain' AND parent_domain_id = ".intval($data['old']['parent_domain_id'])." AND domain_id != ".intval($data['old']['domain_id']));
							foreach($tmp as $tmprec) {
								// we normalize the folder entries because we need to compare them
								$tmp_folder = preg_replace('/[\/]{2,}/', '/', $tmprec['web_folder']); // replace / occuring multiple times
								if(substr($tmp_folder, 0, 1) === '/') $tmp_folder = substr($tmp_folder, 1);
								if(substr($tmp_folder, -1) === '/') $tmp_folder = substr($tmp_folder, 0, -1);

								// add this path and it's parent paths to used_paths array
								while(strpos($tmp_folder, '/') !== false) {
									if(in_array($tmp_folder, $used_paths) == false) $used_paths[] = $tmp_folder;
									$tmp_folder = substr($tmp_folder, 0, strrpos($tmp_folder, '/'));
								}
								if(in_array($tmp_folder, $used_paths) == false) $used_paths[] = $tmp_folder;
							}
							unset($tmp);

							// loop and check if the path is still used and stop at first used one
							// set do_delete to false so nothing gets deleted if the web_folder itself is still used
							$do_delete = false;
							while(count($path_elements) > 0) {
								$tmp_folder = implode('/', $path_elements);
								if(in_array($tmp_folder, $used_paths) == true) break;

								// this path is not used - set it as path to delete, strip the last element from the array and set do_delete to true
								$delete_folder = $tmp_folder;
								$do_delete = true;
								array_pop($path_elements);
							}
							unset($tmp_folder);
							unset($used_paths);
						}

						if($do_delete === true && $delete_folder !== '') exec('rm -rf '.$docroot.'/'.$delete_folder);

						unset($delete_folder);
						unset($path_elements);
					}
				}

				//remove the php fastgi starter script if available
				if ($data['old']['php'] == 'fast-cgi') {
					$fastcgi_starter_path = str_replace('[system_user]', $data['old']['system_user'], $fastcgi_config['fastcgi_starter_path']);
					if($data['old']['type'] == 'vhost') {
						if (is_dir($fastcgi_starter_path)) {
							exec('rm -rf '.$fastcgi_starter_path);
						}
					} else {
						$fcgi_starter_script = $fastcgi_starter_path.$fastcgi_config['fastcgi_starter_script'].'_web'.$data['old']['domain_id'];
						if (file_exists($fcgi_starter_script)) {
							exec('rm -f '.$fcgi_starter_script);
						}
					}
				}

				// remove PHP-FPM pool
				if ($data['old']['php'] == 'php-fpm') {
					$this->php_fpm_pool_delete($data, $web_config);
				}

				//remove the php cgi starter script if available
				if ($data['old']['php'] == 'cgi') {
					// TODO: fetch the date from the server-settings
					$web_config['cgi_starter_path'] = $web_config['website_basedir'].'/php-cgi-scripts/[system_user]/';

					$cgi_starter_path = str_replace('[system_user]', $data['old']['system_user'], $web_config['cgi_starter_path']);
					if($data['old']['type'] == 'vhost') {
						if (is_dir($cgi_starter_path)) {
							exec('rm -rf '.$cgi_starter_path);
						}
					} else {
						$cgi_starter_script = $cgi_starter_path.'php-cgi-starter_web'.$data['old']['domain_id'];
						if (file_exists($cgi_starter_script)) {
							exec('rm -f '.$cgi_starter_script);
						}
					}
				}

				$app->log('Removing website: '.$docroot, LOGLEVEL_DEBUG);

				// Delete the symlinks for the sites
				$client = $app->db->queryOneRecord('SELECT client_id FROM sys_group WHERE sys_group.groupid = '.intval($data['old']['sys_groupid']));
				$client_id = intval($client['client_id']);
				unset($client);
				$tmp_symlinks_array = explode(':', $web_config['website_symlinks']);
				if(is_array($tmp_symlinks_array)) {
					foreach($tmp_symlinks_array as $tmp_symlink) {
						$tmp_symlink = str_replace('[client_id]', $client_id, $tmp_symlink);
						$tmp_symlink = str_replace('[website_domain]', $data['old']['domain'], $tmp_symlink);
						// Remove trailing slash
						if(substr($tmp_symlink, -1, 1) == '/') $tmp_symlink = substr($tmp_symlink, 0, -1);
						// delete the symlink
						if(is_link($tmp_symlink)) {
							$app->system->unlink($tmp_symlink);
							$app->log('Removing symlink: '.$tmp_symlink, LOGLEVEL_DEBUG);
						}
					}
				}
				// end removing symlinks
			}

			// Delete the log file directory
			$vhost_logfile_dir = escapeshellcmd('/var/log/ispconfig/httpd/'.$data['old']['domain']);
			if($data['old']['domain'] != '' && !stristr($vhost_logfile_dir, '..')) exec('rm -rf '.$vhost_logfile_dir);
			$app->log('Removing website logfile directory: '.$vhost_logfile_dir, LOGLEVEL_DEBUG);

			if($data['old']['type'] == 'vhost') {
				//delete the web user
				$command = 'killall -u '.escapeshellcmd($data['old']['system_user']).' ; userdel';
				$command .= ' '.escapeshellcmd($data['old']['system_user']);
				exec($command);
				if($apache_chrooted) $this->_exec('chroot '.escapeshellcmd($web_config['website_basedir']).' '.$command);

			}

			//* Remove the awstats configuration file
			if($data['old']['stats_type'] == 'awstats') {
				$this->awstats_delete($data, $web_config);
			}

			if($data['old']['type'] == 'vhostsubdomain') {
				$app->system->web_folder_protection($parent_web_document_root, true);
			}

			if($apache_chrooted) {
				$app->services->restartServiceDelayed('httpd', 'restart');
			} else {
				// request a httpd reload when all records have been processed
				$app->services->restartServiceDelayed('httpd', 'reload');
			}

		}
		if($data['old']['type'] != 'vhost') $app->system->web_folder_protection($data['old']['document_root'], true);
	}

	//* This function is called when a IP on the server is inserted, updated or deleted
	function server_ip($event_name, $data) {
		global $app, $conf;

		// load the server configuration options
		$app->uses('getconf');
		$web_config = $app->getconf->get_server_config($conf['server_id'], 'web');

		$app->load('tpl');

		$tpl = new tpl();
		$tpl->newTemplate('apache_ispconfig.conf.master');
		$tpl->setVar('apache_version', $app->system->getapacheversion());
		$records = $app->db->queryAllRecords('SELECT * FROM server_ip WHERE server_id = '.$conf['server_id']." AND virtualhost = 'y'");

		$records_out= array();
		if(is_array($records)) {
			foreach($records as $rec) {
				if($rec['ip_type'] == 'IPv6') {
					$ip_address = '['.$rec['ip_address'].']';
				} else {
					$ip_address = $rec['ip_address'];
				}
				$ports = explode(',', $rec['virtualhost_port']);
				if(is_array($ports)) {
					foreach($ports as $port) {
						$port = intval($port);
						if($port > 0 && $port < 65536 && $ip_address != '') {
							$records_out[] = array('ip_address' => $ip_address, 'port' => $port);
						}
					}
				}
			}
		}


		if(count($records_out) > 0) {
			$tpl->setLoop('ip_adresses', $records_out);
		}

		$vhost_file = escapeshellcmd($web_config['vhost_conf_dir'].'/ispconfig.conf');
		$app->system->file_put_contents($vhost_file, $tpl->grab());
		$app->log('Writing the conf file: '.$vhost_file, LOGLEVEL_DEBUG);
		unset($tpl);

	}

	//* Create or update the .htaccess folder protection
	function web_folder_user($event_name, $data) {
		global $app, $conf;

		$app->uses('system');

		if($event_name == 'web_folder_user_delete') {
			$folder_id = $data['old']['web_folder_id'];
		} else {
			$folder_id = $data['new']['web_folder_id'];
		}

		$folder = $app->db->queryOneRecord("SELECT * FROM web_folder WHERE web_folder_id = ".intval($folder_id));
		$website = $app->db->queryOneRecord("SELECT * FROM web_domain WHERE domain_id = ".intval($folder['parent_domain_id']));

		if(!is_array($folder) or !is_array($website)) {
			$app->log('Not able to retrieve folder or website record.', LOGLEVEL_DEBUG);
			return false;
		}

		$web_folder = 'web';
		if($website['type'] == 'vhostsubdomain') $web_folder = $website['web_folder'];

		//* Get the folder path.
		if(substr($folder['path'], 0, 1) == '/') $folder['path'] = substr($folder['path'], 1);
		if(substr($folder['path'], -1) == '/') $folder['path'] = substr($folder['path'], 0, -1);
		$folder_path = escapeshellcmd($website['document_root'].'/' . $web_folder . '/'.$folder['path']);
		if(substr($folder_path, -1) != '/') $folder_path .= '/';

		//* Check if the resulting path is inside the docroot
		if(stristr($folder_path, '..') || stristr($folder_path, './') || stristr($folder_path, '\\')) {
			$app->log('Folder path "'.$folder_path.'" contains .. or ./.', LOGLEVEL_DEBUG);
			return false;
		}

		//* Create the folder path, if it does not exist
		if(!is_dir($folder_path)) {
			$app->system->mkdirpath($folder_path);
			$app->system->chown($folder_path, $website['system_user']);
			$app->system->chgrp($folder_path, $website['system_group']);
		}

		//* Create empty .htpasswd file, if it does not exist
		if(!is_file($folder_path.'.htpasswd')) {
			$app->system->touch($folder_path.'.htpasswd');
			$app->system->chmod($folder_path.'.htpasswd', 0751);
			$app->system->chown($folder_path.'.htpasswd', $website['system_user']);
			$app->system->chgrp($folder_path.'.htpasswd', $website['system_group']);
			$app->log('Created file '.$folder_path.'.htpasswd', LOGLEVEL_DEBUG);
		}

		/*
		$auth_users = $app->db->queryAllRecords("SELECT * FROM web_folder_user WHERE active = 'y' AND web_folder_id = ".intval($folder_id));
		$htpasswd_content = '';
		if(is_array($auth_users) && !empty($auth_users)){
			foreach($auth_users as $auth_user){
				$htpasswd_content .= $auth_user['username'].':'.$auth_user['password']."\n";
			}
		}
		$htpasswd_content = trim($htpasswd_content);
		@file_put_contents($folder_path.'.htpasswd', $htpasswd_content);
		$app->log('Changed .htpasswd file: '.$folder_path.'.htpasswd',LOGLEVEL_DEBUG);
		*/

		if(($data['new']['username'] != $data['old']['username'] || $data['new']['active'] == 'n') && $data['old']['username'] != '') {
			$app->system->removeLine($folder_path.'.htpasswd', $data['old']['username'].':');
			$app->log('Removed user: '.$data['old']['username'], LOGLEVEL_DEBUG);
		}

		//* Add or remove the user from .htpasswd file
		if($event_name == 'web_folder_user_delete') {
			$app->system->removeLine($folder_path.'.htpasswd', $data['old']['username'].':');
			$app->log('Removed user: '.$data['old']['username'], LOGLEVEL_DEBUG);
		} else {
			if($data['new']['active'] == 'y') {
				$app->system->replaceLine($folder_path.'.htpasswd', $data['new']['username'].':', $data['new']['username'].':'.$data['new']['password'], 0, 1);
				$app->log('Added or updated user: '.$data['new']['username'], LOGLEVEL_DEBUG);
			}
		}


		//* Create the .htaccess file
		//if(!is_file($folder_path.'.htaccess')) {
		$begin_marker = '### ISPConfig folder protection begin ###';
		$end_marker = "### ISPConfig folder protection end ###\n\n";
		$ht_file = $begin_marker."\nAuthType Basic\nAuthName \"Members Only\"\nAuthUserFile ".$folder_path.".htpasswd\nrequire valid-user\n".$end_marker;

		if(file_exists($folder_path.'.htaccess')) {
			$old_content = $app->system->file_get_contents($folder_path.'.htaccess');

			if(preg_match('/' . preg_quote($begin_marker, '/') . '(.*?)' . preg_quote($end_marker, '/') . '/s', $old_content, $matches)) {
				$ht_file = str_replace($matches[0], $ht_file, $old_content);
			} else {
				$ht_file .= $old_content;
			}
		}
		unset($old_content);

		$app->system->file_put_contents($folder_path.'.htaccess', $ht_file);
		$app->system->chmod($folder_path.'.htaccess', 0751);
		$app->system->chown($folder_path.'.htaccess', $website['system_user']);
		$app->system->chgrp($folder_path.'.htaccess', $website['system_group']);
		$app->log('Created/modified file '.$folder_path.'.htaccess', LOGLEVEL_DEBUG);
		//}

	}

	//* Remove .htaccess and .htpasswd file, when folder protection is removed
	function web_folder_delete($event_name, $data) {
		global $app, $conf;

		$folder_id = $data['old']['web_folder_id'];

		$folder = $data['old'];
		$website = $app->db->queryOneRecord("SELECT * FROM web_domain WHERE domain_id = ".intval($folder['parent_domain_id']));

		if(!is_array($folder) or !is_array($website)) {
			$app->log('Not able to retrieve folder or website record.', LOGLEVEL_DEBUG);
			return false;
		}

		$web_folder = 'web';
		if($website['type'] == 'vhostsubdomain') $web_folder = $website['web_folder'];

		//* Get the folder path.
		if(substr($folder['path'], 0, 1) == '/') $folder['path'] = substr($folder['path'], 1);
		if(substr($folder['path'], -1) == '/') $folder['path'] = substr($folder['path'], 0, -1);
		$folder_path = realpath($website['document_root'].'/' . $web_folder . '/'.$folder['path']);
		if(substr($folder_path, -1) != '/') $folder_path .= '/';

		//* Check if the resulting path is inside the docroot
		if(substr($folder_path, 0, strlen($website['document_root'])) != $website['document_root']) {
			$app->log('Folder path is outside of docroot.', LOGLEVEL_DEBUG);
			return false;
		}

		//* Remove .htpasswd file
		if(is_file($folder_path.'.htpasswd')) {
			$app->system->unlink($folder_path.'.htpasswd');
			$app->log('Removed file '.$folder_path.'.htpasswd', LOGLEVEL_DEBUG);
		}

		//* Remove .htaccess file
		if(is_file($folder_path.'.htaccess')) {
			$begin_marker = '### ISPConfig folder protection begin ###';
			$end_marker = "### ISPConfig folder protection end ###\n\n";

			$ht_file = $app->system->file_get_contents($folder_path.'.htaccess');

			if(preg_match('/' . preg_quote($begin_marker, '/') . '(.*?)' . preg_quote($end_marker, '/') . '/s', $ht_file, $matches)) {
				$ht_file = str_replace($matches[0], '', $ht_file);
			} else {
				$ht_file = str_replace("AuthType Basic\nAuthName \"Members Only\"\nAuthUserFile ".$folder_path.".htpasswd\nrequire valid-user", '', $ht_file);
			}

			if(trim($ht_file) == '') {
				$app->system->unlink($folder_path.'.htaccess');
				$app->log('Removed file '.$folder_path.'.htaccess', LOGLEVEL_DEBUG);
			} else {
				$app->system->file_put_contents($folder_path.'.htaccess', $ht_file);
				$app->log('Removed protection content from file '.$folder_path.'.htaccess', LOGLEVEL_DEBUG);
			}
		}
	}

	//* Update folder protection, when path has been changed
	function web_folder_update($event_name, $data) {
		global $app, $conf;

		$website = $app->db->queryOneRecord("SELECT * FROM web_domain WHERE domain_id = ".intval($data['new']['parent_domain_id']));

		if(!is_array($website)) {
			$app->log('Not able to retrieve folder or website record.', LOGLEVEL_DEBUG);
			return false;
		}

		$web_folder = 'web';
		if($website['type'] == 'vhostsubdomain') $web_folder = $website['web_folder'];

		//* Get the folder path.
		if(substr($data['old']['path'], 0, 1) == '/') $data['old']['path'] = substr($data['old']['path'], 1);
		if(substr($data['old']['path'], -1) == '/') $data['old']['path'] = substr($data['old']['path'], 0, -1);
		$old_folder_path = realpath($website['document_root'].'/' . $web_folder . '/'.$data['old']['path']);
		if(substr($old_folder_path, -1) != '/') $old_folder_path .= '/';

		if(substr($data['new']['path'], 0, 1) == '/') $data['new']['path'] = substr($data['new']['path'], 1);
		if(substr($data['new']['path'], -1) == '/') $data['new']['path'] = substr($data['new']['path'], 0, -1);
		$new_folder_path = escapeshellcmd($website['document_root'].'/' . $web_folder . '/'.$data['new']['path']);
		if(substr($new_folder_path, -1) != '/') $new_folder_path .= '/';

		//* Check if the resulting path is inside the docroot
		if(stristr($new_folder_path, '..') || stristr($new_folder_path, './') || stristr($new_folder_path, '\\')) {
			$app->log('Folder path "'.$new_folder_path.'" contains .. or ./.', LOGLEVEL_DEBUG);
			return false;
		}
		if(stristr($old_folder_path, '..') || stristr($old_folder_path, './') || stristr($old_folder_path, '\\')) {
			$app->log('Folder path "'.$old_folder_path.'" contains .. or ./.', LOGLEVEL_DEBUG);
			return false;
		}

		//* Check if the resulting path is inside the docroot
		if(substr($old_folder_path, 0, strlen($website['document_root'])) != $website['document_root']) {
			$app->log('Old folder path '.$old_folder_path.' is outside of docroot.', LOGLEVEL_DEBUG);
			return false;
		}
		if(substr($new_folder_path, 0, strlen($website['document_root'])) != $website['document_root']) {
			$app->log('New folder path '.$new_folder_path.' is outside of docroot.', LOGLEVEL_DEBUG);
			return false;
		}

		//* Create the folder path, if it does not exist
		if(!is_dir($new_folder_path)) $app->system->mkdirpath($new_folder_path);

		$begin_marker = '### ISPConfig folder protection begin ###';
		$end_marker = "### ISPConfig folder protection end ###\n\n";

		if($data['old']['path'] != $data['new']['path']) {


			//* move .htpasswd file
			if(is_file($old_folder_path.'.htpasswd')) {
				$app->system->rename($old_folder_path.'.htpasswd', $new_folder_path.'.htpasswd');
				$app->log('Moved file '.$old_folder_path.'.htpasswd to '.$new_folder_path.'.htpasswd', LOGLEVEL_DEBUG);
			}

			//* delete old .htaccess file
			if(is_file($old_folder_path.'.htaccess')) {
				$ht_file = $app->system->file_get_contents($old_folder_path.'.htaccess');

				if(preg_match('/' . preg_quote($begin_marker, '/') . '(.*?)' . preg_quote($end_marker, '/') . '/s', $ht_file, $matches)) {
					$ht_file = str_replace($matches[0], '', $ht_file);
				} else {
					$ht_file = str_replace("AuthType Basic\nAuthName \"Members Only\"\nAuthUserFile ".$old_folder_path.".htpasswd\nrequire valid-user", '', $ht_file);
				}

				if(trim($ht_file) == '') {
					$app->system->unlink($old_folder_path.'.htaccess');
					$app->log('Removed file '.$old_folder_path.'.htaccess', LOGLEVEL_DEBUG);
				} else {
					$app->system->file_put_contents($old_folder_path.'.htaccess', $ht_file);
					$app->log('Removed protection content from file '.$old_folder_path.'.htaccess', LOGLEVEL_DEBUG);
				}
			}

		}

		//* Create the .htaccess file
		if($data['new']['active'] == 'y') {
			$ht_file = $begin_marker."\nAuthType Basic\nAuthName \"Members Only\"\nAuthUserFile ".$new_folder_path.".htpasswd\nrequire valid-user\n".$end_marker;

			if(file_exists($new_folder_path.'.htaccess')) {
				$old_content = $app->system->file_get_contents($new_folder_path.'.htaccess');

				if(preg_match('/' . preg_quote($begin_marker, '/') . '(.*?)' . preg_quote($end_marker, '/') . '/s', $old_content, $matches)) {
					$ht_file = str_replace($matches[0], $ht_file, $old_content);
				} else {
					$ht_file .= $old_content;
				}
			}

			$app->system->file_put_contents($new_folder_path.'.htaccess', $ht_file);
			$app->system->chmod($new_folder_path.'.htaccess', 0751);
			$app->system->chown($new_folder_path.'.htaccess', $website['system_user']);
			$app->system->chgrp($new_folder_path.'.htaccess', $website['system_group']);
			$app->log('Created/modified file '.$new_folder_path.'.htaccess', LOGLEVEL_DEBUG);
			
			//* Create empty .htpasswd file, if it does not exist
			if(!is_file($folder_path.'.htpasswd')) {
				$app->system->touch($new_folder_path.'.htpasswd');
				$app->system->chmod($new_folder_path.'.htpasswd', 0751);
				$app->system->chown($new_folder_path.'.htpasswd', $website['system_user']);
				$app->system->chgrp($new_folder_path.'.htpasswd', $website['system_group']);
				$app->log('Created file '.$new_folder_path.'.htpasswd', LOGLEVEL_DEBUG);
			}
		}

		//* Remove .htaccess file
		if($data['new']['active'] == 'n' && is_file($new_folder_path.'.htaccess')) {
			$ht_file = $app->system->file_get_contents($new_folder_path.'.htaccess');

			if(preg_match('/' . preg_quote($begin_marker, '/') . '(.*?)' . preg_quote($end_marker, '/') . '/s', $ht_file, $matches)) {
				$ht_file = str_replace($matches[0], '', $ht_file);
			} else {
				$ht_file = str_replace("AuthType Basic\nAuthName \"Members Only\"\nAuthUserFile ".$new_folder_path.".htpasswd\nrequire valid-user", '', $ht_file);
			}

			if(trim($ht_file) == '') {
				$app->system->unlink($new_folder_path.'.htaccess');
				$app->log('Removed file '.$new_folder_path.'.htaccess', LOGLEVEL_DEBUG);
			} else {
				$app->system->file_put_contents($new_folder_path.'.htaccess', $ht_file);
				$app->log('Removed protection content from file '.$new_folder_path.'.htaccess', LOGLEVEL_DEBUG);
			}
		}


	}

	public function ftp_user_delete($event_name, $data) {
		global $app, $conf;

		$ftpquota_file = $data['old']['dir'].'/.ftpquota';
		if(file_exists($ftpquota_file)) $app->system->unlink($ftpquota_file);

	}



	/**
	 * This function is called when a Webdav-User is inserted, updated or deleted.
	 *
	 * @author Oliver Vogel
	 * @param string $event_name
	 * @param array $data
	 */
	public function webdav($event_name, $data) {
		global $app, $conf;

		/*
		 * load the server configuration options
		*/
		$app->uses('getconf');
		$web_config = $app->getconf->get_server_config($conf['server_id'], 'web');

		if (($event_name == 'webdav_user_insert') || ($event_name == 'webdav_user_update')) {

			/*
			 * Get additional informations
			*/
			$sitedata = $app->db->queryOneRecord('SELECT document_root, domain, system_user, system_group FROM web_domain WHERE domain_id = ' . $data['new']['parent_domain_id']);
			$documentRoot = $sitedata['document_root'];
			$domain = $sitedata['domain'];
			$user = $sitedata['system_user'];
			$group = $sitedata['system_group'];
			$webdav_user_dir = $documentRoot . '/webdav/' . $data['new']['dir'];

			/* Check if this is a chrooted setup */
			if($web_config['website_basedir'] != '' && @is_file($web_config['website_basedir'].'/etc/passwd')) {
				$apache_chrooted = true;
				$app->log('Info: Apache is chrooted.', LOGLEVEL_DEBUG);
			} else {
				$apache_chrooted = false;
			}

			//* We dont want to have relative paths here
			if(stristr($webdav_user_dir, '..')  || stristr($webdav_user_dir, './')) {
				$app->log('Folder path '.$webdav_user_dir.' contains ./ or .. '.$documentRoot, LOGLEVEL_WARN);
				return false;
			}

			//* Check if the resulting path exists if yes, if it is inside the docroot
			if(is_dir($webdav_user_dir) && substr(realpath($webdav_user_dir), 0, strlen($documentRoot)) != $documentRoot) {
				$app->log('Folder path '.$webdav_user_dir.' is outside of docroot '.$documentRoot, LOGLEVEL_WARN);
				return false;
			}

			/*
			 * First the webdav-root - folder has to exist
			*/
			if(!is_dir($webdav_user_dir)) {
				$app->log('Webdav User directory '.$webdav_user_dir.' does not exist. Creating it now.', LOGLEVEL_DEBUG);
				$app->system->mkdirpath($webdav_user_dir);
			}

			/*
			 * The webdav - Root needs the group/user as owner and the apache as read and write
			*/
			//$this->_exec('chown ' . $user . ':' . $group . ' ' . escapeshellcmd($documentRoot . '/webdav/'));
			//$this->_exec('chmod 770 ' . escapeshellcmd($documentRoot . '/webdav/'));
			$app->system->chown($documentRoot . '/webdav', $user);
			$app->system->chgrp($documentRoot . '/webdav', $group);
			$app->system->chmod($documentRoot . '/webdav', 0770);

			/*
			 * The webdav folder (not the webdav-root!) needs the same (not in ONE step, because the
			 * pwd-files are owned by root)
			*/
			//$this->_exec('chown ' . $user . ':' . $group . ' ' . escapeshellcmd($webdav_user_dir.' -R'));
			//$this->_exec('chmod 770 ' . escapeshellcmd($webdav_user_dir.' -R'));
			$app->system->chown($webdav_user_dir, $user);
			$app->system->chgrp($webdav_user_dir, $group);
			$app->system->chmod($webdav_user_dir, 0770);

			/*
			 * if the user is active, we have to write/update the password - file
			 * if the user is inactive, we have to inactivate the user by removing the user from the file
			*/
			if ($data['new']['active'] == 'y') {
				$this->_writeHtDigestFile( $webdav_user_dir . '.htdigest', $data['new']['username'], $data['new']['dir'], $data['new']['password']);
			}
			else {
				/* empty pwd removes the user! */
				$this->_writeHtDigestFile( $webdav_user_dir . '.htdigest', $data['new']['username'], $data['new']['dir'], '');
			}

			/*
			 * Next step, patch the vhost - file
			*/
			$vhost_file = escapeshellcmd($web_config['vhost_conf_dir'] . '/' . $domain . '.vhost');
			$this->_patchVhostWebdav($vhost_file, $documentRoot . '/webdav');

			/*
			 * Last, restart apache
			*/
			if($apache_chrooted) {
				$app->services->restartServiceDelayed('httpd', 'restart');
			} else {
				// request a httpd reload when all records have been processed
				$app->services->restartServiceDelayed('httpd', 'reload');
			}

		}

		if ($event_name == 'webdav_user_delete') {
			/*
			 * Get additional informations
			*/
			$sitedata = $app->db->queryOneRecord('SELECT document_root, domain FROM web_domain WHERE domain_id = ' . $data['old']['parent_domain_id']);
			$documentRoot = $sitedata['document_root'];
			$domain = $sitedata['domain'];

			/*
			 * We dont't want to destroy any (transfer)-Data. So we do NOT delete any dir.
			 * So the only thing, we have to do, is to delete the user from the password-file
			*/
			$this->_writeHtDigestFile( $documentRoot . '/webdav/' . $data['old']['dir'] . '.htdigest', $data['old']['username'], $data['old']['dir'], '');

			/*
			 * Next step, patch the vhost - file
			*/
			$vhost_file = escapeshellcmd($web_config['vhost_conf_dir'] . '/' . $domain . '.vhost');
			$this->_patchVhostWebdav($vhost_file, $documentRoot . '/webdav');

			/*
			 * Last, restart apache
			*/
			if($apache_chrooted) {
				$app->services->restartServiceDelayed('httpd', 'restart');
			} else {
				// request a httpd reload when all records have been processed
				$app->services->restartServiceDelayed('httpd', 'reload');
			}
		}
	}


	/**
	 * This function writes the htdigest - files used by webdav and digest
	 * more info: see http://riceball.com/d/node/424
	 * @author Oliver Vogel
	 * @param string $filename The name of the digest-file
	 * @param string $username The name of the webdav-user
	 * @param string $authname The name of the realm
	 * @param string $pwd      The password-hash of the user
	 */
	private function _writeHtDigestFile($filename, $username, $authname, $pwdhash ) {
		global $app;

		$changed = false;
		if(is_file($filename) && !is_link($filename)) {
			$in = fopen($filename, 'r');
			$output = '';
			/*
			* read line by line and search for the username and authname
			*/
			while (preg_match("/:/", $line = fgets($in))) {
				$line = rtrim($line);
				$tmp = explode(':', $line);
				if ($tmp[0] == $username && $tmp[1] == $authname) {
					/*
					* found the user. delete or change it?
					*/
					if ($pwdhash != '') {
						$output .= $tmp[0] . ':' . $tmp[1] . ':' . $pwdhash . "\n";
					}
					$changed = true;
				}
				else {
					$output .= $line . "\n";
				}
			}
			fclose($in);
		}
		/*
		 * if we didn't change anything, we have to add the new user at the end of the file
		*/
		if (!$changed) {
			$output .= $username . ':' . $authname . ':' . $pwdhash . "\n";
		}


		/*
		 * Now lets write the new file
		*/
		if(trim($output) == '') {
			$app->system->unlink($filename);
		} else {
			$app->system->file_put_contents($filename, $output);
		}
	}

	/**
	 * This function patches the vhost-file and adds all webdav - user.
	 * This function is written, because the creation of the vhost - file is sophisticated and
	 * i don't want to make it more "heavy" by also adding this code too...
	 * @author Oliver Vogel
	 * @param string $fileName The Name of the .vhost-File (path included)
	 * @param string $webdavRoot The root of the webdav-folder
	 */
	private function _patchVhostWebdav($fileName, $webdavRoot) {
		global $app;
		$in = fopen($fileName, 'r');
		$output = '';
		$inWebdavSection = false;

		/*
		 * read line by line and search for the username and authname
		*/
		while ($line = fgets($in)) {
			/*
			 *  is the "replace-comment" found...
			*/
			if (trim($line) == '# WEBDAV BEGIN') {
				/*
				 * The begin of the webdav - section is found, so ignore all lines til the end  is found
				*/
				$inWebdavSection = true;

				$output .= "      # WEBDAV BEGIN\n";

				/*
				 * add all the webdav-dirs to the webdav-section
				*/
				$files = @scandir($webdavRoot);
				if(is_array($files)) {
					foreach($files as $file) {
						if (substr($file, strlen($file) - strlen('.htdigest')) == '.htdigest' && preg_match("/^[a-zA-Z0-9\-_\.]*$/", $file)) {
							/*
						 * found a htdigest - file, so add it to webdav
						*/
							$fn = substr($file, 0, strlen($file) - strlen('.htdigest'));
							$output .= "\n";
							// $output .= "      Alias /" . $fn . ' ' . $webdavRoot . '/' . $fn . "\n";
							// $output .= "      <Location /" . $fn . ">\n";
							$output .= "      Alias /webdav/" . $fn . ' ' . $webdavRoot . '/' . $fn . "\n";
							$output .= "      <Location /webdav/" . $fn . ">\n";
							$output .= "        DAV On\n";
							$output .= '        BrowserMatch "MSIE" AuthDigestEnableQueryStringHack=On'."\n";
							$output .= "        AuthType Digest\n";
							$output .= "        AuthName \"" . $fn . "\"\n";
							$output .= "        AuthUserFile " . $webdavRoot . '/' . $file . "\n";
							$output .= "        Require valid-user \n";
							$output .= "        Options +Indexes \n";
							$output .= "        Order allow,deny \n";
							$output .= "        Allow from all \n";
							$output .= "      </Location> \n";
						}
					}
				}
			}
			/*
			 *  is the "replace-comment-end" found...
			*/
			if (trim($line) == '# WEBDAV END') {
				/*
				 * The end of the webdav - section is found, so stop ignoring
				*/
				$inWebdavSection = false;
			}

			/*
			 * Write the line to the output, if it is not in the section
			*/
			if (!$inWebdavSection) {
				$output .= $line;
			}
		}
		fclose($in);

		/*
		 * Now lets write the new file
		*/
		$app->system->file_put_contents($fileName, $output);

	}

	//* Update the awstats configuration file
	private function awstats_update ($data, $web_config) {
		global $app;

		$web_folder = $data['new']['web_folder'];
		if($data['new']['type'] == 'vhost') $web_folder = 'web';
		$awstats_conf_dir = $web_config['awstats_conf_dir'];

		if(!is_dir($data['new']['document_root']."/" . $web_folder . "/stats/")) mkdir($data['new']['document_root']."/" . $web_folder . "/stats");
		if(!@is_file($awstats_conf_dir.'/awstats.'.$data['new']['domain'].'.conf') || ($data['old']['domain'] != '' && $data['new']['domain'] != $data['old']['domain'])) {
			if ( @is_file($awstats_conf_dir.'/awstats.'.$data['old']['domain'].'.conf') ) {
				$app->system->unlink($awstats_conf_dir.'/awstats.'.$data['old']['domain'].'.conf');
			}

			$content = '';
			$content .= "Include \"".$awstats_conf_dir."/awstats.conf\"\n";
			$content .= "LogFile=\"/var/log/ispconfig/httpd/".$data['new']['domain']."/access.log\"\n";
			$content .= "SiteDomain=\"".$data['new']['domain']."\"\n";
			$content .= "HostAliases=\"www.".$data['new']['domain']."  localhost 127.0.0.1\"\n";

			$app->system->file_put_contents($awstats_conf_dir.'/awstats.'.$data['new']['domain'].'.conf', $content);
			$app->log('Created AWStats config file: '.$awstats_conf_dir.'/awstats.'.$data['new']['domain'].'.conf', LOGLEVEL_DEBUG);
		}

		if(is_file($data['new']['document_root']."/" . $web_folder . "/stats/index.html")) $app->system->unlink($data['new']['document_root']."/" . $web_folder . "/stats/index.html");
		if(file_exists("/usr/local/ispconfig/server/conf-custom/awstats_index.php.master")) {
			$app->system->copy("/usr/local/ispconfig/server/conf-custom/awstats_index.php.master", $data['new']['document_root']."/" . $web_folder . "/stats/index.php");
		} else {
			$app->system->copy("/usr/local/ispconfig/server/conf/awstats_index.php.master", $data['new']['document_root']."/" . $web_folder . "/stats/index.php");
		}
	}

	//* Delete the awstats configuration file
	private function awstats_delete ($data, $web_config) {
		global $app;

		$awstats_conf_dir = $web_config['awstats_conf_dir'];

		if ( @is_file($awstats_conf_dir.'/awstats.'.$data['old']['domain'].'.conf') ) {
			$app->system->unlink($awstats_conf_dir.'/awstats.'.$data['old']['domain'].'.conf');
			$app->log('Removed AWStats config file: '.$awstats_conf_dir.'/awstats.'.$data['old']['domain'].'.conf', LOGLEVEL_DEBUG);
		}
	}

	//* Update the PHP-FPM pool configuration file
	private function php_fpm_pool_update ($data, $web_config, $pool_dir, $pool_name, $socket_dir) {
		global $app, $conf;
		//$reload = false;

		if($data['new']['php'] == 'php-fpm'){
			if(trim($data['new']['fastcgi_php_version']) != ''){
				$default_php_fpm = false;
				list($custom_php_fpm_name, $custom_php_fpm_init_script, $custom_php_fpm_ini_dir, $custom_php_fpm_pool_dir) = explode(':', trim($data['new']['fastcgi_php_version']));
				if(substr($custom_php_fpm_ini_dir, -1) != '/') $custom_php_fpm_ini_dir .= '/';
			} else {
				$default_php_fpm = true;
			}
		} else {
			if(trim($data['old']['fastcgi_php_version']) != '' && $data['old']['php'] == 'php-fpm'){
				$default_php_fpm = false;
				list($custom_php_fpm_name, $custom_php_fpm_init_script, $custom_php_fpm_ini_dir, $custom_php_fpm_pool_dir) = explode(':', trim($data['old']['fastcgi_php_version']));
				if(substr($custom_php_fpm_ini_dir, -1) != '/') $custom_php_fpm_ini_dir .= '/';
			} else {
				$default_php_fpm = true;
			}
		}

		$app->uses("getconf");
		$web_config = $app->getconf->get_server_config($conf["server_id"], 'web');

		if($data['new']['php'] != 'php-fpm'){
			if(@is_file($pool_dir.$pool_name.'.conf')){
				$app->system->unlink($pool_dir.$pool_name.'.conf');
				//$reload = true;
			}
			if($data['old']['php'] == 'php-fpm'){
				if(!$default_php_fpm){
					$app->services->restartService('php-fpm', 'reload:'.$custom_php_fpm_init_script);
				} else {
					$app->services->restartService('php-fpm', 'reload:'.$conf['init_scripts'].'/'.$web_config['php_fpm_init_script']);
				}
			}
			//if($reload == true) $app->services->restartService('php-fpm','reload');
			return;
		}

		$app->load('tpl');
		$tpl = new tpl();
		$tpl->newTemplate('php_fpm_pool.conf.master');
		$tpl->setVar('apache_version', $app->system->getapacheversion());
		
		$apache_modules = $app->system->getapachemodules();
		
		// Use sockets, but not with apache 2.4 on centos (mod_proxy_fcgi) as socket support is buggy in that version
		if($data['new']['php_fpm_use_socket'] == 'y' && in_array('fastcgi_module',$apache_modules)){
			$use_tcp = 0;
			$use_socket = 1;
			if(!is_dir($socket_dir)) $app->system->mkdirpath($socket_dir);
		} else {
			$use_tcp = 1;
			$use_socket = 0;
		}
		$tpl->setVar('use_tcp', $use_tcp);
		$tpl->setVar('use_socket', $use_socket);

		$fpm_socket = $socket_dir.$pool_name.'.sock';
		$tpl->setVar('fpm_socket', $fpm_socket);
		$tpl->setVar('fpm_listen_mode', '0660');

		$tpl->setVar('fpm_pool', $pool_name);
		$tpl->setVar('fpm_port', $web_config['php_fpm_start_port'] + $data['new']['domain_id'] - 1);
		$tpl->setVar('fpm_user', $data['new']['system_user']);
		$tpl->setVar('fpm_group', $data['new']['system_group']);
		$tpl->setVar('pm', $data['new']['pm']);
		$tpl->setVar('pm_max_children', $data['new']['pm_max_children']);
		$tpl->setVar('pm_start_servers', $data['new']['pm_start_servers']);
		$tpl->setVar('pm_min_spare_servers', $data['new']['pm_min_spare_servers']);
		$tpl->setVar('pm_max_spare_servers', $data['new']['pm_max_spare_servers']);
		$tpl->setVar('pm_process_idle_timeout', $data['new']['pm_process_idle_timeout']);
		$tpl->setVar('pm_max_requests', $data['new']['pm_max_requests']);
		$tpl->setVar('document_root', $data['new']['document_root']);
		$tpl->setVar('security_level', $web_config['security_level']);
		$tpl->setVar('domain', $data['new']['domain']);
		$php_open_basedir = ($data['new']['php_open_basedir'] == '')?escapeshellcmd($data['new']['document_root']):escapeshellcmd($data['new']['php_open_basedir']);
		$tpl->setVar('php_open_basedir', $php_open_basedir);
		if($php_open_basedir != ''){
			$tpl->setVar('enable_php_open_basedir', '');
		} else {
			$tpl->setVar('enable_php_open_basedir', ';');
		}

		// Custom php.ini settings
		$final_php_ini_settings = array();
		$custom_php_ini_settings = trim($data['new']['custom_php_ini']);
		if($custom_php_ini_settings != ''){
			// Make sure we only have Unix linebreaks
			$custom_php_ini_settings = str_replace("\r\n", "\n", $custom_php_ini_settings);
			$custom_php_ini_settings = str_replace("\r", "\n", $custom_php_ini_settings);
			$ini_settings = explode("\n", $custom_php_ini_settings);
			if(is_array($ini_settings) && !empty($ini_settings)){
				foreach($ini_settings as $ini_setting){
					$ini_setting = trim($ini_setting);
					if(substr($ini_setting, 0, 1) == ';') continue;
					if(substr($ini_setting, 0, 1) == '#') continue;
					if(substr($ini_setting, 0, 2) == '//') continue;
					list($key, $value) = explode('=', $ini_setting, 2);
					$value = trim($value);
					if($value != ''){
						$key = trim($key);
						switch (strtolower($value)) {
						case '0':
							// PHP-FPM might complain about invalid boolean value if you use 0
							$value = 'off';
						case '1':
						case 'on':
						case 'off':
						case 'true':
						case 'false':
						case 'yes':
						case 'no':
							$final_php_ini_settings[] = array('ini_setting' => 'php_admin_flag['.$key.'] = '.$value);
							break;
						default:
							$final_php_ini_settings[] = array('ini_setting' => 'php_admin_value['.$key.'] = '.$value);
						}
					}
				}
			}
		}

		$tpl->setLoop('custom_php_ini_settings', $final_php_ini_settings);

		$app->system->file_put_contents($pool_dir.$pool_name.'.conf', $tpl->grab());
		$app->log('Writing the PHP-FPM config file: '.$pool_dir.$pool_name.'.conf', LOGLEVEL_DEBUG);
		unset($tpl);

		// delete pool in all other PHP versions
		$default_pool_dir = escapeshellcmd($web_config['php_fpm_pool_dir']);
		if(substr($default_pool_dir, -1) != '/') $default_pool_dir .= '/';
		if($default_pool_dir != $pool_dir){
			if ( @is_file($default_pool_dir.$pool_name.'.conf') ) {
				$app->system->unlink($default_pool_dir.$pool_name.'.conf');
				$app->log('Removed PHP-FPM config file: '.$default_pool_dir.$pool_name.'.conf', LOGLEVEL_DEBUG);
				$app->services->restartService('php-fpm', 'reload:'.$conf['init_scripts'].'/'.$web_config['php_fpm_init_script']);
			}
		}
		$php_versions = $app->db->queryAllRecords("SELECT * FROM server_php WHERE php_fpm_init_script != '' AND php_fpm_ini_dir != '' AND php_fpm_pool_dir != '' AND server_id = ".$conf["server_id"]);
		if(is_array($php_versions) && !empty($php_versions)){
			foreach($php_versions as $php_version){
				if(substr($php_version['php_fpm_pool_dir'], -1) != '/') $php_version['php_fpm_pool_dir'] .= '/';
				if($php_version['php_fpm_pool_dir'] != $pool_dir){
					if ( @is_file($php_version['php_fpm_pool_dir'].$pool_name.'.conf') ) {
						$app->system->unlink($php_version['php_fpm_pool_dir'].$pool_name.'.conf');
						$app->log('Removed PHP-FPM config file: '.$php_version['php_fpm_pool_dir'].$pool_name.'.conf', LOGLEVEL_DEBUG);
						$app->services->restartService('php-fpm', 'reload:'.$php_version['php_fpm_init_script']);
					}
				}
			}
		}
		// Reload current PHP-FPM after all others
		sleep(1);
		if(!$default_php_fpm){
			$app->services->restartService('php-fpm', 'reload:'.$custom_php_fpm_init_script);
		} else {
			$app->services->restartService('php-fpm', 'reload:'.$conf['init_scripts'].'/'.$web_config['php_fpm_init_script']);
		}

		//$reload = true;

		//if($reload == true) $app->services->restartService('php-fpm','reload');
	}

	//* Delete the PHP-FPM pool configuration file
	private function php_fpm_pool_delete ($data, $web_config) {
		global $app, $conf;

		if(trim($data['old']['fastcgi_php_version']) != '' && $data['old']['php'] == 'php-fpm'){
			$default_php_fpm = false;
			list($custom_php_fpm_name, $custom_php_fpm_init_script, $custom_php_fpm_ini_dir, $custom_php_fpm_pool_dir) = explode(':', trim($data['old']['fastcgi_php_version']));
			if(substr($custom_php_fpm_ini_dir, -1) != '/') $custom_php_fpm_ini_dir .= '/';
		} else {
			$default_php_fpm = true;
		}

		if($default_php_fpm){
			$pool_dir = escapeshellcmd($web_config['php_fpm_pool_dir']);
		} else {
			$pool_dir = $custom_php_fpm_pool_dir;
		}

		if(substr($pool_dir, -1) != '/') $pool_dir .= '/';
		$pool_name = 'web'.$data['old']['domain_id'];

		if ( @is_file($pool_dir.$pool_name.'.conf') ) {
			$app->system->unlink($pool_dir.$pool_name.'.conf');
			$app->log('Removed PHP-FPM config file: '.$pool_dir.$pool_name.'.conf', LOGLEVEL_DEBUG);

			//$app->services->restartService('php-fpm','reload');
		}

		// delete pool in all other PHP versions
		$default_pool_dir = escapeshellcmd($web_config['php_fpm_pool_dir']);
		if(substr($default_pool_dir, -1) != '/') $default_pool_dir .= '/';
		if($default_pool_dir != $pool_dir){
			if ( @is_file($default_pool_dir.$pool_name.'.conf') ) {
				$app->system->unlink($default_pool_dir.$pool_name.'.conf');
				$app->log('Removed PHP-FPM config file: '.$default_pool_dir.$pool_name.'.conf', LOGLEVEL_DEBUG);
				$app->services->restartService('php-fpm', 'reload:'.$conf['init_scripts'].'/'.$web_config['php_fpm_init_script']);
			}
		}
		$php_versions = $app->db->queryAllRecords("SELECT * FROM server_php WHERE php_fpm_init_script != '' AND php_fpm_ini_dir != '' AND php_fpm_pool_dir != '' AND server_id = ".$data['old']['server_id']);
		if(is_array($php_versions) && !empty($php_versions)){
			foreach($php_versions as $php_version){
				if(substr($php_version['php_fpm_pool_dir'], -1) != '/') $php_version['php_fpm_pool_dir'] .= '/';
				if($php_version['php_fpm_pool_dir'] != $pool_dir){
					if ( @is_file($php_version['php_fpm_pool_dir'].$pool_name.'.conf') ) {
						$app->system->unlink($php_version['php_fpm_pool_dir'].$pool_name.'.conf');
						$app->log('Removed PHP-FPM config file: '.$php_version['php_fpm_pool_dir'].$pool_name.'.conf', LOGLEVEL_DEBUG);
						$app->services->restartService('php-fpm', 'reload:'.$php_version['php_fpm_init_script']);
					}
				}
			}
		}

		// Reload current PHP-FPM after all others
		sleep(1);
		if(!$default_php_fpm){
			$app->services->restartService('php-fpm', 'reload:'.$custom_php_fpm_init_script);
		} else {
			$app->services->restartService('php-fpm', 'reload:'.$conf['init_scripts'].'/'.$web_config['php_fpm_init_script']);
		}
	}

	function client_delete($event_name, $data) {
		global $app, $conf;

		$app->uses("getconf");
		$web_config = $app->getconf->get_server_config($conf["server_id"], 'web');

		$client_id = intval($data['old']['client_id']);
		if($client_id > 0) {

			$client_dir = $web_config['website_basedir'].'/clients/client'.$client_id;
			if(is_dir($client_dir) && !stristr($client_dir, '..')) {
				// remove symlinks from $client_dir
				$files = array_diff(scandir($client_dir), array('.', '..'));
				if(is_array($files) && !empty($files)){
					foreach($files as $file){
						if(is_link($client_dir.'/'.$file)){
							unlink($client_dir.'/'.$file);
							$app->log('Removed symlink: '.$client_dir.'/'.$file, LOGLEVEL_DEBUG);
						}
					}
				}

				@rmdir($client_dir);
				$app->log('Removed client directory: '.$client_dir, LOGLEVEL_DEBUG);
			}

			if($app->system->is_group('client'.$client_id)){
				$this->_exec('groupdel client'.$client_id);
				$app->log('Removed group client'.$client_id, LOGLEVEL_DEBUG);
			}
		}

	}

	//* Wrapper for exec function for easier debugging
	private function _exec($command) {
		global $app;
		$app->log('exec: '.$command, LOGLEVEL_DEBUG);
		exec($command);
	}

	private function _checkTcp ($host, $port) {

		$fp = @fsockopen($host, $port, $errno, $errstr, 2);

		if ($fp) {
			fclose($fp);
			return true;
		} else {
			return false;
		}
	}

	public function create_relative_link($f, $t) {
		global $app;

		// $from already exists
		$from = realpath($f);

		// realpath requires the traced file to exist - so, lets touch it first, then remove
		@$app->system->unlink($t); touch($t);
		$to = realpath($t);
		@$app->system->unlink($t);

		// Remove from the left side matching path elements from $from and $to
		// and get path elements counts
		$a1 = explode('/', $from); $a2 = explode('/', $to);
		for ($c = 0; $a1[$c] == $a2[$c]; $c++) {
			unset($a1[$c]); unset($a2[$c]);
		}
		$cfrom = implode('/', $a1);

		// Check if a path is fully a subpath of another - no way to create symlink in the case
		if (count($a1) == 0 || count($a2) == 0) return false;

		// Add ($cnt_to-1) number of "../" elements to left side of $cfrom
		for ($c = 0; $c < (count($a2)-1); $c++) { $cfrom = '../'.$cfrom; }

		return symlink($cfrom, $to);
	}

	private function _rewrite_quote($string) {
		return str_replace(array('.', '*', '?', '+'), array('\\.', '\\*', '\\?', '\\+'), $string);
	}

	private function _is_url($string) {
		return preg_match('/^(f|ht)tp(s)?:\/\//i', $string);
	}

	private function get_seo_redirects($web, $prefix = ''){
		$seo_redirects = array();

		if(substr($web['domain'], 0, 2) === '*.') $web['subdomain'] = '*';

		if($web['subdomain'] == 'www' || $web['subdomain'] == '*'){
			if($web['seo_redirect'] == 'non_www_to_www'){
				$seo_redirects[$prefix.'seo_redirect_origin_domain'] = str_replace('.', '\.', $web['domain']);
				$seo_redirects[$prefix.'seo_redirect_target_domain'] = 'www.'.$web['domain'];
				$seo_redirects[$prefix.'seo_redirect_operator'] = '';
			}
			if($web['seo_redirect'] == '*_domain_tld_to_www_domain_tld'){
				// ^(example\.com|(?!\bwww\b)\.example\.com)$
				// ^(example\.com|((?:\w+(?:-\w+)*\.)*)((?!www\.)\w+(?:-\w+)*)(\.example\.com))$
				$seo_redirects[$prefix.'seo_redirect_origin_domain'] = '('.str_replace('.', '\.', $web['domain']).'|((?:\w+(?:-\w+)*\.)*)((?!www\.)\w+(?:-\w+)*)(\.'.str_replace('.', '\.', $web['domain']).'))';
				$seo_redirects[$prefix.'seo_redirect_target_domain'] = 'www.'.$web['domain'];
				$seo_redirects[$prefix.'seo_redirect_operator'] = '';
			}
			if($web['seo_redirect'] == '*_to_www_domain_tld'){
				$seo_redirects[$prefix.'seo_redirect_origin_domain'] = 'www\.'.str_replace('.', '\.', $web['domain']);
				$seo_redirects[$prefix.'seo_redirect_target_domain'] = 'www.'.$web['domain'];
				$seo_redirects[$prefix.'seo_redirect_operator'] = '!';
			}
		}
		if($web['seo_redirect'] == 'www_to_non_www'){
			$seo_redirects[$prefix.'seo_redirect_origin_domain'] = 'www\.'.str_replace('.', '\.', $web['domain']);
			$seo_redirects[$prefix.'seo_redirect_target_domain'] = $web['domain'];
			$seo_redirects[$prefix.'seo_redirect_operator'] = '';
		}
		if($web['seo_redirect'] == '*_domain_tld_to_domain_tld'){
			// ^(.+)\.example\.com$
			$seo_redirects[$prefix.'seo_redirect_origin_domain'] = '(.+)\.'.str_replace('.', '\.', $web['domain']);
			$seo_redirects[$prefix.'seo_redirect_target_domain'] = $web['domain'];
			$seo_redirects[$prefix.'seo_redirect_operator'] = '';
		}
		if($web['seo_redirect'] == '*_to_domain_tld'){
			$seo_redirects[$prefix.'seo_redirect_origin_domain'] = str_replace('.', '\.', $web['domain']);
			$seo_redirects[$prefix.'seo_redirect_target_domain'] = $web['domain'];
			$seo_redirects[$prefix.'seo_redirect_operator'] = '!';
		}
		return $seo_redirects;
	}

} // end class

?>
