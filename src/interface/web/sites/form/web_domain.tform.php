<?php

/*
	Form Definition

	Tabledefinition

	Datatypes:
	- INTEGER (Forces the input to Int)
	- DOUBLE
	- CURRENCY (Formats the values to currency notation)
	- VARCHAR (no format check, maxlength: 255)
	- TEXT (no format check)
	- DATE (Dateformat, automatic conversion to timestamps)

	Formtype:
	- TEXT (Textfield)
	- TEXTAREA (Textarea)
	- PASSWORD (Password textfield, input is not shown when edited)
	- SELECT (Select option field)
	- RADIO
	- CHECKBOX
	- CHECKBOXARRAY
	- FILE

	VALUE:
	- Wert oder Array

	Hint:
	The ID field of the database table is not part of the datafield definition.
	The ID field must be always auto incement (int or bigint).

	Search:
	- searchable = 1 or searchable = 2 include the field in the search
	- searchable = 1: this field will be the title of the search result
	- searchable = 2: this field will be included in the description of the search result


*/

$form["title"]    = "Web Domain";
$form["description"]  = "";
$form["name"]    = "web_domain";
$form["action"]   = "web_domain_edit.php";
$form["db_table"]  = "web_domain";
$form["db_table_idx"] = "domain_id";
$form["db_history"]  = "yes";
$form["tab_default"] = "domain";
$form["list_default"] = "web_domain_list.php";
$form["auth"]   = 'yes'; // yes / no

$form["auth_preset"]["userid"]  = 0; // 0 = id of the user, > 0 id must match with id of current user
$form["auth_preset"]["groupid"] = 0; // 0 = default groupid of the user, > 0 id must match with groupid of current user
$form["auth_preset"]["perm_user"] = 'riud'; //r = read, i = insert, u = update, d = delete
$form["auth_preset"]["perm_group"] = 'riud'; //r = read, i = insert, u = update, d = delete
$form["auth_preset"]["perm_other"] = ''; //r = read, i = insert, u = update, d = delete

// Clients may not change the website basic settings if they are not resellers
if($app->auth->has_clients($_SESSION['s']['user']['userid']) || $app->auth->is_admin()) {
	$web_domain_edit_readonly = false;
} else {
	$web_domain_edit_readonly = true;
}

$wildcard_available = true;
$ssl_available = true;
if(!$app->auth->is_admin()) {
	$client_group_id = $_SESSION["s"]["user"]["default_group"];
	$client = $app->db->queryOneRecord("SELECT limit_wildcard, limit_ssl FROM sys_group, client WHERE sys_group.client_id = client.client_id and sys_group.groupid = $client_group_id");

	if($client['limit_wildcard'] != 'y') $wildcard_available = false;
	if($client['limit_ssl'] != 'y') $ssl_available = false;
}

$form["tabs"]['domain'] = array (
	'title'  => "Domain",
	'width'  => 100,
	'template'  => "templates/web_domain_edit.htm",
	'readonly' => $web_domain_edit_readonly,
	'fields'  => array (
		//#################################
		// Begin Datatable fields
		//#################################
		'server_id' => array (
			'datatype' => 'INTEGER',
			'formtype' => 'SELECT',
			'default' => '',
			'validators'    => array (  0 => array (    'type'  => 'NOTEMPTY',
					'errmsg'=> 'no_server_error'),
			),
			'datasource' => array (  'type' => 'SQL',
				'querystring' => 'SELECT server_id,server_name FROM server WHERE mirror_server_id = 0 AND web_server = 1 AND {AUTHSQL} ORDER BY server_name',
				'keyfield'=> 'server_id',
				'valuefield'=> 'server_name'
			),
			'value'  => ''
		),
		'ip_address' => array (
			'datatype' => 'VARCHAR',
			'formtype' => 'SELECT',
			'default' => '',
			/*'datasource'	=> array ( 	'type'	=> 'SQL',
										'querystring' => "SELECT ip_address,ip_address FROM server_ip WHERE ip_type = 'IPv4' AND {AUTHSQL} ORDER BY ip_address",
										'keyfield'=> 'ip_address',
										'valuefield'=> 'ip_address'
									 ),*/
			'value'  => '',
			'searchable' => 2
		),
		'ipv6_address' => array (
			'datatype' => 'VARCHAR',
			'formtype' => 'SELECT',
			'default' => '',
			/*'datasource'	=> array ( 	'type'	=> 'SQL',
										'querystring' => "SELECT ip_address,ip_address FROM server_ip WHERE ip_type = 'IPv6' AND {AUTHSQL} ORDER BY ip_address",
										'keyfield'=> 'ip_address',
										'valuefield'=> 'ip_address'
									 ),*/
			'value'  => '',
			'searchable' => 2
		),
		'domain' => array (
			'datatype' => 'VARCHAR',
			'formtype' => 'TEXT',
			'filters'   => array( 0 => array( 'event' => 'SAVE',
					'type' => 'IDNTOASCII'),
				1 => array( 'event' => 'SHOW',
					'type' => 'IDNTOUTF8'),
				2 => array( 'event' => 'SAVE',
					'type' => 'TOLOWER')
			),
			'validators'    => array (  0 => array (    'type'  => 'CUSTOM',
					'class' => 'validate_domain',
					'function' => 'web_domain',
					'errmsg'=> 'domain_error_regex'),
			),
			'default' => '',
			'value'  => '',
			'width'  => '30',
			'maxlength' => '255',
			'searchable' => 1
		),
		'type' => array (
			'datatype' => 'VARCHAR',
			'formtype' => 'SELECT',
			'default' => 'y',
			'value'  => array('vhost' => 'Site', 'alias' => 'Alias')
		),
		'parent_domain_id' => array (
			'datatype' => 'INTEGER',
			'formtype' => 'SELECT',
			'default' => '',
			'datasource' => array (  'type' => 'SQL',
				'querystring' => "SELECT domain_id,domain FROM web_domain WHERE type = 'site' AND {AUTHSQL} ORDER BY domain",
				'keyfield'=> 'domain_id',
				'valuefield'=> 'domain'
			),
			'value'  => ''
		),
		'vhost_type' => array (
			'datatype' => 'VARCHAR',
			'formtype' => 'SELECT',
			'default' => 'y',
			'value'  => array('name' => 'Namebased', 'ip' => 'IP-Based')
		),
		'hd_quota' => array (
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'validators' => array (  0 => array ( 'type' => 'NOTEMPTY',
					'errmsg'=> 'hd_quota_error_empty'),
				1 => array ( 'type' => 'REGEX',
					'regex' => '/^(\-1|[0-9]{1,10})$/',
					'errmsg'=> 'hd_quota_error_regex'),
			),
			'default' => '-1',
			'value'  => '',
			'width'  => '7',
			'maxlength' => '7'
		),
		'traffic_quota' => array (
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'validators' => array (  0 => array ( 'type' => 'NOTEMPTY',
					'errmsg'=> 'traffic_quota_error_empty'),
				1 => array ( 'type' => 'REGEX',
					'regex' => '/^(\-1|[0-9]{1,10})$/',
					'errmsg'=> 'traffic_quota_error_regex'),
			),
			'default' => '-1',
			'value'  => '',
			'width'  => '7',
			'maxlength' => '7'
		),
		'cgi' => array (
			'datatype' => 'VARCHAR',
			'formtype' => 'CHECKBOX',
			'default' => 'n',
			'value'  => array(0 => 'n', 1 => 'y')
		),
		'ssi' => array (
			'datatype' => 'VARCHAR',
			'formtype' => 'CHECKBOX',
			'default' => 'n',
			'value'  => array(0 => 'n', 1 => 'y')
		),
		'suexec' => array (
			'datatype' => 'VARCHAR',
			'formtype' => 'CHECKBOX',
			'default' => 'y',
			'value'  => array(0 => 'n', 1 => 'y')
		),
		'errordocs' => array (
			'datatype' => 'INTEGER',
			'formtype' => 'CHECKBOX',
			'default' => '1',
			'value'  => array(0 => '0', 1 => '1')
		),
		'subdomain' => array (
			'datatype' => 'VARCHAR',
			'formtype' => 'SELECT',
			'default' => 'www',
			'validators'    => array (  0 => array (    'type'  => 'CUSTOM',
					'class' => 'validate_domain',
					'function' => 'web_domain_autosub',
					'errmsg'=> 'domain_error_autosub'),
			),
			'value'  => ($wildcard_available ? array('none' => 'none_txt', 'www' => 'www.', '*' => '*.') : array('none' => 'none_txt', 'www' => 'www.'))
		),
		'ssl' => array (
			'datatype' => 'VARCHAR',
			'formtype' => 'CHECKBOX',
			'default' => 'n',
			'value'  => array(0 => 'n', 1 => 'y')
		),
		'ssl_letsencrypt' => array (
			'datatype' => 'VARCHAR',
			'formtype' => 'CHECKBOX',
			'default' => 'n',
			'value'  => array(0 => 'n', 1 => 'y')
		),
		'php' => array (
			'datatype' => 'VARCHAR',
			'formtype' => 'SELECT',
			'default' => 'fast-cgi',
			'valuelimit' => 'client:web_php_options',
			'value'  => array('no' => 'disabled_txt', 'fast-cgi' => 'Fast-CGI', 'cgi' => 'CGI', 'mod' => 'Mod-PHP', 'suphp' => 'SuPHP', 'php-fpm' => 'PHP-FPM'),
			'searchable' => 2
		),
		'fastcgi_php_version' => array (
			'datatype' => 'VARCHAR',
			'formtype' => 'SELECT',
			'default' => '',
			/*'datasource'	=> array ( 	'type'	=> 'SQL',
										'querystring' => "SELECT ip_address,ip_address FROM server_ip WHERE ip_type = 'IPv4' AND {AUTHSQL} ORDER BY ip_address",
										'keyfield'=> 'ip_address',
										'valuefield'=> 'ip_address'
									 ),*/
			'value'  => ''
		),
		'perl' => array (
			'datatype' => 'VARCHAR',
			'formtype' => 'CHECKBOX',
			'default' => 'n',
			'value'  => array(0 => 'n', 1 => 'y')
		),
		'ruby' => array (
			'datatype' => 'VARCHAR',
			'formtype' => 'CHECKBOX',
			'default' => 'n',
			'value'  => array(0 => 'n', 1 => 'y')
		),
		'python' => array (
			'datatype' => 'VARCHAR',
			'formtype' => 'CHECKBOX',
			'default' => 'n',
			'value'  => array(0 => 'n', 1 => 'y')
		),
		'active' => array (
			'datatype' => 'VARCHAR',
			'formtype' => 'CHECKBOX',
			'default' => 'y',
			'value'  => array(0 => 'n', 1 => 'y')
		),
		//#################################
		// ENDE Datatable fields
		//#################################
	)
);


$form["tabs"]['redirect'] = array (
	'title'  => "Redirect",
	'width'  => 100,
	'template'  => "templates/web_domain_redirect.htm",
	'readonly' => false,
	'fields'  => array (
		//#################################
		// Begin Datatable fields
		//#################################
		'redirect_type' => array (
			'datatype' => 'VARCHAR',
			'formtype' => 'SELECT',
			'default' => '',
			'value'  => array('' => 'no_redirect_txt', 'no' => 'no_flag_txt', 'R' => 'R', 'L' => 'L', 'R,L' => 'R,L', 'R=301,L' => 'R=301,L', 'last' => 'last', 'break' => 'break', 'redirect' => 'redirect', 'permanent' => 'permanent', 'proxy' => 'proxy')
		),
		'redirect_path' => array (
			'datatype' => 'VARCHAR',
			'validators' => array (  0 => array ( 'type' => 'REGEX',
					'regex' => '@^(([\.]{0})|((ftp|https?)://([-\w\.]+)+(:\d+)?(/([\w/_\.\,\-\+\?\~!:%]*(\?\S+)?)?)?)|(\[scheme\]://([-\w\.]+)+(:\d+)?(/([\w/_\.\-\,\+\?\~!:%]*(\?\S+)?)?)?)|(/(?!.*\.\.)[\w/_\.\-]{1,255}/))$@',
					'errmsg'=> 'redirect_error_regex'),
			),
			'formtype' => 'TEXT',
			'default' => '',
			'value'  => '',
			'width'  => '30',
			'maxlength' => '255'
		),
		'seo_redirect' => array (
			'datatype' => 'VARCHAR',
			'formtype' => 'SELECT',
			'default' => '',
			'value'  => array('' => 'no_redirect_txt', 'non_www_to_www' => 'domain.tld => www.domain.tld', 'www_to_non_www' => 'www.domain.tld => domain.tld', '*_domain_tld_to_domain_tld' => '*.doman.tld => domain.tld', '*_domain_tld_to_www_domain_tld' => '*.domain.tld => www.domain.tld', '*_to_domain_tld' => '* => domain.tld', '*_to_www_domain_tld' => '* => www.domain.tld')
		),
		'rewrite_rules' => array (
			'datatype' => 'TEXT',
			'formtype' => 'TEXT',
			'default' => '',
			'value'  => '',
			'width'  => '30',
			'maxlength' => '255'
		),
		//#################################
		// ENDE Datatable fields
		//#################################
	)
);

if($ssl_available) {
	$form["tabs"]['ssl'] = array (
		'title'  => "SSL",
		'width'  => 100,
		'template'  => "templates/web_domain_ssl.htm",
		'readonly' => false,
		'fields'  => array (
			//#################################
			// Begin Datatable fields
			//#################################
			'ssl_state' => array (
				'datatype' => 'VARCHAR',
				'formtype' => 'TEXT',
				'validators' => array (  0 => array ( 'type' => 'REGEX',
						'regex' => '/^(([\.]{0})|([-a-zA-Z0-9._,&äöüÄÖÜ ]{1,255}))$/',
						'errmsg'=> 'ssl_state_error_regex'),
				),
				'default' => '',
				'value'  => '',
				'width'  => '30',
				'maxlength' => '255'
			),
			'ssl_locality' => array (
				'datatype' => 'VARCHAR',
				'formtype' => 'TEXT',
				'validators' => array (  0 => array ( 'type' => 'REGEX',
						'regex' => '/^(([\.]{0})|([-a-zA-Z0-9._,&äöüÄÖÜ ]{1,255}))$/',
						'errmsg'=> 'ssl_locality_error_regex'),
				),
				'default' => '',
				'value'  => '',
				'width'  => '30',
				'maxlength' => '255'
			),
			'ssl_organisation' => array (
				'datatype' => 'VARCHAR',
				'formtype' => 'TEXT',
				'validators' => array (  0 => array ( 'type' => 'REGEX',
						'regex' => '/^(([\.]{0})|([-a-zA-Z0-9._,&äöüÄÖÜ ]{1,255}))$/',
						'errmsg'=> 'ssl_organisation_error_regex'),
				),
				'default' => '',
				'value'  => '',
				'width'  => '30',
				'maxlength' => '255'
			),
			'ssl_organisation_unit' => array (
				'datatype' => 'VARCHAR',
				'formtype' => 'TEXT',
				'validators' => array (  0 => array ( 'type' => 'REGEX',
						'regex' => '/^(([\.]{0})|([-a-zA-Z0-9._,&äöüÄÖÜ ]{1,255}))$/',
						'errmsg'=> 'ssl_organistaion_unit_error_regex'),
				),
				'default' => '',
				'value'  => '',
				'width'  => '30',
				'maxlength' => '255'
			),
			/*
		'ssl_country' => array (
			'datatype'	=> 'VARCHAR',
			'formtype'	=> 'TEXT',
			'validators'	=> array ( 	0 => array (	'type'	=> 'REGEX',
														'regex' => '/^(([\.]{0})|([A-Z]{2,2}))$/',
														'errmsg'=> 'ssl_country_error_regex'),
									),
			'default'	=> '',
			'value'		=> '',
			'width'		=> '2',
			'maxlength'	=> '2'
		),
		*/
			'ssl_country' => array (
				'datatype' => 'VARCHAR',
				'formtype' => 'SELECT',
				'default' => '',
				'datasource' => array (  'type' => 'SQL',
					'querystring' => 'SELECT iso,printable_name FROM country ORDER BY printable_name',
					'keyfield'=> 'iso',
					'valuefield'=> 'printable_name'
				),
				'value'  => ''
			),
			'ssl_domain' => array (
				'datatype' => 'VARCHAR',
				'formtype' => 'TEXT',
				'default' => '',
				'value'  => '',
				'width'  => '30',
				'maxlength' => '255'
			),
			'ssl_key' => array (
				'datatype' => 'TEXT',
				'formtype' => 'TEXTAREA',
				'default' => '',
				'value'  => '',
				'cols'  => '30',
				'rows'  => '10'
			),
			'ssl_request' => array (
				'datatype' => 'TEXT',
				'formtype' => 'TEXTAREA',
				'default' => '',
				'value'  => '',
				'cols'  => '30',
				'rows'  => '10'
			),
			'ssl_cert' => array (
				'datatype' => 'TEXT',
				'formtype' => 'TEXTAREA',
				'default' => '',
				'value'  => '',
				'cols'  => '30',
				'rows'  => '10'
			),
			'ssl_bundle' => array (
				'datatype' => 'TEXT',
				'formtype' => 'TEXTAREA',
				'default' => '',
				'value'  => '',
				'cols'  => '30',
				'rows'  => '10'
			),
			'ssl_action' => array (
				'datatype' => 'VARCHAR',
				'formtype' => 'SELECT',
				'default' => '',
				'value'  => array('' => 'none_txt', 'save' => 'save_certificate_txt', 'create' => 'create_certificate_txt', 'del' => 'delete_certificate_txt')
			),
			//#################################
			// ENDE Datatable fields
			//#################################
		)
	);
}

//* Statistics
$form["tabs"]['stats'] = array (
	'title'  => "Stats",
	'width'  => 100,
	'template'  => "templates/web_domain_stats.htm",
	'readonly' => false,
	'fields'  => array (
		//#################################
		// Begin Datatable fields
		//#################################
		'stats_password' => array (
			'datatype' => 'VARCHAR',
			'formtype' => 'PASSWORD',
			'validators' => array(
				0 => array(
					'type' => 'CUSTOM',
					'class' => 'validate_password',
					'function' => 'password_check',
					'errmsg' => 'weak_password_txt'
				)
			),
			'encryption' => 'CRYPT',
			'default' => '',
			'value'  => '',
			'width'  => '30',
			'maxlength' => '255'
		),
		'stats_type' => array (
			'datatype' => 'VARCHAR',
			'formtype' => 'SELECT',
			'default' => 'webalizer',
			'value'  => array('webalizer' => 'Webalizer', 'awstats' => 'AWStats', '' => 'None')
		),
		//#################################
		// ENDE Datatable fields
		//#################################
	)
);

// if($_SESSION["s"]["user"]["typ"] == 'admin') {

//* Backup
$form["tabs"]['backup'] = array (
	'title'  => "Backup",
	'width'  => 100,
	'template'  => "templates/web_domain_backup.htm",
	'readonly' => false,
	'fields'  => array (
		//#################################
		// Begin Datatable fields
		//#################################
		'backup_interval' => array (
			'datatype' => 'VARCHAR',
			'formtype' => 'SELECT',
			'default' => '',
			'value'  => array('none' => 'no_backup_txt', 'daily' => 'daily_backup_txt', 'weekly' => 'weekly_backup_txt', 'monthly' => 'monthly_backup_txt')
		),
		'backup_copies' => array (
			'datatype' => 'INTEGER',
			'formtype' => 'SELECT',
			'default' => '',
			'value'  => array('1' => '1', '2' => '2', '3' => '3', '4' => '4', '5' => '5', '6' => '6', '7' => '7', '8' => '8', '9' => '9', '10' => '10')
		),
		'backup_excludes' => array (
			'datatype' => 'VARCHAR',
			'validators' => array (  0 => array ( 'type' => 'REGEX',
					'regex' => '@^(?!.*\.\.)[-a-zA-Z0-9_/.~,*]*$@',
					'errmsg'=> 'backup_excludes_error_regex'),
			),
			'formtype' => 'TEXT',
			'default' => '',
			'value'  => '',
			'width'  => '30',
			'maxlength' => '255'
		),
		//#################################
		// ENDE Datatable fields
		//#################################
	),
	'plugins' => array (
		'backup_records' => array (
			'class'   => 'plugin_backuplist',
			'options' => array(
			)
		)
	)
);

// }

if($_SESSION["s"]["user"]["typ"] == 'admin') {

	$form["tabs"]['advanced'] = array (
		'title'  => "Options",
		'width'  => 100,
		'template'  => "templates/web_domain_advanced.htm",
		'readonly' => false,
		'fields'  => array (
			//#################################
			// Begin Datatable fields
			//#################################
			'document_root' => array (
				'datatype' => 'VARCHAR',
				'formtype' => 'TEXT',
				'validators' => array (  0 => array ( 'type' => 'NOTEMPTY',
						'errmsg'=> 'documentroot_error_empty'),
				),
				'default' => '',
				'value'  => '',
				'width'  => '30',
				'maxlength' => '255'
			),
			'system_user' => array (
				'datatype' => 'VARCHAR',
				'formtype' => 'TEXT',
				'validators' => array (  0 => array ( 'type' => 'NOTEMPTY',
						'errmsg'=> 'sysuser_error_empty'),
						1 => array(
							'type' => 'CUSTOM',
							'class' => 'validate_systemuser',
							'function' => 'check_sysuser',
							'check_names' => true,
							'errmsg' => 'invalid_system_user_or_group_txt'
						),
				),
				'default' => '',
				'value'  => '',
				'width'  => '30',
				'maxlength' => '255'
			),
			'system_group' => array (
				'datatype' => 'VARCHAR',
				'formtype' => 'TEXT',
				'validators' => array (  0 => array ( 'type' => 'NOTEMPTY',
						'errmsg'=> 'sysgroup_error_empty'),
						1 => array(
							'type' => 'CUSTOM',
							'class' => 'validate_systemuser',
							'function' => 'check_sysgroup',
							'check_names' => true,
							'errmsg' => 'invalid_system_user_or_group_txt'
						),
				),
				'default' => '',
				'value'  => '',
				'width'  => '30',
				'maxlength' => '255'
			),
			'allow_override' => array (
				'datatype' => 'VARCHAR',
				'formtype' => 'TEXT',
				'validators' => array (  0 => array ( 'type' => 'NOTEMPTY',
						'errmsg'=> 'allow_override_error_empty'),
				),
				'default' => 'All',
				'value'  => '',
				'width'  => '30',
				'maxlength' => '255'
			),
			'php_fpm_use_socket' => array (
				'datatype' => 'VARCHAR',
				'formtype' => 'CHECKBOX',
				'default' => 'n',
				'value'  => array(0 => 'n', 1 => 'y')
			),
			'pm' => array (
				'datatype' => 'VARCHAR',
				'formtype' => 'SELECT',
				'default' => 'dynamic',
				'value'  => array('static' => 'static', 'dynamic' => 'dynamic', 'ondemand' => 'ondemand (PHP Version >= 5.3.9)')
			),
			'pm_max_children' => array (
				'datatype' => 'INTEGER',
				'formtype' => 'TEXT',
				'validators' => array (  0 => array ( 'type' => 'REGEX',
						'regex' => '/^([1-9][0-9]{0,10})$/',
						'errmsg'=> 'pm_max_children_error_regex'),
				),
				'default' => '10',
				'value'  => '',
				'width'  => '3',
				'maxlength' => '3'
			),
			'pm_start_servers' => array (
				'datatype' => 'INTEGER',
				'formtype' => 'TEXT',
				'validators' => array (  0 => array ( 'type' => 'REGEX',
						'regex' => '/^([1-9][0-9]{0,10})$/',
						'errmsg'=> 'pm_start_servers_error_regex'),
				),
				'default' => '2',
				'value'  => '',
				'width'  => '3',
				'maxlength' => '3'
			),
			'pm_min_spare_servers' => array (
				'datatype' => 'INTEGER',
				'formtype' => 'TEXT',
				'validators' => array (  0 => array ( 'type' => 'REGEX',
						'regex' => '/^([1-9][0-9]{0,10})$/',
						'errmsg'=> 'pm_min_spare_servers_error_regex'),
				),
				'default' => '1',
				'value'  => '',
				'width'  => '3',
				'maxlength' => '3'
			),
			'pm_max_spare_servers' => array (
				'datatype' => 'INTEGER',
				'formtype' => 'TEXT',
				'validators' => array (  0 => array ( 'type' => 'REGEX',
						'regex' => '/^([1-9][0-9]{0,10})$/',
						'errmsg'=> 'pm_max_spare_servers_error_regex'),
				),
				'default' => '5',
				'value'  => '',
				'width'  => '3',
				'maxlength' => '3'
			),
			'pm_process_idle_timeout' => array (
				'datatype' => 'INTEGER',
				'formtype' => 'TEXT',
				'validators' => array (  0 => array ( 'type' => 'REGEX',
						'regex' => '/^([1-9][0-9]{0,10})$/',
						'errmsg'=> 'pm_process_idle_timeout_error_regex'),
				),
				'default' => '10',
				'value'  => '',
				'width'  => '3',
				'maxlength' => '6'
			),
			'pm_max_requests' => array (
				'datatype' => 'INTEGER',
				'formtype' => 'TEXT',
				'validators' => array (  0 => array ( 'type' => 'REGEX',
						'regex' => '/^([0-9]{1,11})$/',
						'errmsg'=> 'pm_max_requests_error_regex'),
				),
				'default' => '0',
				'value'  => '',
				'width'  => '3',
				'maxlength' => '6'
			),
			'php_open_basedir' => array (
				'datatype' => 'VARCHAR',
				'formtype' => 'TEXT',
				/*'validators'	=> array ( 	0 => array (	'type'	=> 'NOTEMPTY',
														'errmsg'=> 'php_open_basedir_error_empty'),
									),   */
				'default' => 'All',
				'value'  => '',
				'width'  => '30',
				'maxlength' => '255'
			),
			'custom_php_ini' => array (
				'datatype' => 'TEXT',
				'formtype' => 'TEXT',
				'default' => '',
				'value'  => '',
				'width'  => '30',
				'maxlength' => '255'
			),
			'apache_directives' => array (
				'datatype' => 'TEXT',
				'formtype' => 'TEXT',
				'validators' => array (  0 => array(
							'type' => 'CUSTOM',
							'class' => 'validate_domain',
							'function' => 'web_apache_directives',
							'errmsg' => 'apache_directive_blockd_error'
						),
				),
				'default' => '',
				'value'  => '',
				'width'  => '30',
				'maxlength' => '255'
			),
			'nginx_directives' => array (
				'datatype' => 'TEXT',
				'formtype' => 'TEXT',
				'default' => '',
				'value'  => '',
				'width'  => '30',
				'maxlength' => '255'
			),
			'proxy_directives' => array (
				'datatype' => 'TEXT',
				'formtype' => 'TEXT',
				'default' => '',
				'value'  => '',
				'width'  => '30',
				'maxlength' => '255'
			),
			'added_date' => array (
				'datatype'	=> 'DATE',
				'formtype'	=> 'TEXT',
				'default'	=> date($app->lng('conf_format_dateshort')),
				'value'		=> '',
				'separator'	=> '',
				'width'		=> '15',
				'maxlength'	=> '15',
				'rows'		=> '',
				'cols'		=> ''
			),
			'added_by' => array (
				'datatype' => 'VARCHAR',
				'formtype' => 'TEXT',
				'default' => $_SESSION['s']['user']['username'],
				'value'  => '',
				'separator' => '',
				'width'  => '30',
				'maxlength' => '255',
				'rows'  => '',
				'cols'  => ''
			),
			//#################################
			// ENDE Datatable fields
			//#################################
		)
	);

}


?>
