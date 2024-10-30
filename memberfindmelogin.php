<?php
/*
Plugin Name: MembershipWorks Login Connector
Plugin URI: https://membershipworks.com
Description: Provides single sign-on to WordPress for MembershipWorks membership system
Version: 6.4
Author: MembershipWorks
Author URI: https://membershipworks.com
License: GPL2
*/

/*  Copyright 2013-2023  SOURCEFOUND INC.  (email : info@sourcefound.com)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License, version 2, as 
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

define('SF_WPL',6);

$SF_widget_login='<div class="login-form">'
	.'<p class="login-username"><label style="display:block">'.__('Email').'</label><input type="text" name="log" class="input" size="20" onkeyup="if(event.keyCode==13)sf_wpl(this.parentNode.parentNode);"></p>'
	.'<p class="login-password"><label style="display:block">'.__('Password').'</label><input type="password" name="pwd" class="input" size="20" onkeyup="if(event.keyCode==13)sf_wpl(this.parentNode.parentNode);"></p>'
	.'<p class="login-submit">'
		.'<input type="submit" class="button-primary" style="margin-right:10px" value="'.__('Sign In').'" onclick="sf_wpl(this.parentNode.parentNode);return false;">'
		.'<a style="white-space:nowrap" onclick="this.parentNode.style.display=this.parentNode.parentNode.querySelector(\'.login-password\').style.display=\'none\';this.parentNode.parentNode.querySelector(\'.login-request\').style.display=\'\';">Forgot password?</a>'
	.'</p>'
	.'<p class="login-request" style="display:none">'
		.'<input type="submit" class="button-primary" value="'.__('Email Password').'" onclick="sf_wpl(this.parentNode.parentNode,\'pwd\');return false;">'
	.'</p>'
.'</div>'
.'<div style="display:none">'
	.'<p class="login-message">-</p>'
	.'<p class="login-ack"><input type="submit" class="button-primary" value="'.__('Continue').'" onclick="var n=this.parentNode.parentNode;n.style.display=\'none\';n=n.parentNode.querySelector(\'.login-form\');n.style.display=\'\';n.querySelector(\'.login-password\').style.display=n.querySelector(\'.login-submit\').style.display=\'\';n.querySelector(\'.login-request\').style.display=\'none\';return false;"></p>'
.'</div>'
.'<script>function sf_wpl(n,act,uid){var a,i,log=false,pwd=false,red=false,xml,f=n.parentNode.querySelector(".login-form"),m=n.parentNode.querySelector(".login-message");'
	.'for(a=n.parentNode.querySelectorAll("input"),i=0;i<a.length;i++)if(a[i].name){if(a[i].name=="log")log=encodeURIComponent(a[i].value);else if(a[i].name=="pwd"){if(act)a[i].value="";else pwd=encodeURIComponent(a[i].value);}else if (a[i].name=="red")red=a[i].value;}'
	.'if(!log){f.querySelector(\'input[name=log]\').focus();return false;}'
	.'if(!act&&f.querySelector(\'.login-submit\').style.display)act=\'pwd\';'
	.'if(!(act||pwd)){f.querySelector(\'input[name=pwd]\').focus();return false;}'
	.'f.style.display=m.parentNode.querySelector(".login-ack").style.display="none";'
	.'m.parentNode.style.display="";'
	.'m.innerHTML="Please wait...";'
	.'xml=new XMLHttpRequest();'
	.'xml.open("POST","'.str_replace(array('http://','https://'),'//',esc_url(admin_url('admin-ajax.php'))).'",true);'
	.'xml.setRequestHeader("Content-type","application/x-www-form-urlencoded");'
	.'xml.onreadystatechange=function(){if(this.readyState==4){'
		.'if(this.status==200){'
			.'if(this.responseText==="OK"){'
				.'if(act){'
					.'m.innerHTML="Your password has been emailed to you! Please check your spam folder too in case the email lands there.";'
				.'}else{'
					.'if(red)location=red;else location.reload();return;'
				.'}'
			.'}else{'
				.'m.innerHTML=this.responseText;'
			.'}'
			.'m.parentNode.querySelector(".login-ack").style.display="";'
		.'}else{alert("Login system error");}'
	.'}};'
	.'i=String.fromCharCode(38);'
	.'if(act)xml.send("action=sf_password"+i+"user_login="+log+(uid?(i+"uid="+uid):""));'
	.'else xml.send("action=sf_login"+i+"log="+log+i+"pwd="+pwd);'
	.'return false;'
.'}</script>';

if (is_admin()) {
	if (!empty($_REQUEST['action'])&&$_REQUEST['action']=='sf_password')
		add_action('wp_ajax_nopriv_sf_password','sf_password');
	if (!empty($_REQUEST['action'])&&$_REQUEST['action']=='sf_login')
		add_action('wp_ajax_nopriv_sf_login','sf_login');
	if (!empty($_REQUEST['action'])&&$_REQUEST['action']=='sf_logout')
		add_action('wp_ajax_sf_logout','sf_logout');
}

function sf_mfl_init() {
	global $current_user;
	if (defined('DOING_AJAX')&&defined('WP_ADMIN')&&!empty($_REQUEST['action']))
		return;
	$user=wp_get_current_user();
	if ($user->exists()) {
		if (empty($_COOKIE['SFSF'])&&($uid=get_user_meta(get_current_user_id(),'SF_ID',true))&&wp_get_current_user()->user_login==$uid) {
			wp_destroy_current_session();
			wp_clear_auth_cookie();
			wp_set_current_user(0);
		}
	} else {
		if (!empty($_COOKIE['SFSF'])) {
			sf_mfl_clear_auth_cookie();
		}
	}
}
add_action('init','sf_mfl_init');

function sf_mfl_clear_auth_cookie() {
	if (defined('SF_WPL_LOGOUT'))
		return;
	if (empty($_COOKIE['SFSF']))
		return;
	setcookie('SFSF','',time()+8640000,'/');
	$_COOKIE['SFSF']='';
}
add_action('clear_auth_cookie','sf_mfl_clear_auth_cookie');

function sf_mfl_nocache_headers($headers) {
	$headers['Cache-Control']='no-cache, must-revalidate, max-age=0, no-store';
	return $headers;
}
add_filter('nocache_headers','sf_mfl_nocache_headers');

function sf_wpl_deactivate() {
	$set=get_option('sf_set');
	if (!empty($set)&&!empty($set['wpl']))
		update_option('sf_set',array_diff_key($set,array('wpl'=>1)));
}
register_deactivation_hook(__FILE__,'sf_wpl_deactivate');

class sf_widget_login extends WP_Widget {
	public function __construct() {
		parent::__construct('sf_widget_login','MembershipWorks Login',array('description'=>'Login/logout to WordPress and MembershipWorks'));
	}
	public function widget($args,$instance) {
		global $current_user,$SF_widget_login;
		extract($args);
		$id=str_replace('-','_',$this->id);
		$title=apply_filters('widget_title',$instance['title']);
		if (empty($title))
			echo str_replace('widget_sf_widget_login','widget_sf_widget_login widget_no_title',$before_widget);
		else
			echo $before_widget;
		if (!empty($title))
			echo $before_title.$title.$after_title;
		if (is_user_logged_in()) {
			$set=get_option('sf_set');
			$uid=get_user_meta(get_current_user_id(),'SF_ID',true);
			echo '<p style="margin-top:0">'.__('Hello').' '.$current_user->display_name.'!</p>'
				.'<input type="submit" class="button-primary" onclick="sf_wpl();return false;" value="Logout"/>'
				.'<script>function sf_wpl(){var xml=new XMLHttpRequest();'
					.'xml.open("POST","'.esc_url(str_replace(array('http://','https://'),'//',admin_url('admin-ajax.php'))).'",true);'
					.'xml.setRequestHeader("Content-type","application/x-www-form-urlencoded");'
					.'xml.onreadystatechange=function(){if(this.readyState==4){location="'.(empty($set['out'])?get_site_url():$set['out']).'";}};'
					.'xml.send("action=sf_logout");'
					.'return false;'
				.'}</script>';
		} else {
			if (!empty($instance['url']))
				echo '<input type="hidden" name="red" value="'.esc_url($instance['url']).'">';
			echo $SF_widget_login;
		}
		echo $after_widget;
	}
	public function update($new_instance,$old_instance ) {
		$instance=$old_instance;
		$instance['title']=strip_tags($new_instance['title']);
		$instance['url']=trim($new_instance['url']);
		return $instance;
	}
	public function form($instance) {
		$instance=wp_parse_args($instance,array('title'=>'','url'=>''));
		echo '<p><label for="'.$this->get_field_id('title').'">Title:</label><input class="widefat" id="'.$this->get_field_id('title').'" name="'.$this->get_field_name('title').'" type="text" value="'.esc_attr($instance['title']).'" /></p>'
			.'<p><label for="'.$this->get_field_id('url').'">Redirect URL:</label><input class="widefat" id="'.$this->get_field_id('url').'" name="'.$this->get_field_name('url').'" type="text" value="'.esc_attr($instance['url']).'" placeholder="empty=current page" /></p>';
	}
}
function sf_widget_login_init() {
	register_widget('sf_widget_login');
}
add_action('widgets_init','sf_widget_login_init');

function sf_login() {
	$act=isset($_REQUEST['action'])?$_REQUEST['action']:'login';
	$msg=false;
	if (!defined('SF_WPL')||defined('SF_WPL_LOGIN')||empty($_POST['log'])||!strpos($_POST['log'],'@')||empty($_POST['pwd'])) {
		// do nothing
	} else if (($id=username_exists(sanitize_user($_POST['log'])))&&!get_user_meta($id,'SF_ID',true)) {
		// do standard WP login
	} else if (($set=get_option('sf_set'))&&!empty($set['org'])) {
		define('SF_WPL_LOGIN',true);
		$user_login=$_POST['log'];
		$user_password=$_POST['pwd'];
		for($try=0;$try<3;$try++) {
			$rsp=wp_remote_post((empty($set['ssl'])||$set['ssl']!='2'?'https':'http').'://api.membershipworks.com/v1/usr',array('method'=>'POST','headers'=>array('from'=>isset($_SERVER['HTTP_X_FORWARDED_FOR'])?$_SERVER['HTTP_X_FORWARDED_FOR']:$_SERVER['REMOTE_ADDR']),'user-agent'=>$_SERVER['HTTP_USER_AGENT'],'body'=>array('org'=>$set['org'],'eml'=>$user_login,'pwd'=>$user_password)));
			if (is_wp_error($rsp)) usleep(100000); else break;
		}
		if (is_wp_error($rsp)) {
			$msg=implode(', ',$rsp->get_error_messages());
		} else if (empty($rsp['response'])) {
			$msg='Network error, please try again later';
		} else if ($rsp['response']['code']!=200||empty($rsp['body'])) {
			$msg='Server error, please try again later';
		} else if (($rsp=json_decode($rsp['body'],true))&&!empty($rsp['uid'])) {
			$nam=empty($rsp['nam'])?(empty($rsp['ctc'])?(empty($rsp['biz'])?'':$rsp['biz']):$rsp['ctc']):$rsp['nam'];
			$doc=array('nickname'=>$nam,'user_nicename'=>$nam,'display_name'=>$nam);
			if (isset($rsp['url'])) $doc['user_url']=$rsp['url'];
			$id=username_exists($rsp['uid']);
			add_filter('send_email_change_email','__return_false');
			add_filter('send_password_change_email','__return_false');
			if (is_null($id)||$id===false) {
				$id=wp_create_user($rsp['uid'],$user_password,$user_login);
				if (is_wp_error($id)&&$id->get_error_code()=='existing_user_email')
					$id=wp_create_user($rsp['uid'],$user_password);
				$doc['show_admin_bar_front']='false';
			} else {
				wp_update_user(array('ID'=>$id,'user_email'=>$user_login)); // update email separately
				wp_set_password($user_password,$id); // update password separately
			}
			if (!is_null($id)&&$id!==false&&!is_wp_error($id)) {
				$doc['ID']=$id;
				wp_update_user($doc); // update names separately
				update_user_meta($id,'SF_ID',$rsp['uid']);
				setcookie('SFSF',rawurlencode($rsp['SF']),time()+8640000,'/');
				if ($act=='sf_login') {
					$user=wp_signon(array('user_login'=>$rsp['uid'],'user_password'=>$user_password,'remember'=>true),force_ssl_admin()||!empty($_SERVER['HTTPS'])?true:false);
					$msg=is_wp_error($user)?('Could not synchronize login '.$user->get_error_message()):'OK';
				} else {
					$_POST['log']=$rsp['uid'];
					$_POST['pwd']=$user_password;
				}
			} else if ($act=='sf_login') {
				$msg='Could not create WP user';
			}
		} else if ($act=='sf_login') {
			$msg=!empty($rsp)&&!empty($rsp['error'])?$rsp['error']:'Email not found or invalid password';
		}
	}
	if ($act=='sf_login'&&empty($msg))
		$msg='Invalid request';
	if (!empty($msg)) {
		if (ob_get_contents()) ob_clean();
		echo $msg;
		wp_die();
	}
}
add_action('login_form_login','sf_login');

function sf_authenticate(&$user_login,&$user_password) {
	if (!defined('SF_WPL')||defined('SF_WPL_LOGIN')||empty($user_login)||!strpos($user_login,'@')||empty($user_password)) {
		// do nothing
	} else if (($id=username_exists(sanitize_user($user_login)))&&!get_user_meta($id,'SF_ID',true)) {
		// do standard WP login
	} else if (($set=get_option('sf_set'))&&!empty($set['org'])) {
		define('SF_WPL_LOGIN',true);
		for($try=0;$try<3;$try++) {
			$rsp=wp_remote_post((empty($set['ssl'])||$set['ssl']!='2'?'https':'http').'://api.membershipworks.com/v1/usr',array('method'=>'POST','headers'=>array('from'=>isset($_SERVER['HTTP_X_FORWARDED_FOR'])?$_SERVER['HTTP_X_FORWARDED_FOR']:$_SERVER['REMOTE_ADDR']),'user-agent'=>$_SERVER['HTTP_USER_AGENT'],'body'=>array('org'=>$set['org'],'eml'=>$user_login,'pwd'=>$user_password)));
			if (is_wp_error($rsp)) usleep(100000); else break;
		}
		if (!is_wp_error($rsp)&&($rsp=json_decode($rsp['body'],true))&&!empty($rsp['uid'])) {
			$nam=empty($rsp['nam'])?(empty($rsp['ctc'])?(empty($rsp['biz'])?'':$rsp['biz']):$rsp['ctc']):$rsp['nam'];
			$doc=array('nickname'=>$nam,'user_nicename'=>$nam,'display_name'=>$nam);
			if (isset($rsp['url'])) $doc['user_url']=$rsp['url'];
			$id=username_exists($rsp['uid']);
			if (is_null($id)||$id===false) {
				$id=wp_create_user($rsp['uid'],$user_password,$user_login);
				if (is_wp_error($id)&&$id->get_error_code()=='existing_user_email')
					$id=wp_create_user($rsp['uid'],$user_password);
				$doc['show_admin_bar_front']='false';
			} else {
				wp_update_user(array('ID'=>$id,'user_email'=>$user_login)); // update email separately
				wp_set_password($user_password,$id); // update password separately
			}
			if (!is_null($id)&&$id!==false&&!is_wp_error($id)) {
				$doc['ID']=$id;
				wp_update_user($doc); // update names separately
				update_user_meta($id,'SF_ID',$rsp['uid']);
				setcookie('SFSF',rawurlencode($rsp['SF']),time()+8640000,'/');
				$user_login=$rsp['uid'];
			}
		}
	}
}
add_action('wp_authenticate','sf_authenticate',1,2);

function sf_logout() {
	if (defined('SF_WPL_LOGOUT'))
		return;
	if (($set=get_option('sf_set'))&&!empty($set['org'])&&defined('SF_WPL')&&isset($_COOKIE['SFSF'])) {
		define('SF_WPL_LOGOUT',true);
		setcookie('SFSF','',time()+8640000,'/');
		if (isset($_REQUEST['action'])&&$_REQUEST['action']=='sf_logout') {
			wp_logout();
			if (ob_get_contents()) ob_clean();
			echo 'OK';
			wp_die();
		}
	}
}
add_action('login_form_logout','sf_logout');
add_action('wp_logout','sf_logout');

function sf_password() {
	$act=isset($_REQUEST['action'])?$_REQUEST['action']:'password';
	$msg=false;
	$id=empty($_POST['user_login'])?false:username_exists(sanitize_user($_POST['user_login']));
	if ($id!==false&&get_user_meta($id,'SF_ID',true))
		$id=false;
	if ($act!='sf_password'&&$id!==false)
		return; // do standard WP password reset
	if (!empty($_POST['user_login'])&&strpos($_POST['user_login'],'@')&&($set=get_option('sf_set'))&&!empty($set['org'])&&defined('SF_WPL')) {
		$qry=array('Z'=>time(),'org'=>$set['org'],'pwd'=>'','eml'=>$_POST['user_login']);
		if (!empty($_POST['uid'])) $qry['uid']=$_POST['uid'];
		for($try=0;$try<3;$try++) {
			$rsp=wp_remote_get((empty($set['ssl'])||$set['ssl']!='2'?'https':'http').'://api.membershipworks.com/v1/usr?'.http_build_query($qry),array('headers'=>array('from'=>isset($_SERVER['HTTP_X_FORWARDED_FOR'])?$_SERVER['HTTP_X_FORWARDED_FOR']:$_SERVER['REMOTE_ADDR']),'user-agent'=>$_SERVER['HTTP_USER_AGENT']));
			if (is_wp_error($rsp)) usleep(100000); else break;
		}
		if (is_wp_error($rsp)) {
			if ($act=='sf_password')
				$msg=$rsp->get_error_message();
		} else if (empty($rsp['body'])) {
			if ($act=='sf_password') {
				$msg='OK';
			} else {
				wp_safe_redirect(empty($_REQUEST['redirect_to'])?'wp-login.php?checkemail=confirm':$_REQUEST['redirect_to']);
				die();
			}
		} else if (($rsp=json_decode($rsp['body'],true))&&!empty($rsp['error'])) {
			if ($act=='sf_password'&&$id!==false)
				$msg='Password for this account cannot be reset through this widget';
			else
				$msg=$rsp['error'];
		} else if (isset($rsp[0])) { // multiple options
			if ($act=='sf_password') {
				$msg='<p>Select the account you are requesting the password for:</p>';
				foreach ($rsp as $usr) {
					$msg.='<p><a style="cursor:pointer" onclick="sf_wpl(this.parentNode.parentNode.parentNode,\'pwd\',\''.esc_attr($usr['_id']).'\')">'.(empty($usr['ctc'])?$usr['nam']:($usr['ctc'].' ('.$usr['nam'].')')).'</a></p>';
				}
			} else {
				$msg='<html><head></head><body style="background:#f1f1f1"><div style="margin:auto;padding:8% 0 0;width:320px"><p style="padding:20px 0;text-align:center;background:#fff;border:1px solid #ddd;border-left:4px solid #7AD03A">Select the account you are requesting the password for</p><div style="background:#fff;padding:10px 0;border:1p solid #ddd">';
				foreach ($rsp as $usr) {
					$msg.='<form action="'.esc_url(site_url('wp-login.php')).'" method="post" style="margin:0">'
						.'<input type="hidden" name="action" value="'.esc_attr($_REQUEST['action']).'">'
						.'<input type="hidden" name="redirect_to" value="'.esc_attr($_REQUEST['redirect_to']).'">'
						.'<input type="hidden" name="user_login" value="'.esc_attr($_POST['user_login']).'">'
						.'<input type="hidden" name="uid" value="'.esc_attr($usr['_id']).'">'
						.'<input type="submit" value="'.esc_attr(empty($usr['ctc'])?$usr['nam']:($usr['ctc'].' ('.$usr['nam'].')')).'" class="hvr" style="cursor:pointer;display:block;border:none;padding:10px 0;margin:0;width:100%">'
						.'</form>';
				}
				$msg.='</div></div><style>.hvr{background:transparent}.hvr:hover{background:#0074a2;color:#fff}</style></body></html>';
			}
		}
	}
	if ($act=='sf_password'&&empty($msg))
		$msg='Invalid request';
	if (!empty($msg)) {
		if (ob_get_contents()) ob_clean();
		echo $msg;
		die();
	}
}
add_action('login_form_lostpassword','sf_password');
add_action('login_form_retrievepassword','sf_password');

function sf_get_avatar($avatar,$id_or_email,$size,$default,$alt) {
	if (!is_numeric($size)) $size='96';
	if (is_numeric($id_or_email))
		$uid=get_user_meta(intval($id_or_email),'SF_ID',true);
	elseif (is_object($id_or_email)&&!empty($id_or_email->user_id))
		$uid=get_user_meta(intval($id_or_email->user_id),'SF_ID',true);
	if (isset($uid)&&$uid)
		return '<img alt="'.($alt?esc_attr($alt):'').'" onerror="this.src=\'//cdn.membershipworks.com/u/n_ico.jpg\'" src="//cdn.membershipworks.com/u/'.$uid.'_ico.jpg" class="avatar avatar-'.$size.' photo" height="'.$size.'" width="'.$size.'" />';
	else
		return $avatar;
}
add_filter('get_avatar','sf_get_avatar',99,5);

?>