<?php
/*
* Plugin Name: Security Assassin
* Plugin URI: http://yur4enko.com/category/moi-proekty/security-assassin
* Description: It protects against third-party access the file system on your site and/or hide your site from users who did not login
* Version: 1.1.4
* Author: Evgen Yurchenko
* Text Domain: security-assassin
* Domain Path: /languages/
* Author URI: http://yur4enko.com/
*/

/*  Copyright 2015 Evgen Yurchenko  (email: evgen@yur4enko.com)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc.
*/

//wp=>2.8.0(3.6.0) php=>5.2.4
class wp_sac {  
    //НОВОЕ ЯДРО
    //ФУНКЦИИ КЛАССА
    
    //Защита от созадния класса
    private function __construct() { //wp=>0.0.0 php=>5.2.4
        return NULL;
    }

    //защита от клона
    private function __clone() { //wp=>0.0.0 php=>5.2.4
        return NULL;
    }
    
    //защита от клона
    private function __wakeup() {//wp=>0.0.0 php=>5.2.4
        return NULL;
    }
    
    //КОНЕЦ ФУНКЦИИ КЛАССА
    
    //ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
    //Валидация версии
    private static function is_version_valid($vers,$what='wp') {//wp=>0.0.0 php=>5.2.4
        if ($what == 'wp'){
            return version_compare(get_bloginfo('version'), $vers,'>=');
        } elseif ($what == 'php'){
            return version_compare(phpversion(), $vers,'>=');
        }
    }
    
    //Валидация системы
    private static function is_system_ready(){//wp=>0.0.0 php=>5.2.4
        $return = TRUE;
        if (!wp_sac::is_version_valid('2.8') || !wp_sac::is_version_valid('5.2.4','php')) {
            $return = FALSE;
        }
        return $return;
    }
    
    //Получаем ссылки на файлы системы
    private static function getsystemdirs($param) {//wp=>2.6.0 php=>5.2.4
        $dirs = array();
        $site = get_option('home');
        $ret = '';
        if ($param == 'content') {
            $ret = str_replace($site.'/', '', content_url().'/');
        }
        if ($param == 'admin') {
            $ret = str_replace($site.'/', '', admin_url());
        }
        if ($param == 'includes') {
            $ret = str_replace($site.'/', '', includes_url());
        }
        if ($param == 'prefix') {
            $files = get_option('siteurl');
            $tmp = str_replace($site, '', $files);
            $ret = ($tmp == '')?'':substr($tmp, 1).'/';
        }
        return $ret;
    }    
    
    //Получаем уровень доступа пользователя
    private static function get_user_level(){//wp=>2.0.3 php=>5.2.4
        $user = wp_get_current_user();
        return $user->user_level;
    }
    
    //Проставляем галочки в чебоксах
    private static function checket($value){//wp=>0.0.0 php=>5.2.4
        return (empty($value))?'':' checked';
    }
    //КОНЕЦ ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
    
    //РАБОТА С HTACCESS
    //Получаем путь к файлу htaccess
    private static function gethtaccessfile(){//wp=>0.71 php=>5.3.0
        $pref = wp_sac::getsystemdirs('prefix');
        $path = empty($pref)?ABSPATH:substr(ABSPATH, 0, -strlen($pref));
        return $path.'.htaccess';
    }
    
    //получаем чистый список правил
    private static function getcleancont() {//wp=>0.0.0 php=>5.2.4
        $f = fopen(wp_sac::gethtaccessfile(), 'r');
        $p = '';
        $isit = FALSE;
        if ($f) {
            while (($str = fgets($f)) !== FALSE) {
                if (stristr($str, '#Security Assassin START')) {
                    $isit = TRUE;
                }
                if (!$isit) {
                    $p .= $str;
                }
                if (stristr($str, '#Security Assassin END')) {
                    $isit = FALSE;
                }
            }
        }
        fclose($f);
        return $p;
    }
    
    //Обновляем htaccess
    private static function updatethaccess($text = FALSE) {//wp=>0.0.0 php=>5.2.4
        file_put_contents(wp_sac::gethtaccessfile(), 
                          ($text === FALSE)?wp_sac::genRules().wp_sac::getcleancont():$text);
    }
    //КОНЕЦ РАБОТА С HTACCESS
    
    //ФУНКЦИИ ЯДРА
    //**ЗАЩИЩЕННЫЕ**
    //Поучаем занчение настройки
    private static function getset($name,$def=NULL){//wp=>1.5.0 php=>5.2.4
        $settings = get_option('WPA_set');
        if (gettype($settings) != 'array'){
            $settings = array();
        }
        return (array_key_exists($name,$settings))?$settings[$name]:$def; 
    }
    
    //получаем текст правил htaccess
    private static function genRules() { //wp=>0.0.0 php=>5.2.4    
        //Начало текста
        $ret = "#Security Assassin START \n";
        $ret .= "RewriteEngine On \n";
        //Обработка исключений
        $exceptions = wp_sac::getset('exceptions',array());
        foreach ($exceptions as $value) {
            if (!empty($value)){
                if ($value[0] != '/') {
                    $value = '/'.$value;
                }
                $ret .= 'RewriteCond %{REQUEST_URI} !^' . $value . "$ [NC] \n";
            }
        }
        //системные папки
        $link = wp_sac::getset('link');
        $systemprotect = wp_sac::getset('sysdirprotect');
        $r['content'] = 'RewriteCond %{REQUEST_URI} ^/' .wp_sac::getsystemdirs('content')."(.*).php$ [NC,OR] \n";
        $r['includes'] = 'RewriteCond %{REQUEST_URI} ^/' . wp_sac::getsystemdirs('includes')."(.*).php$ [NC,OR] \n";
        $r['admin'] = 'RewriteCond %{REQUEST_URI} ^/' . wp_sac::getsystemdirs('admin')."(.*)/(.*).php$ [NC,OR] \n";
        if (empty($systemprotect)) {
            $systemprotect = array();
        }
        
        if (array_key_exists('includes', $systemprotect)){
            $ret .= 'RewriteCond %{REQUEST_URI} !^/'. wp_sac::getsystemdirs('includes')."js/tinymce/wp-tinymce.php$ [NC] \n";
        }
        foreach ($systemprotect as $key => $value) {
            if (!empty($value)) {
                $ret .= $r[$key];
            }
        }
        
        //Пользовательские директории
        $userrules =  wp_sac::getset('userrules');
        if (!is_array($userrules)) {
            $userrules = array();
        }
        foreach ($userrules as $value) {
            if (!empty($value)){
                if ($value[0] != '/') {
                    $value = '/'.$value;
                }
                $ret .= 'RewriteCond %{REQUEST_URI} ^'.$value."/(.*).php$ [NC,OR] \n";
            }
        }
        
        //XML-RPC
        $xmlrpc = wp_sac::getset('xmlrpc');
        if (!empty($xmlrpc)){
            $ret .= 'RewriteCond %{REQUEST_URI} ^/'.wp_sac::getsystemdirs('prefix')."xmlrpc.php$ [NC,OR] \n";
        }
        
        if (substr($ret, -6) == ",OR] \n") {
            $ret = substr($ret, 0, -6)."] \n"; 
        } 
        if (substr($ret, -4) != "On \n") {
            $ret .= "RewriteRule ^(.*)$ ".$link." [R=301,L] \n";
        }
        //Конец файла
        $ret .= "#Security Assassin END \n";
        return $ret;
    }
    
    //Валидация htaccess
    private static function htaccesswrong() {//wp=>0.0.0 php=>5.2.4
        $f = fopen(wp_sac::gethtaccessfile(), 'r');
        $temp = '';
        $rules = wp_sac::genRules();
        $arrayofrules = explode("\n", $rules);
        $i = 0;
        $isit = FALSE;
        if ($f){
            while (($str = fgets($f)) !== FALSE) {
                If (trim($str) == '#Security Assassin START') {
                    $isit = TRUE;
                }
                if ($isit) {
                    if (trim($str) == trim($arrayofrules[$i])) {
                        if (trim($str) == '#Security Assassin END') {
                            fclose($f);
                            return FALSE;
                        }
                    } else {
                        fclose($f);
                        return TRUE;
                    }
                    $i++;
                }
            }
        }
        return TRUE;
    }
    
    private static function do_setting ($activetab) {//wp=>1.0.0 php=>5.2.4
        $setting = get_option('WPA_set');
        if ($activetab == 'files') {
            $inp['content'] = filter_input(INPUT_POST, 'r1');
            $inp['includes'] = filter_input(INPUT_POST, 'r2');
            $inp['admin'] = filter_input(INPUT_POST, 'r3');
            $setting['sysdirprotect'] = $inp;
            $setting['xmlrpc'] = filter_input(INPUT_POST, 'xmlrpc');
            
            $setting['link'] = filter_input(INPUT_POST, 'link');

            $exceptions = filter_input(INPUT_POST, 'exceptions');
            $arrayofexceptions = explode("\n", $exceptions);
            $setting['exceptions'] = $arrayofexceptions;

            $userrules = filter_input(INPUT_POST, 'userrules');
            $arrayofuserrules = explode("\n", $userrules);
            $setting['userrules'] = $arrayofuserrules;
        } elseif ($activetab == 'user') {
            $setting['hideguest'] = filter_input(INPUT_POST, 'hide');
            $setting['min_user_level'] = filter_input(INPUT_POST, 'min_user_level');
            $setting['block_user_link'] = filter_input(INPUT_POST, 'block_user_link');
        } elseif ($activetab == 'bonus') {
            $setting['newear'] = filter_input(INPUT_POST, 'newear');
        }
        update_option('WPA_set', $setting);
        wp_sac::updatethaccess();
    }

        //**ОТКРЫТЫЕ**
    //инициализация языка
    static function initlang(){//wp=>2.7.0 php=>5.2.4
        load_plugin_textdomain('security-assassin', false, dirname(plugin_basename(__FILE__)).'/languages');
    }
    
    //Блокировка доступа не залогиненным пользователям
    static function hide_guest(){//wp=>2.7.0(3.6.0) php=>5.2.4
        global $wpdb; //подгружаем глобальную базу данных
        
        $set = wp_sac::getset('hideguest');
        if (!empty($set)) {
            $redirect_link = '';
            $block_user_link = wp_sac::getset('block_user_link');
            $thispage = get_option('home').filter_input(INPUT_SERVER, 'REQUEST_URI');
            if (is_user_logged_in()) {
                $min_user_level = wp_sac::getset('min_user_level');
                $curent_user_level = wp_sac::get_user_level();
                if ($curent_user_level<$min_user_level){
                    $redirect_link = (empty($block_user_link))?wp_login_url($thispage):$block_user_link;
                } 
            } else {
                $redirect_link = wp_login_url($thispage);
            }
            if (!empty($redirect_link)) {
                $urlparam = filter_input(INPUT_SERVER, 'QUERY_STRING');
                if (empty($urlparam)){
                    $urlparam = wp_login_url();
                } else {
                    $urlparam = wp_login_url().'?'.$urlparam;
                }
                //Создаем список исключений
                //страница авторизации
                $allowurlarray[] = $urlparam;
                //страница регистрации
                if (self::is_version_valid('3.6')){
                    $allowurlarray[] = wp_registration_url(); 
                }
                //страница для залогиненных но не разрешеных
                if (!empty($block_user_link)){
                    $allowurlarray[] = get_option('home').$block_user_link;
                }
                //Страницы активации
                if (!in_array($thispage, $allowurlarray)){
                    //Проверяем может этот пользователь пытается активироваться
                    //Получаем ключи активации
                    $activate_keys = $wpdb->get_results("SELECT activation_key FROM ".$wpdb->prefix."signups WHERE active=0");
                    if ($activate_keys != NULL) {//проверяем если ли желающие активироваться
                        //Проверяем если закрывающий слеш
                        $corection = (substr($thispage, -1) == '/')?-1:0;
                        foreach ($activate_keys as $value) {
                            if ($value->activation_key == substr($thispage, -strlen($value->activation_key)-1,$corection)){
                                return;//подтверждаем пользователь пытается активироваться
                            }
                        }
                    }
                    wp_redirect($redirect_link);
                    exit;
                }
            }
        }
    }
    
    //Добавление пункта меню
    static function add_menu(){//wp=>1.5.0 php=>5.2.4
        add_options_page('Security Assassin', 'Security Assassin', 'activate_plugins', __FILE__, array('wp_sac','main_settings'));
    }
    
    //форма настроек
    static function main_settings() {//wp=>1.5.0 php=>5.3.0
        $tmp = filter_input(INPUT_POST, 'apply');
        $activetab = filter_input(INPUT_GET, 'tab');
        $activetab = (empty($activetab))?'files':$activetab;
        if (!empty($tmp)) {
            wp_sac::do_setting($activetab);
        }
        
        $hideguest = wp_sac::getset('hideguest');
        $newear = wp_sac::getset('newear');
        $n = wp_sac::getset('sysdirprotect');
        $link = wp_sac::getset('link','http://localhost');
        if (!isset($userrules)){
            $userrules = '';
            $arrayofuserrules = wp_sac::getset('userrules',array());
            $i = 0;
            foreach ($arrayofuserrules as $value) {
                $i++;
                $userrules .=($i==1)?"".$value:"\n".$value;                
            }
        }
        if (!isset($exceptions)){
            $exceptions = '';
            $arrayofexceptions = wp_sac::getset('exceptions',array());
            $i = 0;
            foreach ($arrayofexceptions as $value) {
                $i++;
                $exceptions .=($i==1)?"".$value:"\n".$value;                
            }
        }
        //даные для шаблона
        $min_user_level = wp_sac::getset('min_user_level');
        $textnovalid = (wp_sac::is_version_valid('3.6'))?'':__(' (in wordpress to 3.6 may not be stable)','security-assassin');
        $block_user_link = wp_sac::getset('block_user_link');        
        $n_content = wp_sac::checket($n['content']);
        $n_includes = wp_sac::checket($n['includes']);
        $n_admin = wp_sac::checket($n['admin']);
        $hideguest = wp_sac::checket($hideguest);
        $newear = wp_sac::checket($newear);
        $xmlrpc = wp_sac::checket(wp_sac::getset('xmlrpc'));
        $t1 = __('Security Assassin protected directory:','security-assassin');
        $t2 = __('User directorys:','security-assassin');
        $t3 = __('* to specify the path to the folder on the root of the site','security-assassin');
        $t4 = __('Example : wp-content/cache','security-assassin');
        $t5 = __('Exception files:','security-assassin');
        $t6 = __('Forward to :','security-assassin');
        $t7 = __('Hide site for guest','security-assassin');
        $t8 = __('Minimal user_level for view','security-assassin');
        $t9 = __('close to: 0 - accessible to all , 1 - subscribers, 2 - and contributor , 3 - and authors , 8 - and editors , 10 - only available Super User','security-assassin');
        $t10 = __('Link for blocked users','security-assassin');
        $t11 = __('Turn Christmas mood','security-assassin');
        $t12 = __('Apply','security-assassin');
        $t13 = __('*specify the path from the root site','security-assassin');
        $t14 = __('Close XML-RPC','security-assassin');
        //Создаем табы меню
        $tabs = array(
            array('url'=>add_query_arg(array('tab'=>'files')),
                'label'=>__('File system','security-assassin'),
                'get'=>'files'),
            array('url'=>add_query_arg(array('tab'=>'user')),
                'label'=>__('Users settings','security-assassin'),
                'get'=>'user'),
            array('url'=>add_query_arg(array('tab'=>'bonus')),
                'label'=>__('Additional features','security-assassin'),
                'get'=>'bnus')
        );        
        //подгружаем шаблон
        include __DIR__.'/template/admin.html';
    }
    
    //Предупреждения в админ панели
    static function notification() {//wp=>2.6.0 php=>5.2.4
        $tmp = filter_input(INPUT_POST, 'apply');
        if (!empty($tmp)) {
            return;
        }
        if (wp_sac::htaccesswrong()){
            echo '<div class="error"><a href="'
                .admin_url('options-general.php?page=security-assassin%2Fsecurity-assassin.php').
                '">'.__('Need update setting','security-assassin').'</a></div>';
        }
    }
    
    //Включаем новогоднее настроение
    static function newear(){//wp=>2.6.0 php=>5.2.4
        $set = get_option('WPA_set');
        if (!empty($set['newear'])) {
            wp_enqueue_script('snow.js',plugins_url( '/js/snow.js', __FILE__ ));
        }
    }
    
    //Управление оперциями над плагином
    static function edit_actions_links($links,$file){//wp=>2.6.0 php=>5.2.4
        if ($file == 'security-assassin/security-assassin.php'){
            $addlink['settings'] = '<a href="' . admin_url( 'options-general.php?page=security-assassin%2Fsecurity-assassin.php' ) . '">'.__('Settings','security-assassin').'</a>';
            $links = $addlink + $links;
        }
        return $links;
    }
    
    //Предупреждение о отключении плагина
    static function notification_no_valid_system() {//wp=>0.0. php=>5.2.4
        echo '<div class="error"><b>' . __('Security Assassin was disabled!!', 'security-assassin') . '</b></br>' .
            __('For use Security Assassin you need a WordPress 2.8 or higher and php 5.2.4 or higher', 'security-assassin') .'</div>';
        return;
    }

    //КОНЕЦ ФУНКЦИИ ЯДРА
      
    //РАБОЧИЕ ФУНКЦИИ
    //Активация 
    static function activations() {//wp=>2.8.0 php=>5.2.4 (5.2.4)
        if (wp_sac::is_system_ready()){
            //Легкий переход от wp assassin к security assassin
            $patch = 'wp-assassin/wp-assassin.php';
            if (is_plugin_active($patch)){
                $deactivate_this = array($patch);
                $active_plugins = array_diff(get_option('active_plugins'), $deactivate_this);
                update_option('active_plugins', $active_plugins);
                $patch = substr(plugin_dir_path(__FILE__),0,-18).'/wp-assassin';
                unlink($patch.'/readme.txt');
                unlink($patch.'/wp-assassin.php');
                rmdir($patch);
                wp_sac::updatethaccess(wp_sac::getcleancont('#WP-Assassin'));
            }
        }
        
        if (!get_option('WPA_set')) {//затычка для совместимости до 3.1
            add_option('WPA_set', array());
            wp_sac::updatethaccess();
        }
    }
    
    //Деактивация плагина
    static function deactivations() {//wp=>0.0.0 php=>5.2.4
        wp_sac::updatethaccess(wp_sac::getcleancont());
    }
    
    //Чистка при удалении
    static function wpadelete(){//wp=>1.2.0 php=>5.2.4
        wp_sac::updatethaccess(wp_sac::getcleancont());
        delete_option('WPA_set');
    }
    
    //Проверка соответсвия системы и загрузка ядра
    static function letsstart() {//wp=>2.8.0 php=>5.2.4
        if (wp_sac::is_system_ready()){ //Все ок работаем
            //Языковая поддержка
            add_action('init', array('wp_sac', 'initlang'));
            //Прячем сайт от гостей
            add_action('init', array('wp_sac', 'hide_guest'));
            //Админ меню
            add_action('admin_menu', array('wp_sac', 'add_menu'));
            //Предупреждения в админ меню
            add_action('admin_notices', array('wp_sac', 'notification'));
            //Новогоднее настроение
            add_action('wp_enqueue_scripts', array('wp_sac', 'newear'));
            //Управление оперциями над плагином
            add_filter('plugin_action_links', array('wp_sac', 'edit_actions_links'), 10, 4);
        } else {
            //Деактивируем плагин и выводим предупреждение о несоответсвии системы
            add_action('admin_notices', array('wp_sac', 'notification_no_valid_system'));
            $patch = 'security-assassin/security-assassin.php';
            $deactivate_this = array($patch);
            $active_plugins = array_diff(get_option('active_plugins'), $deactivate_this);
            update_option('active_plugins', $active_plugins);
        }
    }
}

//wp=>2.7.0 php=>5.2.4
//Активация
register_activation_hook( __FILE__,array('wp_sac','activations'));
//Деактивация
register_deactivation_hook( __FILE__,array('wp_sac','deactivations')); 
//Удаление
register_uninstall_hook(__FILE__,array('wp_sac','wpadelete'));
//Проверка соответсвия системы и загрузка ядра
add_action('plugins_loaded',array('wp_sac','letsstart'));