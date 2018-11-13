# username.github.io
<?php
/*
 * 京推推CMS导购核心接口文件
 *
 * @file        京推推CMS导购客户端
 * @package     core
*/

// 推荐使用 notepad++ 修改本文件

// 站点的appid （请勿修改）
$appid = '15212';

// 站点的appkey（请勿修改）
$appkey = 'd3ebb2574b38ddabcb14c96213309ba4';

// 当前客户端版本
$version = '1.0.6';

// 文件编码
header("Content-type:text/html;charset=utf-8");

$server = "";
if(is_SSL()){
	$server =  'https://capi.jingtuitui.com/';
}else{
	$server =  'http://capi.jingtuitui.com/';
}
$website = './';
$basedir = str_replace( '\\', '/', dirname($_SERVER['SCRIPT_NAME']) );

if( !is_readable( $website ) && !is_writable( $website ) && !is_executable( $website ) ){
    echo "请检查目录权限";
    exit;
}

$requestMethod = strtoupper(@$_SERVER["REQUEST_METHOD"]);

if( empty( $_REQUEST['r'] ) && empty( $_REQUEST['tasks'] ) ){
	$requestUrl = '';
}else{
	$requestUrl = str_replace('r=','', @$_SERVER["QUERY_STRING"] );
}

$cache = new CacheHelper();
$tasks = isset( $_REQUEST['tasks'] ) ? $_REQUEST['tasks'] : NULL;
$words = isset( $_REQUEST['secret'] ) ? $_REQUEST['secret'] : NULL;

if( $tasks == 'clean' ){
	$cache->clean();
    exit( 'succeed' );
}

if( $tasks == 'version' ){
    exit( $version );
}

if( $tasks == 'system' && $appkey == $words ){
	phpinfo();
    exit;
}

if( $tasks == 'update' && $appkey == $words ){
	$detail = isset( $_POST['detail'] ) ? $_POST['detail'] : NULL;
	$detail && file_put_contents('index.php', $detail);
    exit;
}

if( preg_match('/item\/(\w+)/i', $requestUrl, $match) && ( !is_numeric($match[1]) || strlen($match[1]) > 6 ) ){
    exit( 'invalid' );
}

if( preg_match('/search\/\?kw=(.*)/i', $requestUrl, $match) && !preg_match('/^[\+\?=&%a-zA-Z0-9]+$/', $match[1]) ){
    exit( 'special' );
}

$ref = @$_SERVER['HTTP_REFERER'];
if( preg_match('/search\//i', $requestUrl, $match) && $ref && strpos( $ref, $_SERVER['HTTP_HOST'] ) === FALSE ) {
	exit( 'referer' );
}

$key = md5($requestUrl . CacheHelper::isMobile() . CacheHelper::isIPad() . CacheHelper::isIPhone() . CacheHelper::isMicroMessenger() . $_SERVER['HTTP_HOST']);
if ($requestMethod == 'GET') {
    $cacheData = $cache->Get($key);

    if ($cacheData !== false) {
        echo $cacheData;
        exit;
    }
}

$documentUrl = @$_SERVER["PHP_SELF"];

$httpHelper = new HttpHelper($appid, $appkey, $version, $documentUrl);
$html = $httpHelper->getHtml($server, $requestUrl, $requestMethod == 'POST' ? @$_POST : array(), $requestMethod);
if( $path = preg_match("/^(\w+)/i", $requestUrl, $matches) ){
	$html = preg_replace('/<a(.+?)href="\?/','<a$1href="?r='.$matches[0].'/?',$html);
}else{
	$html = preg_replace('/<a(.+?)href="\?/','<a$1href="?r=?',$html);
}
$html = preg_replace('/action="\//','action="/?r=',$html);
$html = preg_replace('/<a(.+?)href="\//','<a$1href="/?r=',$html);


if ($requestMethod == 'GET' && !empty($html)) {
    $cache->Set($key, $html, 300);
}
echo $html;

function is_SSL(){
	if(!isset($_SERVER['HTTPS']))
		return FALSE;
	if($_SERVER['HTTPS']==1){  //Apache
		return TRUE;
	}elseif($_SERVER['HTTPS']=='on'){ //IIS
		return TRUE;
	}elseif($_SERVER['SERVER_PORT']==443){ //其他
		return TRUE;
	}
	return FALSE;

}

class HttpHelper{
    protected $appid;
    protected $key;
    protected $documentUrl;

    public function __construct($appid, $key, $version, $documentUrl){
        $this->appid = $appid;
        $this->key = $key;
        $this->version = $version;
        $this->documentUrl = $documentUrl;
    }

    /**
     * @param $url
     * @param $requestUrl
     * @param array $param
     * @param string $method
     * @param bool $isAjax
     * @param string $cookie
     * @param string $refer
     * @param null $userAgent
     * @return string
     */
    public function getHtml($url, $requestUrl, $param = array(), $method = 'GET', $isAjax = null, $cookie = NULL, $refer = null, $userAgent = null){
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_HEADER, 1);
        empty($refer) && $refer = @$_SERVER['HTTP_REFERER'];
        $ua = $userAgent;
        empty($ua) && $ua = @$_SERVER['HTTP_USER_AGENT'];
        curl_setopt($ch, CURLOPT_TIMEOUT, 20);
        curl_setopt($ch, CURLOPT_USERAGENT, $ua);
        curl_setopt($ch, CURLOPT_REFERER, $refer);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 0);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

        $header = array(
            'APPID: ' . $this->appid,
            'APPKEY: ' . $this->key,
            'VERSION: ' . $this->version,
            'CMS-HOST: ' . @$_SERVER["HTTP_HOST"],
            'DOCUMENT-URL: ' . $this->documentUrl,
            'REQUEST-URL: ' . $requestUrl,
        );
        $url = $url . $requestUrl;

        $_isAjax = false;
        if ($isAjax) {
            $_isAjax = true;
        }
        if (!$_isAjax && $isAjax === null) {
            $_isAjax = $this->getIsAjaxRequest();
        }
        if ($_isAjax) {
            $header[] = 'X_REQUESTED_WITH: XMLHttpRequest';
        }
        $clientIp = $this->get_real_ip();
        if (!empty($clientIp)) {
            $header[] = 'CLIENT-IP: ' . $clientIp;
            $header[] = 'X-FORWARDED-FOR: ' . $clientIp;
        }

        curl_setopt($ch, CURLOPT_HTTPHEADER, $header);

        if (empty($cookie)) {
            $cookie = $_COOKIE;
        }
        if (is_array($cookie)) {
            $str = '';
            foreach ($cookie as $k => $v) {
                $str .= $k . '=' . $v . '; ';
            }
            $cookie = $str;
        }
        if (!empty($cookie)) {
            curl_setopt($ch, CURLOPT_COOKIE, $cookie);
        }
        if (strtolower($method) == 'post') {
            curl_setopt($ch, CURLOPT_POST, TRUE);
            if ($param) {
                curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($param));
            }
            curl_setopt($ch, CURLOPT_URL, $url);
        } else {
            curl_setopt($ch, CURLOPT_HTTPGET, TRUE);
            if ($param) {
                $urlInfo = parse_url($url);
                $q = array();
                if (isset($urlInfo['query']) && !empty($urlInfo['query'])) {
                    parse_str($urlInfo['query'], $q);
                }
                $q = array_merge($q, $param);
                $cUrl = sprintf('%s://%s%s%s%s',
                    $urlInfo['scheme'],
                    $urlInfo['host'],
                    isset($urlInfo['port']) ? ':' . $urlInfo['port'] : '',
                    isset($urlInfo['path']) ? $urlInfo['path'] : '',
                    count($q) ? '?' . http_build_query($q) : '');
                curl_setopt($ch, CURLOPT_URL, $cUrl);
            } else {
                curl_setopt($ch, CURLOPT_URL, $url);
            }
        }

        $r = curl_exec($ch);
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $header = mb_substr($r, 0, $headerSize);
        $r = mb_substr($r, $headerSize);
        curl_close( $ch );
        unset($ch);

        $headers = explode("\r\n", $header);
        foreach ($headers as $h) {
            $h = trim($h);
            if (empty($h) || preg_match('/^(HTTP|Connection|EagleId|Server|X\-Powered\-By|Date|Transfer\-Encoding|Content)/i', $h)) {
                continue;
            }
            header($h);
        }
        return $r;
    }

    function get_real_ip(){
        if (@$_SERVER["HTTP_X_FORWARDED_FOR"]) {
            $ip = @$_SERVER["HTTP_X_FORWARDED_FOR"];
        } elseif (@$_SERVER["HTTP_CLIENT_IP"]) {
            $ip = @$_SERVER["HTTP_CLIENT_IP"];
        } elseif (@$_SERVER["REMOTE_ADDR"]) {
            $ip = @$_SERVER["REMOTE_ADDR"];
        } elseif (getenv("HTTP_X_FORWARDED_FOR")) {
            $ip = getenv("HTTP_X_FORWARDED_FOR");
        } elseif (getenv("HTTP_CLIENT_IP")) {
            $ip = getenv("HTTP_CLIENT_IP");
        } elseif (getenv("REMOTE_ADDR")) {
            $ip = getenv("REMOTE_ADDR");
        } else {
            $ip = "";
        }
        return $ip;
    }

    public function getIsAjaxRequest(){
        return isset($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH'] === 'XMLHttpRequest';
    }
}

class CacheHelper{

    protected $dir = '';

    public function __construct(){
        $this->dir = dirname(__FILE__) . DIRECTORY_SEPARATOR . 'cache';
        if (is_dir($this->dir)) {
            return;
        }
        @mkdir($this->dir);
    }

    public function Set($key, $value, $expire = 360){
        $data = array(
            'time' => time(),
            'expire' => $expire,
            'value' => $value
        );
        @file_put_contents($this->dir . DIRECTORY_SEPARATOR . md5($key) . 'cache', serialize($data));
    }

    public function Get($key){
        $file = $this->dir . DIRECTORY_SEPARATOR . md5($key) . 'cache';
        if (!file_exists($file)) {
            return false;
        }
        $str = @file_get_contents($file);
        if (empty($str)) {
            return false;
        }
        $data = @unserialize($str);
        if (!isset($data['time']) || !isset($data['expire']) || !isset($data['value'])) {
            return false;
        }
        if ($data['time'] + $data['expire'] < time()) {
            return false;
        }
        return $data['value'];
    }

    static function isMobile(){
        $ua = @$_SERVER['HTTP_USER_AGENT'];
        return preg_match('/(iphone|android|Windows\sPhone)/i', $ua);
    }

    public function clean(){
        if (!empty($this->dir) && is_dir($this->dir)) {
            @rmdir($this->dir);
        }
        $files = scandir($this->dir);
        foreach ($files as $file) {
            @unlink($this->dir . DIRECTORY_SEPARATOR . $file);
        }
    }


    static function isMicroMessenger(){
        $ua = @$_SERVER['HTTP_USER_
