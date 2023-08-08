<?
$_SERVER["DOCUMENT_ROOT"] = realpath(dirname(__FILE__)."/../../..");

define("NO_KEEP_STATISTIC", true);
define("NOT_CHECK_PERMISSIONS",true);
define("BX_CRONTAB", true);
define("BX_NO_ACCELERATOR_RESET", true);

$cliParams = getopt(null, ["monitorio-key:"]);

require($_SERVER["DOCUMENT_ROOT"]."/bitrix/modules/main/include/prolog_before.php");

use \Bitrix\Main\Web\HttpClient;

if (function_exists('mb_internal_encoding'))
    mb_internal_encoding('ISO-8859-1');

CModule::IncludeModule('bitrix.xscan');

set_time_limit(0);

ini_set('memory_limit', '10000M');

$progress = 0;
$total = 0;
$inprogress = False;

$start_path = $_SERVER['DOCUMENT_ROOT'];
$start_path = rtrim($start_path, '/');

$scaner = new CBitrixXscan($progress, $total);

var_dump($scaner->doc_root);

$scaner->scan_log =  $scaner->doc_root. '/bitrix/modules/bitrix.xscan/file_list_cli.txt';
$scaner->start_time = PHP_INT_MAX;

file_put_contents($scaner->scan_log, '');
file_put_contents($scaner->doc_root. '/bitrix/modules/bitrix.xscan/file_list.txt', '');

$scaner->clean(); // new scan
$scaner->CheckEvents();
$scaner->CheckAgents();
$scaner->Count_total($start_path);
$scaner->Search($start_path);


// Обработка исключений:
// file_list_cli.ignore
// И результативный список с учетом исключений записать в file_list.txt
$ignorelist = implode(" #### ", file(__DIR__ . '/file_list_ignore.txt'));
//var_dump($ignorelist);
//file
$productionLog = str_replace(basename($scaner->scan_log), "file_list.txt", $scaner->scan_log);
file_put_contents($productionLog, "");
$fp = @fopen($scaner->scan_log, "r");
if ($fp) {
    while (($row = fgets($fp)) !== false) {
        $row = trim($row);
        //var_dump($row);
        // preg_match("#$row#ium", $ignorelist)
        if (stripos($ignorelist, $row)===false) {
            echo "[LISTED] ".$row."\n";
            file_put_contents($productionLog, $row."\n", FILE_APPEND);
        }
        else {
            echo "[IGNORED] ".$row."\n";
        }
    }
    fclose($fp);
}

if (filesize($productionLog)>0 && !empty($cliParams['monitorio-key'])) {
    $httpClient = new HttpClient();
    
    $httpClient->post('https://monitorio.io/api/notifications/add/', json_encode([
        'key' => $cliParams['monitorio-key'],
        'tpl' => 'malware',
        'params' => [
            'list' => file_get_contents($productionLog),
        ],
    ]));
}

echo "DONE\n";

$connection = \Bitrix\Main\Application::getConnection();
$connection->disconnect();

exit;