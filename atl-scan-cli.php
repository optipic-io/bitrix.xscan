<?
$_SERVER["DOCUMENT_ROOT"] = realpath(dirname(__FILE__)."/../../..");

define("NO_KEEP_STATISTIC", true);
define("NOT_CHECK_PERMISSIONS",true);
define("BX_CRONTAB", true);
define("BX_NO_ACCELERATOR_RESET", true);

require($_SERVER["DOCUMENT_ROOT"]."/bitrix/modules/main/include/prolog_before.php");

CModule::IncludeModule('bitrix.xscan');

set_time_limit(0);

ini_set('memory_limit', '10000M');
//var_dump(ini_get('memory_limit'));exit;

//IncludeModuleLangFile(__FILE__);

if (function_exists('mb_internal_encoding'))
    mb_internal_encoding('ISO-8859-1');

define('XSCAN_LOG', $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/bitrix.xscan/file_list_cli.txt');
define('XSCAN_DB_LOG', $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/bitrix.xscan/db_list_cli.txt');
define('XSCAN_DATABASE', $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/bitrix.xscan/database.json');

define('ATL_XSCAN_LOG_IGNORE', $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/bitrix.xscan/file_list_ignore.txt');

//define('START_TIME', time()); // засекаем время старта
define('START_TIME', PHP_INT_MAX); // ставим время старта заранее большое чтобы анализ в CLI-режиме не завершался по таймауту

$strError = '';

$START_PATH = $_SERVER['DOCUMENT_ROOT'].'/bitrix/modules/main/';

if (!$START_PATH)
    $START_PATH = $_SERVER['DOCUMENT_ROOT'];

/*if (file_exists(XSCAN_LOG))
    unlink(XSCAN_LOG);*/

/*if (file_exists(XSCAN_DB_LOG))
    unlink(XSCAN_DB_LOG);*/

//CBitrixXscan::CheckEvents();
//CBitrixXscan::CheckAgents();

var_dump($START_PATH);

//CBitrixXscan::Search($START_PATH); 




// @TODO: Надо сделать исключение из результатов XSCAN_DB_LOG те строки, которые соответствуют 1в1 строкам из file_list_cli.ignore
// file_list_cli.ignore
// И результативный список с учетом исключений записать в file_list.txt
$ignorelist = implode(" #### ", file(ATL_XSCAN_LOG_IGNORE));
var_dump($ignorelist);
//file
$productionLog = str_replace(basename(XSCAN_LOG), "file_list.txt", XSCAN_LOG);
file_put_contents($productionLog, "");
$fp = @fopen(XSCAN_LOG, "r");
if ($fp) {
    while (($row = fgets($fp)) !== false) {
        $row = trim($row);
        //var_dump($row);
        // preg_match("#$row#ium", $ignorelist)
        if (stripos($ignorelist, $row)===false) {
            //echo $row."\n";
            file_put_contents($productionLog, $row."\n", FILE_APPEND);
        }
    }
    fclose($fp);
}