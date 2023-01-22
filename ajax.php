<?php

class CBitrixXscanAjax
{
    private static function get_file()
    {
        $file = '';

        if (isset($_REQUEST['file'])) {
            $file = '/' . trim($_REQUEST['file'], '/');
        }

        return $file;
    }

    private static function prison()
    {
        $file = self::get_file();

        if (!$file || !file_exists($file)) {
            $msg = CBitrixXscanFork::ShowMsg(GetMessage("BITRIX_XSCAN_FILE_NOT_FOUND") . htmlspecialcharsbx($file), 'red');
        } else {
            $new_f = preg_replace('#\.php[578]?$#i', '.ph_', $file);
            if (rename($file, $new_f)) {
                $msg = CBitrixXscanFork::ShowMsg(GetMessage("BITRIX_XSCAN_RENAMED") . htmlspecialcharsbx($new_f));
            } else {
                $msg = CBitrixXscanFork::ShowMsg(GetMessage("BITRIX_XSCAN_ERR_RENAME") . htmlspecialcharsbx($file), 'red');
            }
        }

        return $msg;
    }

    private static function release()
    {
        $file = self::get_file();

        if (!$file || !file_exists($file)) {
            $msg = CBitrixXscanFork::ShowMsg(GetMessage("BITRIX_XSCAN_FILE_NOT_FOUND") . htmlspecialcharsbx($file), 'red');
        } else {
            $new_f = preg_replace('#\.ph_$#', '.php', $file);
            if (rename($file, $new_f)) {
                $msg = CBitrixXscanFork::ShowMsg(GetMessage("BITRIX_XSCAN_RENAMED") . htmlspecialcharsbx($new_f));
            } else {
                $msg = CBitrixXscanFork::ShowMsg(GetMessage("BITRIX_XSCAN_ERR_RENAME") . htmlspecialcharsbx($file), 'red');
            }
        }

        return $msg;
    }

    private static function hide()
    {
        $file = self::get_file();
        $msg = '';

        $ent = XScanResultTable::getList(['select' => ['id'], 'filter' => ['src' => $file]])->fetch();

        if ($ent) {
            XScanResultTable::delete($ent['id']);
            $msg = CBitrixXscanFork::ShowMsg(GetMessage("BITRIX_XSCAN_HIDED") . htmlspecialcharsbx($file));
        }

        return $msg;
    }

    private static function add_error()
    {
        $file = self::get_file();
        $msg = '';
        if ($file) {
            XScanResultTable::add(['type' => 'file', 'src' => $file, 'message' => 'error', 'score' => 0.5]);
        }

        return $msg;
    }

    private static function scan($scaner, $nav, $start_path)
    {

        if (!is_dir($start_path)) {
            $msg = GetMessage("BITRIX_XSCAN_NACALQNYY_PUTQ_NE_NA");
            return ['error' => $msg];
        }

        if ($_REQUEST['clean'] == 'Y') {
            $scaner->clean(); // new scan
            $scaner->CheckEvents();
            $scaner->CheckAgents();
            $scaner->Count_total($start_path);
        }


        if ($_REQUEST['break_point']) { // continue scan
            $scaner->skip_path = $_REQUEST['break_point'];
        } else {
            $_SESSION['xscan_page'] = 1;
            $nav->setCurrentPage(1);
        }

        session_write_close();

        $scaner->Search($start_path);
        $scaner->SavetoDB();

        $prc = $scaner->total == 0 ? 100 : (int)($scaner->progress * 100 / $scaner->total);

        if ($scaner->break_point) {
            $inprogress = True;
        }

        return ['progress' => $scaner->progress, 'total' => $scaner->total, 'break_point' => $scaner->break_point, 'prc' => $prc];

    }


    public static function run($scaner, $nav, $start_path)
    {
        header('Content-Type:application/json; charset=UTF-8');
        $msg = '';
        $response = ['error' => $msg];

        $action = $_REQUEST['action'];

        if (!check_bitrix_sessid()) {
            $msg = CBitrixXscanFork::ShowMsg(GetMessage("BITRIX_XSCAN_SESSIA_USTARELA_OBN"), 'red');
            $response = ['error' => $msg];
        }
        elseif (in_array($action, ['prison', 'release', 'hide', 'add_error'], true)) {
            $msg = self::$action();
            $response = ['error' => $msg];
        }
        elseif ($action == 'scan'){
            $response = self::scan($scaner, $nav, $start_path);
        }

        echo \Bitrix\Main\Web\Json::encode($response);

        CMain::FinalActions();
        die();

    }
}