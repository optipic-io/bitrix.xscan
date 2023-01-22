<?
require_once($_SERVER["DOCUMENT_ROOT"] . "/bitrix/modules/main/include/prolog_admin_before.php");
require_once($_SERVER["DOCUMENT_ROOT"] . BX_ROOT . "/modules/main/prolog.php");

if (!$USER->IsAdmin())
    $APPLICATION->AuthForm();

IncludeModuleLangFile(__FILE__);

if (function_exists('mb_internal_encoding'))
    mb_internal_encoding('ISO-8859-1');


$strError = '';
$file = '';

$APPLICATION->SetTitle(GetMessage("BITRIX_XSCAN_SEARCH"));
require($_SERVER["DOCUMENT_ROOT"] . BX_ROOT . "/modules/main/include/prolog_admin_after.php");

session_write_close();

\Bitrix\Main\UI\Extension::load("ui.layout-form");
\Bitrix\Main\UI\Extension::load("ui.buttons");
\Bitrix\Main\UI\Extension::load("ui.dialogs.messagebox");
\Bitrix\Main\UI\Extension::load("ui.progressbar");
\Bitrix\Main\UI\Extension::load("ui.alerts");

$progress = isset($_REQUEST['progress']) ? (int)$_REQUEST['progress'] : 0;
$total = isset($_REQUEST['total']) ? (int)$_REQUEST['total'] : 0;
$inprogress = False;

$scaner = new CBitrixXscan($progress, $total);

$action = $_REQUEST['action'];

if (in_array($action, ['prison', 'release'], true) && !check_bitrix_sessid()) {
    CBitrixXscan::ShowMsg(GetMessage("BITRIX_XSCAN_SESSIA_USTARELA_OBN"), 'red');
    $action = 'none';
}

if (in_array($action, ['prison', 'release', 'showfile'], true) && isset($_REQUEST['file'])) {
    $file = '/' . trim($_REQUEST['file'], '/');

    if (!file_exists($file)) {
        CBitrixXscan::ShowMsg(GetMessage("BITRIX_XSCAN_FILE_NOT_FOUND") . htmlspecialcharsbx($file), 'red');
        $action = 'none';
    }
}

if ($action === 'prison' && $file) {

    $new_f = preg_replace('#\.php[578]?$#i', '.ph_', $file);
    if (rename($file, $new_f)) {
        CBitrixXscan::ShowMsg(GetMessage("BITRIX_XSCAN_RENAMED") . htmlspecialcharsbx($new_f));
    } else {
        CBitrixXscan::ShowMsg(GetMessage("BITRIX_XSCAN_ERR_RENAME") . htmlspecialcharsbx($file), 'red');
    }

} elseif ($action === 'release' && $file) {

    $new_f = preg_replace('#\.ph_$#', '.php', $file);
    if (rename($file, $new_f)) {
        CBitrixXscan::ShowMsg(GetMessage("BITRIX_XSCAN_RENAMED") . htmlspecialcharsbx($new_f));
    } else {
        CBitrixXscan::ShowMsg(GetMessage("BITRIX_XSCAN_ERR_RENAME") . htmlspecialcharsbx($file), 'red');
    }

} elseif ($action === 'showfile' && $file) {
    ?>

    <div class="ui-alert ui-alert-icon-warning">
        <span class="ui-alert-message"><strong><?= GetMessage("BITRIX_XSCAN_FAYL") ?></strong> <?= htmlspecialcharsbx($file) ?></span>
    </div>

    <?php

    if ($res = $scaner->CheckFile($file)) {

        if ($scaner->last_reg && empty($scaner->last_regs)) {
            ?>
            <div class="ui-alert ui-alert-danger ui-alert-icon-danger" style="flex-wrap: wrap">
                <span class="ui-alert-message"><strong><?= GetMessage("BITRIX_XSCAN_PODOZRITELQNYY_KOD") ?></strong></span>
                <span style="width: 100%"><br></span>
                <span><?= nl2br(htmlspecialcharsbx($scaner->last_reg)); ?></span>
            </div>
            <?php
        }
        foreach ($scaner->last_regs as $i => $value) {
            ?>

            <div class="ui-alert ui-alert-danger ui-alert-icon-danger" style="flex-wrap: wrap">
                <span class="ui-alert-message"><strong><?= GetMessage("BITRIX_XSCAN_PODOZRITELQNYY_KOD") ?></strong></span>
                <span style="width: 100%"><br></span>
                <span class="ui-alert-message"><?= $res[$i] ?></span>
                <span style="width: 100%"><br></span>
                <span><?= nl2br(htmlspecialcharsbx($value)); ?></span>
            </div>

            <?php

        }

    } else {
        CBitrixXscan::ShowMsg(GetMessage("BITRIX_XSCAN_FAYL_NE_VYGLADIT_POD"), 'green');
    }

    echo '<div class="ui-alert"><span class="ui-alert-message">' . highlight_file($file, true) . '</span></div>';

    die();
}

$start_path = isset($_REQUEST['start_path']) ? $_REQUEST['start_path'] : $_SERVER['DOCUMENT_ROOT'];
$start_path = rtrim($start_path, '/');

if (!is_dir($start_path))
    $strError = GetMessage("BITRIX_XSCAN_NACALQNYY_PUTQ_NE_NA");

if ($_REQUEST['go'] && !$strError && check_bitrix_sessid()) {

    if ($_REQUEST['break_point']){ // continue scan
        $scaner->skip_path = $_REQUEST['break_point'];
    }
    else {
        $scaner->clean(); // new scan
        $scaner->CheckEvents();
        $scaner->CheckAgents();
        $scaner->Count_total($start_path);
    }

    $scaner->Search($start_path);

    $prc = $scaner->total == 0 ? 100 : (int)($scaner->progress * 100 / $scaner->total);

    if ($scaner->break_point) {
        $inprogress = True;
        ?>
        <form method="post" id="postform" action="">
            <?= bitrix_sessid_post() ?>
            <input type=hidden name="start_path" value="<?= htmlspecialcharsbx($start_path) ?>">
            <input type=hidden name="go" value="Y">
            <input type=hidden name="progress" value="<?= $scaner->progress ?>">
            <input type=hidden name="total" value="<?= $scaner->total ?>">
            <input type=hidden name="break_point" value="<?= htmlspecialcharsbx($scaner->break_point) ?>">
        </form>
        <?
        // CBitrixXscan::ShowMsg('<b>' . GetMessage("BITRIX_XSCAN_IN_PROGRESS") . '...</b><br>' . GetMessage("BITRIX_XSCAN_CURRENT_FILE") . ': <i>' . htmlspecialcharsbx($scaner->break_point) . '</i>');
        ?>

        <div class="ui-progressbar ui-progressbar-bg">
            <div class="ui-progressbar-text-before">
                <strong><?= GetMessage("BITRIX_XSCAN_IN_PROGRESS") ?></strong>
            </div>
            <div class="ui-progressbar-track">
                <div class="ui-progressbar-bar" style="width:<?= $prc ?>%;"></div>
            </div>
            <div class="ui-progressbar-text-after"> <?= $scaner->progress ?> / <?= $scaner->total ?></div>
        </div><br>


        <script>window.setTimeout("document.getElementById('postform').submit()", 500);</script><? // таймаут чтобы браузер показал текст
    } elseif (!file_exists($scaner->scan_log) && !file_exists($scaner->db_log)) {
        CBitrixXscan::ShowMsg(GetMessage("BITRIX_XSCAN_COMPLETED"));
    }
} else {
    if ($strError) {
        CBitrixXscan::ShowMsg($strError, 'red');
    }
    ?>
    <form method="post" action="">

    <?= bitrix_sessid_post() ?>
    <input type=hidden name=go value="Y">

    <div class="ui-form-row-inline">

        <div class="ui-form-row ui-form-row-line">
            <div class="ui-form-label">
                <div class="ui-ctl-label-text"><?= GetMessage("BITRIX_XSCAN_NACALQNYY_PUTQ") ?></div>
            </div>

            <div class="ui-form-content" style="margin-right: 15px">
                <div class="ui-ctl ui-ctl-textbox ui-ctl-w100">
                    <input name=start_path value="<?= htmlspecialcharsbx($start_path) ?>" class="ui-ctl-element">
                </div>
            </div>

            <div class="ui-form-content">
                <button type="submit"
                        class="ui-btn ui-btn-primary"><?= GetMessage("BITRIX_XSCAN_START_SCAN") ?></button>
            </div>
        </div>

    </div>
    </form><?
}

$list = $scaner->CheckBadLog($inprogress);

$APPLICATION->IncludeComponent(
    'bitrix:main.ui.grid',
    '',
    [
        'GRID_ID' => 'report_list',
        'COLUMNS' => [
            ['id' => 'FILE_NAME', 'name' => GetMessage("BITRIX_XSCAN_NAME"), 'default' => true],
            ['id' => 'FILE_TYPE', 'name' => GetMessage("BITRIX_XSCAN_TYPE"), 'default' => true],
            ['id' => 'FILE_SIZE', 'name' => GetMessage("BITRIX_XSCAN_SIZE"), 'default' => true],
            ['id' => 'FILE_MODIFY', 'name' => GetMessage("BITRIX_XSCAN_M_DATE"), 'default' => true],
            ['id' => 'ACTIONS', 'name' => GetMessage("BITRIX_XSCAN_ACTIONS"), 'default' => true],
        ],
        'ROWS' => $list,
        'TOTAL_ROWS_COUNT' => count($list),
        'SHOW_ROW_CHECKBOXES' => false,
        'SHOW_GRID_SETTINGS_MENU' => true,
        'SHOW_SELECTED_COUNTER' => false,
        'SHOW_TOTAL_COUNTER' => True,
        'ALLOW_COLUMNS_RESIZE' => true,
        'ALLOW_HORIZONTAL_SCROLL' => true,
    ]
);

?>

<form method="POST" id="xscanform">
<?= bitrix_sessid_post() ?>
<input type="hidden" name="action" id="xscanaction" value="">
<input type="hidden" name="file" id="xscanfile" value="">
</form>
<script>

    function xscan_prison(file){
        BX.UI.Dialogs.MessageBox.confirm('<?= GetMessage("BITRIX_XSCAN_WARN") ?>', () => {
            document.getElementById('xscanaction').value = 'prison';
            document.getElementById('xscanfile').value = file;
            document.getElementById('xscanform').submit()
        });
    }

    function xscan_release(file){
        BX.UI.Dialogs.MessageBox.confirm('<?= GetMessage("BITRIX_XSCAN_WARN_RELEASE") ?>', () => {
            document.getElementById('xscanaction').value = 'release';
            document.getElementById('xscanfile').value = file;
            document.getElementById('xscanform').submit()
        });
    }

</script>


<?php

require($_SERVER["DOCUMENT_ROOT"] . BX_ROOT . "/modules/main/include/epilog_admin_before.php");
require($_SERVER["DOCUMENT_ROOT"] . BX_ROOT . "/modules/main/include/epilog_admin_after.php");
?>
