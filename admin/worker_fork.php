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

if (isset($_REQUEST['ajax'])) {
    CModule::includemodule('bitrix.xscan');
} else {
    require($_SERVER["DOCUMENT_ROOT"] . BX_ROOT . "/modules/main/include/prolog_admin_after.php");
}

if (isset($_POST['files'])) {
    if (!check_bitrix_sessid()) {
        $strError = CBitrixXscanFork::ShowMsg(GetMessage("BITRIX_XSCAN_SESSIA_USTARELA_OBN"), 'red');
        echo $strError;
        die();
    }

    $filter = [
        'type' => 'file'
    ];

    $all = isset($_POST['all']) && $_POST['all'] === 'true';

    if (!$all) {
        $filesId = Bitrix\Main\Web\Json::decode($_POST['files']);
        $filter['@id'] = $filesId;
    }

    $list = XScanResultTable::getList([
        'select' => [
            'src'
        ],
        'filter' => $filter
    ])->fetchAll();

    $files = array_column($list, 'src');

    $tempDir = CTempFile::GetDirectoryName(1);
    CheckDirPath($tempDir);
    $tempFile = $tempDir . Bitrix\Main\Security\Random::getString(32);

    $zip = CBXArchive::GetArchive($tempFile, 'ZIP');
    $zip->Pack($files);

    $tempFile = \CFile::MakeFileArray($tempFile);

    \CFile::ViewByUser($tempFile, [
        "force_download" => true,
        "attachment_name" => 'xscan_results.zip',
    ]);

    \Bitrix\Main\Application::getInstance()->end();
}


$grid_options = new Bitrix\Main\Grid\Options('report_list');
$nav_params = $grid_options->GetNavParams();

$nav = new \Bitrix\Main\UI\PageNavigation("report_list");
$nav->allowAllRecords(false)
    ->setPageSize($nav_params['nPageSize']);


if (isset($_GET['grid_action']) && $_GET['grid_action'] === 'more' && $_GET['grid_id'] === $grid_options->getId()) {
    $nav->setCurrentPage($_GET['report_list']);
} elseif (isset($_GET['grid_action']) && $_GET['grid_action'] === 'pagination') {
    $nav->initFromUri();
} elseif (isset($_SESSION['xscan_page'])) {
    $nav->setCurrentPage($_SESSION['xscan_page']);
}

$_SESSION['xscan_page'] = $nav->getCurrentPage();


\Bitrix\Main\UI\Extension::load("ui.layout-form");
\Bitrix\Main\UI\Extension::load("ui.buttons");
\Bitrix\Main\UI\Extension::load("ui.dialogs.messagebox");
\Bitrix\Main\UI\Extension::load("ui.progressbar");
\Bitrix\Main\UI\Extension::load("ui.alerts");

$progress = isset($_REQUEST['progress']) ? (int)$_REQUEST['progress'] : 0;
$total = isset($_REQUEST['total']) ? (int)$_REQUEST['total'] : 0;
$inprogress = False;

$scaner = new CBitrixXscanFork($progress, $total);

$action = $_REQUEST['action'];
$start_path = isset($_REQUEST['start_path']) ? $_REQUEST['start_path'] : $_SERVER['DOCUMENT_ROOT'];
$start_path = rtrim($start_path, '/');


if (isset($_REQUEST['ajax'])) {
    \CBitrixXscanAjax::run($scaner, $nav, $start_path);
    die();
}

if ($action === 'showfile') {

    if (isset($_REQUEST['file'])) {
        $file = '/' . trim($_REQUEST['file'], '/');
    }

    if (!$file || !file_exists($file)) {
        echo CBitrixXscanFork::ShowMsg(GetMessage("BITRIX_XSCAN_FILE_NOT_FOUND") . htmlspecialcharsbx($file), 'red');
    } else {

        $stat = stat($file);

        ?>

        <div class="ui-alert ui-alert-icon-warning">
            <span class="ui-alert-message"><strong><?= GetMessage("BITRIX_XSCAN_FAYL") ?></strong> <?= htmlspecialcharsbx($file) ?></span>
        </div>

        <div class="ui-alert ui-alert-icon-warning">
            <span class="ui-alert-message"><strong><?= GetMessage("BITRIX_XSCAN_M_DATE") ?></strong> <?= ConvertTimeStamp($stat['mtime'], "FULL") ?></span>
        </div>

        <div class="ui-alert ui-alert-icon-warning">
            <span class="ui-alert-message"><strong><?= GetMessage("BITRIX_XSCAN_C_DATE") ?></strong> <?= ConvertTimeStamp($stat['ctime'], "FULL") ?></span>
        </div>

        <?php

        $res = $scaner->CheckFile($file);
        if ($res) {
            ?>

            <div class="ui-alert ui-alert-icon-warning">
                <span class="ui-alert-message"><strong><?= GetMessage("BITRIX_XSCAN_SCORE") ?></strong> <?= htmlspecialcharsbx($scaner->score) ?></span>
            </div>

            <?php

            foreach ($scaner->results as $value) {
                ?>

                <div class="ui-alert ui-alert-danger ui-alert-icon-danger" style="flex-wrap: wrap">
                    <span class="ui-alert-message"><strong><?= GetMessage("BITRIX_XSCAN_PODOZRITELQNYY_KOD") ?></strong></span>
                    <span style="width: 100%"><br></span>
                    <span class="ui-alert-message"><?= $value['subj'] ?></span>
                    <span style="width: 100%"><br></span>
                    <span><?= nl2br(htmlspecialcharsbx($value['code'])); ?></span>
                </div>

                <?php

            }

        } elseif (in_array($file, $scaner->errors)) {
            echo CBitrixXscanFork::ShowMsg(GetMessage("BITRIX_XSCAN_FILE_ERROR"), 'red');
        } else {
            echo CBitrixXscanFork::ShowMsg(GetMessage("BITRIX_XSCAN_FAYL_NE_VYGLADIT_POD"), 'green');
        }

        echo '<div class="ui-alert"><span class="ui-alert-message">' . highlight_file($file, true) . '</span></div>';

        CMain::FinalActions();
        die();
    }
}

?>

<form method="post" action="" onsubmit="return false;">

    <?= bitrix_sessid_post() ?>
    <div class="ui-form-row-inline">

        <div class="ui-form-row ui-form-row-line">
            <div class="ui-form-label">
                <div class="ui-ctl-label-text"><?= GetMessage("BITRIX_XSCAN_NACALQNYY_PUTQ") ?></div>
            </div>

            <div class="ui-form-content" style="margin-right: 15px">
                <div class="ui-ctl ui-ctl-textbox ui-ctl-w100">
                    <input id="start_path" name="start_path" value="<?= htmlspecialcharsbx($start_path) ?>"
                           class="ui-ctl-element">
                </div>
            </div>

            <div class="ui-form-content">
                <button type="submit" onclick="Start();" id="start_button"
                        class="ui-btn ui-btn-primary"><?= GetMessage("BITRIX_XSCAN_START_SCAN") ?></button>
            </div>
        </div>

    </div>
</form>

<form hidden id="download-form" method="POST" target="_blank">
    <?= bitrix_sessid_post() ?>
    <input value="" name="files" id="input-files">
    <input value="" name="all" id="input-checkbox">
</form>

<script>

    function xscan_download(files) {
        var gridObject = BX.Main.gridManager.getById("report_list");
        var grid = gridObject.instance
        var selectedIds = grid.getRows().getSelectedIds();

        var checkboxAll = document.getElementById('actallrows_report_list')
        var inputCheckbox = document.getElementById('input-checkbox')
        if (checkboxAll.checked) {
            inputCheckbox.value = true
        } else {
            inputCheckbox.value = false
        }

        var form = document.getElementById('download-form')
        var input = document.getElementById('input-files')
        input.value = JSON.stringify(selectedIds);
        form.submit()

        return true;
    }

    function xscan_prison(file) {
        BX.UI.Dialogs.MessageBox.confirm('<?= GetMessage("BITRIX_XSCAN_WARN") ?>', () => {

            BX.ajax.post(window.location.href,
                {
                    'sessid': BX.bitrix_sessid(),
                    'ajax': true,
                    'action': 'prison',
                    'file': file

                },
                function (result) {
                    result = JSON.parse(result);
                    BX('alert_msg').innerHTML = result['msg'] || result['error'];
                    GridRenew();
                }
            );

            return true;

        });
    }

    function xscan_hide(file) {
        BX.UI.Dialogs.MessageBox.confirm('<?= GetMessage("BITRIX_XSCAN_HIDE") ?>', () => {

            BX.ajax.post(window.location.href,
                {
                    'sessid': BX.bitrix_sessid(),
                    'ajax': true,
                    'action': 'hide',
                    'file': file

                },
                function (result) {
                    result = JSON.parse(result);
                    BX('alert_msg').innerHTML = result['msg'] || result['error'];
                    GridRenew();
                }
            );

            return true;

        });
    }

    function xscan_release(file) {
        BX.UI.Dialogs.MessageBox.confirm('<?= GetMessage("BITRIX_XSCAN_WARN_RELEASE") ?>', () => {

            BX.ajax.post(window.location.href,
                {
                    'sessid': BX.bitrix_sessid(),
                    'ajax': true,
                    'action': 'release',
                    'file': file

                },
                function (result) {
                    result = JSON.parse(result);
                    BX('alert_msg').innerHTML = result['msg'] || result['error'];
                    GridRenew();
                }
            );

            return true;

        });
    }

    function Start() {
        BX('start_button').classList.add('ui-btn-wait');
        BX('start_button').disabled = true;
        BX('alert_msg').innerHTML = '';
        go('Y');
    }

    function GridRenew() {
        var gridObject = BX.Main.gridManager.getById("report_list");

        if (gridObject.hasOwnProperty('instance')) {
            gridObject.instance.reloadTable('POST', {});
        }
    }

    function go(clean = 'N', progress = '', total = '', break_point = '') {
        BX.ajax({
            url: window.location.href,
            method: 'POST',
            data: {
                'sessid': BX.bitrix_sessid(),
                'timeout': 3600,
                'action': 'scan',
                'ajax': true,
                'progress': progress,
                'total': total,
                'clean': clean,
                'break_point': break_point,
                'start_path': BX('start_path').value,

            },
            onsuccess: function (result) {
                result = JSON.parse(result);
                // BX('results').innerHTML = result;
                GridRenew();
                if (result['error']) {
                    BX('alert_msg').innerHTML = result['error'];
                }

                if (result['break_point']) {
                    BX('progress_bar').style.display = '';
                    BX('progress').innerHTML = result['progress'] + " / " + result['total'];
                    BX('progressprc').style.width = result['prc'] + '%';

                    go('N', result['progress'], result['total'], result['break_point']);
                } else {
                    BX('start_button').classList.remove('ui-btn-wait');
                    BX('start_button').disabled = false;
                    BX('progress_bar').style.display = 'none';
                }
            },
            onfailure: function (err, status, conf) {

                if (conf && conf.xhr && conf.xhr.getResponseHeader('xscan-bp')) {
                    bp = conf.xhr.getResponseHeader('xscan-bp');

                    BX.ajax.post(window.location.href,
                        {
                            'sessid': BX.bitrix_sessid(),
                            'ajax': true,
                            'action': 'add_error',
                            'file': bp

                        },
                        function (result) {
                            // result = JSON.parse(result);
                            // BX('alert_msg').innerHTML = result['msg'] || result['error'];
                            go('N', progress, total, break_point);
                        }
                    );
                }
            }
        });

    }

</script>
<?

$sort = $grid_options->GetSorting(['sort' => ['ID' => 'asc'], 'vars' => ['by' => 'by', 'order' => 'order']]);
$list = \CBitrixXscanFork::getList($inprogress, $nav, $sort);
$total = \CBitrixXscanFork::getTotal();
$nav->setRecordCount($total);

$snippet = new \Bitrix\Main\Grid\Panel\Snippet();

?>

<div id="results">
    <div id="alert_msg">
    </div>

    <div id="progress_bar" style="display: none" class="ui-progressbar ui-progressbar-bg">
        <div class="ui-progressbar-text-before">
            <strong><?= GetMessage("BITRIX_XSCAN_IN_PROGRESS") ?></strong>
        </div>
        <div class="ui-progressbar-track">
            <div class="ui-progressbar-bar" id="progressprc" style=""></div>
        </div>
        <div class="ui-progressbar-text-after" id="progress"></div>
    </div>
    <br>

    <?

    $APPLICATION->IncludeComponent(
        'bitrix:main.ui.grid',
        '',
        [
            'GRID_ID' => 'report_list',
            'COLUMNS' => [
                ['id' => 'ID', 'name' => 'id', 'sort' => 'id', 'default' => true],
                ['id' => 'FILE_NAME', 'name' => GetMessage("BITRIX_XSCAN_NAME"), 'default' => true],
                ['id' => 'FILE_TYPE', 'name' => GetMessage("BITRIX_XSCAN_TYPE"), 'default' => true],
                ['id' => 'FILE_SIZE', 'name' => GetMessage("BITRIX_XSCAN_SIZE"), 'default' => true],
                ['id' => 'FILE_SCORE', 'name' => GetMessage("BITRIX_XSCAN_SCORE"), 'sort' => 'score', 'default' => true],
                ['id' => 'FILE_MODIFY', 'name' => GetMessage("BITRIX_XSCAN_M_DATE"), 'default' => true],
                ['id' => 'FILE_CREATE', 'name' => GetMessage("BITRIX_XSCAN_C_DATE"), 'default' => true],
                ['id' => 'ACTIONS', 'name' => GetMessage("BITRIX_XSCAN_ACTIONS"), 'default' => true],
                ['id' => 'HIDE', 'name' => GetMessage("BITRIX_XSCAN_HIDE_BTN"), 'default' => true],

            ],
            'ROWS' => $list,
            'TOTAL_ROWS_COUNT' => $total,
            'SHOW_ROW_CHECKBOXES' => false,
            'SHOW_GRID_SETTINGS_MENU' => true,
            'SHOW_TOTAL_COUNTER' => true,
            'ALLOW_COLUMNS_RESIZE' => true,
            'ALLOW_HORIZONTAL_SCROLL' => true,
            'ALLOW_SORT' => true,

            'AJAX_MODE' => 'Y',
            'AJAX_ID' => \CAjax::GetComponentID('bitrix:main.ui.grid', '', ''),
            'AJAX_OPTION_JUMP' => 'N',
            'AJAX_OPTION_STYLE' => 'N',
            'AJAX_OPTION_HISTORY' => 'N',

            'NAV_OBJECT' => $nav,
            'CURRENT_PAGE' => $nav->getCurrentPage(),
            'NAV_PARAM_NAME' => $nav->getId(),
            'SHOW_NAVIGATION_PANEL' => true,
            'SHOW_PAGINATION' => true,
            'SHOW_MORE_BUTTON' => false,
            'ENABLE_NEXT_PAGE' => true,

            'SHOW_CHECK_ALL_CHECKBOXES' => true,
            'SHOW_ROW_CHECKBOXES' => true,
            'SHOW_SELECTED_COUNTER' => true,
            'SHOW_ACTION_PANEL' => true,
            'ACTION_PANEL' => [
                'GROUPS' => [
                    [
                        'ITEMS' => [
                            [
                                "TYPE" => \Bitrix\Main\Grid\Panel\Types::BUTTON,
                                "ID" => "action_button_download",
                                "NAME" => "action_button_download",
                                "TEXT" => GetMessage("BITRIX_XSCAN_DOWNLOAD"),
                                'ONCHANGE' => array(
                                    array(
                                        'ACTION' => Bitrix\Main\Grid\Panel\Actions::CALLBACK,
                                        'DATA' => [["JS" => "xscan_download()"]]
                                    )
                                )
                            ],
                            $snippet->getForAllCheckbox()
                        ],
                    ]
                ],
            ],


            'SHOW_PAGESIZE' => true,
            'DEFAULT_PAGE_SIZE' => 20,
            'PAGE_SIZES' => [
                ['NAME' => "5", 'VALUE' => '5'],
                ['NAME' => '10', 'VALUE' => '10'],
                ['NAME' => '20', 'VALUE' => '20'],
                ['NAME' => '50', 'VALUE' => '50'],
                ['NAME' => '100', 'VALUE' => '100']
            ],

        ]
    );


    ?>

</div>

<?php

require($_SERVER["DOCUMENT_ROOT"] . BX_ROOT . "/modules/main/include/epilog_admin_before.php");
require($_SERVER["DOCUMENT_ROOT"] . BX_ROOT . "/modules/main/include/epilog_admin_after.php");

?>
