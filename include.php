<?php

IncludeModuleLangFile(__FILE__);

include 'include_fork.php';

class CBitrixXscan
{
    static $var = '\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*';
    static $spaces = "[ \r\t\n]*";
    static $request = '(?:_REQUEST|_GET|_POST|_COOKIE|_SERVER(?!\[[\'"]DOCUMENT_ROOT[\'"]\])|_FILES)';
    static $functions = '(?:parse_str|hex2bin|str_rot13|base64_decode|url_decode|str_replace|str_ireplace|preg_replace|move_uploaded_file)';
    static $evals = '(?:assert|call_user_func|call_user_func_array|create_function|eval|exec|ob_start|passthru|pcntl_exec|popen|proc_open|set_include_path|shell_exec|system)';
    static $mehtods = [
        'Bitrix\Im\Call\Auth::authorizeById',
        'Bitrix\ImOpenLines\Controller\Widget\Filter\Authorization::authorizeById',
        'Bitrix\Imopenlines\Widget\Auth::authorizeById',
        'Bitrix\Sale\Delivery\Services\Automatic::createConfig',
        'Bitrix\Sender\Internals\DataExport::toCsv',
        'Bitrix\Sender\Internals\QueryController\Base::call',
        'CAllSaleBasket::ExecuteCallbackFunction',
        'CAllSaleOrder::PrepareSql',
        'CBPHelper::UsersStringToArray',
        'CControllerClient::RunCommand',
        'CMailFilter::CheckPHP',
        'CMailFilter::DoPHPAction',
        'CRestUtil::makeAuth',
        'CSaleHelper::getOptionOrImportValues',
        'CWebDavTools::sendJsonResponse'
    ];
    static $false_positives = ['ccdc7c7643c52c8cc313a5af18580146', 'ff3d9141a08d409ce96775d4091358bc', '7265d268d6d1843bb7108743f98648bb',
        '72ba0bb291d7950b4006853378c475b7', '784ab9089dfd3b2f4c597aa07046e2ed', 'ffda51650cd91c68f83c15e1e5f77e46', 'a35be1e5ef336d242a4eee17f204090e',
        '24246e5ac49bb58beed4b56266d528b2', 'c4c43d1e54cdcb45e66076e93fe9a739', 'c5b01f22634f1b96af7142f00e76e443', '7ad7a07752cfbf340d9ce0b6bc60bdb1',
        '003056b0f65740cf66c99d98dbc02eba', '416091c668c50afac291a5dd276479f2', '89e68d5b18d921dec379157d109062a3', 'd2e76a80444bc2ab7f3dd6c2e93bb16c',
        '455ec8dc4a120cec4def29880ffa968b', 'c13f8602a8f791b182c16dd72fa93291', '522da22626c1c8cc640947875c52a28d', 'a147d2816c1ee2d7f08efedb34b5d1f4',
        '27630c44c06c558e6bf6eeb49a475f2d', 'f990a8b0fff344aae999368264600b2b', '713f137b35f1d8bf6548f8a5e18a9efc', 'cdd13ea93001b55487ffd866742366e9',
        '354b269d318fb418c80c29168a9d8d42', 'a926bd8ecc4a1b2dbff7e0f4ea14e406', '7d68da0cf40985b6b87434977c3100b8', 'de5d58d2749fc2cfd796d3b0fdd9047a',
        'dd71d285292e8a72b1446718b60607a6', 'ccb96959f1c09974fb729f9c7d5eb319', '68cea6597cc7e5af2cae86cdafc2a276', '761868820ef59ca9fe1535169805d39c',
        'bbc4cb219f69c35cd8e178078a0928f5', '5845bf76cd3ad143295797e46a67e1b5', 'd8cba3a8eb94222089e1b36aaefd9217', '5742c75a42cce8f71b8961b995588e78',
        '1472819204dc9215825bbeb96823fed3', 'bc6147c35bafe7c2fce78d3c70c9e92d', '6c0aa366b12b0a0c3a1eeacf84e337ca', '901e1737048f2826442a7afe48e0b159',
        'd564e262bc4b280b476de4f7888c83dd', 'e5b6694b4c40c6e713e9e1cfa42f55d9', '1284b0a46eca8486052317f2dd3ef424', '31e6708ecb62a5bf7a68d5ad6972bebd',
        '32ceeba804f43db52bdca0d14bee03cb', '3794c999c4238204eaf7848039744d3e', '3a7f5b0dcaa27078b262ef37f8cb3bc0', '5b21f1d65b6bfea6747e9b1ff5f3d06c',
        '6380f1e455efc0ef9dbbf1dd48b2ba41', '6941b48b77fcc2187a53cceb8694e541', '75abefbc6a2ca49149b18660ca942777', '7e24395a2a28c34a1b9c919408315062',
        '8611dc0a761f4a9b2c5ed99b81657efb', '90cbff4984b3ea3f59b6de6a94ae0efe', '90d89384d895dedbf3313afaab247da5', 'c8914556cadb79053151b88f36bed832',
        'cc4e00794dbd6441995578590ff0282b', 'd28b0e9fe66a6e4cc924c03802e03a1a', 'd4d21f2bbecb53ac9cc9a634b3bb5609', '8f10419ddc7b4e5b44758b73f782160c',
        '3e133ee7e671531cdd79b3206f99eeea', 'fd6e460b6c017162294d28ae127894d0', '1dc9a550af340229ad40ffd09e966dbf', '6fd25ad574e114d3d9dad6aa6ba52862',
        'b4a543b3625102e88449359bc4072ec2', '10649cca682bff4a5e9eb4c0eb49f37c', '32f930c56730f7ec99bb78347f35bb7e', 'b63a6f75a494d5a7f01f493448748495',
        '4c18b3e833b5e67e689024c82f93ba84', '3fe1fada5786d9361253f86eb34980cd', '418d38f1569d28ef395b3e0928d84381', 'ce96a9e912bff2459d5eed604758a20d',
        '20882715987583fe28f6a7b9b2eb6ebb', 'fa05d4daf5f468e3a9db4d652e82d1f6', 'ec187bb6b0f2479647cc11b937c1b711', '03cb96f5499260dfe60b6b0ea79519d5',
        'e3a807a033079af29228c2a74ff87304', 'eeba599b86d6ff5dc602de7f2bec8f6f', '65ec1380d492b9d5c6014670d34f92b5', '40d0ce0377e909bd6a8524f1e7fc0143',
        'e82d0ad925a760e046d1dff6c33f1a04', '91183c9852df6e1fed799df7b3df3282', 'ce339aa93843c519997e76e760410f6b', '81cfca7669f355025697a8f1520228d2',
        '49dd017be24439c73d3af424c21ad2a1', 'b1bd02f501686d4c8a309fdcf5d1e46e', '4495838f0f8f3d507971d53c362ff0e2', '4e5cbc8fe50667c7872404e5a9eb4adb',
        'a807f5d3ed575ee83d1cebaa76e3d706', '4d6b616171dbf06ff57d1dab8ea6bbce', 'c825bf6b2102964aaedad4930e9188d7', '7b6220493dd891604e5b7f43b55f30c3',
        'bde611db5c3545005a7270edcffd8dc2', 'a85abce54b4deb8cb157438dddca5a7c', '213353e3b82caa1fbe43db4b87f16305'];


    public $database = false;
    public $scan_log = null;
    public $doc_root = null;
    public $db_log = null;
    public $db_file = null;
    public $start_time = null;
    public $base_dir = null;

    public $last_reg = null;
    public $last_regs = [];
    public $break_point = null;
    public $skip_path = null;
    public $found = false;
    public $mem_enought = false;
    public $progress = 0;
    public $total = 0;


    function __construct($progress = 0, $total = 0)
    {
        $this->doc_root = rtrim($_SERVER['DOCUMENT_ROOT'], '/');
        $this->scan_log =  $this->doc_root. '/bitrix/modules/bitrix.xscan/file_list.txt';
        $this->db_log = $this->doc_root . '/bitrix/modules/bitrix.xscan/db_list.txt';
        $this->db_file = $this->doc_root . '/bitrix/modules/bitrix.xscan/database.json';
        $this->start_time = time();

        $mem = (int)ini_get('memory_limit');

        $this->mem_enought = $mem == -1 || $mem >= 128;

        $this->progress = $progress;
        $this->total = $total;

    }


    function clean()
    {
        if (file_exists($this->scan_log))
            unlink($this->scan_log);

        if (file_exists($this->db_log))
            unlink($this->db_log);
    }


    public static function OnBuildGlobalMenu(&$aGlobalMenu, &$aModuleMenu)
    {
        if ($GLOBALS['APPLICATION']->GetGroupRight("main") < "R")
            return;

        $MODULE_ID = basename(dirname(__FILE__));
        $aMenu = array(
            //"parent_menu" => "global_menu_services",
            "parent_menu" => "global_menu_settings",
            "section" => $MODULE_ID,
            "sort" => 50,
            "text" => $MODULE_ID,
            "title" => '',
//			"url" => "partner_modules.php?module=".$MODULE_ID,
            "icon" => "",
            "page_icon" => "",
            "items_id" => $MODULE_ID . "_items",
            "more_url" => array(),
            "items" => array()
        );

        if (file_exists($path = dirname(__FILE__) . '/admin')) {
            if ($dir = opendir($path)) {
                $arFiles = array();

                while (false !== $item = readdir($dir)) {
                    if (in_array($item, array('.', '..', 'menu.php')))
                        continue;

                    if (!file_exists($file = $_SERVER['DOCUMENT_ROOT'] . '/bitrix/admin/' . $MODULE_ID . '_' . $item))
                        file_put_contents($file, '<' . '? require($_SERVER["DOCUMENT_ROOT"]."/bitrix/modules/' . $MODULE_ID . '/admin/' . $item . '");?' . '>');

                    $arFiles[] = $item;
                }

                sort($arFiles);

                foreach ($arFiles as $item)
                    $aMenu['items'][] = array(
                        'text' => strpos($item, 'fork') !== false ? GetMessage("BITRIX_XSCAN_SEARCH_FORK") : GetMessage("BITRIX_XSCAN_SEARCH"),
                        'url' => $MODULE_ID . '_' . $item,
                        'module_id' => $MODULE_ID,
                        "title" => "",
                    );
            }
        }
        $aModuleMenu[] = $aMenu;
    }


    function CheckEvents()
    {
        global $DB;

        $r = $DB->Query('SELECT * from b_module_to_module');

        while ($row = $r->Fetch()) {
            if ($row['TO_CLASS'] && $row['TO_METHOD']) {
                $class_method = trim($row['TO_CLASS'] . '::' . $row['TO_METHOD'], '\\');
                if (in_array($class_method, self::$mehtods)) {
                    if (false === file_put_contents($this->db_log, $class_method . "\t" . $row['ID'] . "\t" . '[050] dangerous method at event, check arguments' . "\n", 8)) {
                        ShowError('Write error: ' . $this->db_log);
                        die();
                    }
                }
            }
        }
    }

    function CheckAgents()
    {
        global $DB;

        $r = $DB->Query('SELECT * from b_agent');

        while ($row = $r->Fetch()) {
            if ($row['NAME'] && $errors = $this->CheckCode($row['NAME'])) {

                $error = [];
                foreach ($errors as $value) {
                    $error[] = $value[0];
                }
                $error = implode(' ', $error);

                if (false === file_put_contents($this->db_log, '_AGENT_' . "\t" . $row['ID'] . "\t" . $error . "\n", 8)) {
                    ShowError('Write error: ' . $this->db_log);
                    die();
                }
            }
        }
    }

    static function crc($a)
    {
        return crc32(implode('|', $a));
    }

    static function CountBlocks($src, &$result)
    {
        $code = strtolower($src);

        $code = preg_replace('~<\?(php|=)?~', '', $code);
        $code = preg_replace('~<[^>$()]*?>~', '', $code);
        $code = str_replace('?>', '', $code);
        $code = preg_split('~[\n;{}(),\s]+~', $code);

        $arr = [];

        foreach ($code as $chunk) {
            $chunk = trim($chunk);

            if ($chunk !== '') {
                $arr[] = $chunk;
            }
        }

        $crcs = [];

        if (!empty($arr)) {
            while (count($arr) < 3) {
                $arr[] = $arr[0];
            }

            $block = [$arr[0], $arr[1], $arr[2]];
            $crcs[] = self::crc($block);

            $end = count($arr) - 1;
            for ($i = 3; $i <= $end; $i++) {
                $block = [$block[1], $block[2], $arr[$i]];
                $crcs[] = self::crc($block);
            }
        }

        $result = array_unique($crcs);

        unset($code);
        unset($arr);
        unset($crcs);

    }


    function SearchInDataBase($src)
    {
        $result = [];
        $found = [];
        self::CountBlocks($src, $result);

        foreach ($result as $token) {
            if (isset($this->database['tokens'][$token])) {
                foreach ($this->database['tokens'][$token] as $shell) {
                    if (!isset($found[$shell])) {
                        $found[$shell] = 0;
                    }
                    $found[$shell] += 1;
                }
            }
        }

        $bFound = False;

        foreach ($found as $key => $value) {
            if ($value / $this->database['shells'][$key] > 0.8) {
                $bFound = true;
                break;
            }
        }

        unset($result);
        unset($found);

        return $bFound;

    }

    function CheckFile($file_path)
    {
        static $me;
        if (!$me)
            $me = realpath(__FILE__);
        if (realpath($file_path) == $me)
            return false;

        if ($this->SystemFile($file_path))
            return false;

        # CODE 100
        if (basename($file_path) == '.htaccess') {
            $src = file_get_contents($file_path);
            $res = preg_match('#<(\?|script)#i', $src, $regs);
            if ($res) {
                $this->last_reg = $regs[0];
                return '[100] htaccess';
            }

            if (preg_match_all('#x-httpd-php[578]?\s+(.+)#i', $src, $regs)) {
                foreach ($regs[1] as $i => $val) {
                    $this->last_reg = $regs[0][$i];
                    $val = preg_split('/\s+/', $val);
                    foreach ($val as $ext) {
                        $ext = trim(strtolower($ext), '"\'');
                        if (!in_array($ext, ['.php', '.php5', '.php7', '.html', '']))
                            return '[100] htaccess';
                    }
                }
            }

            return false;
        }

        # CODE 110
        if (preg_match('#^/upload/.*\.php$#i', str_replace($this->doc_root, '', $file_path))) {
            return '[110] php file in upload dir';
        }

        if (!preg_match('#\.php[578]?$#i', $file_path, $regs))
            return false;

        # CODE 200
        if (false === $src = file_get_contents($file_path))
            return '[200] read error';

        $errors = $this->CheckCode($src, $file_path);

        $error = [];
        foreach ($errors as $value) {
            $error[] = $value[0];
            $this->last_regs[] = trim($value[1]);
        }

        unset($errors);
        return $error ? $error : false;
    }

    function IsFalsePositive($file_path, $code, $status)
    {
        if ($this->doc_root && strpos($file_path, $this->doc_root) === 0) {
            $file_path = substr($file_path, strlen($this->doc_root));
        } elseif ($this->base_dir) {
            $file_path = substr($file_path, strlen($this->base_dir));
        }
        
        if (strpos($file_path , '/') !== 0){
			$file_path = '/' . $file_path;
		}

        $file_path = preg_replace('#^/bitrix/modules/[a-z0-9._]+/install/components/bitrix#', '/bitrix/components/bitrix', $file_path);
        $checksum = md5($file_path . '|' . trim($code) . '|' . $status);

        return in_array($checksum, self::$false_positives, true);
    }

    function CheckCode($src, $file_path = false)
    {
        $results = [];

        if (!$this->database && is_file($this->db_file) && $this->mem_enought) {
            $tmp = file_get_contents($this->db_file);
            $this->database = json_decode($tmp, true);
            unset($tmp);
        }

        $src = preg_replace('#/\*.*?\*/#s', '', $src);
        $src = preg_replace('#[\r\n][ \t]*//.*#m', '', $src);
        $src = preg_replace('/[\r\n][ \t]*#.*/m', '', $src);

        # CODE 007
        if ($this->database && $this->SearchInDataBase($src)) {
            $results[] = ['[007] looks like a well-known shell', ''];
            return $results; // is not false-positive
        }

        $stat_vuln_check = self::CountVars($src) > 3 ? self::StatVulnCheck($src) : true;

        # CODE 300
        if (preg_match_all('#(?:[^a-z:>]|^)' . self::$evals . self::$spaces . '\(([^\)]*)\)#i', $src, $regs)) {
            foreach ($regs[1] as $i => $value) {
                $this->last_reg = $regs[0][$i];

                if (preg_match('#\$(_COOKIE|_GET|_POST|_REQUEST|_FILES|[a-z_]{2,}[0-9]{2,})#', $value)) {
                    $status = '[300] eval';
                    if (!$this->IsFalsePositive($file_path, $this->last_reg, $status)) {
                        $results[] = [$status, $this->last_reg];
                    }
                }

                if (preg_match('#' . self::$var . '#', $value, $vars)) {
                    $var = $vars[0];
                    if (preg_match('#' . preg_quote($var) . self::$spaces . ' = ' . self::$spaces . '[^;]*\$' . self::$request . '#', $src)) {
                        $status = '[300] possible eval';
                        if (!$this->IsFalsePositive($file_path, $this->last_reg, $status)) {
                            $results[] = [$status, $this->last_reg];
                        }
                    }
                }
            }
        }


        # CODE 301
        if (preg_match_all('#\b(eval|exec|passthru|pcntl_exec|popen|proc_open|set_include_path|shell_exec|system)\b#i', $src, $regs)) {
            $this->last_reg = implode('|', $regs[0]);
            $regs[0] = array_map('strtolower', $regs[0]);
            if (count($regs[0]) > 2 && count(array_unique($regs[0])) > 2) {
                $status = '[301] too many eval functions/words';
                if (!$this->IsFalsePositive($file_path, $this->last_reg, $status)) {
                    $results[] = [$status, $this->last_reg];
                }
            }

        }

        # CODE 302
        if (preg_match_all('#preg_replace' . self::$spaces . '(\(((?>[^()]+)|(?-2))*\))#i', $src, $regs)) {
            foreach ($regs[1] as $i => $val) {
                $this->last_reg = $regs[0][$i];
                $spiltter = $val[2];
                $spl = $spiltter === '#' ? '~' : '#';
                if (preg_match($spl . preg_quote($spiltter) . '[imsxADSUXju]*e[imsxADSUXju]*[\'"]' . $spl, $val)) {
                    $status = '[302] preg_replace_eval';
                    if (!$this->IsFalsePositive($file_path, $this->last_reg, $status)) {
                        $results[] = [$status, $this->last_reg];
                    }
                }
            }
        }


        # CODE 303
        if (preg_match_all('#create_function' . self::$spaces . '\(' . self::$spaces . '[^;]+(base64_decode|assert|pack|substr|rot13)#i', $src, $regs)) {
            foreach ($regs[0] as $i => $value) {
                $this->last_reg = $value;
                $status = '[303] create_function';
                if (!$this->IsFalsePositive($file_path, $this->last_reg, $status)) {
                    $results[] = [$status, $this->last_reg];
                }
            }
        }

        # CODE 304
        if (preg_match_all('#' . '(?:filter_input|filter_input_array|filter_var|filter_var_array)' . self::$spaces . '(\(((?>[^()]+)|(?-2))*\))#i', $src, $regs)) {
            foreach ($regs[1] as $i => $value) {
                $this->last_reg = $regs[0][$i];
                if (preg_match_all('#(?:_POST|_GET|_COOKIE|_REQUEST|FILTER_CALLBACK|1024|filter_input|filter_var)|' . self::$evals . '|' . self::$functions . '#i', $value) > 1) {
                    $status = '[304] filter_callback';
                    if (!$this->IsFalsePositive($file_path, $this->last_reg, $status)) {
                        $results[] = [$status, $this->last_reg];
                    }
                }
            }
        }

        # CODE 305
        if (preg_match_all('#function\s' . self::$spaces . '(\w+)#i', $src, $regs)) {
            foreach ($regs[1] as $i => $value) {
                if (preg_match_all('#eval\(' . self::$spaces . preg_quote($value) . '#i', $src, $regs2)) {
                    $this->last_reg = $regs[0][$i] . " <...> eval(" . $regs[1][$i];
                    $status = '[305] strange function and eval';
                    if (!$this->IsFalsePositive($file_path, $this->last_reg, $status)) {
                        $results[] = [$status, $this->last_reg];
                    }
                }
            }
        }

        # CODE 321
        if (preg_match_all('#[A-Za-z0-9+/]{20,}=*#i', $src, $regs)) {
            foreach ($regs[0] as $val) {
                $this->last_reg = $val;
                $val = base64_decode($val);
                if (preg_match('#(' . self::$request . '|' . self::$functions . '|' . self::$evals . ')#', $val)) {
                    $status = '[321] base64_encoded code';
                    if (!$this->IsFalsePositive($file_path, $this->last_reg, $status)) {
                        $results[] = [$status, $this->last_reg];
                    }
                }
            }
        }


        # CODE 337
        if (preg_match('#\b(wp-config|/etc/passwd|/etc/hosts|mysql_pdo|__halt_compiler)\b#i', $src, $regs)) {
            $this->last_reg = $regs[0];
            $status = '[337] strings from black list';

            if (!$this->IsFalsePositive($file_path, $this->last_reg, $status)) {
                $results[] = [$status, $this->last_reg];
            }

        }

        # CODE 350
        if (preg_match_all('#' . self::$var . self::$spaces . '=' . self::$spaces . '\$(GLOBALS|_COOKIE|_GET|_POST|_REQUEST)' . self::$spaces . '[^\[]#', $src, $regs)) {
            if ($stat_vuln_check) {
                foreach ($regs[0] as $i => $value) {
                    $this->last_reg = $value;
                    $status = '[350] global vars manipulation';
                    if (!$this->IsFalsePositive($file_path, $this->last_reg, $status)) {
                        $results[] = [$status, $this->last_reg];
                    }
                }
            }
        }

        # CODE 400
        if (preg_match_all('#\$(USER|GLOBALS..USER..)->Authorize' . self::$spaces . '(\(((?>[^()]+)|(?-2))*\))#i', $src, $regs)) {

            foreach ($regs[3] as $i => $val) {
                $this->last_reg = $regs[0][$i];

                $val = explode(',', $val)[0];

                if (preg_match('#' . self::$request . '|([\'"]?0?[xbe]?[0-9]+[\'"]?)#', $val)) {
                    $status = '[400] bitrix auth';
                    if (!$this->IsFalsePositive($file_path, $this->last_reg, $status)) {
                        $results[] = [$status, $this->last_reg];
                    }

                }
            }
        }

        # CODE 500
        if (preg_match_all('#[\'"](php://filter|phar://)#i', $src, $regs)) {
            foreach ($regs[0] as $i => $value) {
                $this->last_reg = $value;
                $status = '[500] php wrapper';

                if (!$this->IsFalsePositive($file_path, $this->last_reg, $status)) {
                    $results[] = [$status, $this->last_reg];
                }
            }
        }

        # CODE 600
        if (preg_match_all('#(include|require)(_once)?' . self::$spaces . '\([^\)]+\.([a-z0-9]+).' . self::$spaces . '\)#i', $src, $regs)) {
            foreach ($regs[0] as $i => $value) {
                $this->last_reg = $value;
                if ($regs[3][$i] != 'php' && $regs[3][$i] != 'html') {
                    $status = '[600] strange include';
                    if (!$this->IsFalsePositive($file_path, $this->last_reg, $status)) {
                        $results[] = [$status, $this->last_reg];
                    }
                }
            }
        }

        # CODE 610
        if (preg_match_all('#\$_{3,}[^a-z_]#i', $src, $regs)) {
            foreach ($regs[0] as $i => $value) {
                $this->last_reg = $value;
                $status = '[610] strange vars';
                if (!$this->IsFalsePositive($file_path, $this->last_reg, $status)) {
                    $results[] = [$status, $this->last_reg];
                }
            }
        }

        # CODE 615
        if (preg_match_all('#\${["\']\\\\x[0-9]{2}[a-z0-9\\\\]+["\']}#i', $src, $regs)) {
            foreach ($regs[0] as $i => $value) {
                $this->last_reg = $value;
                $status = '[615] hidden vars';
                if (!$this->IsFalsePositive($file_path, $this->last_reg, $status)) {
                    $results[] = [$status, $this->last_reg];
                }
            }
        }


        # CODE 620
        if (preg_match_all("#\$(?:[\x80-\xff][_\x80-\xff]*|_(?:[\x80-\xff][_\x80-\xff]*|_[_\x80-\xff]+))" . self::$spaces . '=#i', $src, $regs)) {
            foreach ($regs[0] as $i => $value) {
                $this->last_reg = $value;
                $status = '[620] binary vars';
                if (!$this->IsFalsePositive($file_path, $this->last_reg, $status)) {
                    $results[] = [$status, $this->last_reg];
                }
            }
        }

        # CODE 630
        if (preg_match('#[a-z0-9+=/\n\r]{255,}#im', $src, $regs)) {
            $this->last_reg = $regs[0];
            if (!preg_match('#data:image/[^;]+;base64,[a-z0-9+=/]{255,}#i', $src, $regs)) {
                $status = '[630] long line';
                if (!$this->IsFalsePositive($file_path, $this->last_reg, $status)) {
                    $results[] = [$status, $this->last_reg];
                }
            }
        }

        # CODE 640
        if (preg_match_all('#exif_read_data\(#i', $src, $regs)) {
            foreach ($regs[0] as $i => $value) {
                $this->last_reg = $value;
                $status = '[640] strange exif';
                if (!$this->IsFalsePositive($file_path, $this->last_reg, $status)) {
                    $results[] = [$status, $this->last_reg];
                }
            }
        }

        # CODE 650
        if (preg_match_all('#[^\\\\]' . self::$var . self::$spaces . '\(#i', $src, $regs)) {
            foreach ($regs[0] as $i => $value) {
                $this->last_reg = $value;
                if ($stat_vuln_check) {
                    $status = '[650] variable as a function';

                    if (!$this->IsFalsePositive($file_path, $this->last_reg, $status)) {
                        $results[] = [$status, $this->last_reg];
                    }
                }
            }
        }

        # CODE 660
        if (preg_match_all('#' . self::$var . '(' . self::$spaces . '\[[\'"]?[a-z0-9]+[\'"]?\])+' . self::$spaces . '\(#i', $src, $regs)) {
            foreach ($regs[0] as $i => $value) {
                $this->last_reg = $value;
                if ($stat_vuln_check) {
                    $status = '[660] array member as a function';
                    if (!$this->IsFalsePositive($file_path, $this->last_reg, $status)) {
                        $results[] = [$status, $this->last_reg];
                    }
                }
            }
        }

        # CODE 661
        if (preg_match_all('#' . self::$var . self::$spaces . '(\[(((?>[^\[\]]+)|(?-3))|(?:\\\'(?:[^\\\'\\\\]|\\\\.)*\\\')|(?:\"(?:[^\"\\\\]|\\\\.)*\"))*\]' . self::$spaces . ')+' . self::$spaces . '(\(((?>[^()]+)|(?-2))*\))#is', $src, $regs)) {
            if ($stat_vuln_check || preg_match('#' . self::$functions . '#', $src)) {
                foreach ($regs[0] as $i => $value) {
                    $this->last_reg = $value;
                    $status = '[661] array member as a function';
                    if (!$this->IsFalsePositive($file_path, $this->last_reg, $status)) {
                        $results[] = [$status, $this->last_reg];
                    }
                }
            } else {
                foreach ($regs[0] as $i => $value) {
                    if (preg_match('#' . self::$request . '#', $value)) {
                        $this->last_reg = $value;
                        $status = '[661] array member as a function';
                        if (!$this->IsFalsePositive($file_path, $this->last_reg, $status)) {
                            $results[] = [$status, $this->last_reg];
                        }
                    }
                }
            }
        }

        # CODE 662
        if (preg_match_all('#(?<=\W|^)(\w++)' . self::$spaces . '(\(((?>[^()\\\'\"]+)|(?:\\\'(?:[^\\\'\\\\]|\\\\.)*\\\')|(?:\"(?:[^\"\\\\]|\\\\.)*\")|(?-2))*\))' . self::$spaces . '(\(((?>[^()]+)|(?-2))*\))#is', $src, $regs)) {

            foreach ($regs[1] as $i => $val) {
                $this->last_reg = $regs[0][$i];
                if ($val !== '_' && function_exists($val)) {
                    $status = '[662] function return as a function';

                    if (!$this->IsFalsePositive($file_path, $this->last_reg, $status)) {
                        $results[] = [$status, $this->last_reg];
                    }

                }
            }
        }

        # CODE 663
        if (preg_match("#^.*([\x01-\x08\x0b\x0c\x0f-\x1f])#m", $src, $regs)) {
            $this->last_reg = $regs[1];
            if (!preg_match('#^\$ser_content = #', $regs[0])) {
                $status = '[663] binary data';

                if (!$this->IsFalsePositive($file_path, $this->last_reg, $status)) {
                    $results[] = [$status, $this->last_reg];
                }
            }
        }

        # CODE 665
        if ($file_path && preg_match_all('#(\\\\x[a-f0-9]{2}|\\\\[0-9]{2,3})#i', $src, $regs)) {
            $this->last_reg = implode(" ", $regs[1]);
            if (strlen(implode('', $regs[1])) / filesize($file_path) > 0.1) {
                $status = '[665] chars by code';

                if (!$this->IsFalsePositive($file_path, $this->last_reg, $status)) {
                    $results[] = [$status, $this->last_reg];
                }
            }
        }

        # CODE 700
        if (preg_match_all('#file_get_contents\(\$[^\)]+\);[^a-z]*file_put_contents#mi', $src, $regs)) {
            foreach ($regs[0] as $i => $value) {
                $this->last_reg = $value;
                $status = '[700] file from variable';
                if (!$this->IsFalsePositive($file_path, $this->last_reg, $status)) {
                    $results[] = [$status, $this->last_reg];
                }
            }
        }

        # CODE 710
        if (preg_match_all('#file_get_contents\([\'"]https?://#mi', $src, $regs)) {
            foreach ($regs[0] as $i => $value) {
                $this->last_reg = $value;
                $status = '[710] file from the Internet';
                if (!$this->IsFalsePositive($file_path, $this->last_reg, $status)) {
                    $results[] = [$status, $this->last_reg];
                }
            }
        }

        # CODE 800
        if (preg_match_all('#preg_replace\(\$_#mi', $src, $regs)) {
            foreach ($regs[0] as $i => $value) {
                $this->last_reg = $value;
                $status = '[800] preg_replace pattern from variable';
                if (!$this->IsFalsePositive($file_path, $this->last_reg, $status)) {
                    $results[] = [$status, $this->last_reg];
                }
            }
        }

        # CODE 888
        if (strpos($src, '`') !== false) { // for some perfomance

            $src_w = preg_replace_callback(
                '/<script[^>]*>.*?<\/script>/is',
                function ($matches) {
                    $php = [];
                    preg_match_all('/<\?(?:php|=).+?\?>/is', $matches[0], $php);
                    return count($php) ? implode("\n", $php[0]) : "";
                },
                $src
            );

            $src_w = preg_replace('#(?:\\\'(?:[^\\\'\\\\]|\\\\.)*\\\')|(?:\"(?:[^\"\\\\]|\\\\.)*\")#s', '""', $src_w);
            $src_w = str_ireplace(' it`s ', ' it\'is ', $src_w);

            if (preg_match_all('#`.+?`#s', $src_w, $regs)) {
                foreach ($regs[0] as $i => $value) {
                    if (preg_match('#\b(?:ls|cat|tac|sed|awk|head|tail|php|python|perl|bash|sh|wget|curl|cp|rm|mv|find|grep|pwd|cd|rmdir|mkdir)\b#i', $value)) {
                        $this->last_reg = $value;
                        $status = '[887] backticks with command';
                        if (!$this->IsFalsePositive($file_path, $this->last_reg, $status)) {
                            $results[] = [$status, $this->last_reg];
                        }
                    } elseif (preg_match('#' . self::$request . '#', $value)) {
                        $this->last_reg = $value;
                        $status = '[888] backticks with request';
                        if (!$this->IsFalsePositive($file_path, $this->last_reg, $status)) {
                            $results[] = [$status, $this->last_reg];
                        }
                    } elseif (preg_match('/\$/', $value)) {
                        $this->last_reg = $value;
                        $status = '[889] backticks with var';
                        if (!$this->IsFalsePositive($file_path, $this->last_reg, $status)) {
                            $results[] = [$status, $this->last_reg];
                        }
                    }

                }
            }
            unset($src_w);
        }

        /*
        # CODE 670
        if (preg_match('#('.self::$var.')'.self::$spaces.'\('.self::$spaces.self::$var.'#i', $code, $regs))
        {
            $this->last_reg = $regs[0];
            $src_var = $regs[1];
            while(preg_match('#\$'.str_replace('$', '', $src_var).self::$spaces.'='.self::$spaces.'('.self::$var.')#i', $code, $regs))
            {
                $src_var = str_replace('$', '', $regs[1]);
            }
            if (preg_match('#^(GLOBAL|_COOKIE|_GET|_POST|_REQUEST)$#', $src_var))
                return '[670] function from global var';
        } */

        # CODE END
        unset($regs);
        return $results;
    }

    static function CountVars($str)
    {
        $regular = '#' . self::$var . '#';
        if (!preg_match_all($regular, $str, $regs))
            return 0;
        $ar0 = $regs[0];
        $ar0 = array_unique($ar0);
        $ar0 = array_filter($ar0, function ($v) {
            return !in_array($v, ['$_GET', '$_POST', '$_REQUEST', '$_GET', '$_SERVER', '$_FILES', '$APPLICATION', '$DB', '$USER']);
        });

        return count($ar0);
    }

    static function StatVulnCheck($str, $bAll = false)
    {
        $regular = $bAll ? '#\$?[a-z_]+#i' : '#' . self::$var . '#';
        if (!preg_match_all($regular, $str, $regs))
            return false;
        $ar0 = $regs[0];
        $ar1 = array_unique($ar0);
        $uniq = count($ar1) / count($ar0);

        $ar2 = array();
        foreach ($ar1 as $var) {
            if ($bAll && function_exists($var))
                $p = 0;
            elseif ($bAll && preg_match('#^[a-z]{1,2}$#i', $var))
                $p = 1;
            elseif (preg_match('#^\$?(function|php|csv|sql|__DIR__|__FILE__|__LINE__|DBDebug|DBType|DBName|DBPassword|DBHost|APPLICATION)$#i', $var))
                $p = 0;
            elseif (preg_match('#__#', $var))
                $p = 1;
            elseif (preg_match('#^\$(ar|str)[A-Z]#', $var, $regs))
                $p = 0;
            elseif (preg_match_all('#([qwrtpsdfghjklzxcvbnm]{3,}|[a-z]+[0-9]+[a-z]+)#i', $var, $regs))
                $p = strlen(implode('', $regs[0])) / strlen($var) > 0.3;
            else
                $p = 0;

//			if ($p)
//				echo $var." => ".$p."<br>";
            $ar2[] = $p;
        }
        $prob = array_sum($ar2) / count($ar2);
        if ($prob < 0.3)
            return false;

        if (!$bAll)
            return self::StatVulnCheck($str, true);

        return true;
    }

    function Search($path)
    {
        $path = str_replace('\\', '/', $path);
        do {
            $path = str_replace('//', '/', $path, $cnt);
        } while ($cnt);

        if ($this->start_time && time() - $this->start_time > 10) {
            if (!$this->break_point)
                $this->break_point = $path;
            return;
        }

        if ($this->skip_path && !$this->found) // проверим, годится ли текущий путь
        {
            if (0 !== self::bin_strpos($this->skip_path, dirname($path))) // отбрасываем имя или идём ниже
                return;

            if ($this->skip_path == $path) // путь найден, продолжаем искать текст
                $this->found = true;
        }

        if (is_dir($path)) // dir
        {
            $p = realpath($path);
            if (strpos($p, $this->doc_root . '/bitrix/cache') === 0
                || strpos($p, $this->doc_root . '/bitrix/managed_cache') === 0
                || strpos($p, $this->doc_root . '/bitrix/stack_cache') === 0
            )
                return;

            if (is_link($path)) {
                $d = dirname($path);
                if (strpos($p, $d) !== false || strpos($d, $p) !== false) // если симлинк ведет на папку внутри структуры сайта или на папку выше
                    return true;
            }

            $dir = opendir($path);
            while ($item = readdir($dir)) {
                if ($item == '.' || $item == '..')
                    continue;

                $this->Search($path . '/' . $item);
            }
            closedir($dir);
        } else // file
        {
            if (!$this->skip_path || $this->found) {
                $this->progress += 1;
                if ($res = $this->CheckFile($path)) {
                    $this->Mark($path, $res);
                }
            }
        }
    }

    function Count_total($path)
    {
        $path = str_replace('\\', '/', $path);
        do {
            $path = str_replace('//', '/', $path, $cnt);
        } while ($cnt);

        if (is_dir($path)) // dir
        {
            $p = realpath($path);
            if (strpos($p, $this->doc_root . '/bitrix/cache') === 0
                || strpos($p, $this->doc_root . '/bitrix/managed_cache') === 0
                || strpos($p, $this->doc_root . '/bitrix/stack_cache') === 0
            )
                return;

            if (is_link($path)) {
                $d = dirname($path);
                if (strpos($p, $d) !== false || strpos($d, $p) !== false) // если симлинк ведет на папку внутри структуры сайта или на папку выше
                    return true;
            }

            $dir = opendir($path);
            while ($item = readdir($dir)) {
                if ($item == '.' || $item == '..')
                    continue;

                $this->Count_total($path . '/' . $item);
            }
            closedir($dir);
        } else // file
        {
            $this->total += 1;
        }
    }

    function SystemFile($f)
    {
        static $system = array(
            '/bitrix/modules/controller/install/activities/bitrix/controllerremoteiblockactivity/controllerremoteiblockactivity.php',
            '/bitrix/activities/bitrix/controllerremoteiblockactivity/controllerremoteiblockactivity.php',
            '/bitrix/modules/main/classes/general/update_class.php',
            '/bitrix/modules/main/classes/general/file.php',
            '/bitrix/modules/imconnectorserver/lib/connectors/telegrambot/emojiruleset.php',
            '/bitrix/modules/imconnectorserver/lib/connectors/facebook/emojiruleset.php',
            '/bitrix/modules/main/include.php',
            '/bitrix/modules/main/classes/general/update_client.php',
            '/bitrix/modules/main/install/wizard/wizard.php',
            '/bitrix/modules/main/start.php',
            '/bitrix/modules/landing/lib/mutator.php',
            '/bitrix/modules/main/tools.php',
            '/bitrix/modules/main/lib/engine/response/redirect.php',
            '/bitrix/modules/main/lib/config/option.php',
            '/bitrix/modules/main/classes/general/main.php'
        );
        foreach ($system as $path)
            if (preg_match('#' . $path . '$#', $f))
                return true;
        return false;
    }

    static function bin_strpos($s, $a)
    {
        if (function_exists('mb_orig_strpos'))
            return mb_orig_strpos($s, $a);
        return strpos($s, $a);
    }

    function Mark($f, $type)
    {
        if (is_array($type))
            $type = implode(' <br> ', array_unique($type));

        if (false === file_put_contents($this->scan_log, $f . "\t" . $type . "\n", 8)) {
            ShowError('Write error: ' . $this->scan_log);
            die();
        }
    }

    static function ShowMsg($str, $color = 'green')
    {
        $class = $color == 'green' ? 'ui-alert-primary ui-alert-icon-info' : 'ui-alert-danger ui-alert-icon-danger';
        echo '<br><div class="ui-alert ' . $class . '"><span class="ui-alert-message">' . $str . '</span></div><br>';
    }

    static function HumanSize($s)
    {
        $i = 0;
        $ar = array('b', 'kb', 'M', 'G');
        while ($s > 1024) {
            $s /= 1024;
            $i++;
        }
        return round($s, 1) . ' ' . $ar[$i];
    }

    static function getIsolateButton($file_path)
    {
        $file_path = htmlspecialcharsbx(CUtil::JSEscape($file_path));
        return '<a class="ui-btn ui-btn-danger ui-btn-sm" style="text-decoration: none; color: #ffffff;" onclick="xscan_prison(\'' . $file_path . '\')">' . GetMessage("BITRIX_XSCAN_ISOLATE") . '</a>';
    }

    static function getUnIsolateButton($file_path)
    {
        $file_path = htmlspecialcharsbx(CUtil::JSEscape($file_path));
        return '<a class="ui-btn ui-btn-success ui-btn-sm" style="text-decoration: none; color: #ffffff;" onclick="xscan_release(\'' . $file_path . '\')">' . GetMessage("BITRIX_XSCAN_UNISOLATE") . '</a>';

    }

    static function getFileWatchLink($file_path)
    {
        return sprintf(
            '<a target="_blank" href="?action=showfile&file=%s">%s</a>',
            urlencode($file_path),
            htmlspecialcharsbx($file_path)
        );
    }

    static function getFileWatchButton($file_path)
    {
        return sprintf(
            '<a class="ui-btn ui-btn-sm" style="text-decoration: none; color: #ffffff;" target="_blank" href="?action=showfile&file=%s">' . GetMessage("BITRIX_XSCAN_WATCH_EVENT") . '</a>',
            urlencode($file_path)
        );
    }

    static function getEventWatchLink($event, $table, $id)
    {
        return sprintf(
            '<a target="_blank" href="/bitrix/admin/perfmon_row_edit.php?table_name=%s&pk[ID]=%d">%s</a>',
            $table,
            $id,
            htmlspecialcharsbx($event)
        );
    }

    static function getEventWatchButton($table, $id)
    {
        return sprintf(
            '<a class="ui-btn ui-btn-sm" target="_blank" style="text-decoration: none; color: #ffffff;" href="/bitrix/admin/perfmon_row_edit.php?table_name=%s&pk[ID]=%d">' . GetMessage("BITRIX_XSCAN_WATCH_EVENT") . '</a>',
            $table,
            $id
        );
    }

    function CheckBadLog($inprogress)
    {
        if (file_exists($this->db_log) || file_exists($this->scan_log)) {
            self::ShowMsg(GetMessage("BITRIX_XSCAN_COMPLETED_FOUND"), 'red');
        }

        $output = [];

        if (file_exists($this->db_log)) {
            $ar = file($this->db_log);
            foreach ($ar as $line) {
                list($event, $id, $type) = explode("\t", $line);
                {
                    $table = $event === '_AGENT_' ? 'b_agent' : 'b_module_to_module';
                    $output[] = [
                        'data' => [
                            'FILE_NAME' => self::getEventWatchLink($event, $table, $id),
                            'FILE_TYPE' => $type,
                            'ACTIONS' => self::getEventWatchButton($table, $id)
                        ]
                    ];
                }
            }
        }

        if (file_exists($this->scan_log)) {

            $ar = file($this->scan_log);
            foreach ($ar as $line) {
                list($f, $type) = explode("\t", $line);
                {
                    $code = preg_match('#\[([0-9]+)\]#', $type, $regs) ? $regs[1] : 0;
                    $fu = urlencode(trim($f));
                    $bInPrison = strpos('[100]', $type) === false;

                    if (!file_exists($f) && file_exists($new_f = preg_replace('#\.php[578]?$#i', '.ph_', $f))) {
                        $bInPrison = false;
                        $f = $new_f;
                        $fu = urlencode(trim($new_f));
                    }

                    if ($inprogress) {
                        $action = self::getFileWatchButton($f);
                    } else {
                        $action = substr($f, -4) !== '.ph_' ? self::getIsolateButton($f) : self::getUnIsolateButton($f);
                    }

                    $output[] = [
                        'data' => [
                            'FILE_NAME' => self::getFileWatchLink($f),
                            'FILE_TYPE' => $type,
                            'FILE_SIZE' => self::HumanSize(filesize($f)),
                            'FILE_MODIFY' => ConvertTimeStamp(filemtime($f)),
                            'ACTIONS' => $action
                        ]
                    ];
                }
            }
        }
        return $output;
    }
}

?>
