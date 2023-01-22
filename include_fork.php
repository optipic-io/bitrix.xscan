<?php

//define('XSCAN_DEBUG', true);

require_once 'autoload.php';
include_once 'result.php';
include_once 'ajax.php';

use PhpParser\Error;
use PhpParser\ParserFactory;
use PhpParser\Node;
use PhpParser\NodeFinder;


IncludeModuleLangFile(__FILE__);

class CBitrixXscanFork
{
    static $var = '\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*';
    static $spaces = "[ \r\t\n]*";
    static $request = '(?:_REQUEST|_GET|_POST|_COOKIE|_SERVER(?!\[[\'"]DOCUMENT_ROOT[\'"]\])|_FILES)';
    static $functions = '(?:parse_str|hex2bin|str_rot13|base64_decode|url_decode|str_replace|str_ireplace|preg_replace|move_uploaded_file)';

    static $evals = ['eval', 'assert', 'create_function', 'exec', 'passthru', 'pcntl_exec', 'popen', 'proc_open', 'set_include_path', 'shell_exec', 'system'];

    static $evals_reg = '(?:assert|call_user_func|call_user_func_array|create_function|eval|exec|ob_start|passthru|pcntl_exec|popen|proc_open|set_include_path|shell_exec|system)';
    static $black_reg = '(wp-config|adminer_errors|/etc/passwd|/etc/hosts|mysql_pdo|__halt_compiler|/bin/sh|registerPHPFunctions|[e3]xp[l1][o0][i1][7td])';

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
    public $false_positives = ['b4cd0dcca178dbc12935e505860864ad', 'f9577fd4ffb4024a8b1c7a63247e52e7', 'cc6969f6a56325d5676bc02a268057f8',
        'cba577f08ad1a3e317d06d0bdbe03366', '84538b0cc03a220e051f0a5ba40317d0', 'fb01bfdb768e74f0947ecd1c6c4167f7', 'e3f7b36652d5432a52ff018adc600360',
        'c8e5f74977fdf2a8d7248545d57a8d7c', '86443c0c17e4da4e06a924867fca4bcc', '403eaa724f83f80b8bed8ef63463d6de', 'f33a3cd15fe1d65769adde12b61a6bb0',
        '390abb2dbcbd79d14b4f273f12839a65', '2ddb4120f80604d184c607cf9306aa65', 'b4eae279d91f26778cc0f93612c74388', '2a6af38cbb033a904433cd3e1eadfadb',
        'fd4114c3bb9e07afa58db91d1ac11db4', '43fdb449abc4a6848e822d40c770ad54', '19653fa539bbe8b3f2cc49a219978d26', '3cc92656b0b7aa744dfd6b8387b3a9d3',
        'ae6c25799d6a3023e4f23d69f60044d3', '894891406c72d7cca43fc7501cd4b473', 'f9efb0c08221ac4d015ad6aa4340d455', '78b4b8369d47450887ad1548f52c80c5',
        'eaa23061708431aeb28415ea8dd27cb2', 'c425820d051882ebc61dfe8c108ac72d', 'dcc8e224faf7b4094b881564ed94789d', '8c80d134691fdb636763e8ed67b7d143',
        '6575ba25270b69970bf53f8bc210e4e6', '265e36e2bce92126da4a73d87db0b2ed', '09b60f01cf625e299d7ef0677d7a5367', '387f09c20c44e8b2b4a7706f58775aa0',
        'ef4c6c009540957716824e53beb0e8eb', 'e4d103f6d4acb336cb59cc431df42b40', 'dae1b8d50911dd5c8667913cc1db635b', '22a3b69f22a086112deb4591141c3dcb',
        '341508805f1c3816d4dfbb6a84342c95', 'cfc085fd010b1efce3731e6c98fa2f87', '34752d188ee363dcec504ee56d6f7bed', '4478dcde3c9ff61592b8bd8b00668d1d',
        'f556e2b15879546200d6a47f4b696bea', 'f8fbccf0db5cf5ffd338c1068de965f7', 'a5fec4031b669a2d8025631ae4f9e3a5', 'e172aac95a944e737ee8966d744a4e49',
        '2db62cdafbbaf7ea26553bcdc74d377a', '24e0497031a7323c287f5a77a608a8b9', '2384aa85e8cae5590d7e96ae3b25787c', '1598f297245597f37a4b11def98d60b7',
        '1d058e7a0a4b9095e731f8f7148d4529', '31d3833ae7e956276b9d593c5c8ec6ce', '553c1676cb778525776b82c772fbac31', '8ee4547e4873fdfb53f59d91f8aedd8d',
        '611d16e8c11e4f9d6b6707786e2cf5bc', '0a5deb34f71a8e42076a220431f50ca0', 'd73fed02e89b82de599b4f5f9d589830', '0ddcbfd3762a1f1f402309aeeb150cfa',
        '4ede7019a94c00a8e94205155dbad454', '75bb0ce98bf36b96335971216c525b32', 'e43026ce215037c8e6c24eae51996167', 'f6d240c3b174966cbd139c4cccdae300',
        'f1ce7ac751e65a2cf590626a3bf4f900', '1e06181a8d4bc14aacbb86ac65cdc7be', '97411f7ff5862f81e91bbb5617485d04', '2593813e3712e99987ad6d5b06eae11d',
        'deded9267b5b14c32e9fbf0cc5ca9f73', '74481a264ba70e1604ba489969c65a44', '8b8022e7c9a404cd30bd55607003176f', '311db714976f9c64446e98716624ffe1',
        'b886d99707eab606a5eaf118cc8fc43f', '01a025a9a675695e2657091d5aff41ba', '1e9a8e92d6b1f20fd02a00f9f466da75', '0e9af9605537bb40720e88d98f0c359a',
        '85570b6f7c744679c862a2512a3ef261', 'd5e4e8dc87c16bf54b7e14639bc7154f', '25da164fa9d73ed94066c547f2b74cab', 'faf29b5b0d74f29aa4822a38e9c65f49',
        'ee78927e279c1b8857ea09fd3d2523a7', '4cb3337060be283482142f8ef392d2e0', '963697c9ee9e8d40a78438edd440b633', 'f1e9c59c39ebafc5f9f0ff74966fd240',
        '43e69f730a50b4788847fcd513c5dfbd', '89b691a1d83e43fb4ff30d38b7a35350', '92beffc5fa4408b11919002940792cca', 'c7c1f5c8f0794af2a3c6b6d39d692edb',
        '5a19d6928517c7f75e30f6b2c08d85b6', 'a92fc52f68d96feab15089164d0affb5', 'b7d458daa8258795953220c21ccb5b1e', '6ca18f5ea11eee563824cd82cedb09fc',
        '9b70f6f2f8f7fc2b0121f7fac9d13528', '0bff3775ab445ead681e2161fb72f68e', '89fd649f48e5fe2ba5cc30b2c708fbf9', 'b8d539780d1b279c7339e65c0d0adf48',
        '5fdb1f8fb980accb9c631b1e17a15ef5', 'dc1b54b70aba45502ebdfb3d792c8fb9', '1fafed24ed01e293107b75cea7577200', 'f9d82f974e2cae527dbe324c152e43f8',
        '8316d568f5455bbe92044783b77b0448', 'd48fbf5c7bdd99be4d70a2a6296d2f61', 'b5f0a4f473216004bdb56bbc6af0ef7c', 'd90ee0d040a226e4c0fcbf527d505f44',
        '0b8832919c2db5fed2394e842767d7c2', '48999592df6fc140289c655986600a6d', 'e2d8ea17c624717c526f08b40d46dfdf', '5e9045825eca260b652e1b376154dad5',
        '0a314daa859a9e5b2ef3a283481b6180', '88d32c43f47d139be47e14f2432afa51', 'd5f0dae2c9694f5e775538e230697306', '667d57fdf738cfe8177627b835b0246b',
        '6dce187f71ca54aa35da6e185aa5ba48', '51aaacf1d9b10b366de0bd886ec6c36c', 'b9be9145ff5b8c2d21a76c18ca311921', 'f8231ff8181e4930682a0a2f06b9381b',
        '4028015cd190a17d45e87ded0bfb3e47', 'c184e55459d15c5367d4dcb1a398e7ab', 'f923ef53381d8067e68beb0e056abe5d', '0dd63a40f4a80fa2abc51178869c329b',
        '14308124e820aa667cbb3e8fece4782e', '37ad3ae100ceb2adf369e9b1ef704d5c', 'c974d4e5bdc60da86e97bdee96f5e100', '9223e925409363b7db262cfea1b6a7e2',
        '012e9c936782f3a388afd505be7d80b8', 'a80791c30ecc7f9f97bd148c2d4b88a2', '95fe1cf54f5eb9afeec986b0c7cde915', '6efeb1c2b20df1a0b15e78c367255d16',
        'a8cf90e0195abe27d91eac8e73f86b78', 'a7e37e5dd04b51074a841a0bda7f22c1', 'c5ce6e939fe1061dc069c5fc4c237829', 'bbb4f3dac9a8a5e4471694a0a7fff6a7',
        'a7cb54ad97c350203b36899b5f233839', '8fc8f4891c5be11967851b40bf60a22f', '6477c3cc50d3d49f16d0e6365af13bb7', '40d0ce0377e909bd6a8524f1e7fc0143',
        'a72da233d7982f7129aba75d5759cb1d', '22a612acd639b40c7522d8db1273f39a', '3fe1fada5786d9361253f86eb34980cd', 'bbbac18a974d556a4677f3f0a72209bd',
        '349908668d99a0891fd38ff9db95cf6e', 'ee402a4f4441418be5c171d6a5f1c596', '1d9c0245a618cea4e5b93cca9006f904', 'fd7645435dbb0d9b7398500ff1028f2b',
        'd8cba3a8eb94222089e1b36aaefd9217', '8840545872730d7c133fe305f8c16260', '4a2d4a2f51507c8f8c65ac8704357903', '9ff349f064d4a252b6784194feacbdf3',
        '8eb089ad84af62471bbac6196b744068', '714dc8c269f876a169b51c9a46974b4b', 'a12531758906e42273580bcecd924187', '169ec4346ff4bb3be637897f04659813',
        'fa7d825dd782359e037116b43bb14bcd', 'adf7fabcffcf3151a704d7f917ca2279', '8a4eead89fccc87e5e49a10711239d16', '831bc46374c02842c97236742b786442',
        '7f5074ae1e7bc37bf7ad8dfeb32781d3', 'ca7c749a740de6a46a5f767c8c6fe4f0', 'f17005d04d38935fc1da872c6c170a04', '5acbf1ea71ff222ede536e4271b630f4',
        'ce0b36793128682ed49783731e5e49b4', 'ff9e3953196be49393e912ae3ae79845', 'be19c2f93a998dc6cbd8ffca050947aa', '2b5dc9b103d8b73419131b665131dada',
        '4a4a264c65ab9a0cb0fc683d756319ac', '0f6e9c98d38c2a6164028d24ffa3ab58', '45a94d1aea1bc1b770b694bfb9d5538c', 'bcde108c9067f0a131ea2ac9c8652c16',
        '8eaa7cf0428ed0c4a155c387e59424df', '6d0657a05c94ff07a0178655b5774e92', 'bdd1bc5d625d24a6438bd9d882696274', '05b42f758702e5ef05c476a8a87a0462',
        'a833468b1426b225a9620762750f86ee', '181f1db8941ff8c6b1f6118bcfa6b85f', '7bf4be2a2941c3971b0ff8300667e1a8', '58498eb72d3f93c81aeadbe5584198c2',
        'ab734aec5952d500488128d82f3c7c94', '8617e05e921d08a0ea8b67ca4225960b', '56131deea62db7378524973bd971dd6d', '5867e60fefcfeccd02d69310d2e46e7e',
        '24d9677f3dbaf25ab748e32f2b295843', '2ccd1c610df520da549fb098dd8578aa', '863dcbf5892f6d55456cc5d6aaa363cb', '72df7bc09dae9df746c8bba5afa8b182',
        '0740901426c28699d11c2ddc4bee0871', 'b64161e5b9028b8c8ed21933a67292ee', '743cbcba276fbf03b508b4e91a26a77c', 'b35bd27bf49885d63b9985ee63f1a23c',
        '231c43b77380125e2a635fd7c8346b03', '54e8c62482c81172527d2cf8849b567c', 'db2c25d1c4b3bcf52b352f9098efd663', '7dec0d485d066f769a1ea044ee9015ac',
        'c2a94b54128b295eaf8c1310ecc09ba7', '2375ac324244710597fe3f4e580fa77d', 'ae8f3c05c37d88f3dc34f5871d06d7a5', 'cc0061338d7ed0804f96f85b30c8b383',
        '0a956541ee9fe3f96a3d756737f97bdb', 'b971ef216151d30c3058f90ef91a170d', '3d4cb44aa596c4cb71e5832f4fe03e8a', 'f4b11ff30ba1838ff705ba55a22c8a51',
        'f95930a6a47880794c67e23b8d3c677b', 'e1187a996282be60cf572a16ce302833', '447b3a22b3a7fc9232b2a648ab6059ce', 'f50501737d47b8dd5549fa0e16e7501d',
        'a1e8869a52483d6c4ce403b86e74e17c', '8487afbc7d030421fb89feca37c33935', 'bb42a9fa9db4e713adbf55014ecc4793', '39edf8b962869054228932be34c5479c',
        '1f42cd7aa14e240f93f368a24670196b', '1cb5425c0e19c55a1ab32e210e0d5c47', '55f505fece8591862d149c0626f768e0', '58fbc62ff3d00f60c1ca29381ffed898',
        'c7840653475718024787aa205e741458', '41eb0db3a00bdaa9b9317170be98c5c0', '15ce789bfa6def986df98160b43c7565', 'de4f7ee97d421cf14d3951c0b4e5c2dd',
        '4d6b616171dbf06ff57d1dab8ea6bbce', 'a85abce54b4deb8cb157438dddca5a7c', 'bde611db5c3545005a7270edcffd8dc2', '40142320d26a29586dc8528cfb183aac',
        '4a171d5dc7381cce26227c5d83b5ba0c', 'b41d3b390f0f5ac060f9819e40bda7eb', '379918e8f6486ce9a7bb2ed5a69dbee6', 'e58ff78a953ec2d4012825dfbfc03032',
        '76817db6072d4d7c512fb67224ecd38a', '5f091eff2d1a95dc0213f91cc884925c', '23233e04f5391d33aff4ff46c6933216', 'b00df40b6e55ba29c5ea0fcc16e0a771',
        '1425dc46c5afae051a753a45d12d9558', '8b4be9b5cf7d7565f57d92addfdae83d', '266c40e7b80a217c0818555f3fba48cd', 'd262870ce44ffc4611038fff73227425',
        'a31a84da4bd4621f4e75fd6ccf9464a2', '45e7dfa69630c5ad949e559148876422', '5cc0e27dbcecfd682918e2c3f0dd23cf', '2f30c490f0fec71235626cc0f588f003',
        '3ac77ac5553c8455b11b687318c98760', '99e03068ab461cb188ee4d35e479830c', 'dd224767ea26d9891ea038c1f61e3468', 'a90b6bfefe0eeafe924396c05c025ebb',
        '1cabd7dae7275223b1c8172814d8ddbb', 'fc9150badf7e1cb2ae14cbc4b1822a6c', '7e5cc2377240c866b377a69e9dcf2e3f', '482b63404570c2a8aba9fb230cefaf27',
        '3aa8bd47c582c009465cd14bec581d07', '3ec0964a60de75235490170c19962a8f', 'ba46185a715cf82573f8f8870d99afc1', 'b3fd6b9e38989a4a0b64e72a5e64e907',
        '40fb23ce084b404d795c2f289ed51201', 'd79d028a3d038b28cea2af72814963d4', '1039343505c0c699e51b17fde593f5ea', '6d1956834b87120730c047f763c1db93',
        'd3f953549c08d13f8de2822dc8cedddf', '6f89aa0d2caf51dbfecbb1bd65704871', '73f348802f62793bbca3af4ec074da1d', '54ef208d2240e853c9f65c8dee47df91',
        'b927f7b045f72c9757f0c62ec3627f1d', '01eae0811290b93f0458d8aac5f0db35', 'b45278f9005f20c9b8d917255f77970a', '3b2f6666670161db2c3409d3f2927d46',
        '4b6c9eac9ef69d62c765c3c99ecd54dc', '1463dc4e73bdacdb6aa7ef5994522817', '8d217e6a6c3a1e8ee58031561708aa27', '9510b333984249622b6596f4d381cbb6',
        'e0645c5429234b5db676ad9dad9fb35b', '4cc4c6d7fdac1e7d0d78e2e218f63313', 'c37e7046e94fb1e2059b068834b10581', '4a831d3f724d731ba5aa2e39251016cf',
        '80e62ce841f68cf40439e7ddfd4a891a', '7b60c78710cdd6d30cfc7c9a2e2b4c2a', 'a1fc89e3a2fe09089908b13ec32c2298', '6dc7c6801d7eb7301f2d4fe879d4b2d5',
        '99ff5d742518b864bec71f0ee1c23a5e', '0ee94edfc7f4582f79b905dd91ac0201', 'ebf0b260888473ed00f076871bd0bab9', '507090eae9aca49578e23a5fc861c5a1',
        'fa15adaa5f749e63338da290565df9c0', '0114bff07c7843783c77ecce74531fd1', 'd56476b61570fd3b9bc2abcb826e775e', '3531f039485d12b630a9ab0131b54647',
        '25e9cc8ff31190ba591597d9c4922344', '92d9bf77559c7ae80ad2bddeaa1105fb', '1c4934bb92ecb27d2e1036c717396f63', '77449486afc383e5ce24b76a9bcbfa49',
        'e11c9047c7a2f82dccc4ec1154da9187', 'e6df2c6ecfc5a1b595913ee54ecf4495', '43cfbcbd1debe45ff53f49c9c5c02205', 'b2b7f6c696d579c118f243c9b38a95a1',
        'a8adb1d8a48667380280e18ebbe8e4d2', 'cd8a39633e78bcd2940e74f94380d0fb', 'eb0ae7e372a7f465f954260611dc9136', '24c9f64f3e9d47ed5ab8134d132d7360',
        'd865f8ff3e9f73cf015d07eacdefe2fb', 'c78a0c63a0c1c3c57bbf9bb940fbfe2a', '664d6fc1fc23ce56c7c1ca8575c2aca7', '0aaff4403e4ae8233188efd0f7fc34a5',
        '686071005f9aa9dfeb04db5d2c73ce2a', '2298d311630c971f73ba823862c431b0', '1e6b9e282d69a6891531b86376550683', 'a334bb00fa4b11392804865274281dd7',
        '0e8611eaa10005c2aa79d7b72b486cdd', '22b8a74940dca3b5645c04d3b0620978', '4ed0e3ecea2b33c58f01706d86e37eac', 'add5350b8b80c6f9ec0902fe953ee2bb',
        'f454f39a15ec9240d93df67536372c1b', '3d59f29ebee622000387b9128e7f5807', '039d9fe1ab5c4ed0597cdf5fe02f8ee7', '4b8345e71500ba0fe4f7111113111110',
        '8c97a1dd94e9c5b50da9b04004224d07', '498c6727980de07e423f5df3fc5abea2', 'c2a51a47594a4f62c0fb2c233704e27d', '8f60e8f5a703f2249d1f91da93944019',
        '74048f8a0bdec47f8c562fb9ac605df1', 'c8bd6645714efe0a320e2c7cc341995e', '14014be61f68575e1e8e4c192cc9dacf', 'fd4cbd61c22fd367d5f91b2f2a99e25a',
        'ed37e0575e9d7b5a261f943c3ab58b09', '72e78677758fb7f8e8ee0d1bc9abf684', '4e2d6d251d664f13fcf770a49d81b03d', 'c20d43dac20f4f5d7f9a7523881280e1',
        'd7968b74655f61e738c3466c2eebab34', '1ee000ce8762fb03d726b281a246d135', '27ee8709c4fc56dc0b43043c8c7d6819', '8b4a1e5420ac6706cb5944119f1838e6',
        '977a74bc53d3e424c041682c333ba430', 'd0187e6b0e43945d41f69cb60f20b317', 'c9750bf5d8f325fc85f7596ad47fa920', '3442365e421bc8ac02991db2b9fad2f2',
        '1b41cb86952bf0ce2f4e4b407cd996bd', '700c1aed073c7f73d34037fe3cd227c1', '7f26117feab0cb110f315b673d7e6cc5', '61fcfc73562a52c4c70488be1aac2d86',
        'bf7c5d93e432fdfdea39e33eb8857f41', '525fc0a96620b55f8a8dbcfc970f28a0', 'f6e1266d8355b881ee8d186914086d5f', 'd0beed57ee75cdd9312cf9310f359541',
        'ca764640ee4cf63d920b4428795d7256', '239782bca3a0529c1dde351db8c76f88', '0d6ba38e155cbd3cd8ae61243c855979', '01f561a999bda11221c922c657853b3b',
        '7ac4a2afcee04e683b092eb9402ee7ed', '1d5eb769111fc9c7be2021300ee5740e', '4d2cb64743ff3647bad4dea540d5b08e', '8061dc5864ce300288874d39ddcb4393',
        '8edc6c37de3337a454e770359e38368a', '132852d97e74c431f3f50de50b3d4320', '652e6eb68f393ffcfd2a136e06f1749d', '4fd6c85a3633703bd90dd3de923b20c8',
        '7c40653895fc8fd116400dab38c1d01a', '58ce90e11265e1816a89545851fd02a5', 'c9e0259e04fd70870e58ae45cd6b0559', 'dcec57eb656d7071811d5acf2c458344',
        'a1a02fe2f22877aaeaa3acfee7124813', '847ef973898198be3b46ef9fe83a26a9', 'a0b424dfafa2511cc1196b5ae095444b', '54b073321d41f544808ad755909b5eb1',
        '6ce6153733db7196ac1da0c64a8368dd', '54b073321d41f544808ad755909b5eb1', '6ce6153733db7196ac1da0c64a8368dd', '29bba835e33ab80598f88e438857f342',
        '1442db4a717ed00a10e7468ba79f8718', '3bdc79e30dd69dd772499439bf23f425', 'e0efc0aaa89de653176929f853934e96', '613daabc7b72f3aacb3e506ecaea40d4', 
        '4d56661845e06da37a6d5027ae4b0aab', '80ccc8843206fc7c6a08486748204c1b', '4d56661845e06da37a6d5027ae4b0aab', '80ccc8843206fc7c6a08486748204c1b',
        'a5b078e8aedc3e9ffa127487350f1111', '0560f452bafbdbc357734cc69f54d1d2'];


    static $default_config = ['request' => true, 'from_request' => true, 'crypted' => true, 'files' => true,
        'assigned' => false, 'params' => false, 'concat' => true, 'hardcoded' => false, 'value' => true];

    public $database = false;
    public $db_log = null;
    public $db_file = null;
    public $doc_root = null;

    public $start_time = null;
    public $time_limit = null;
    public $base_dir = null;

    public $break_point = null;
    public $skip_path = null;
    public $found = false;
    public $mem_enought = false;
    public $progress = 0;
    public $total = 0;
    public $errors = [];

    # todo: !!!!
    static $cryptors = ['rot13', 'str_rot13', 'base32_decode', 'base64_decode', 'gzinflate', 'unserialize',
        'url_decode', 'pack', 'unpack', 'hex2bin', 'bzdecompress', 'gzuncompress', 'lzf_decompress', 'strrev'];

    static $string_change = ['preg_replace', 'str_ireplace', 'str_replace', 'substr', 'strrev'];

    static $scoring = [
        '[337] strings from black list' => ['self' => 0.9],
        '[630] long line' => ['self' => 0.4],
        '[321] base64_encoded code' => ['self' => 0.8],
        '[610] strange vars' => ['self' => 0.5],
        '[302] preg_replace_eval' => ['self' => 0.9],
        '[663] binary data' => ['self' => 0.75],
        '[640] strange exif' => ['self' => 0.6],
        '[500] php wrapper' => ['self' => 0.7],
        '[665] chars by code' => ['self' => 0.5],
        '[665] encoded code' => ['self' => 0.8],
        '[665] chars by code' => ['self' => 0.8],


        '[303] create_function' =>
            [
                'self' => 0.8,
                'args' =>
                    [
                        'strange concatination' => 0.8,
                        'hardcoded value' => 0.1,
                        'request' => 1,
                        'danger function' => 0.8,
                        'var from params' => 0.3,
                        'var was not assigned' => 0.7,
                        'crypted var' => 0.5,
                        'var from request' => 0.8,
                    ],
            ],
        '[300] eval' =>
            [
                'self' => 1,
                'args' =>
                    [
                        'strange concatination' => 0.4,
                        'hardcoded value' => 0.1,
                        'request' => 1,
                        'danger function' => 0.8,
                        'var from params' => 0.3,
                        'var was not assigned' => 0.7,
                        'crypted var' => 0.5,
                        'var from request' => 0.9,
                    ],
            ],
        '[302] unsafe callable argument' =>
            [
                'self' => 0.8,
                'args' =>
                    [
                        'strange concatination' => 0.8,
                        'hardcoded value' => 0.1,
                        'request' => 1,
                        'danger function' => 0.8,
                        'var from params' => 0.3,
                        'var was not assigned' => 0.7,
                        'crypted var' => 0.5,
                        'var from request' => 0.8,
                    ],
            ],
        '[307] danger method' =>
            [
                'self' => 1,
                'args' =>
                    [
                        'strange concatination' => 0.4,
                        'hardcoded value' => 0.1,
                        'request' => 1,
                        'danger function' => 0.8,
                        'var from params' => 0.3,
                        'var was not assigned' => 0.7,
                        'crypted var' => 0.5,
                        'var from request' => 0.9,
                    ],
            ],
        '[662] function return as a function' =>
            [
                'self' => 0.9,
                'args' =>
                    [
                        'strange concatination' => 0.8,
                        'hardcoded value' => 0.1,
                        'request' => 1,
                        'danger function' => 1,
                        'var from params' => 0.3,
                        'var was not assigned' => 0.7,
                        'crypted var' => 0.7,
                        'var from request' => 0.8,
                    ],
            ],
        '[663] strange function' =>
            [
                'self' => 1,
                'args' =>
                    [
                        'strange concatination' => 1,
                        'hardcoded value' => 0.1,
                        'request' => 1,
                        'danger function' => 1,
                        'var from params' => 0.8,
                        'var was not assigned' => 0.7,
                        'crypted var' => 0.8,
                        'var from request' => 0.9,
                    ],
            ],
        '[302] eregi' =>
            [
                'self' => 0.8,
                'args' =>
                    [
                        'strange concatination' => 0.8,
                        'hardcoded value' => 0.1,
                        'request' => 1,
                        'danger function' => 0.8,
                        'var from params' => 0.3,
                        'var was not assigned' => 0.7,
                        'crypted var' => 0.5,
                        'var from request' => 0.8,
                    ],
            ],
        '[887] backticks' =>
            [
                'self' => 1,
                'args' =>
                    [
                        'strange concatination' => 0.8,
                        'hardcoded value' => 0.1,
                        'request' => 1,
                        'danger function' => 0.8,
                        'var from params' => 0.3,
                        'var was not assigned' => 0.7,
                        'crypted var' => 0.5,
                        'var from request' => 0.8,
                    ],
            ],
        '[600] strange include' =>
            [
                'self' => 0.8,
                'args' =>
                    [
                        'strange concatination' => 0.8,
                        'hardcoded value' => 0.1,
                        'request' => 1,
                        'danger function' => 0.8,
                        'var from params' => 0.3,
                        'var was not assigned' => 0.7,
                        'crypted var' => 0.5,
                        'var from request' => 0.8,
                    ],
            ],
        '[660] array member as a function' =>
            [
                'self' => 0.9,
                'args' =>
                    [
                        'strange concatination' => 0.8,
                        'hardcoded value' => 0.1,
                        'request' => 1,
                        'danger function' => 0.8,
                        'var from params' => 0.3,
                        'var was not assigned' => 0.5,
                        'crypted var' => 0.5,
                        'var from request' => 0.8,
                    ],
            ],
        '[298] mysql function' =>
            [
                'self' => 0.6,
                'args' =>
                    [
                        'strange concatination' => 0.8,
                        'hardcoded value' => 0.1,
                        'request' => 1,
                        'danger function' => 0.8,
                        'var from params' => 0.9,
                        'var was not assigned' => 0.7,
                        'crypted var' => 0.5,
                        'var from request' => 0.8,
                    ],
            ],
        '[300] command injection' =>
            [
                'self' => 1,
                'args' =>
                    [
                        'strange concatination' => 0.7,
                        'hardcoded value' => 0.1,
                        'request' => 1,
                        'danger function' => 0.8,
                        'var from params' => 0.6,
                        'var was not assigned' => 0.7,
                        'crypted var' => 0.5,
                        'var from request' => 0.9,
                    ],
            ],
        '[299] mail function' =>
            [
                'self' => 0.6,
                'args' =>
                    [
                        'strange concatination' => 0.8,
                        'hardcoded value' => 0.1,
                        'request' => 1,
                        'danger function' => 0.8,
                        'var from params' => 0.3,
                        'var was not assigned' => 0.7,
                        'crypted var' => 0.5,
                        'var from request' => 0.8,
                    ],
            ],
        '[650] variable as a function' =>
            [
                'self' => 0.9,
                'args' =>
                    [
                        'strange concatination' => 0.8,
                        'hardcoded value' => 0.1,
                        'request' => 1,
                        'danger function' => 0.8,
                        'var from params' => 0.3,
                        'var was not assigned' => 0.5,
                        'crypted var' => 0.5,
                        'var from request' => 0.8,
                    ],
            ],
        '[304] filter_callback' =>
            [
                'self' => 0.6,
                'args' =>
                    [
                        'strange concatination' => 0.8,
                        'hardcoded value' => 0.1,
                        'request' => 1,
                        'danger function' => 0.8,
                        'var from params' => 0.3,
                        'var was not assigned' => 0.7,
                        'crypted var' => 0.5,
                        'var from request' => 0.8,
                    ],
            ],
        '[305] strange function and eval' =>
            [
                'self' => 0.8,
                'args' =>
                    [
                        'strange concatination' => 0.8,
                        'hardcoded value' => 0.1,
                        'request' => 1,
                        'danger function' => 0.8,
                        'var from params' => 0.3,
                        'var was not assigned' => 0.7,
                        'crypted var' => 0.5,
                        'var from request' => 0.8,
                    ],
            ],
        '[301] file operations' =>
            [
                'self' => 0.5,
                'args' =>
                    [
                        'strange concatination' => 0.4,
                        'hardcoded value' => 0.1,
                        'request' => 1,
                        'danger function' => 0.8,
                        'var from params' => 0.3,
                        'var was not assigned' => 0.7,
                        'crypted var' => 0.5,
                        'var from request' => 0.8,
                    ],
            ],
        '[400] bitrix auth' =>
            [
                'self' => 0.9,
                'args' =>
                    [
                        'strange concatination' => 0.8,
                        'hardcoded value' => 1,
                        'request' => 1,
                        'danger function' => 0.8,
                        'var from params' => 0.3,
                        'var was not assigned' => 0.7,
                        'crypted var' => 0.5,
                        'var from request' => 0.8,
                    ],
            ],
    ];

    public $results = [];
    public $result_collection = Null;
    public $score = 1;

    function __construct($progress = 0, $total = 0)
    {
        $this->doc_root = rtrim($_SERVER['DOCUMENT_ROOT'], '/');

        $this->result_collection = class_exists('XScanResults') ? new XScanResults() : [];
        $this->db_file = $this->doc_root . '/bitrix/modules/bitrix.xscan/database.json';
        $this->start_time = time();

        $mem = (int)ini_get('memory_limit');
        $this->time_limit = ini_get('max_execution_time') ?: 30;
        $this->time_limit = min($this->time_limit, 30);
        $this->time_limit = $this->time_limit * 0.7;

        $this->mem_enought = $mem == -1 || $mem >= 128;

        $this->progress = $progress;
        $this->total = $total;

        $this->parser = (new PhpParser\ParserFactory)->create(PhpParser\ParserFactory::PREFER_PHP7);
        $this->nodeFinder = new NodeFinder;
        $this->errorHandler = new PhpParser\ErrorHandler\Collecting;
        $this->pprinter = new PhpParser\PrettyPrinter\Standard;

        if (class_exists('XScanResultTable')){
            $errs = XScanResultTable::getList(['select' => ['src'], 'filter' => ['type' => 'file', 'message' => 'error']]);

            while ($row = $errs->fetch()) {
                $this->errors[] = $row['src'];
            }
        }

    }

    function clean()
    {
        global $DB;
        $DB->Query("TRUNCATE TABLE b_xscan_results", true);
        $this->errors = [];
    }


//    public static function OnBuildGlobalMenu(&$aGlobalMenu, &$aModuleMenu)
//    {
//        if ($GLOBALS['APPLICATION']->GetGroupRight("main") < "R")
//            return;
//
//        $MODULE_ID = basename(dirname(__FILE__));
//        $aMenu = array(
//            //"parent_menu" => "global_menu_services",
//            "parent_menu" => "global_menu_settings",
//            "section" => $MODULE_ID,
//            "sort" => 50,
//            "text" => $MODULE_ID,
//            "title" => '',
////			"url" => "partner_modules.php?module=".$MODULE_ID,
//            "icon" => "",
//            "page_icon" => "",
//            "items_id" => $MODULE_ID . "_items",
//            "more_url" => array(),
//            "items" => array()
//        );
//
//        if (file_exists($path = dirname(__FILE__) . '/admin')) {
//            if ($dir = opendir($path)) {
//                $arFiles = array();
//
//                while (false !== $item = readdir($dir)) {
//                    if (in_array($item, array('.', '..', 'menu.php')))
//                        continue;
//
//                    if (!file_exists($file = $_SERVER['DOCUMENT_ROOT'] . '/bitrix/admin/' . $MODULE_ID . '_' . $item))
//                        file_put_contents($file, '<' . '? require($_SERVER["DOCUMENT_ROOT"]."/bitrix/modules/' . $MODULE_ID . '/admin/' . $item . '");?' . '>');
//
//                    $arFiles[] = $item;
//                }
//
//                sort($arFiles);
//
//                foreach ($arFiles as $item)
//                    $aMenu['items'][] = array(
//                        'text' => GetMessage("BITRIX_XSCAN_SEARCH"),
//                        'url' => $MODULE_ID . '_' . $item,
//                        'module_id' => $MODULE_ID,
//                        "title" => "",
//                    );
//            }
//        }
//        $aModuleMenu[] = $aMenu;
//    }


    function CheckEvents()
    {
        global $DB;

        $r = $DB->Query('SELECT * from b_module_to_module');

        while ($row = $r->Fetch()) {
            if ($row['TO_CLASS'] && $row['TO_METHOD']) {
                $class_method = trim($row['TO_CLASS'] . '::' . $row['TO_METHOD'], '\\');
                $found = false;
                foreach (self::$mehtods as $mtd) {
                    if (stripos($class_method, $mtd) !== False) {
                        $found = true;
                        break;
                    }
                }

                if ($found) {
                    $result = (new XScanResult)->setType('event')->setSrc($row['ID'])->setScore(1)->setMessage('[050] dangerous method at event, check arguments');
                    $this->result_collection[] = $result;
                }
            }
        }
    }

    function CheckAgents()
    {
        global $DB;

        $r = $DB->Query('SELECT * from b_agent');

        while ($row = $r->Fetch()) {
            if (!$row['NAME']) {
                continue;
            }

            $src = "<?php\n" . $row['NAME'] . "\n?>";
            $this->CheckCode($src);

            if ($this->results) {

                $message = [];
                foreach ($this->results as $res) {
                    $message[] = $res['subj'];
                }

                if (is_array($message)) {
                    $message = implode(' <br> ', array_unique($message));
                }

                $result = (new XScanResult)->setType('agent')->setSrc($row['ID'])->setScore(1)->setMessage($message);
                $this->result_collection[] = $result;

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

    function addResult($subj, $code, $score)
    {
        $this->results[] = ['subj' => $subj, 'code' => $code, 'score' => $score];
    }

    function CheckFile($file_path)
    {
        static $me;
        if (!$me)
            $me = realpath(__FILE__);
        if (realpath($file_path) == $me) {
            return false;
        }

        if (in_array($file_path, $this->errors)) {
            return false;
        }

        if ($this->SystemFile($file_path)) {
            return false;
        }

        # CODE 100
        if (basename($file_path) == '.htaccess') {
            $src = file_get_contents($file_path);
            $res = preg_match('#<(\?|script)#i', $src, $regs);
            if ($res) {
                $this->addResult('[100] htaccess', $regs[0], 1);
                return true;
            }

            if (preg_match_all('#x-httpd-php[578]?\s+(.+)#i', $src, $regs)) {
                foreach ($regs[1] as $i => $val) {
                    $val = preg_split('/\s+/', $val);
                    foreach ($val as $ext) {
                        $ext = trim(strtolower($ext), '"\'');
                        if (!in_array($ext, ['.php', '.php5', '.php7', '.html', ''])) {
                            $this->addResult('[100] htaccess', $regs[0][$i], 1);
                            return true;
                        }
                    }
                }
            }

            return false;
        }

        # CODE 110
        if (preg_match('#^/upload/.*\.php$#i', str_replace($this->doc_root, '', $file_path))) {
            $this->addResult('[110] php file in upload dir', '', 1);
            return true;
        }

        if (!preg_match('#\.php[578]?$#i', $file_path, $regs)) {
            return false;
        }

        # CODE 200
        if (false === $src = file_get_contents($file_path)) {
            $this->addResult('[200] read error', '', 1);
            return true;
        }

        $this->CheckCode($src, $file_path);
        $tot = 1;

        foreach ($this->results as $value) {
            $tot = $tot * (1 - $value['score']);
        }

        $tot = round(1 - $tot, 2);

        $this->score = $tot;

        return !empty($this->results);

    }

    function CalcChecksum($file_path, $code, $subj)
    {
        if ($this->doc_root && strpos($file_path, $this->doc_root) === 0) {
            $file_path = substr($file_path, strlen($this->doc_root));
        } elseif ($this->base_dir) {
            $file_path = substr($file_path, strlen($this->base_dir));
        }

        if (strpos($file_path, '/') !== 0) {
            $file_path = '/' . $file_path;
        }

        $file_path = preg_replace('#^/bitrix/modules/[a-z0-9._]+/install/components/bitrix#', '/bitrix/components/bitrix', $file_path);
        $checksum = md5($file_path . '|' . trim($code) . '|' . $subj);

        return $checksum;
    }

    function IsFalsePositive($checksum)
    {
        return in_array($checksum, $this->false_positives, true);
    }

    function CheckCode(&$src, $file_path = false)
    {
        $this->results = [];
        $file_path = $file_path ? $file_path : '';

        if (!$this->database && is_file($this->db_file) && $this->mem_enought) {
            $tmp = file_get_contents($this->db_file);
            $this->database = json_decode($tmp, true);
            unset($tmp);
        }


        $code = mb_convert_encoding($src, 'UTF-8', 'CP1251');

        $code = preg_replace("/<\?=/", "<?php echo ", $code);
        $code = preg_replace("/<\?(?!php)/", "<?php ", $code);
        $code = preg_replace("/else if\s*\(/", "elseif (", $code); // crutch

        $parser = $this->parser;
        $errorHandler = $this->errorHandler;
        $pprinter = $this->pprinter;

        $errorHandler->clearErrors();

        try {
            $stmts = $parser->parse($code, $errorHandler);
            $params = [];

            if (!$stmts && $errorHandler->getErrors()) {
                throw new Exception('syntax error in file');
            }

            $this->CheckStmts($stmts, $params, $file_path);

        } catch (Exception $e) {
            //  echo 'Parse Error: ' . $file_path . " " . $e->getMessage() . "\n";
            $this->addResult('[000] syntax error in file', '', 1);
        }

        # REGEXP BASED CODES

        $src = preg_replace('#/\*.*?\*/#s', '', $src);
        $src = preg_replace('#[\r\n][ \t]*//.*#m', '', $src);
        $src = preg_replace('/[\r\n][ \t]*#.*/m', '', $src);

        # CODE 007
        if ($this->database && $this->SearchInDataBase($src)) {
            $this->addResult('[007] looks like a well-known shell', '', 1);
            return true; // is not false-positive
        }

        # CODE 302
        if (preg_match_all('#preg_replace' . self::$spaces . '(\(((?>[^()]+)|(?-2))*\))#i', $src, $regs)) {
            foreach ($regs[1] as $i => $val) {
                $code = $regs[0][$i];
                $spiltter = $val[2];
                $spl = $spiltter === '#' ? '~' : '#';
                if (preg_match($spl . preg_quote($spiltter) . '[imsxADSUXju]*e[imsxADSUXju]*[\'"]' . $spl, $val)) {
                    $status = '[302] preg_replace_eval';
                    $checksum = $this->CalcChecksum($file_path, $code, $status);
                    if (!$this->IsFalsePositive($checksum)) {
                        $this->addResult($status, $code, self::CaclCrit($status));
                    }
                }
            }
        }

        $content = preg_replace('/[\'"]\s*?\.\s*?[\'"]/smi', '', $src);

        # CODE 321
        if (preg_match_all('#[A-Za-z0-9+/]{20,}=*#i', $content, $regs)) {
            foreach ($regs[0] as $val) {
                $code = $val;
                $val = base64_decode($val);
                if (preg_match('#(' . self::$request . '|' . self::$functions . '|' . self::$evals_reg . '|' . self::$black_reg . ')#i', $val)) {
                    $status = '[321] base64_encoded code';
                    $checksum = $this->CalcChecksum($file_path, $code, $status);
                    if (!$this->IsFalsePositive($checksum)) {
                        $this->addResult($status, $code, self::CaclCrit($status));
                    }
                }
            }
        }
//        unset($content);


        # CODE 337
        if (preg_match_all('#' . self::$black_reg . '#i', $content, $regs)) {
            $code = implode(' | ', $regs[0]);

            $status = '[337] strings from black list';
            $checksum = $this->CalcChecksum($file_path, $code, $status);
            if (!$this->IsFalsePositive($checksum)) {
                $this->addResult($status, $code, self::CaclCrit($status));
            }
        }

        # CODE 400
        /*        if (preg_match_all('#\$(USER|GLOBALS..USER..)->Authorize' . self::$spaces . '(\(((?>[^()]+)|(?-2))*\))#i', $src, $regs)) {*/
//
//            foreach ($regs[3] as $i => $val) {
//                $code = $regs[0][$i];
//
//                $val = explode(',', $val)[0];
//
//                if (preg_match('#' . self::$request . '|([\'"]?0?[xbe]?[0-9]+[\'"]?)#', $val)) {
//                    $status = '[400] bitrix auth';
//                    if ($checksum = $this->CalcChecksum($file_path, $code, $status)  && $this->IsFalsePositive($checksum)) {
//                        $this->results[] = [$status, $code];
//                    }
//
//                }
//            }
//        }

        # CODE 500
        if (preg_match_all('#[\'"](php://filter|phar://)#i', $content, $regs)) {
            foreach ($regs[0] as $i => $value) {
                $code = $value;
                $status = '[500] php wrapper';
                $checksum = $this->CalcChecksum($file_path, $code, $status);
                if (!$this->IsFalsePositive($checksum)) {
                    $this->addResult($status, $code, self::CaclCrit($status));
                }

            }
        }

        # CODE 630
        if (preg_match('#[a-z0-9+=/\n\r]{255,}#im', $src, $regs)) {
            $code = $regs[0];
            if (!preg_match('#data:image/[^;]+;base64,[a-z0-9+=/]{255,}#i', $src, $regs)) {
                $status = '[630] long line';
                $checksum = $this->CalcChecksum($file_path, $code, $status);
                if (!$this->IsFalsePositive($checksum)) {
                    $this->addResult($status, $code, self::CaclCrit($status));
                }
            }
        }

        # CODE 640
        if (preg_match_all('#exif_read_data\(#i', $src, $regs)) {
            foreach ($regs[0] as $i => $value) {
                $code = $value;
                $status = '[640] strange exif';
                $checksum = $this->CalcChecksum($file_path, $code, $status);
                if (!$this->IsFalsePositive($checksum)) {
                    $this->addResult($status, $code, self::CaclCrit($status));
                }
            }
        }

        # CODE 663
        if (preg_match("#^.*([\x01-\x08\x0b\x0c\x0f-\x1f])#m", $src, $regs)) {
            $code = $regs[1];
            if (!preg_match('#^\$ser_content = #', $regs[0])) {
                $status = '[663] binary data';
                $checksum = $this->CalcChecksum($file_path, $code, $status);
                if (!$this->IsFalsePositive($checksum)) {
                    $this->addResult($status, $code, self::CaclCrit($status));
                }
            }
        }

        # CODE 665
        if ($file_path && preg_match_all('#(?:\\\\x[a-f0-9]{2}|\\\\[0-9]{2,3})+#i', $content, $regs)) {
            $regs = $regs[0];
            $all = implode("", $regs);
            if (count($regs) > 1) {
                $regs[] = $all;
            }
            $found = False;

            foreach ($regs as $code) {
                $val = stripcslashes($code);
                if (preg_match('#(' . self::$request . '|' . self::$functions . '|' . self::$evals_reg . '|' . self::$black_reg . ')#i', $val)) {
                    $status = '[665] encoded code';
                    $checksum = $this->CalcChecksum($file_path, $code, $status);
                    if (!$this->IsFalsePositive($checksum)) {
                        $this->addResult($status, $code, self::CaclCrit($status));
                        $found = True;
                    }
                } elseif (preg_match_all('#[A-Za-z0-9+/]{20,}=*#i', $val, $regs)) {
                    foreach ($regs[0] as $val) {
                        $val = base64_decode($val);
                        if (preg_match('#(' . self::$request . '|' . self::$functions . '|' . self::$evals_reg . '|' . self::$black_reg . ')#i', $val)) {
                            $status = '[665] encoded code';
                            $checksum = $this->CalcChecksum($file_path, $code, $status);
                            if (!$this->IsFalsePositive($checksum)) {
                                $this->addResult($status, $code, self::CaclCrit($status));
                                $found = True;
                            }
                        }
                    }
                }
            }

            if (!$found && strlen($all) / filesize($file_path) > 0.1) {
                $status = '[665] chars by code';
                $checksum = $this->CalcChecksum($file_path, $code, $status);
                if (!$this->IsFalsePositive($checksum)) {
                    $this->addResult($status, $code, self::CaclCrit($status));
                }
            }

        }

        unset($src);
        unset($content);

        return !empty($this->results);
    }


    function CheckStmts($stmts, &$params, $file_path, $in_closure = False)
    {
        $nodeFinder = $this->nodeFinder;
        $pprinter = $this->pprinter;

        $nodeFinder->find($stmts, function (Node $node) use (&$file_path) {
            if ($node instanceof Node\Stmt\Function_ || $node instanceof Node\Stmt\ClassMethod) {
                $this->CheckStmts($node->stmts, $node->params, $file_path);
                $node->stmts = [];
            } elseif ($node instanceof Node\Expr\Closure) {
                $this->CheckStmts($node->stmts, $node->params, $file_path, true);
                $node->stmts = [];
            } elseif ($node instanceof Node\Expr\ArrowFunction) {
                $this->CheckStmts($node->expr, $node->params, $file_path, true);
                $node->stmts = [];
            }
        });

        $nodes = ['assigns' => [], 'variables' => [], 'params' => [], 'foreaches' => [], 'calls' => [], 'evals' => [], 'backticks' => [], 'includes' => [], 'auth' => [], 'mtds' => []];
        $extract = false;

        $nodeFinder->find($stmts, function (Node $node) use (&$nodes, &$pprinter, &$extract) {

            if ($node->getComments()) {
                $node->setAttribute('comments', []);
            }

//            if ($node instanceof Node\Stmt\Function_) {
//                $name = $node->name instanceof Node\Identifier ? $node->name->toString() : False;
//                if (is_string($name) && self::isVarStrange('$' . trim($name, '_'))) {
//                    $this->addResult('[110] strange function name', $name, 0.3);
//                }
//            }
            if ($node instanceof Node\Expr\Assign || $node instanceof Node\Expr\AssignOp) {
                $nodes['assigns'][] = $node;
            }
            if ($node instanceof Node\Expr\Variable) {
                $nodes['variables'][] = $node;
            }
            if ($node instanceof Node\Stmt\Foreach_) {
                $nodes['foreaches'][] = $node;
            }
            if ($node instanceof Node\Expr\FuncCall) {
                $nodes['calls'][] = $node;
                if ($node->name instanceof Node\Name && $node->name->toLowerString() === 'extract') {
                    if (count($node->args) < 2 || $pprinter->prettyPrintExpr($node->args[1]->value) !== 'EXTR_SKIP') {
                        $extract = True;
                    }
                }
            }
            if ($node instanceof Node\Expr\Eval_) {
                $nodes['evals'][] = $node;
            }
            if ($node instanceof Node\Expr\ShellExec) {
                $nodes['backticks'][] = $node;
            }
            if ($node instanceof Node\Expr\Include_) {
                $nodes['includes'][] = $node;
            }
            if ($node instanceof Node\Expr\MethodCall && $node->name instanceof Node\Identifier && $node->name->toLowerString() == 'authorize'
                && preg_match('/user/i', $pprinter->prettyPrintExpr($node->var))) {

                $nodes['auth'][] = $node;
            }

            if ($node instanceof Node\Expr\StaticCall) {
                $nodes['mtds'][] = $node;
            }

            # this is dirty hack
            if ($node instanceof Node\Expr\ArrayDimFetch && $node->var instanceof Node\Expr\Variable && $node->var->name == '_SERVER') {
                $dim = $node->dim instanceof Node\Scalar\String_ ? $node->dim->value : "qwerty";
                if (!preg_match('/^(?:DOCUMENT_ROOT|SERVER_ADDR|REMOTE_ADDR|SERVER_NAME|HTTPS|SERVER_PORT|REMOTE_PORT)$/', $dim)) {
                    $node->var->name = '_REQUEST';
                }
            }

//            if ($node instanceof Node\Expr\ArrayDimFetch && $node->var instanceof Node\Expr\Variable && $node->var->name == 'GLOBALS') {
//                $dim = $node->dim instanceof Node\Scalar\String_ ? $node->dim->value : "qwerty";
//                if (preg_match('/^(?:_GET|_POST|_REQUEST|_COOKIE|_FILES|_SERVER)$/', $dim)) {
//                    $node->var->name = '_REQUEST';
//                }
//            }
        });

        $vars_names = [];

        $vars = [
            'request' => ['_GET' => true, '_POST' => true, '_REQUEST' => true, '_COOKIE' => true, '_FILES' => true],
            'params' => [],
            'from_request' => [],
            'crypted' => [],
            'assigned' => ['_GET' => true, '_POST' => true, '_REQUEST' => true, '_COOKIE' => true, '_SESSION' => true,
                '_SERVER' => true, '_FILES' => true, 'this' => true, 'USER' => true, 'DB' => true, 'APPLICATION' => true],
            'values' => [],
            'closures' => []
        ];

        foreach ($nodes['variables'] as $var) {
            if (is_string($var->name)) {
                $var = '$' . $var->name;
            } else {
                $var = $this->pprinter->prettyPrintExpr($var->name);
            }

            $vars_names[] = $var;

        }
        $vars_names = array_unique($vars_names);

        foreach ($params as $param) {
            $n = substr($this->pprinter->prettyPrintExpr($param->var), 1);
            $vars['params'][$n] = true;
            $vars['assigned'][$n] = true;

            if ($param->type instanceof Node\Name\FullyQualified && implode('', $param->type->parts) == 'Closure') {
                $vars['closures'][] = $n;
            }
        }

        foreach ($nodes['assigns'] as $fnd) {
            $n = substr($this->pprinter->prettyPrintExpr($fnd->var), 1);
            $vars['assigned'][$n] = true;
            if ($fnd->expr instanceof Node\Expr\Closure) {
                $vars['closures'][] = $n;
            }
        }

        foreach ($nodes['foreaches'] as $fnd) {
            if ($fnd->keyVar) {
                $n = substr($this->pprinter->prettyPrintExpr($fnd->keyVar), 1);
                $vars['assigned'][$n] = true;
            }
            if ($fnd->valueVar) {
                $n = substr($this->pprinter->prettyPrintExpr($fnd->valueVar), 1);
                $vars['assigned'][$n] = true;
            }
        }

        for ($_ = 0; $_ < 2; $_++) {
            $res = [];
            foreach ($nodes['assigns'] as $node) {
                $flag = $nodeFinder->findFirst($node->expr,
                    function (Node $node) use (&$vars) {
                        return $node instanceof Node\Expr\Variable && is_string($node->name) && $node->name && (isset($vars['request'][$node->name]) || isset($vars['from_request'][$node->name]));
                    }
                );

                if ($flag) {
                    $res[] = $node;
                }

            }

            foreach ($res as $fnd) {
                $n = substr($this->pprinter->prettyPrintExpr($fnd->var), 1);
                $vars['from_request'][$n] = true;
            }

        }


        for ($_ = 0; $_ < 1; $_++) {
            $res = [];
            foreach ($nodes['assigns'] as $node) {
                $flag = $nodeFinder->findFirst($node->expr,
                    function (Node $node) {
                        return $node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name &&
                            in_array($node->name->toLowerString(), self::$cryptors, True);
                    }
                );
                if ($flag) {
                    $res[] = $node;
                }

            }

            foreach ($res as $fnd) {
                $n = substr($this->pprinter->prettyPrintExpr($fnd->var), 1);
                $vars['crypted'][$n] = true;
            }
        }

        foreach ($nodes['assigns'] as $fnd) {
            $n = substr($this->pprinter->prettyPrintExpr($fnd->var), 1);
            $tmp = $this->parseValue($fnd->expr, $vars);
            if (!isset($vars['values'][$n])) {
                $vars['values'][$n] = $tmp;
            } else {
                $vars['values'][$n] .= '|' . $tmp;
            }
        }

//        print_r($vars['values']);

        $crypto_vars = array_keys($vars['crypted']);

        # CODE 300

        $res = [];
        $config = self::genConfig(['params' => True, 'assigned' => $extract]);
        foreach ($nodes['evals'] as $node) {
            [$flag, $comment] = $this->CheckArg($node->expr, $vars, $config);
            if ($flag) {
                $node->setAttribute('comment', $comment);
                $res[] = $node;
            }
        }

        $this->CheckResults($res, '[300] eval', $file_path);

        # CODE 298

        $sql_map = [
            'mysqli_connect' => [0, 1, 2, 3],
            'mysqli_query' => [1],
            'mysqli_real_query' => [1],
            # i know its removed at php7
            'mysql_connect' => [0, 1, 2],
            'mysql_query' => [1],
            'mysql_db_query' => [0, 1]
        ];

        $config = self::genConfig(['params' => true]);
        $res = $this->searchFunctions($nodes['calls'], $sql_map, $nodeFinder, $vars, $config);

        $this->CheckResults($res, '[298] mysql function', $file_path);

        # CODE 299

        $mail_map = [
            'mail' => [0],
            'bxmail' => [0],
        ];

        $config = self::genConfig();
        $res = $this->searchFunctions($nodes['calls'], $mail_map, $nodeFinder, $vars, $config);

        $this->CheckResults($res, '[299] mail function', $file_path);

        # CODE 300

        $evals_map = [
            'assert' => [0],
            'create_function' => [0],
            'exec' => [0],
            'passthru' => [0],
            'pcntl_exec' => [0],
            'popen' => [0],
            'proc_open' => [0],
            'set_include_path' => [0],
            'shell_exec' => [0],
            'system' => [0]
        ];

        $config = self::genConfig(['params' => true, 'assigned' => $extract]);
        $res = $this->searchFunctions($nodes['calls'], $evals_map, $nodeFinder, $vars, $config);

        $this->CheckResults($res, '[300] command injection', $file_path);

        # CODE 301

        $files_map = [
            'copy' => [1], // 0,1
            'file_get_contents' => [0],
            'file_put_contents' => [0],
            'move_uploaded_file' => [1], // 0,1
            'opendir' => [0],
            'fopen' => [0]
        ];

        $config = self::genConfig(['concat' => false, 'files' => false, 'value' => false]);
        $res = $this->searchFunctions($nodes['calls'], $files_map, $nodeFinder, $vars, $config);

        $this->CheckResults($res, '[301] file operations', $file_path);

        # CODE 302

        $f_w_clb_map = ['call_user_func' => [0],
            'call_user_func_array' => [0],
            'forward_static_call' => [0],
            'forward_static_call_array' => [0],
            'register_shutdown_function' => [0],
            'register_tick_function' => [0],
            'ob_start' => [0],
            'usort' => [1],
            'uasort' => [1],
            'uksort' => [1],
            'array_walk' => [1],
            'array_walk_recursive' => [1],
            'array_reduce' => [1],
            'array_intersect_ukey' => [2],
            'array_uintersect' => [2],
            'array_uintersect_assoc' => [2],
            'array_intersect_uassoc' => [2],
            'array_uintersect_uassoc' => [2, 3],
            'array_diff_ukey' => [2],
            'array_udiff' => [2],
            'array_udiff_assoc' => [2],
            'array_diff_uassoc' => [2],
            'array_udiff_uassoc' => [2, 3],
            'array_filter' => [1],
            'array_map' => [0],
            'mb_ereg_replace_callback' => [1]
        ];

        $config = self::genConfig();
        $res = $this->searchFunctions($nodes['calls'], $f_w_clb_map, $nodeFinder, $vars, $config);

        $this->CheckResults($res, '[302] unsafe callable argument', $file_path);

        # CODE 303

        $some_calls = array_filter($nodes['calls'], function (Node $node) use (&$danger) {
            return $node->name instanceof Node\Name && $node->name->toLowerString() == 'create_function';
        }
        );

        $res = [];
        foreach ($some_calls as $node) {
            $flag = $nodeFinder->findFirst($node->args,
                function (Node $node) {
                    return ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name && (!function_exists($node->name->toLowerString())
                                || in_array($node->name->toLowerString(), self::$cryptors, true)
                                || in_array($node->name->toLowerString(), self::$string_change, true))
                        ) ||
                        ($node instanceof Node\Scalar\String_ && preg_match('/(?:assert|' . implode('|', self::$cryptors) . ')/i', $node->value));
                }
            );

            if ($flag) {
                $res[] = $node;
            }
        }

        $this->CheckResults($res, '[303] create_function', $file_path);

        # CODE 304

        $clb = ['filter_input', 'filter_input_array', 'filter_var', 'filter_var_array'];

        $some_calls = array_filter($nodes['calls'], function (Node $node) use (&$clb) {
            return $node->name instanceof Node\Name && in_array($node->name->toLowerString(), $clb, True);
        }
        );


        $res = [];
        foreach ($some_calls as $node) {
            if (preg_match_all('#(?:_POST|_GET|_COOKIE|_REQUEST|FILTER_CALLBACK|1024|filter_input|filter_var)|' . self::$evals_reg . '|' . self::$functions . '#i', $pprinter->prettyPrint($node->args)) > 1) {
                $res[] = $node;
            }
        }

        $this->CheckResults($res, '[304] filter_callback', $file_path);

        # CODE 305

        $res = [];
        foreach ($nodes['evals'] as $node) {
            $flag = $nodeFinder->findFirst($node->expr,
                function (Node $node) {
                    return ($node instanceof Node\Expr\FuncCall && (
                            ($node->name instanceof Node\Name && !function_exists($node->name->toLowerString())) ||
                            ($node->name instanceof Node\Expr\Variable) ||
                            ($node->name instanceof Node\Expr\ArrayDimFetch)
                        )
                    );
                }
            );

            if ($flag) {
                $node->setAttribute('comment', 'strange code');
                $res[] = $node;
            }
        }

        $this->CheckResults($res, '[305] strange function and eval', $file_path);

        # CODE 306

        $eregi_map = [
            'mb_eregi_replace' => [1],
            'mb_ereg_replace' => [1],
        ];

        $config = self::genConfig();
        $res = $this->searchFunctions($nodes['calls'], $eregi_map, $nodeFinder, $vars, $config);

        $this->CheckResults($res, '[302] eregi', $file_path);

        # CODE 307

        $res = [];
        foreach ($nodes['mtds'] as $node) {
            $class = $node->class instanceof Node\Name ? $node->class->toString() : '';
            $mtd = $node->name instanceof Node\Identifier ? $node->name->toString() : '';

            if (!$class || !$mtd) {
                continue;
            }

            $class_method = "$class::$mtd";
            foreach (self::$mehtods as $mtd) {
                if (stripos($class_method, $mtd) !== False) {

                    $arg = isset($node->args[0]) ? $node->args[0] : False;

                    [$flag, $comment] = $this->CheckArg($arg->value, $vars, $config);
                    if ($flag) {
                        $res[] = $node;
                        $node->setAttribute('comment', $comment);
                    }
                    break;
                }
            }

        }

        $this->CheckResults($res, '[307] danger method', $file_path);

        # CODE 400

        $config = self::genConfig(['hardcoded' => True]);

        $res = [];
        foreach ($nodes['auth'] as $node) {

            $arg = isset($node->args[0]) ? $node->args[0] : False;
            $flag = False;
            $comment = '';

            [$flag, $comment] = $this->CheckArg($arg->value, $vars, $config);
            if ($flag) {
                $node->setAttribute('comment', $comment);

                $res[] = $node;
            }
        }

        $this->CheckResults($res, '[400] bitrix auth', $file_path);

        # CODE 600

        $res = [];
        $config = self::genConfig(['concat' => false, 'value' => false]);

        foreach ($nodes['includes'] as $node) {
            $flag = false;
            $comment = '';

            $inc = $pprinter->prettyPrintExpr($node->expr);

            if (preg_match('/\.(gif|png|jpg|jpeg|var|pdf|exe)/i', $inc)) {
                $flag = True;
                $comment = 'gif|png|jpg|jpeg|var|pdf|exe';
            } elseif (preg_match('#(https?|ftps?|compress\.zlib|php|glob|data|phar)://#i', $inc)) {
                $flag = True;
                $comment = 'wrapper';
            } else {
                [$flag, $comment] = $this->CheckArg($node->expr, $vars, $config);
//                    $flag = $flag || $nodeFinder->findFirst($node->expr,
//                            function (Node $node) use (&$vars) {
//                                return $node instanceof Node\Expr\Variable && is_string($node->name) && $node->name && (isset($vars['request'][$node->name]) || isset($vars['crypted'][$node->name]));
//                            }
//                        );
            }


            if ($flag) {
                $node->setAttribute('comment', $comment);
                $res[] = $node;
            }
        }

        $this->CheckResults($res, '[600] strange include', $file_path);

        # CODE 610 615 620

        $checked = [];
        foreach ($nodes['variables'] as $var) {
            $v = $this->pprinter->prettyPrintExpr($var);
            if (in_array($v, $checked, true)) {
                continue;
            }
            $checked[] = $v;
            if (preg_match('#\$_{3,}#i', $v)) {
                $subj = '[610] strange vars';
                $checksum = $this->CalcChecksum($file_path, $v, $subj);
                if (!$this->IsFalsePositive($checksum)) {
                    $this->addResult($subj, $v, self::CaclCrit($subj));
                }

            }

            if (preg_match('#\${["\']\\\\x[0-9]{2}[a-z0-9\\\\]+["\']}#i', $v)) {
                $subj = '[615] hidden vars';
                $checksum = $this->CalcChecksum($file_path, $v, $subj);
                if (!$this->IsFalsePositive($checksum)) {
                    $this->addResult($subj, $v, self::CaclCrit($subj));
                }

            }

            if (preg_match("#\$(?:[\x80-\xff][_\x80-\xff]*|_(?:[\x80-\xff][_\x80-\xff]*|_[_\x80-\xff]+))" . self::$spaces . '=#i', $v)) {
                $subj = '[620] binary vars';
                $checksum = $this->CalcChecksum($file_path, $v, $subj);
                if (!$this->IsFalsePositive($checksum)) {
                    $this->addResult($subj, $v, self::CaclCrit($subj));
                }

            }
        }

        # CODE 650

        $res = [];
        $config = self::genConfig();

        foreach ($nodes['calls'] as $node) {
            $flag = false;
            $comment = '';
            if ($node->name instanceof Node\Expr\Variable) {
                $var = is_string($node->name) ? '$' . $node->name : $this->pprinter->prettyPrintExpr($node->name);
                $name = substr($var, 1);

                [$flag, $comment] = $this->CheckArg($node->name, $vars, $config);
                if (!$flag) {
                    $flag = $nodeFinder->findFirst($node->args,
                        function (Node $node) {
                            return $node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Expr\Variable;
                        });

                    if ($flag) {
                        $comment = 'functions inside';
                    }

                }

                if (!$flag) {
                    foreach ($node->args as $arg) {
                        [$flag, $comment] = $this->CheckArg($arg->value, $vars, $config);
                        if ($flag) {
                            $comment = $comment;
                            break;
                        }
                    }
                }
                if (!$flag && !in_array($name, $vars['closures'], True) && !$in_closure) {
                    $comment = 'other';
                    if (self::isVarStrange($var)) {
                        $comment = 'strange var';
                    }
                    $flag = true;
                }

                if ($flag) {
                    $node->setAttribute('comment', $comment);
                    $res[] = $node;
                }

            }

        }

        $this->CheckResults($res, '[650] variable as a function', $file_path);

        # CODE 660

        $config = self::genConfig();

        $res = [];
        foreach ($nodes['calls'] as $node) {
            if ($node->name instanceof Node\Expr\ArrayDimFetch) {
                $res[] = $node;

                [$flag, $comment] = $this->CheckArg($node->name, $vars, $config);


                if (!$flag) {
                    foreach ($node->args as $arg) {
                        [$flag, $comment] = $this->CheckArg($arg->value, $vars, $config);
                        if ($flag) {
                            break;
                        }
                    }
                }

                if ($flag) {
                    $node->setAttribute('comment', $comment);
                }
            }
        }

        $this->CheckResults($res, '[660] array member as a function', $file_path);

        # CODE 662

        $config = self::genConfig();

        $res = [];
        foreach ($nodes['calls'] as $node) {
            if ($node->name instanceof Node\Expr\FuncCall) {
                $res[] = $node;

                [$flag, $comment] = $this->CheckArg($node->name, $vars, $config);
                if ($flag) {
                    $node->setAttribute('comment', $comment);
                }

            }
        }

        $this->CheckResults($res, '[662] function return as a function', $file_path);


        $res = [];
        foreach ($nodes['calls'] as $node) {
            if ($node->name instanceof Node\Scalar\String_ || $node->name instanceof Node\Expr\BinaryOp) {
                $res[] = $node;

                [$flag, $comment] = $this->CheckArg($node->name, $vars, $config);
                if ($flag) {
                    $node->setAttribute('comment', $comment);
                }

            }
        }

        $this->CheckResults($res, '[663] strange function', $file_path);

        # CODE 887

        $this->CheckResults($nodes['backticks'], '[887] backticks', $file_path);

        unset($stmts, $nodes, $some_calls, $res, $req, $code);

    }

    public static function genConfig($options = false)
    {
        $config = self::$default_config;
        if (is_array($options)) {
            foreach ($options as $key => $val) {
                $config[$key] = $val;
            }
        }

        return $config;
    }

    public function searchFunctions(&$all_calls, &$funcs_map, &$nodeFinder, &$vars, &$config)
    {
        $funcs = array_keys($funcs_map);

        $some_calls = array_filter($all_calls, function (Node $node) use (&$funcs) {
            return $node->name instanceof Node\Name && in_array($node->name->toLowerString(), $funcs, True);
        }
        );

        $result = [];
        foreach ($some_calls as $node) {
            $ret = False;
            $func = $node->name->toLowerString();

            $comment = '';

            foreach ($funcs_map[$func] as $i) {
                if (!isset($node->args[$i]) || $ret) {
                    continue;
                }

                if ($node->args[$i] instanceof Node\Arg && $node->args[$i]->value instanceof Node\Expr\Closure) {
                    continue;
                }

                $arg = $node->args[$i]->value;

                [$ret, $comment] = $this->CheckArg($arg, $vars, $config);
            }

            if ($ret && $comment) {
                $node->setAttribute('comment', $comment);
                $result[] = $node;
            }
        }
        return $result;
    }

    public function parseValue($node, &$vars)
    {
        $ret = '';
        $temp_name = False;

        while ($node instanceof Node\Expr\ArrayDimFetch || $node instanceof Node\Expr\PropertyFetch) {
            if ($node instanceof Node\Expr\ArrayDimFetch && $node->dim instanceof Node\Scalar\String_ and $node->dim->value == 'tmp_name') {
                $temp_name = True;
            }
            if ($node instanceof Node\Expr\ArrayDimFetch && $node->var instanceof Node\Expr\Variable && $node->var->name == 'GLOBALS'
                && $node->dim instanceof Node\Scalar\String_) {
                $node = new Node\Expr\Variable($node->dim->value);
            } else {
                $node = $node->var;
            }
        }

        if ($node instanceof Node\Expr\Variable) {
            $name = $node->name;
            if (is_string($name) && $name) {
                if (isset($vars['values'][$name])) {
                    $ret = $vars['values'][$name];
                } elseif (isset($vars['request'][$name]) && !$temp_name) {
                    $ret = '$_REQUEST';
                } elseif (isset($vars['from_request'][$name])) {
                    $ret = '$_FROM_REQUEST';
                } elseif (isset($vars['crypted'][$name])) {
                    $ret = 'CRYPTED';
                } elseif (isset($vars['params'][$name])) {
                    $ret = 'PARAMS';
                }
            }
        } elseif ($node instanceof Node\Expr\BinaryOp) {
            $left = $this->parseValue($node->left, $vars);
            $right = $this->parseValue($node->right, $vars);

            if ($node instanceof Node\Expr\BinaryOp\Div && (int)$right != 0) {
                $ret = (string)((int)$left / (int)$right);
            } elseif ($node instanceof Node\Expr\BinaryOp\Mul) {
                $ret = (string)((int)$left * (int)$right);
            } elseif ($node instanceof Node\Expr\BinaryOp\Minus) {
                $ret = (string)((int)$left - (int)$right);
            } elseif ($node instanceof Node\Expr\BinaryOp\Plus) {
                $ret = (string)((int)$left + (int)$right);
            } elseif ($node instanceof Node\Expr\BinaryOp\BitwiseXor) {
                $ret = (string)($left ^ $right);
            } else {
                $ret = $left . $right;
            }

        } elseif ($node instanceof Node\Scalar\Encapsed) {
            foreach ($node->parts as $part) {
                $part = $this->parseValue($part, $vars);
                $ret .= $part;
            }
        } elseif ($node instanceof Node\Scalar\LNumber ||
            $node instanceof Node\Scalar\DNumber ||
            $node instanceof Node\Scalar\String_ ||
            $node instanceof Node\Scalar\EncapsedStringPart
        ) {
            $ret = (string)$node->value;
        } elseif ($node instanceof Node\Expr\FuncCall) {
            $name = $node->name instanceof Node\Name ? $node->name->toLowerString() : "\$v";

            if ($name === 'chr') {
                $v = $this->parseValue($node->args[0]->value, $vars);
                $ret = chr((int)$v);
            } else {

                $args = [];
                foreach ($node->args as $arg) {
                    $args[] = $this->parseValue($arg->value, $vars);
                }

                $ret = "$name(" . implode(",", $args) . ")";

                [$a, $b] = self::checkString($ret);
                $ret = $a ? $b : '';
                unset($args);
            }
        } elseif ($node instanceof Node\Expr\Ternary) {

            $if = $this->parseValue($node->if, $vars);
            $ret = $if ?: $this->parseValue($node->else, $vars);

        }

        return $ret;
    }

    public function CheckArg($arg, &$vars, &$config)
    {
        $ret = False;
        $comment = '';
        $temp_name = False;

        while ($arg instanceof Node\Expr\ArrayDimFetch || $arg instanceof Node\Expr\PropertyFetch) {
            if ($arg instanceof Node\Expr\ArrayDimFetch && $arg->dim instanceof Node\Scalar\String_ and $arg->dim->value == 'tmp_name') {
                $temp_name = True;
            }

            if ($arg instanceof Node\Expr\ArrayDimFetch && $arg->var instanceof Node\Expr\Variable && $arg->var->name == 'GLOBALS'
                && $arg->dim instanceof Node\Scalar\String_) {
                $arg = new Node\Expr\Variable($arg->dim->value);
            } else {
                $arg = $arg->var;
            }
        }

        $temp_name = $temp_name && ($arg instanceof Node\Expr\Variable and is_string($arg->name) && $arg->name == '_FILES');

        while ($arg instanceof Node\Expr\ConstFetch) {
            $arg = $arg->name;
        }

        if ($config['hardcoded'] && (
                $arg instanceof Node\Scalar\LNumber ||
                $arg instanceof Node\Scalar\DNumber ||
                $arg instanceof Node\Scalar\String_ ||
                $arg instanceof Node\Scalar\Encapsed)
        ) {
            $comment = 'hardcoded value';
            $ret = true;
        } elseif ($arg instanceof Node\Expr\Variable) {
            $name = $arg->name;
            $ret = is_string($name) && $name && ($config['files'] || (!$config['files'] && !$temp_name)) && (
                    ($config['request'] && isset($vars['request'][$name]) && $comment = 'request') ||
                    ($config['from_request'] && isset($vars['from_request'][$name]) && $comment = 'var from request') ||
                    ($config['crypted'] && isset($vars['crypted'][$name]) && $comment = 'crypted var') ||
                    ($config['assigned'] && !isset($vars['assigned'][$name]) && $comment = 'var was not assigned') ||
                    ($config['params'] && isset($vars['params'][$name]) && $comment = 'var from params') ||
                    ($name == 'GLOBALS' && $comment = 'strange globals')
                );
        } elseif ($arg instanceof Node\Expr\FuncCall && $arg->name instanceof Node\Name) {
            $name = $arg->name->toLowerString();
            $ret = in_array($name, self::$evals, True) || in_array($name, ['getenv'], True) || ($config['crypted'] && in_array($name, self::$cryptors, True));
            if (!$ret) {
                foreach ($arg->args as $argv) {
                    [$ret, $comment] = $this->CheckArg($argv->value, $vars, $config);
                    if ($ret) {
                        break;
                    }
                }
            } else {
                $comment = 'danger function';
            }
        } elseif ($arg instanceof Node\Scalar\String_) {
            $comment = 'danger function';
            $ret = preg_match('/^(' . implode('|', self::$evals) . '|call_user_func|getenv)$/i', $arg->value);
        } elseif ($arg instanceof Node\Scalar\EncapsedStringPart) {
            $comment = 'danger function';
            $ret = preg_match('/(' . implode('|', self::$evals) . '|call_user_func|getenv)/i', $arg->value);
        } elseif ($arg instanceof Node\Name) {
            $comment = 'danger function';
            $func = $arg->toLowerString();
            $ret = preg_match('/(' . implode('|', self::$evals) . '|call_user_func|getenv)/i', $func);
        } elseif ($arg instanceof Node\Expr\BinaryOp\Concat || $arg instanceof Node\Expr\BinaryOp\Coalesce) {
            [$a, $b] = $this->CheckArg($arg->left, $vars, $config);
            if ($a) {
                [$ret, $comment] = [$a, $b];
            } else {
                [$a, $b] = $this->CheckArg($arg->right, $vars, $config);
                if ($a) {
                    [$ret, $comment] = [$a, $b];
                } elseif ($config['concat']) {
                    $comment = 'strange concatination';
                    $ret = true;
                }
            }
        } elseif ($arg instanceof Node\Scalar\Encapsed) {
            foreach ($arg->parts as $part) {
                [$a, $b] = $this->CheckArg($part, $vars, $config);
                if ($a) {
                    [$ret, $comment] = [$a, $b];
                }
            }
        } elseif ($arg instanceof Node\Expr\Ternary) {

            [$a, $b] = $this->CheckArg($arg->if, $vars, $config);
            if ($a) {
                [$ret, $comment] = [$a, $b];
            } else {
                [$a, $b] = $this->CheckArg($arg->else, $vars, $config);
                if ($a) {
                    [$ret, $comment] = [$a, $b];
                }
            }

        }

//        print_r($arg);

        if (!$ret && $config['value']) {
            $val = $this->parseValue($arg, $vars);

//            var_dump($val);

            [$ret, $comment] = self::checkString($val);
        }

        return [$ret, $comment];

    }

    public static function checkString($val)
    {

        $ret = '';
        $comment = '';

        if (preg_match('/BXS_(?:EVAL|CRYPTED|BLACKLIST|REQUEST)/', $val, $m)) {
            $ret = true;
            $comment = $m[0];
        } elseif (preg_match('/\b(' . implode('|', self::$evals) . '|getenv)\b/i', $val)) {
            $ret = true;
            $comment = 'BXS_EVAL';
        } elseif (preg_match('/\b(' . implode('|', self::$cryptors) . '|CRYPTED)\b/i', $val)) {
            $ret = true;
            $comment = 'BXS_CRYPTED';
        } elseif (preg_match('#\b' . self::$black_reg . '\b#i', $val)) {
            $ret = true;
            $comment = 'BXS_BLACKLIST';
        } elseif (preg_match('/(\$_REQUEST|\$_FROM_REQUEST)/i', $val)) {
            $ret = true;
            $comment = 'BXS_REQUEST';
        }
        return [$ret, $comment];
    }

    public static function isVarStrange($var)
    {
        $ret = 0;
        $ret = preg_match('/^\$_?([0o]+|[1li]+)$/i', $var); // obfusacator
        $ret = $ret || preg_match('/^\$__/i', $var) || $var == '$_';
        $ret = $ret || preg_match('/__/', $var);
        $ret = $ret || preg_match('/^\$_*[a-z0-9]{1,2}$/i', $var);  // very short

        $ret = $ret || preg_match('/\d{2,}$/i', $var); // 2+ digits in the end
        $ret = $ret || preg_match_all('/[A-Z][a-z][A-Z]/', $var) > 1;  // CaSe dAnCe

        $ret = $ret || preg_match('/[^$a-z0-9_]/i', $var);
        $ret = $ret || preg_match('/[a-z]+[0-9]+[a-z]+/i', $var); // digits in centre

        $ret = $ret || (preg_match_all('#[qwrtpsdfghjklzxcvbnm]{4,}#i', $var, $regs)
                && (strlen(implode('', $regs[0])) / strlen($var) > 0.4));

        return $ret > 0;

    }


    public static function CaclCrit($subj, $com = '')
    {
        if (!isset(self::$scoring[$subj])) {
            die("error: " . $subj);
        }

        $self = self::$scoring[$subj]['self'];

        if ($com == 'other') {
            $arg = 0.3;
        } else {
            $arg = isset(self::$scoring[$subj]['args'][$com]) ? self::$scoring[$subj]['args'][$com] : 1;
        }

        return round($self * $arg, 2);
    }


    public function CheckResults(&$res, $subj, $file_path)
    {
        foreach ($res as $r) {
            $code = $this->pprinter->prettyPrintExpr($r);

            $com = $r->getAttribute('comment', '');
            $crit = self::CaclCrit($subj, $com);
            $checksum = $this->CalcChecksum($file_path, $code, $subj);

            $str = defined('XSCAN_DEBUG') ? "$subj [$com] | $crit | $checksum" : $subj;

            if (!$this->IsFalsePositive($checksum)) {
                $this->addResult($str, $code, $crit);
            }
        }
    }


    public static function ParseNode(&$node)
    {

        if (isset($arr[0])) {
            foreach ($node as $v) {
                self::ParseNode($v);
            }
            return;
        }


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
            $path = str_replace('//', '/', $path, $flag);
        } while ($flag);

        if (php_sapi_name() != "cli"){
            header('xscan-bp: ' . $path, true);
        }

        if ($this->start_time && time() - $this->start_time > $this->time_limit) {
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
                $res = $this->CheckFile($path);
                if ($res) {
                    $this->Mark($path);
                }
            }
        }
    }

    function Count_total($path)
    {
        $path = str_replace('\\', '/', $path);
        do {
            $path = str_replace('//', '/', $path, $flag);
        } while ($flag);

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

    function Mark($f)
    {
        $message = [];
        foreach ($this->results as $res) {
            $message[] = $res['subj'];
        }

        if (is_array($message)) {
            $message = implode(' <br> ', array_unique($message));
        }

        $result = (new XScanResult)->setType('file')->setSrc($f)->setScore($this->score)->setMessage($message);
        $this->result_collection[] = $result;

    }

    function SavetoDB()
    {
        if (isset($this->result_collection) && $this->result_collection) {
            $this->result_collection->save(true);
        }
        unset($this->result_collection);
    }


    static function ShowMsg($str, $color = 'green')
    {
        $class = $color == 'green' ? 'ui-alert-primary ui-alert-icon-info' : 'ui-alert-danger ui-alert-icon-danger';
        return '<br><div class="ui-alert ' . $class . '"><span class="ui-alert-message">' . $str . '</span></div><br>';
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
        return '<a class="ui-btn ui-btn-primary ui-btn-sm" style="text-decoration: none; color: #ffffff;" onclick="xscan_release(\'' . $file_path . '\')">' . GetMessage("BITRIX_XSCAN_UNISOLATE") . '</a>';

    }

    static function getHideButton($file_path)
    {
        $file_path = htmlspecialcharsbx(CUtil::JSEscape($file_path));
        return '<a class="ui-btn ui-btn-success ui-btn-sm" style="text-decoration: none; color: #ffffff;" onclick="xscan_hide(\'' . $file_path . '\')">' . GetMessage("BITRIX_XSCAN_HIDE_BTN") . '</a>';

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

    static function getTotal()
    {
        return XScanResultTable::getCount();
    }

    static function getList($inprogress, $nav, $sort)
    {
        $output = [];

        $results = XScanResultTable::getList([
            'filter' => [],
            'offset' => $nav->getOffset(),
            'limit' => $nav->getlimit(),
            'order' => $sort['sort']
        ]);

        foreach ($results as $result) {
            if ($result['type'] === 'file') {

                $type = $result['message'];
                $f = $result['src'];

                $code = preg_match('#\[([0-9]+)\]#', $type, $regs) ? $regs[1] : 0;
                $fu = urlencode(trim($f));
                $bInPrison = strpos('[100]', $type) === false;

                if (!file_exists($f) && file_exists($new_f = preg_replace('#\.php[578]?$#i', '.ph_', $f))) {
                    $bInPrison = false;
                    $f = $new_f;
                    $fu = urlencode(trim($new_f));
                }

                $action = substr($f, -4) !== '.ph_' ? self::getIsolateButton($f) : self::getUnIsolateButton($f);

                $stat = stat($f);

                $output[] = [
                    'data' => [
                        'ID' => $result['id'],
                        'FILE_NAME' => self::getFileWatchLink($f),
                        'FILE_TYPE' => $type,
                        'FILE_SCORE' => $result['score'],
                        'FILE_SIZE' => self::HumanSize(filesize($f)),
                        'FILE_MODIFY' => ConvertTimeStamp($stat['mtime'], "FULL"),
                        'FILE_CREATE' => ConvertTimeStamp($stat['ctime'], "FULL"),
                        'ACTIONS' => $action,
                        'HIDE' => self::getHideButton($f)
                    ]
                ];


            } else {
                $table = $result['type'] === 'agent' ? 'b_agent' : 'b_module_to_module';
                $output[] = [
                    'data' => [
                        'ID' => $result['id'],
                        'FILE_NAME' => self::getEventWatchLink($result['type'] . " " . $result['src'], $table, $result['src']),
                        'FILE_TYPE' => $result['message'],
                        'FILE_SCORE' => $result['score'],
                        'ACTIONS' => self::getEventWatchButton($table, $result['src'])
                    ]
                ];

            }


        }

        return $output;
    }
}

?>
