<?php

if (!class_exists('\Bitrix\Main\Entity\DataManager')) {
    return;
}

class XScanResultTable extends \Bitrix\Main\Entity\DataManager
{
    public static function getTableName()
    {
        return 'b_xscan_results';
    }

    public static function getMap()
    {
        return array(
            new \Bitrix\Main\Entity\IntegerField('id', array('primary' => true, 'autocomplete' => true)),
            new \Bitrix\Main\Entity\EnumField('type', array(
                'values' => array('file', 'agent', 'event'),
                'default_value' => 'file'
            )),
            new \Bitrix\Main\Entity\StringField('src'),
            new \Bitrix\Main\Entity\StringField('message'),
            new \Bitrix\Main\Entity\FloatField('score'),
        );
    }

    public static function getCollectionClass()
    {
        return XScanResults::class;
    }

    public static function getObjectClass()
    {
        return XScanResult::class;
    }

}


class XScanResults extends EO_XScanResult_Collection
{
}

class XScanResult extends EO_XScanResult
{
}