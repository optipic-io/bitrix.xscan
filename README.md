# Поиск вирусов для 1С-Битрикс

Форк официального модуля bitrix.xscan, но с доп функционалом:
- поддержка разных версий Битрикс (не требует последнюю версию)
- поддержка исключений (ignorelist)
- консольный скрипт для проверки по крону
- отправка уведомлений о найденных вирусах в Monitorio.io

## Как вешать на cron

`0 3 * * * /usr/bin/php -f php <DOCUMENT_ROOT>/bitrix/modules/bitrix.xscan/atl-scan-cli.php --monitorio-key=<SITE_APIKEY_MONITORIO>`