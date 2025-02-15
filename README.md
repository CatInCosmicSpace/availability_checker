
### Пояснения

Программа *availability_checker* позволяет проверить доступность сетевых ресурсов.

Входные данные:
* Текстовый файл, в котором на каждой новой строке записан сетевой ресурс в формате либо доменного имени (например, **google.com**), либо IP-адреса ресурса (например, **8.8.8.8**). По умолчанию файл ищется в папке, в которой содержится программа, под названием `addresses.txt`. При желании можно указать любой другой путь.
* Опционально можно задать количество пингов до ресурса.

Программа работает в системе Windows, так как обращается к WinAPI для отправки запросов через сокет.

Для отправки отчёта в Skype используется бот, сервер для которого написан на Python.
В связи с ограничениями Microsoft сервер с ботом обязательно требует работы про протоколу HTTPS. Также Azure недоступен в России (пока что, какие-то юридические у них проблемы), так что отправка именно вложений через бота недоступна. Однако можно отправлять медиа-файлы, например, картинку. Таким образом, сервер получает из приложения POST-запрос с приложенным отчётом в виде строки, преобразует эту строку в картинку и отправляет контактам, добавившим бота.

Бота можно добавить по ссылке: https://join.skype.com/bot/bec372bc-8acd-43a8-929e-3156dfe8eb5a

Список добавленных контактов сохраняется локально и загружается из файла при загрузке сервера. При добавлении нового контакта файл с сохранёнными контактами обновляется.

Пример присланного ботом отчёта:
![](https://i.ibb.co/HdNJZJY/report.png)
