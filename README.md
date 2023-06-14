#Flask API Example
Этот проект демонстрирует простой API на языке Python с использованием фреймворка Flask. Он реализует следующие функции:

- Аутентификация пользователей с помощью модуля flask_login.
- Загрузка, удаление и просмотр файлов в формате CSV с помощью модуля werkzeug.utils.
- Получение данных из файлов CSV с возможностью фильтрации и сортировки с помощью библиотеки pandas.
##Установка и запуск
Для запуска проекта вам потребуется Python 3.6 или выше и следующие библиотеки:

- Flask
- Flask-Login
- Werkzeug
- Pandas

Вы можете установить их с помощью команды:
'''
pip install -r requirements.txt
'''

Также вам нужно создать папку для хранения загруженных файлов и указать ее путь в переменной окружения UPLOAD_FOLDER. Например:
'''
export UPLOAD_FOLDER=/home/user/uploads
'''
Для запуска проекта выполните команду:
'''
python app.py
'''
После этого вы сможете обращаться к API по адресу http://localhost:5000/.

Использование API
API состоит из пяти эндпоинтов:

- '''/login''': Этот эндпоинт принимает GET или POST запросы. Если запрос GET, то он возвращает HTML-форму для ввода имени пользователя и пароля. Если запрос POST, то он проверяет, что имя пользователя и пароль совпадают с данными в словаре users, и если да, то выполняет вход пользователя с помощью функции login_user из модуля flask_login. Затем он перенаправляет пользователя на главную страницу /. Если имя пользователя или пароль неверны, то он возвращает сообщение об ошибке.
- '''/logout''': Этот эндпоинт принимает только GET запросы. Он требует, чтобы пользователь был аутентифицирован с помощью декоратора @login_required из модуля flask_login. Он выполняет выход пользователя с помощью функции logout_user и перенаправляет его на главную страницу /.
- '''/''': Этот эндпоинт принимает только GET запросы. Он также требует, чтобы пользователь был аутентифицирован. Он возвращает приветственное сообщение с идентификатором текущего пользователя, который доступен через атрибут current_user.id.
- '''/upload''': Этот эндпоинт принимает GET или POST запросы. Если запрос GET, то он возвращает HTML-форму для выбора и загрузки файла. Если запрос POST, то он получает файл из объекта request.files и сохраняет его в папку, указанную в конфигурации приложения под ключом UPLOAD_FOLDER. При этом он использует функцию secure_filename из модуля werkzeug.utils для обеспечения безопасности имени файла. Затем он возвращает сообщение об успешной загрузке файла.
- '''/files''': Этот эндпоинт принимает только GET запросы. Он получает список файлов в папке UPLOAD_FOLDER, которые имеют расширение .csv. Затем он возвращает HTML-шаблон, который отображает эти файлы в виде списка с кнопками для удаления каждого файла. Для этого он использует функцию render_template_string из модуля flask и передает ей список файлов как параметр files. Для удаления файла он отправляет POST запрос на эндпоинт /delete с именем файла в поле filename.
- '''/data''': Этот эндпоинт принимает только GET запросы. Он получает имя файла из параметра filename в объекте request.args. Если имя файла не указано, то он возвращает сообщение об ошибке с кодом 400. Если файл не найден в папке UPLOAD_FOLDER, то он возвращает сообщение об ошибке с кодом 404. Иначе он читает файл с помощью библиотеки pandas и преобразует его в объект типа DataFrame. Затем он проверяет наличие других параметров в объекте request.args, таких как filter_column, filter_value и sort_column, и применяет соответствующие операции фильтрации и сортировки к объекту DataFrame. Наконец, он возвращает HTML-шаблон, который отображает данные из объекта DataFrame в виде таблицы. Для этого он также использует функцию render_template_string и передает ей объект DataFrame как параметр df. Для итерации по столбцам и строкам объекта DataFrame он использует атрибуты df.columns и df.itertuples().
- '''/delete''': Этот эндпоинт принимает только POST запросы. Он получает имя файла из поля filename в объекте request.form. Если имя файла не указано, то он возвращает сообщение об ошибке с кодом 400. Если файл не найден в папке UPLOAD_FOLDER, то он возвращает сообщение об ошибке с кодом 404. Иначе он удаляет файл с помощью функции os.remove из модуля os и возвращает сообщение об успешном удалении файла.
Вот примеры запросов и ответов для каждого эндпоинта:

##/login
###GET
Запрос:
'''
GET /login HTTP/1.1
Host: localhost:5000
'''
Ответ:
'''
<form method="post">
    <label for="username">Username:</label>
    <input type="text" id="username" name="username">
    <label for="password">Password:</label>
    <input type="password" id="password" name="password">
    <input type="submit" value="Login">
</form>
'''
##POST
Запрос:
'''
POST /login HTTP/1.1
Host: localhost:5000
Content-Type: application/x-www-form-urlencoded

username=alice&password=secret
'''
Ответ:
'''
HTTP/1.1 302 FOUND
Location: http://localhost:5000/
Set-Cookie: session=eyJfaWQiOnsiIGIiOiJZMkpsYzNNaU9HWXdNVEl6TFRBd01EQXhNakF4T0RnMk5qQXhOekUwT0RZPSJ9fQ.X9x2Lg.w8y3fK7
'''
