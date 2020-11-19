# Proyecto 2 Keychain app
## Requirements
- Python
- django
- ngrock
- djangorestframework
- psycopg2
- cryptography
- djangorestframework-jwt
- pyotp
- backports.pbkdf2
- binascii
- pycryptodome
- twillo
- pycrypto
- django-cors-headers
- django-cron

## Montaje
Se debe de poner la infromación de la base de datos a usar en settings.py.
Una vez setteada la info correr en consola para montar el virtual env
```
source env/bin/activate
```
Instalar todas las dependencias de requirements.txt

Para correr las migrations entrar al folder twoStep y correr
```
python manage.py migrate
```

Para poder montar dentro de localhost correr
```
python manage.py runserver
```

Por ultimo para poder correr la aplicacion de manera local bajar ngrock y correr en el folder donde ngrock se encuentre
OS
```
# 8000 es el puerto
./ngrock http 8000
```
Windows
```
# 8000 es el puerto
./ngrock.exe http 8000
```

Si se desea poner a correr el job para proteger contra rollback attack
```
# 1 hace referencia a cada minuto el cronjob
# {path} hace referencia al path absoluto para llegar al archivo
# en cronjob.log se hara un log del job
*/1 * * * * source /{/.bash_profile && source /{path}/twoStepVerification/env/bin/activate && python /{path}/twoStepVerification/twoStep/manage.py runcrons > /{path}/cronjob.log
```
