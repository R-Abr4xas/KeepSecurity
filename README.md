# Bot de Discord con análisis de archivos y URLs

Este repositorio contiene el código fuente de un bot de Discord programado en Python que utiliza la API de VirusTotal para analizar archivos y URLs en tiempo real en busca de posibles amenazas de seguridad.

## Funcionalidades

- Análisis automático de archivos adjuntos y URLs.
- Comandos para detener y reanudar el análisis en un canal específico (`reanudar_analisis` y `detener_analisis`).
- Comando de ayuda (`help`) para obtener información sobre los comandos disponibles.

## Uso

1. Crea el entorno virtual (aquí encontrarás información de como hacerlo)
2. Instala las librerías utilizadas.
3. Configura el archívo de python con tu token de Discord y tu clave de API de VirusTotal.
4. Ejecuta el código e invita al bot en tu servidor.

Este bot está pensado para ser una base de ciberseguridad de codigo abierto donde cualquiera puede añadir funcionalidades 

## Configuración del entorno

Para ejecutar este bot de Discord, sigue estos pasos:

1. Crea una carpeta donde irá el bot.

2. Abre una terminal y navega hasta el directorio del proyecto.

3. Ejecuta los siguientes comandos para crear y activar un entorno virtual con pipenv:

```bash
pip3 install pipenv
pipenv shell
pipenv install discord.py
```
4. Debes crear una carpeta que se llame src y dentro poner el archivo python llamado main.py que puedes encontrar aquí:

5. Asegurate de instalar todas las dependencias, puedes hacerlo de la siguiente forma:

```bash
pip install regex
pip install discord.py
pip install virus-total-api
```
6. Cambia el bot token de Discord y la api de Virustotal:

7. Ejecuta el bot de la siguiente forma:

```bash
python src/main.py
```

¡Espero que encuentres útil este bot para proteger tu servidor de Discord!
