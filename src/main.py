from discord.ext import commands
import discord
from virus_total_apis import PublicApi
import re
import asyncio
import getpass

# Datos necesarios para correr el bot
API_KEY_VIRUSTOTAL = getpass.getpass("Por favor, introduce tu clave de API de VirusTotal: ")
BOT_TOKEN = getpass.getpass("Por favor, introduce tu token de bot de Discord: ")
api = PublicApi(API_KEY_VIRUSTOTAL)

# Definir los intents que necesita el bot
intents = discord.Intents.all()
bot = commands.Bot(command_prefix='', description="KeepSecurity", help_command=None, intents=intents)

# Expresión regular para identificar patrones de URL
url_regex = re.compile(r'https?://\S+|www\.\S+|\S+\.\S+')

# Mensaje de introducción
introduction_message = ("¡Hola! Soy KeepSecurity, tu asistente de seguridad en Discord. "
                        "Mi función principal es analizar las URLs y archivos compartidos en este servidor "
                        "para verificar su seguridad e integridad.\n\n"
                        "Antes de comenzar, necesito tu consentimiento para analizar cualquier URL o archivo "
                        "que compartas en este servidor. Te aseguro que solo recogeré y procesaré los datos "
                        "necesarios para esta función y no almacenaré ninguna información personal tuya.\n\n"
                        "Si estás de acuerdo con esto, puedes empezar a usar mis servicios simplemente compartiendo "
                        "una URL o un archivo en el servidor. Si no estás de acuerdo, por favor no compartas ninguna "
                        "URL o archivo que quieras que analice.\n\n"
                        "¡Gracias por tu comprensión y cooperación!")

# Lista para almacenar los canales en los que se debe detener el análisis
canales_detener = []

# Función para obtener información de VirusTotal para una URL
async def obtener_resultados_virustotal(url):
    resultado_analisis = api.scan_url(url)
    scan_id = resultado_analisis['results']['scan_id']
    while True:
        await asyncio.sleep(30)  # Esperar 30 segundos antes de verificar el estado del escaneo
        report = api.get_url_report(scan_id)
        if report['results']['response_code'] == 1:
            positives = report['results']['positives']
            total = report['results']['total']
            # Obtener detalles de los escaneos sospechosos
            detalles_sospechosos = ""
            for motor, resultado in report['results']['scans'].items():
                if resultado['result'] not in ['clean site', 'unrated site']:
                    detalles_sospechosos += f"\n{motor}: {resultado['result']}"
            resultado_str = f"**Resultado del análisis para {url}:**\n" \
                            f"**Permalink**: {report['results']['permalink']}\n" \
                            f"**Fecha de análisis:** {report['results']['scan_date']}\n" \
                            f"**Resultado:** {positives} / {total} detectadas como maliciosas\n" \
                            f"**Detalles de escaneo:** {detalles_sospechosos}"
            return resultado_str
        elif report['results']['response_code'] == -2:
            await asyncio.sleep(30)
        else:
            error_str = "Ocurrió un error durante el escaneo."
            return error_str

# Comando !help
@bot.command()
async def help(ctx):
    embed = discord.Embed(title="Comandos disponibles", description="Lista de comandos disponibles para este bot:", color=discord.Color.blurple())
    embed.add_field(name="detener_analisis", value="Detiene el análisis de archivos y URLs en el canal actual.", inline=False)
    embed.add_field(name="reanudar_analisis", value="Reanuda el análisis de archivos y URLs en el canal actual.", inline=False)
    embed.add_field(name="El bot detecta los arrchivos y URLs automaticamente.", value=" ", inline=False)

    await ctx.send(embed=embed)

# Comando para detener el análisis en un canal específico
@bot.command()
async def detener_analisis(ctx):
    # Verificar si el comando se ejecutó en un canal de texto
    if isinstance(ctx.channel, discord.TextChannel):
        # Verificar si el canal ya está en la lista de canales a detener
        if ctx.channel.id in canales_detener:
            await ctx.send("El análisis ya está detenido en este canal.")
        else:
            canales_detener.append(ctx.channel.id)
            await ctx.send("El análisis se ha detenido en este canal.")
    else:
        await ctx.send("Este comando solo puede ser usado en un canal de texto.")

# Comando para reanudar el análisis en un canal específico
@bot.command()
async def reanudar_analisis(ctx):
    # Verificar si el comando se ejecutó en un canal de texto
    if isinstance(ctx.channel, discord.TextChannel):
        # Verificar si el canal está en la lista de canales a detener
        if ctx.channel.id in canales_detener:
            canales_detener.remove(ctx.channel.id)
            await ctx.send("El análisis se ha reanudado en este canal.")
        else:
            await ctx.send("El análisis no está detenido en este canal.")
    else:
        await ctx.send("Este comando solo puede ser usado en un canal de texto.")

# Evento cuando el bot está listo
@bot.event
async def on_ready():
    # Cambiar el estado del bot cuando esté listo
    await bot.change_presence(activity=discord.Game(name="defender servidores"))
    # Envía el mensaje de introducción al primer canal de texto del primer servidor
    guild = bot.guilds[0]
    channel = guild.text_channels[0]
    await channel.send(introduction_message)

# Evento cuando se recibe un mensaje
@bot.event
async def on_message(message):
    # Evitar que el bot responda a sí mismo
    if message.author == bot.user:
        return

    # Verificar si hay archivos adjuntos y analizar cada uno
    if message.attachments:
        for adjunto in message.attachments:
            if not adjunto.content_type.startswith('image'):
                if message.channel.id not in canales_detener:
                    await message.channel.send("Analizando archivos en busca de virus...")
                    resultado_analisis = await obtener_resultados_virustotal(adjunto.url)
                    await message.channel.send(resultado_analisis)

    # Buscar coincidencias de URL en el mensaje y analizar cada una
    urls_encontradas = url_regex.findall(message.content)
    for url in urls_encontradas:
        if message.channel.id not in canales_detener:
            await message.channel.send(f"Analizando URL: {url}...")
            resultado_analisis = await obtener_resultados_virustotal(url)
            await message.channel.send(resultado_analisis)

    # Procesar comandos solo si no se encontraron URLs ni archivos adjuntos
    if not urls_encontradas and not message.attachments:
        try:
            await bot.process_commands(message)
        except commands.CommandNotFound:
            pass  # Ignorar el error CommandNotFoundNotFound

bot.run(BOT_TOKEN)
