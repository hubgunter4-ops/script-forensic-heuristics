# Análisis forense estático de scripts

Herramienta de línea de comandos y reglas heurísticas para revisar scripts Python, Bash/wget y Ruby. El análisis es estático: **los archivos inspeccionados no se ejecutan**. Una coincidencia no demuestra por sí sola que un archivo sea malicioso.

## Archivos

- `extract_metadata.py`: analizador principal de metadatos y formatos.
- `extract_metadata_termux.py`: asistente con explorador de rutas, selector Android y configuración de almacenamiento.
- `review_termux.sh`: revisión rápida desde la terminal; sin argumentos abre el asistente y con rutas lanza el análisis.
- `install_exiftool_termux.sh`: instala/verifica ExifTool usando los repositorios de Termux.
- `examples/advanced_script_rules.json`: reglas para Python, Bash/wget y Ruby.

## Instalación y uso en Termux

Instala Python y, si deseas usar el selector SAF de Android, Termux:API. La aplicación Termux:API debe proceder de la misma fuente/firma que Termux.

```bash
pkg install python termux-api
bash install_exiftool_termux.sh
```

El instalador actualiza los índices (`pkg update`) e instala el paquete `exiftool` con `pkg install -y exiftool`. Termux mantiene un paquete propio que depende de Perl; por eso el instalador no descarga binarios genéricos ni usa `sudo` o CPAN [1]. La gestión de paquetes se realiza con `pkg`/APT en el prefijo de Termux [2].

Para iniciar el asistente:

```bash
python extract_metadata_termux.py
# O el wrapper de revisión:
bash review_termux.sh
```

El asistente tiene una opción para instalar/verificar ExifTool. También admite el selector `termux-storage-get`, exploración de carpetas accesibles, rutas manuales y `termux-setup-storage`. Este último prepara accesos bajo `~/storage/` y puede mostrar un diálogo de permisos Android; la decisión del permiso se toma en el dispositivo. La exploración recursiva no sigue enlaces de directorio y está limitada a 8 niveles y 5.000 archivos; se muestran como máximo 200 entradas y se pueden revisar hasta 200 por ejecución.

Al terminar la selección, el asistente permite guardar el informe en **JSON, HTML, PDF o texto**. Si aceptas la ruta sugerida, los archivos se guardan en el directorio actual con un nombre `informe_forense_...`.

## Revisión desde la terminal

Pasa archivos o carpetas al wrapper; este invoca `extract_metadata.py` en modo forense. Si ExifTool no está en `PATH`, informa cómo instalarlo y continúa omitiendo metadata incrustada:

```bash
bash review_termux.sh ~/storage/shared/Download/foto.jpg
bash review_termux.sh --json --rules examples/advanced_script_rules.json ~/storage/shared/Download/script.py
bash review_termux.sh -r -o informe.json ~/storage/shared/Download
bash review_termux.sh --format html -o informe.html ~/storage/shared/Download/foto.jpg
bash review_termux.sh --format pdf -o informe.pdf ~/storage/shared/Download/foto.jpg
python extract_metadata.py --forense --format pdf -o informe.pdf muestra.exe
```

Los formatos de CLI son `text`, `json`, `html` y `pdf`; `--json` sigue disponible como alias de compatibilidad. PDF requiere `-o/--output`. HTML es un archivo autocontenido. El generador PDF usa solo Python estándar, sin instalar conversores; los caracteres que no pertenezcan a Windows-1252 pueden aparecer como `?` en ese formato. El asistente y el wrapper muestran barras de avance por fase y un indicador durante la lectura de metadata con ExifTool; el progreso va por `stderr`, así que la salida JSON permanece válida.

Sin argumentos, `review_termux.sh` abre el asistente guiado. ExifTool sirve para leer/escribir metadata en muchos formatos y se distribuye como herramienta Perl; el paquete de Termux integra esa dependencia [1] [3].

## Reglas personalizadas

```bash
python extract_metadata.py --rules examples/advanced_script_rules.json archivo.py
python extract_metadata.py --rules examples/advanced_script_rules.json instalador.sh modulo.rb --json
```

`--rules` activa el análisis forense. Las reglas admiten `id`, `description`, `severity`, `extensions`, `flags` (`i`/`m`) y `pattern` (regex de Python). El analizador acepta hasta 100 reglas de hasta 400 caracteres. Algunas formas de repetición anidada se rechazan para evitar expresiones de coste excesivo.

## Herramientas que se pueden integrar

- `file` para identificar formatos por firma y no solo por extensión.
- `binutils` (`readelf`, `strings`) para cabeceras/dependencias ELF y cadenas.
- **YARA** para reglas locales de patrones sobre archivos y muestras.
- **ClamAV** para comparar con firmas antivirus; requiere considerar el tamaño de sus bases de datos y actualizaciones.
- **Androguard** para análisis estático de APK/DEX.
- **binwalk** para identificar estructuras y componentes en firmware.

Son candidatos para futuras integraciones, no dependencias de esta versión. Antes de añadir cada uno habría que verificar disponibilidad y mantenimiento en los repositorios Termux actuales, consumo de almacenamiento y límites de análisis. Las herramientas externas se ejecutarían de forma opcional y sin ejecutar la muestra analizada.

## Alcance y limitaciones

Las reglas se evalúan línea por línea; no reconstruyen flujos entre varias líneas ni detectan toda ofuscación. Una regla puede dar falsos positivos, y no encontrar coincidencias no certifica que un archivo sea seguro. Revisa el contexto, URLs, permisos, destinos y origen antes de concluir.

## Referencias

[1]: https://github.com/termux/termux-packages/blob/master/packages/exiftool/build.sh "Definición oficial del paquete ExifTool de Termux"
[2]: https://github.com/termux/termux-packages/wiki/Package-Management "Gestión de paquetes de Termux"
[3]: https://exiftool.org/install.html "Instalación oficial de ExifTool"
