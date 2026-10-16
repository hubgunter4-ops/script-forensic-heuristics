# Análisis forense estático de scripts

Herramienta de línea de comandos y reglas heurísticas de ejemplo para revisar scripts Python, Bash/wget y Ruby. El análisis es estático: **los archivos inspeccionados no se ejecutan**. Una coincidencia no demuestra por sí sola que un archivo sea malicioso.

## Archivos

- `extract_metadata.py`: analizador principal; extrae metadatos, hashes, entropía y análisis estático de formatos admitidos.
- `extract_metadata_termux.py`: asistente interactivo para Termux, con explorador de rutas y selector Android.
- `examples/advanced_script_rules.json`: reglas avanzadas para Python, Bash/wget y Ruby.

## Uso del analizador

```bash
python extract_metadata.py --rules examples/advanced_script_rules.json archivo.py
python extract_metadata.py --rules examples/advanced_script_rules.json instalador.sh modulo.rb --json
python extract_metadata.py -r ./fuentes --rules examples/advanced_script_rules.json --json -o informe.json
```

`--rules` activa el análisis forense. Las reglas admiten `id`, `description`, `severity`, `extensions`, `flags` (`i`/`m`) y `pattern` (expresión regular de Python). Se permiten hasta 100 reglas de hasta 400 caracteres cada una. Algunas formas de repetición anidada se rechazan para evitar expresiones de coste excesivo.

## Asistente y almacenamiento en Termux

Instala Python y los comandos Termux:API; instala también la aplicación Termux:API desde la misma fuente/firma que Termux:

```bash
pkg install python termux-api
python extract_metadata_termux.py
```

El menú ofrece:

1. `termux-storage-get`: elegir un archivo con el selector de Android; puedes repetir la selección.
2. **Explorar archivos disponibles en la terminal**: elegir una carpeta accesible, buscar de forma inmediata o recursiva, filtrar por extensión/nombre y seleccionar entradas por número.
3. Introducir rutas manualmente.
4. Ejecutar `termux-setup-storage` y después explorar el almacenamiento compartido.

`termux-setup-storage` prepara los accesos bajo `~/storage/` y puede mostrar un diálogo de permisos de Android. Revísalo y concede el permiso desde el dispositivo si quieres acceder al almacenamiento compartido. Después, el explorador incluye ubicaciones disponibles como `~/storage/shared`, `~/storage/downloads`, DCIM, imágenes, vídeos y música. No hay un comando genérico llamado `termux-storage` para conceder el permiso: el comando de configuración es `termux-setup-storage`, y `termux-storage-get` es el selector individual de Termux:API.

La exploración recursiva no sigue enlaces de directorio, está limitada a 8 niveles y 5.000 archivos por búsqueda; muestra como máximo 200 entradas y permite analizar hasta 200 archivos por ejecución. Usa un filtro como `.py,.sh` o un fragmento del nombre para acotar resultados grandes. El dispositivo y Android siguen determinando qué rutas son legibles.

Al iniciar el análisis, puedes proporcionar un JSON de reglas, decidir si intentar leer metadata incrustada con ExifTool y guardar el informe JSON en una ruta elegida. Los archivos elegidos con el selector se copian a una carpeta temporal y se eliminan al terminar.

## Cobertura de las reglas

- **Python:** `eval`/`exec` de datos decodificados o descomprimidos, compilación en modo `exec`, `subprocess` con `shell=True`, solicitudes HTTP salientes y acceso a posibles almacenes locales de credenciales/cookies.
- **Bash/wget:** descarga canalizada a intérpretes, escrituras a directorios temporales, opciones POST, indicadores de conexión inversa y persistencia.
- **Ruby:** evaluación dinámica de contenido decodificado, lanzamiento de procesos y llamadas de red.

Las expresiones personalizadas se aplican línea por línea. No reconstruyen flujos de datos entre varias líneas ni detectan todas las formas de ofuscación. Los patrones de descarga y ejecución pueden ser legítimos en instaladores y scripts de administración. Revisa URL, argumentos, permisos, destino, origen y contexto antes de concluir.

## Fuentes de Termux/Android

- [Termux:API](https://github.com/termux/termux-api)
- [`termux-storage-get`](https://wiki.termux.com/wiki/Termux-storage-get)
- [`termux-setup-storage`](https://wiki.termux.com/wiki/Termux-setup-storage)
