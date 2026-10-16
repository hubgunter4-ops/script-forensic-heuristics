# Análisis forense estático de scripts

Herramienta de línea de comandos y reglas heurísticas de ejemplo para revisar scripts Python, Bash/wget y Ruby. El análisis es estático: **los archivos inspeccionados no se ejecutan**. Una coincidencia no demuestra por sí sola que un archivo sea malicioso.

## Archivos

- `extract_metadata.py`: analizador principal; extrae metadatos, hashes, entropía y análisis estático de formatos admitidos.
- `extract_metadata_termux.py`: asistente interactivo para Termux y el selector Android.
- `examples/advanced_script_rules.json`: reglas avanzadas para Python, Bash/wget y Ruby.

## Uso del analizador

```bash
python extract_metadata.py --rules examples/advanced_script_rules.json archivo.py
python extract_metadata.py --rules examples/advanced_script_rules.json instalador.sh modulo.rb --json
python extract_metadata.py -r ./fuentes --rules examples/advanced_script_rules.json --json -o informe.json
```

`--rules` activa el análisis forense. Las reglas admiten `id`, `description`, `severity`, `extensions`, `flags` (`i`/`m`) y `pattern` (expresión regular de Python). Se permiten hasta 100 reglas de hasta 400 caracteres cada una. Algunas formas de repetición anidada se rechazan para evitar expresiones de coste excesivo.

## Asistente Termux

Instala Python, el paquete de comandos Termux:API y su aplicación complementaria:

```bash
pkg install python termux-api
python extract_metadata_termux.py
```

La aplicación Termux:API debe instalarse desde la misma fuente/firma que Termux. El asistente usa `termux-storage-get` para abrir el selector de archivos de Android y permite repetir la selección para revisar varios archivos. También puedes introducir rutas manualmente. Para preparar accesos a carpetas compartidas de Android, ejecuta `termux-setup-storage` y usa rutas como `~/storage/shared/Download/archivo.py`.

Al iniciar, selecciona el nombre/extensión que quieres usar para el informe, opcionalmente proporciona un JSON de reglas y elige si intentar leer metadata incrustada con ExifTool. Los archivos seleccionados por el selector se copian a una carpeta temporal y se eliminan al acabar.

## Cobertura de las reglas

- **Python:** `eval`/`exec` de datos decodificados o descomprimidos, compilación en modo `exec`, `subprocess` con `shell=True`, solicitudes HTTP salientes y acceso a posibles almacenes locales de credenciales/cookies.
- **Bash/wget:** descarga canalizada a intérpretes, escrituras a directorios temporales, opciones POST, indicadores de conexión inversa y persistencia.
- **Ruby:** evaluación dinámica de contenido decodificado, lanzamiento de procesos y llamadas de red.

Las expresiones personalizadas se aplican línea por línea y al conjunto de extensiones configurado. No reconstruyen flujos de datos entre varias líneas ni detectan todas las formas de ofuscación. Los patrones de descarga y ejecución pueden ser legítimos en instaladores y scripts de administración. Revisa URL, argumentos, permisos, destino, origen y contexto antes de concluir.

## Fuentes de Termux/Android

- [Termux:API](https://github.com/termux/termux-api)
- [`termux-storage-get`](https://wiki.termux.com/wiki/Termux-storage-get)
- [`termux-setup-storage`](https://wiki.termux.com/wiki/Termux-setup-storage)
