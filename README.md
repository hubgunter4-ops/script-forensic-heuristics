# Reglas heurísticas avanzadas para scripts

Conjunto de reglas JSON de ejemplo para el analizador estático de scripts. Incluye patrones orientativos para Python, Bash/wget y Ruby. **No ejecuta código ni declara que un archivo sea malicioso**: cada coincidencia requiere inspección contextual.

## Requisitos

Las reglas usan el formato de configuración `rules` del analizador `extract_metadata.py`. El analizador debe reconocer la extensión del archivo; la versión de este proyecto que acompaña a estas reglas incluye `.rb` (Ruby).

## Uso

Desde el directorio del analizador:

```bash
python extract_metadata.py --rules /ruta/a/advanced_script_rules.json archivo.py
python extract_metadata.py --rules /ruta/a/advanced_script_rules.json instalador.sh modulo.rb --json
```

La opción `--rules` activa el modo forense. Para una salida amplia en un árbol de scripts:

```bash
python extract_metadata.py -r ./fuentes --forense --rules /ruta/a/advanced_script_rules.json --json -o informe.json
```

## Cobertura

- **Python:** `eval`/`exec` de datos decodificados o descomprimidos, compilación en modo `exec`, `subprocess` con `shell=True`, solicitudes HTTP salientes y acceso a posibles almacenes locales de credenciales/cookies.
- **Bash:** `wget`/`curl` canalizados a intérpretes, descargas a directorios temporales, opciones POST de `wget`, indicadores de conexión inversa y cambios de persistencia.
- **Ruby:** evaluación dinámica de contenido decodificado, lanzamiento de procesos y llamadas de red.

Las expresiones se evalúan línea por línea. Por diseño, no reconstruyen flujos de datos entre líneas ni detectan todas las formas ofuscadas. Los patrones de descarga y ejecución pueden ser legítimos en instaladores y scripts de administración; revisa URL, argumentos, permisos, destino, origen y contexto antes de concluir.

## Personalización

Edita `examples/advanced_script_rules.json`. Cada regla define un `id`, `description`, `severity`, `extensions`, `flags` y `pattern` (expresión regular de Python). La severidad es una etiqueta para ordenar la revisión, no una puntuación calculada. Se aceptan hasta 100 reglas, patrones de hasta 400 caracteres y flags `i`/`m`. El analizador rechaza algunas expresiones con repetición anidada para evitar patrones de coste excesivo.

## Seguridad y limitaciones

El analizador lee el texto fuente y no ejecuta el archivo inspeccionado. Estos indicadores pueden generar falsos positivos, y un archivo sin coincidencias no queda certificado como seguro. No uses el informe como única decisión de respuesta a incidentes.
