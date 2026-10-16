#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CORE="$SCRIPT_DIR/extract_metadata.py"
GUIDED="$SCRIPT_DIR/extract_metadata_termux.py"
PYTHON="$(command -v python3 || true)"

if [[ -z "$PYTHON" ]]; then
  echo "Error: instala Python en Termux con: pkg install python" >&2
  exit 2
fi

if [[ ! -f "$CORE" ]]; then
  echo "Error: no se encuentra el analizador principal: $CORE" >&2
  exit 2
fi

if [[ $# -eq 0 ]]; then
  if [[ ! -f "$GUIDED" ]]; then
    echo "Error: no se encuentra el asistente Termux: $GUIDED" >&2
    exit 2
  fi
  exec "$PYTHON" "$GUIDED"
fi

args=(--forense --progress)
if ! command -v exiftool >/dev/null 2>&1; then
  echo "Aviso: ExifTool no está instalado; se omitirán metadatos incrustados." >&2
  echo "Para instalarlo desde Termux: bash '$SCRIPT_DIR/install_exiftool_termux.sh'" >&2
  args+=(--sin-incrustados)
fi

# El analizador lee los archivos y no los ejecuta.
exec "$PYTHON" "$CORE" "${args[@]}" "$@"
