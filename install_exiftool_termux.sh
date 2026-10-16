#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${PREFIX:-}" || "$PREFIX" != */com.termux/files/usr ]]; then
  echo "Error: ejecuta este instalador dentro de Termux, no en Linux de escritorio." >&2
  echo "Se requiere el prefijo Termux estándar y el comando pkg." >&2
  exit 2
fi

if ! command -v pkg >/dev/null 2>&1 || [[ ! -x "$PREFIX/bin/pkg" ]]; then
  echo "Error: no se encuentra pkg en el prefijo Termux ($PREFIX)." >&2
  exit 2
fi

printf '%s\n' "Actualizando los índices del repositorio oficial de Termux..."
pkg update

printf '%s\n' "Instalando ExifTool desde el paquete de Termux (exiftool)..."
pkg install -y exiftool

if ! command -v exiftool >/dev/null 2>&1; then
  echo "Error: pkg finalizó, pero exiftool no aparece en PATH." >&2
  exit 1
fi

printf 'ExifTool instalado: versión '
exiftool -ver
