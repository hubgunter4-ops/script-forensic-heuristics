#!/usr/bin/env python3
"""Asistente guiado para análisis estático en Termux/Android.

El selector lo proporciona Termux:API (`termux-storage-get`). Los archivos
seleccionados se copian temporalmente a $TMPDIR y nunca se ejecutan.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

CORE = Path(__file__).with_name("extract_metadata.py")


def ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print("\nCancelado.")
        raise SystemExit(130)


def choose_by_picker(temporary_dir: Path) -> list[Path]:
    picker = shutil.which("termux-storage-get")
    if not picker:
        print("No se encuentra termux-storage-get.")
        print("Instala el paquete en Termux con: pkg install termux-api")
        print("También instala la aplicación Termux:API desde la misma fuente que Termux.")
        return []

    selected: list[Path] = []
    while True:
        index = len(selected) + 1
        default_name = f"seleccion_{index:02d}.bin"
        name = ask(f"Nombre para el informe (incluye extensión, p. ej. archivo.py) [{default_name}]: ") or default_name
        name = Path(name).name
        if not name or name in (".", ".."):
            print("Nombre no válido; inténtalo de nuevo.")
            continue
        destination = temporary_dir / name
        print("Se abrirá el selector de archivos de Android.")
        try:
            result = subprocess.run([picker, str(destination)], check=False)
        except OSError as exc:
            print(f"No se pudo abrir el selector: {exc}")
            break
        if result.returncode == 0 and destination.is_file():
            selected.append(destination)
            print(f"Archivo copiado temporalmente: {destination.name} ({destination.stat().st_size} bytes)")
        else:
            print("No se seleccionó ningún archivo o el selector devolvió un error.")
        if ask("¿Seleccionar otro archivo? [s/N]: ").lower() not in ("s", "si", "sí", "y", "yes"):
            break
    return selected


def choose_by_path() -> list[Path]:
    selected: list[Path] = []
    print("Introduce una ruta por línea. En Termux puedes usar, por ejemplo, ~/storage/shared/Download/archivo.exe.")
    print("Deja la ruta vacía para terminar.")
    while True:
        raw = ask("Ruta: ")
        if not raw:
            break
        path = Path(raw).expanduser()
        if path.is_file():
            selected.append(path)
            print(f"Añadido: {path}")
        else:
            print("No es un archivo accesible; comprueba la ruta y los permisos de almacenamiento.")
    return selected


def main() -> int:
    if not CORE.is_file():
        print(f"Falta el analizador principal: {CORE}")
        print("Coloca extract_metadata.py en la misma carpeta que este asistente.")
        return 2

    print("=== Análisis forense estático guiado para Termux ===")
    print("Los archivos se inspeccionan; no se ejecutan.")
    print("1) Elegir archivo(s) con el selector de Android (Termux:API)")
    print("2) Escribir ruta(s) manualmente")
    mode = ask("Elige 1 o 2 [1]: ") or "1"
    if mode not in ("1", "2"):
        print("Opción no válida.")
        return 2

    rules_path = ask("Ruta opcional del JSON de reglas personalizadas (Enter para omitir): ")
    if rules_path:
        rules_path = str(Path(rules_path).expanduser())
        if not Path(rules_path).is_file():
            print(f"No existe el archivo de reglas: {rules_path}")
            return 2

    with tempfile.TemporaryDirectory(prefix="termux-forense-") as temp_name:
        temporary_dir = Path(temp_name)
        files = choose_by_picker(temporary_dir) if mode == "1" else choose_by_path()
        if not files:
            print("No hay archivos para analizar.")
            return 1

        report_path = ask("Ruta opcional para guardar el informe JSON (Enter para mostrarlo aquí): ")
        embedded = ask("¿Intentar leer metadatos incrustados con ExifTool, si está instalado? [s/N]: ").lower() in ("s", "si", "sí", "y", "yes")
        command = [sys.executable, str(CORE), "--forense", "--json"]
        if not embedded:
            command.append("--sin-incrustados")
        if rules_path:
            command.extend(["--rules", rules_path])
        if report_path:
            destination = Path(report_path).expanduser()
            if not destination.parent.exists():
                print(f"No existe la carpeta del informe: {destination.parent}")
                return 2
            command.extend(["--output", str(destination)])
        command.extend(str(path) for path in files)
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        if result.stderr:
            print(result.stderr, file=sys.stderr, end="")
        if report_path:
            print(f"Informe guardado en: {Path(report_path).expanduser()}")
            if result.returncode not in (0, 1):
                return result.returncode
            return result.returncode
        try:
            report = json.loads(result.stdout)
            print(json.dumps(report, ensure_ascii=False, indent=2))
        except json.JSONDecodeError:
            print(result.stdout, end="")
            print("No se pudo interpretar la salida JSON del analizador.", file=sys.stderr)
            return 2
        return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
