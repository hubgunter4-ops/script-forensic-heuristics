#!/usr/bin/env python3
"""Asistente guiado para análisis estático en Termux/Android.

Permite usar el selector SAF de Termux:API, explorar archivos y carpetas
accesibles desde Termux, o introducir rutas. Los archivos nunca se ejecutan.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

CORE = Path(__file__).with_name("extract_metadata.py")
MAX_SCAN_FILES = 5000
MAX_DEPTH = 8
MAX_VISIBLE_FILES = 200
MAX_SELECTED_FILES = 200


def ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print("\nCancelado.")
        raise SystemExit(130)


def yes(value: str) -> bool:
    return value.lower() in ("s", "si", "sí", "y", "yes")


def setup_shared_storage() -> bool:
    """Lanza el comando oficial de Termux; Android gestiona el permiso."""
    setup = shutil.which("termux-setup-storage")
    if not setup:
        print("No se encuentra termux-setup-storage; esta función solo está disponible dentro de Termux.")
        return False
    print("Se solicitará/preparará acceso al almacenamiento compartido de Android.")
    print("Si Android muestra un diálogo de permisos, revísalo y acepta solo si lo deseas.")
    try:
        result = subprocess.run([setup], check=False)
    except OSError as exc:
        print(f"No se pudo iniciar termux-setup-storage: {exc}")
        return False
    shared = Path.home() / "storage" / "shared"
    if result.returncode == 0 and shared.exists():
        print(f"Acceso preparado: {shared}")
        return True
    if result.returncode != 0:
        print(f"termux-setup-storage terminó con código {result.returncode}.")
    else:
        print("El comando terminó; comprueba los permisos de almacenamiento en Android y vuelve a intentarlo.")
    return False


def storage_roots() -> list[tuple[str, Path]]:
    home = Path.home()
    candidates = [
        ("Directorio actual", Path.cwd()),
        ("Almacenamiento compartido Android", home / "storage" / "shared"),
        ("Descargas", home / "storage" / "downloads"),
        ("DCIM / cámara", home / "storage" / "dcim"),
        ("Imágenes", home / "storage" / "pictures"),
        ("Vídeos", home / "storage" / "movies"),
        ("Música", home / "storage" / "music"),
        ("Home de Termux", home),
    ]
    roots: list[tuple[str, Path]] = []
    seen: set[str] = set()
    for label, candidate in candidates:
        try:
            if not candidate.is_dir() or not os.access(candidate, os.R_OK | os.X_OK):
                continue
            canonical = candidate.resolve()
            key = str(canonical)
            if key not in seen:
                roots.append((label, candidate))
                seen.add(key)
        except OSError:
            continue
    return roots


def scan_files(root: Path, recursive: bool) -> tuple[list[Path], list[str], bool]:
    """Lista archivos legibles en una raíz, con límites y sin seguir symlinks de directorio."""
    warnings: list[str] = []
    files: list[Path] = []
    truncated = False
    try:
        root = root.expanduser().resolve(strict=True)
    except OSError as exc:
        return [], [f"No se puede acceder a la carpeta: {exc}"], False
    if not root.is_dir():
        return [], [f"No es una carpeta: {root}"], False

    def onerror(exc: OSError) -> None:
        warnings.append(f"No se pudo leer una carpeta: {exc}")

    for current, dirnames, filenames in os.walk(root, topdown=True, followlinks=False, onerror=onerror):
        current_path = Path(current)
        try:
            depth = len(current_path.relative_to(root).parts)
        except ValueError:
            depth = MAX_DEPTH
        if not recursive or depth >= MAX_DEPTH:
            dirnames[:] = []
        else:
            dirnames[:] = sorted(name for name in dirnames if not (current_path / name).is_symlink())
        for filename in sorted(filenames, key=str.casefold):
            candidate = current_path / filename
            try:
                if candidate.is_file():
                    files.append(candidate)
                    if len(files) >= MAX_SCAN_FILES:
                        truncated = True
                        break
            except OSError:
                continue
        if truncated:
            break
    files.sort(key=lambda path: str(path).casefold())
    return files, warnings, truncated


def filter_files(files: list[Path], raw_filter: str) -> list[Path]:
    raw_filter = raw_filter.strip().lower()
    if not raw_filter:
        return files
    terms = [term.strip().removeprefix("*") for term in raw_filter.split(",") if term.strip()]
    if not terms:
        return files
    if all(term.startswith(".") and "/" not in term for term in terms):
        wanted = {term for term in terms}
        return [path for path in files if path.suffix.lower() in wanted]
    return [path for path in files if any(term in path.name.lower() for term in terms)]


def select_from_list(files: list[Path], root: Path) -> list[Path]:
    if not files:
        print("No hay archivos que coincidan con el filtro.")
        return []
    shown = files[:MAX_VISIBLE_FILES]
    print(f"Archivos encontrados: {len(files)}. Se muestran {len(shown)} como máximo.")
    for index, path in enumerate(shown, 1):
        try:
            size = path.stat().st_size
            size_text = f"{size} bytes"
        except OSError:
            size_text = "tamaño no disponible"
        try:
            display_path = path.relative_to(root)
        except ValueError:
            display_path = path
        print(f"{index:3d}) {display_path} [{size_text}]")
    if len(files) > MAX_VISIBLE_FILES:
        print("Hay más de 200 resultados. Filtra por extensión/nombre para acceder a los restantes.")
    print("Introduce índices separados por comas (p. ej. 1,3,5) o 'todos'.")
    raw = ask("Archivos a analizar: ").lower()
    if raw in ("todos", "todo", "all", "a"):
        selected = shown[:MAX_SELECTED_FILES]
        if len(files) > MAX_SELECTED_FILES:
            print(f"Selección limitada a {MAX_SELECTED_FILES} archivos; filtra y vuelve a explorar para reducir el conjunto.")
        return selected
    indexes: list[int] = []
    try:
        for chunk in raw.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            if "-" in chunk:
                first, last = (int(part.strip()) for part in chunk.split("-", 1))
                if first < 1 or last < first or last > len(shown):
                    raise ValueError
                indexes.extend(range(first, last + 1))
            else:
                index = int(chunk)
                if index < 1 or index > len(shown):
                    raise ValueError
                indexes.append(index)
    except ValueError:
        print("Selección inválida; usa índices mostrados, rangos como 2-4 o 'todos'.")
        return []
    unique_indexes = list(dict.fromkeys(indexes))[:MAX_SELECTED_FILES]
    if len(indexes) > MAX_SELECTED_FILES:
        print(f"Selección limitada a {MAX_SELECTED_FILES} archivos.")
    return [shown[index - 1] for index in unique_indexes]


def choose_from_terminal() -> list[Path]:
    roots = storage_roots()
    if not roots:
        print("No se encontraron carpetas legibles.")
        return []
    print("Carpetas accesibles desde Termux (los permisos de Android pueden limitar el contenido):")
    for index, (label, root) in enumerate(roots, 1):
        print(f"{index}) {label}: {root}")
    raw_index = ask("Elige una carpeta: ")
    try:
        index = int(raw_index)
        if index < 1 or index > len(roots):
            raise ValueError
    except ValueError:
        print("Selección de carpeta inválida.")
        return []
    label, root = roots[index - 1]
    recursive = yes(ask(f"¿Incluir subcarpetas de {label}? [s/N]: "))
    files, warnings, truncated = scan_files(root, recursive)
    for warning in warnings[:10]:
        print(f"Aviso: {warning}")
    if len(warnings) > 10:
        print(f"Se omitieron {len(warnings) - 10} avisos adicionales de lectura.")
    if truncated:
        print(f"Se alcanzó el límite de exploración de {MAX_SCAN_FILES} archivos; aplica un filtro para acotar la búsqueda.")
    file_filter = ask("Filtro opcional: extensión (.py,.sh) o texto del nombre [ninguno]: ")
    return select_from_list(filter_files(files, file_filter), root.resolve())


def choose_by_picker(temporary_dir: Path) -> list[Path]:
    picker = shutil.which("termux-storage-get")
    if not picker:
        print("No se encuentra termux-storage-get.")
        print("Instala el paquete en Termux con: pkg install termux-api")
        print("También instala la aplicación Termux:API desde la misma fuente que Termux.")
        return []

    selected: list[Path] = []
    while len(selected) < MAX_SELECTED_FILES:
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
        if not yes(ask("¿Seleccionar otro archivo? [s/N]: ")):
            break
    return selected


def choose_by_path() -> list[Path]:
    selected: list[Path] = []
    print("Introduce una ruta por línea. Ejemplo: ~/storage/shared/Download/archivo.exe.")
    print("Deja la ruta vacía para terminar.")
    while len(selected) < MAX_SELECTED_FILES:
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
    print("1) Seleccionar archivo(s) con el selector Android (termux-storage-get)")
    print("2) Explorar archivos/carpetas accesibles desde la terminal")
    print("3) Escribir ruta(s) manualmente")
    print("4) Ejecutar termux-setup-storage y explorar almacenamiento compartido")
    mode = ask("Elige 1-4 [2]: ") or "2"
    if mode not in ("1", "2", "3", "4"):
        print("Opción no válida.")
        return 2
    if mode == "4":
        setup_shared_storage()
        mode = "2"

    rules_path = ask("Ruta opcional del JSON de reglas personalizadas (Enter para omitir): ")
    if rules_path:
        rules_path = str(Path(rules_path).expanduser())
        if not Path(rules_path).is_file():
            print(f"No existe el archivo de reglas: {rules_path}")
            return 2

    with tempfile.TemporaryDirectory(prefix="termux-forense-") as temp_name:
        temporary_dir = Path(temp_name)
        if mode == "1":
            files = choose_by_picker(temporary_dir)
        elif mode == "2":
            files = choose_from_terminal()
        else:
            files = choose_by_path()
        if not files:
            print("No hay archivos para analizar.")
            return 1

        report_path = ask("Ruta opcional para guardar el informe JSON (Enter para mostrarlo aquí): ")
        embedded = yes(ask("¿Intentar leer metadatos incrustados con ExifTool, si está instalado? [s/N]: "))
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
