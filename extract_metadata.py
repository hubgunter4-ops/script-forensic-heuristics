#!/usr/bin/env python3
"""Extrae metadatos y realiza triage forense estático, sin ejecutar archivos."""
from __future__ import annotations

import argparse
import ast
import datetime as dt
import hashlib
import json
import math
import mimetypes
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import time
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any


def iso_timestamp(timestamp: float) -> str:
    return dt.datetime.fromtimestamp(timestamp, tz=dt.timezone.utc).astimezone().isoformat(timespec="seconds")


def basic_metadata(path: Path) -> dict[str, Any]:
    st = path.stat()
    guessed_type, _ = mimetypes.guess_type(path.name)
    return {
        "archivo": str(path.resolve()),
        "nombre": path.name,
        "extension": path.suffix.lower(),
        "tipo_mime_estimado": guessed_type or "desconocido",
        "tamaño_bytes": st.st_size,
        "tamaño_legible": _human_size(st.st_size),
        "creado_o_cambio_metadatos": iso_timestamp(st.st_ctime),
        "modificado": iso_timestamp(st.st_mtime),
        "ultimo_acceso": iso_timestamp(st.st_atime),
        "permisos": stat.filemode(st.st_mode),
        "es_enlace_simbólico": path.is_symlink(),
    }


def _human_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{size} B"
        value /= 1024
    return f"{size} B"


def _hashes_and_entropy(path: Path) -> tuple[dict[str, str], float, str]:
    hashes = {"MD5": hashlib.md5(), "SHA1": hashlib.sha1(), "SHA256": hashlib.sha256()}
    counts = [0] * 256
    total = 0
    with path.open("rb") as stream:
        header = stream.read(32)
        if path.stat().st_size <= 32:
            data = header
            for value in data:
                counts[value] += 1
            total = len(data)
            for digest in hashes.values():
                digest.update(data)
        else:
            for digest in hashes.values():
                digest.update(header)
            for value in header:
                counts[value] += 1
            total = len(header)
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                for digest in hashes.values():
                    digest.update(chunk)
                chunk_counts = Counter(chunk)
                for value, count in chunk_counts.items():
                    counts[value] += count
    entropy = -sum((count / total) * math.log2(count / total) for count in counts if count) if total else 0.0
    return {name: digest.hexdigest() for name, digest in hashes.items()}, entropy, header.hex(" ")


def _run_tool(command: list[str], timeout: int = 12, limit: int = 16000) -> str | None:
    try:
        result = subprocess.run(command, capture_output=True, text=True, errors="replace", timeout=timeout, check=False)
        text = (result.stdout or result.stderr).strip()
        return text[:limit] if text else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def _progress_bar(stage: str, current: int, total: int, detail: str = "") -> None:
    if total <= 0:
        return
    width = 24
    fraction = min(1.0, max(0.0, current / total))
    filled = int(width * fraction)
    percent = int(fraction * 100)
    suffix = f" {detail[:48]}" if detail else ""
    line = f"\r{stage:<20} [{'#' * filled}{'-' * (width - filled)}] {current}/{total} {percent:3d}%{suffix}"
    sys.stderr.write(line + ("\n" if current >= total else ""))
    sys.stderr.flush()


def _file_identification(path: Path) -> str | None:
    file_tool = shutil.which("file")
    return _run_tool([file_tool, "-b", "--", str(path)], timeout=10, limit=1000) if file_tool else None


def _ascii_strings(path: Path, min_length: int = 4, max_strings: int = 80, max_chars: int = 400) -> list[str]:
    """Devuelve una muestra acotada de cadenas ASCII imprimibles; no decodifica ni ejecuta el archivo."""
    found: list[str] = []
    current = bytearray()
    was_truncated = False

    def finish() -> None:
        nonlocal current, was_truncated
        if len(current) >= min_length and len(found) < max_strings:
            value = current.decode("ascii", errors="replace")
            found.append(value + ("… [cadena truncada]" if was_truncated else ""))
        current = bytearray()
        was_truncated = False

    with path.open("rb") as stream:
        while len(found) < max_strings:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            for byte in chunk:
                if 32 <= byte <= 126:
                    if len(current) < max_chars:
                        current.append(byte)
                    else:
                        was_truncated = True
                else:
                    finish()
                    if len(found) >= max_strings:
                        break
    if len(found) < max_strings:
        finish()
    return found


def _pe_analysis(path: Path) -> dict[str, Any]:
    """Lee estructuras PE/COFF acotadas; no carga ni ejecuta el binario."""
    result: dict[str, Any] = {"formato": "PE/COFF", "analisis_estatico_sin_ejecucion": True}
    architectures = {0x014C: "x86", 0x8664: "x86-64", 0x01C0: "ARM", 0x01C4: "ARMv7", 0xAA64: "ARM64", 0x0200: "IA-64"}
    subsystem_names = {1: "Native", 2: "Windows GUI", 3: "Windows CUI/Console", 7: "POSIX CUI", 9: "Windows CE GUI", 10: "EFI Application", 14: "Xbox"}
    try:
        file_size = path.stat().st_size
        with path.open("rb") as stream:
            dos = stream.read(64)
            if len(dos) < 64 or dos[:2] != b"MZ":
                return {"formato": "No es PE válido", "aviso": "La extensión sugiere .exe/.dll, pero falta la firma MZ."}
            pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
            if pe_offset < 64 or pe_offset > file_size - 24:
                return {"formato": "PE inválido o truncado", "error": "Offset de cabecera PE fuera de los límites del archivo."}
            stream.seek(pe_offset)
            header = stream.read(24)
            if len(header) != 24 or header[:4] != b"PE\0\0":
                return {"formato": "PE inválido o truncado", "error": "No se encontró la firma PE\0\0 esperada."}
            machine, section_count, timestamp, _, _, optional_size, characteristics = struct.unpack("<HHIIIHH", header[4:24])
            optional = stream.read(min(optional_size, 4096))
            optional_magic = struct.unpack_from("<H", optional)[0] if len(optional) >= 2 else 0
            is_pe32_plus = optional_magic == 0x20B
            result.update({
                "arquitectura": architectures.get(machine, f"desconocida (0x{machine:04x})"),
                "numero_secciones": section_count,
                "timestamp_coff_utc": dt.datetime.fromtimestamp(timestamp, tz=dt.timezone.utc).isoformat() if timestamp else None,
                "timestamp_nota": "La marca temporal de PE puede estar ausente o ser falsificada; no es prueba de fecha de compilación.",
                "tipo": "DLL" if characteristics & 0x2000 else ("EXE" if characteristics & 0x0002 else "imagen PE"),
                "caracteristicas_coff_hex": f"0x{characteristics:04x}",
                "formato_cabecera_opcional": "PE32+" if is_pe32_plus else ("PE32" if optional_magic == 0x10B else f"desconocido (0x{optional_magic:04x})"),
            })
            if optional_magic in (0x10B, 0x20B) and len(optional) >= (72 if is_pe32_plus else 72):
                image_base_offset = 24 if is_pe32_plus else 28
                image_base_fmt = "<Q" if is_pe32_plus else "<I"
                result["punto_de_entrada_rva"] = f"0x{struct.unpack_from('<I', optional, 16)[0]:08x}"
                result["image_base"] = f"0x{struct.unpack_from(image_base_fmt, optional, image_base_offset)[0]:x}"
                subsystem = struct.unpack_from("<H", optional, 68)[0]
                dll_flags = struct.unpack_from("<H", optional, 70)[0]
                result["subsistema"] = subsystem_names.get(subsystem, f"desconocido ({subsystem})")
                flags = {"ASLR_dynamic_base": 0x0040, "DEP_NX_compatible": 0x0100, "high_entropy_ASLR": 0x0020, "Control_Flow_Guard": 0x4000, "AppContainer": 0x1000}
                result["protecciones_declaradas"] = [name for name, mask in flags.items() if dll_flags & mask]
                number_offset, directory_offset = ((108, 112) if is_pe32_plus else (92, 96))
                directory_names = {0: "exportaciones", 1: "importaciones", 2: "recursos", 3: "exception_table", 4: "certificado_firma_authenticode"}
                if len(optional) >= number_offset + 4:
                    directory_count = min(struct.unpack_from("<I", optional, number_offset)[0], 16)
                    directories = {}
                    for index in range(directory_count):
                        pos = directory_offset + index * 8
                        if pos + 8 > len(optional):
                            break
                        address, size = struct.unpack_from("<II", optional, pos)
                        if address or size:
                            directories[directory_names.get(index, f"directorio_{index}")] = {"rva_o_offset": f"0x{address:x}", "tamaño": size}
                    result["directorios"] = directories
            section_table = pe_offset + 24 + optional_size
            stream.seek(section_table)
            sections = []
            last_raw_end = section_table
            for index in range(min(section_count, 96)):
                raw = stream.read(40)
                if len(raw) != 40:
                    break
                name, virtual_size, virtual_address, raw_size, raw_offset, _, _, _, _, flags = struct.unpack("<8sIIIIIIHHI", raw)
                section_name = name.split(b"\0", 1)[0].decode("ascii", errors="replace")
                perms = [label for mask, label in ((0x20000000, "execute"), (0x40000000, "read"), (0x80000000, "write")) if flags & mask]
                sections.append({"nombre": section_name, "tamaño_virtual": virtual_size, "tamaño_raw": raw_size, "offset_raw": raw_offset, "permisos": perms, "caracteristicas_hex": f"0x{flags:08x}"})
                last_raw_end = max(last_raw_end, raw_offset + raw_size)
            result["secciones"] = sections
            result["secciones_omitidas_por_limite"] = max(0, section_count - len(sections))
            result["secciones_con_permisos_rwx"] = [section["nombre"] for section in sections if {"read", "write", "execute"}.issubset(section["permisos"])]
            if last_raw_end < file_size:
                result["datos_tras_secciones_bytes"] = file_size - last_raw_end
                result["nota_datos_tras_secciones"] = "Puede ser overlay, firma o datos; su presencia no implica actividad maliciosa."
    except (OSError, struct.error, OverflowError, ValueError) as exc:
        result["error_lectura"] = str(exc)
    return result


def _ast_dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_ast_dotted_name(node.value)}.{node.attr}"
    return type(node).__name__


def load_custom_rules(path: str | None) -> tuple[list[dict[str, Any]], list[str]]:
    if not path:
        return [], []
    errors: list[str] = []
    try:
        data = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [], [f"No se pudo cargar el archivo de reglas {path}: {exc}"]
    entries = data.get("rules") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        return [], ["El JSON de reglas debe contener una lista llamada 'rules'."]
    if len(entries) > 100:
        return [], ["Se permiten como máximo 100 reglas personalizadas."]
    rules: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    allowed_severity = {"info", "low", "medium", "high", "critical"}
    for index, entry in enumerate(entries, 1):
        label = f"regla #{index}"
        if not isinstance(entry, dict):
            errors.append(f"{label}: debe ser un objeto JSON; se omitió.")
            continue
        rule_id, pattern = entry.get("id"), entry.get("pattern")
        if not isinstance(rule_id, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", rule_id):
            errors.append(f"{label}: 'id' debe contener 1-64 caracteres alfanuméricos, punto, guion o guion bajo; se omitió.")
            continue
        label = f"regla {rule_id}"
        if rule_id in seen_ids:
            errors.append(f"{label}: ID duplicado; se omitió.")
            continue
        seen_ids.add(rule_id)
        if not isinstance(pattern, str) or not pattern or len(pattern) > 400:
            errors.append(f"{label}: 'pattern' debe ser una expresión de 1-400 caracteres; se omitió.")
            continue
        # Evita los patrones de regex más habituales que pueden provocar retroceso excesivo.
        risky = re.search(r"\([^)]*(?:[+*]|\{\d)[^)]*\)(?:[+*]|\{\d)", pattern) or re.search(r"\([^)]*\|[^)]*\)(?:[+*]|\{\d)", pattern)
        if risky:
            errors.append(f"{label}: contiene repetición anidada o alternativa repetida; simplifique el patrón y se omitió.")
            continue
        flags = entry.get("flags", "i")
        if not isinstance(flags, str) or any(flag not in "im" for flag in flags):
            errors.append(f"{label}: 'flags' solo admite 'i' (ignorar mayúsculas) y 'm' (multilínea); se omitió.")
            continue
        regex_flags = (re.I if "i" in flags else 0) | (re.M if "m" in flags else 0)
        try:
            compiled = re.compile(pattern, regex_flags)
        except re.error as exc:
            errors.append(f"{label}: expresión regular inválida ({exc}); se omitió.")
            continue
        severity = entry.get("severity", "medium")
        if not isinstance(severity, str) or severity not in allowed_severity:
            errors.append(f"{label}: severidad inválida; use info, low, medium, high o critical. Se omitió.")
            continue
        extensions = entry.get("extensions", [])
        if not isinstance(extensions, list) or any(not isinstance(ext, str) for ext in extensions):
            errors.append(f"{label}: 'extensions' debe ser una lista de extensiones o quedar vacía; se omitió.")
            continue
        rules.append({
            "id": rule_id,
            "description": str(entry.get("description", ""))[:500],
            "severity": severity,
            "extensions": [ext.lower() if ext.startswith(".") else f".{ext.lower()}" for ext in extensions],
            "regex": compiled,
        })
    return rules, errors


def _custom_rule_matches(lines: list[str], suffix: str, rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    matches = []
    for rule in rules:
        if rule["extensions"] and suffix not in rule["extensions"]:
            continue
        matching_lines = []
        total = 0
        for number, line in enumerate(lines, 1):
            bounded_line = line[:4096]
            found = list(rule["regex"].finditer(bounded_line))
            if found:
                total += len(found)
                if len(matching_lines) < 80:
                    matching_lines.append({"linea": number, "coincidencias": len(found), "texto": bounded_line.strip()[:300]})
        if total:
            matches.append({
                "id": rule["id"],
                "severidad": rule["severity"],
                "descripcion": rule["description"],
                "coincidencias": total,
                "lineas_mostradas": matching_lines,
                "coincidencias_omitidas": max(0, total - sum(item["coincidencias"] for item in matching_lines)),
            })
    return matches


def _script_analysis(path: Path, custom_rules: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Analiza texto fuente con parsers/patrones; nunca evalúa el script."""
    suffix = path.suffix.lower()
    limit = 2 * 1024 * 1024
    try:
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
    except OSError as exc:
        return {"formato": "script", "error_lectura": str(exc)}
    truncated = len(raw) > limit
    raw = raw[:limit]
    text = raw.decode("utf-8-sig", errors="replace")
    lines = text.splitlines()
    result: dict[str, Any] = {
        "formato": {".py": "Python", ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".ps1": "PowerShell", ".bat": "Windows batch", ".cmd": "Windows batch", ".rb": "Ruby"}.get(suffix, "script/texto"),
        "lineas_analizadas": len(lines),
        "limite_lectura_bytes": limit,
        "contenido_truncado_para_analisis": truncated,
        "shebang": lines[0][:300] if lines and lines[0].startswith("#!") else None,
        "analisis_estatico_sin_ejecucion": True,
        "indicadores_nota": "Los indicadores son heurísticos y pueden aparecer en software legítimo; requieren revisión contextual y no son un veredicto de malware.",
    }
    if suffix == ".py":
        imports: set[str] = set()
        calls: set[str] = set()
        try:
            tree = ast.parse(text, filename=path.name)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.update(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom):
                    imports.add("." * (node.level or 0) + (node.module or ""))
                elif isinstance(node, ast.Call):
                    calls.add(_ast_dotted_name(node.func))
            result["imports"] = sorted(imports)[:200]
            interesting = ("eval", "exec", "compile", "__import__", "os.system", "os.popen", "subprocess.", "socket.", "ctypes.", "pickle.loads", "marshal.loads", "base64.b64decode", "urllib.request", "requests.")
            result["llamadas_para_revision"] = sorted(name for name in calls if any(token in name for token in interesting))[:100]
            result["parseo_sintactico"] = "correcto"
        except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
            result["parseo_sintactico"] = f"no completado: {type(exc).__name__}: {exc}"
    else:
        checks = {
            "descarga_y_ejecucion_en_cadena": r"(?i)(?:curl|wget|Invoke-WebRequest|DownloadString|Start-BitsTransfer).{0,180}(?:\|\s*(?:sh|bash)|IEX|Invoke-Expression|\bsh\b|\bbash\b)",
            "evaluacion_dinamica": r"(?i)\b(?:eval|iex|Invoke-Expression)\b",
            "contenido_base64": r"(?i)(?:base64\s+(?:-d|--decode)|FromBase64String|EncodedCommand)",
            "shell_remoto_o_red": r"(?i)(?:/dev/tcp/|\bnc\s+-|\bncat\b|\bsocat\b|\bssh\s+-[TRD])",
            "persistencia_o_servicio": r"(?i)(?:schtasks\s+/create|sc\s+create|reg\s+add|crontab\s+-|systemctl\s+enable)",
            "borrado_o_permisos": r"(?i)(?:rm\s+-rf|chmod\s+\+x|Remove-Item.{0,40}-Recurse)",
        }
        indicators = {name: len(re.findall(pattern, text)) for name, pattern in checks.items()}
        result["coincidencias_heuristicas"] = {name: count for name, count in indicators.items() if count}
        matched = []
        for number, line in enumerate(lines, 1):
            if any(re.search(pattern, line) for pattern in checks.values()):
                matched.append({"linea": number, "texto": line.strip()[:300]})
                if len(matched) >= 80:
                    break
        result["lineas_para_revision"] = matched
    if custom_rules:
        result["reglas_personalizadas"] = _custom_rule_matches(lines, suffix, custom_rules)
    return result


def _elf_analysis(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {"formato": "ELF"}
    readelf = shutil.which("readelf")
    if not readelf:
        result["aviso"] = "readelf no está instalado; se omitió el análisis de cabeceras ELF."
        return result
    header = _run_tool([readelf, "-h", "--", str(path)], limit=6000) or ""
    dynamic = _run_tool([readelf, "-d", "--", str(path)], limit=10000) or ""
    notes = _run_tool([readelf, "-n", "--", str(path)], limit=4000) or ""
    result["cabecera"] = {
        key: match.group(1).strip()
        for key, pattern in {
            "clase": r"Class:\s*(.+)",
            "endianness": r"Data:\s*(.+)",
            "tipo": r"Type:\s*(.+)",
            "arquitectura": r"Machine:\s*(.+)",
            "punto_de_entrada": r"Entry point address:\s*(.+)",
        }.items()
        if (match := re.search(pattern, header))
    }
    result["dependencias_y_rutas"] = [line.strip() for line in dynamic.splitlines() if any(tag in line for tag in ("(NEEDED)", "(RPATH)", "(RUNPATH)"))]
    build_id = re.search(r"Build ID:\s*([0-9a-fA-F]+)", notes)
    if build_id:
        result["build_id"] = build_id.group(1)
    result["cabecera_readelf"] = header[:3500] or "No disponible"
    return result


def _archive_analysis(path: Path) -> dict[str, Any] | None:
    if not zipfile.is_zipfile(path):
        return None
    result: dict[str, Any] = {"formato": "ZIP/JAR", "se_extrae_contenido": False}
    try:
        with zipfile.ZipFile(path, "r") as archive:
            members = archive.infolist()
            names = [member.filename for member in members]
            total_uncompressed = sum(member.file_size for member in members)
            result.update({
                "miembros": len(members),
                "tamaño_descomprimido_total_bytes": total_uncompressed,
                "archivos_clase": sum(name.endswith(".class") for name in names),
                "entradas_mostradas": names[:200],
                "entradas_omitidas": max(0, len(names) - 200),
                "entradas_de_firma": [name for name in names if name.upper().startswith("META-INF/") and name.upper().endswith((".SF", ".RSA", ".DSA", ".EC"))],
            })
            manifest = next((m for m in members if m.filename.upper() == "META-INF/MANIFEST.MF"), None)
            if manifest and manifest.file_size <= 512 * 1024:
                raw = archive.read(manifest)
                text = raw.decode("utf-8", errors="replace")
                wanted = ("Main-Class", "Premain-Class", "Agent-Class", "Implementation-Title", "Implementation-Version", "Specification-Version", "Class-Path", "Multi-Release")
                result["manifest"] = {key: value.strip() for line in text.splitlines() if ":" in line for key, value in [line.split(":", 1)] if key in wanted}
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        result["error_lectura"] = str(exc)
    return result


def _rc_analysis(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError as exc:
        return {"formato": "recurso Windows .rc", "error_lectura": str(exc)}
    patterns = {
        "recursos_dialog": r"(?im)^\s*\w+\s+(?:DIALOG|DIALOGEX)\b",
        "recursos_icono_o_cursor": r"(?im)^\s*\w+\s+(?:ICON|CURSOR)\s+",
        "recursos_bitmap": r"(?im)^\s*\w+\s+BITMAP\s+",
        "tablas_de_cadenas": r"(?im)^\s*STRINGTABLE\b",
        "directivas_include": r"(?im)^\s*#\s*include\b",
        "referencias_a_archivos": r'(?im)^\s*\w+\s+(?:RCDATA|HTML|PNG|JPG|AVI|WAVE|TYPELIB|MESSAGETABLE)\s+["<][^">]+[">]',
    }
    return {
        "formato": "recurso Windows .rc (texto; no se compila ni ejecuta)",
        "codificacion_leida": "UTF-8 con reemplazo de bytes inválidos",
        "lineas": len(text.splitlines()),
        "conteos": {name: len(re.findall(pattern, text)) for name, pattern in patterns.items()},
        "includes_y_referencias": [line.strip() for line in text.splitlines() if re.match(r"\s*#\s*include\b|\s*\w+\s+(?:RCDATA|HTML|PNG|JPG|AVI|WAVE|TYPELIB|MESSAGETABLE)\b", line, re.I)][:100],
    }


def forensic_analysis(path: Path, custom_rules: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    hashes, entropy, header_hex = _hashes_and_entropy(path)
    result: dict[str, Any] = {
        "identificacion": _file_identification(path) or "No disponible (comando 'file' ausente)",
        "hashes": hashes,
        "nota_hashes": "MD5 y SHA1 se incluyen por compatibilidad/identificación; para integridad criptográfica usar SHA256.",
        "entropia_shannon_bits_por_byte": round(entropy, 5),
        "entropia_nota": "La entropía alta puede aparecer en datos comprimidos/cifrados; por sí sola no demuestra malware.",
        "primeros_32_bytes_hex": header_hex,
        "cadenas_ascii_muestra": _ascii_strings(path),
        "cadenas_ascii_limite": "Hasta 80 cadenas imprimibles de 4 o más caracteres; cada una se limita a 400 caracteres.",
        "analisis_estatico_sin_ejecucion": True,
    }
    try:
        with path.open("rb") as stream:
            magic = stream.read(4)
        if magic == b"\x7fELF":
            result["formato_especializado"] = _elf_analysis(path)
            if path.suffix.lower() == ".so":
                result["formato_especializado"]["extension_sugerida"] = ".so (biblioteca compartida)"
        elif path.suffix.lower() == ".so":
            result["formato_especializado"] = {"extension_sugerida": ".so", "aviso": "La extensión es .so pero la firma ELF no coincide."}
        if magic[:2] == b"MZ":
            result["formato_especializado"] = _pe_analysis(path)
        elif path.suffix.lower() in (".exe", ".dll"):
            result["formato_especializado"] = {"formato": "No es PE válido", "aviso": "La extensión .exe/.dll no coincide con la firma MZ de Windows PE."}
        archive = _archive_analysis(path)
        if archive:
            result["formato_especializado"] = archive
            if path.suffix.lower() == ".jar":
                result["formato_especializado"]["extension_sugerida"] = ".jar (archivo Java ZIP)"
        elif path.suffix.lower() == ".jar":
            result["formato_especializado"] = {"extension_sugerida": ".jar", "aviso": "La extensión es .jar pero no se reconoce como ZIP válido."}
        if path.suffix.lower() == ".rc":
            result["formato_especializado"] = _rc_analysis(path)
        if path.suffix.lower() in (".py", ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd", ".rb"):
            result["formato_especializado"] = _script_analysis(path, custom_rules)
    except OSError as exc:
        result["error_analisis"] = str(exc)
    return result


def collect_files(inputs: list[str], recursive: bool) -> tuple[list[Path], list[str]]:
    files: list[Path] = []
    errors: list[str] = []
    seen: set[str] = set()
    for raw in inputs:
        path = Path(raw).expanduser()
        if not path.exists():
            errors.append(f"No existe: {raw}")
            continue
        if path.is_file() or path.is_symlink():
            candidates = [path]
        elif path.is_dir():
            candidates = path.rglob("*") if recursive else path.iterdir()
        else:
            errors.append(f"No es un archivo ni un directorio: {raw}")
            continue
        for candidate in candidates:
            try:
                if candidate.is_file() or candidate.is_symlink():
                    key = str(candidate.resolve())
                    if key not in seen:
                        files.append(candidate)
                        seen.add(key)
            except OSError as exc:
                errors.append(f"No se pudo inspeccionar {candidate}: {exc}")
    return files, errors


def extract_embedded(files: list[Path], progress: bool = False) -> tuple[dict[str, dict[str, Any]], str | None]:
    exiftool = shutil.which("exiftool")
    if not exiftool:
        return {}, "ExifTool no está instalado; solo se extrajeron metadatos básicos del sistema de archivos."
    if not files:
        return {}, None
    command = [exiftool, "-json", "-a", "-G1", "-s", "--", *[str(p) for p in files]]
    try:
        if not progress:
            result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=180)
        else:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            started = time.monotonic()
            frame = 0
            frames = "|/-\\"
            sys.stderr.write(f"\rExifTool: metadata incrustada de {len(files)} archivo(s)...")
            sys.stderr.flush()
            while True:
                elapsed = time.monotonic() - started
                remaining = 180 - elapsed
                if remaining <= 0:
                    process.kill()
                    process.communicate()
                    raise subprocess.TimeoutExpired(command, 180)
                try:
                    stdout, stderr = process.communicate(timeout=min(0.35, remaining))
                    break
                except subprocess.TimeoutExpired:
                    sys.stderr.write(f"\rExifTool: procesando [{frames[frame % len(frames)]}] {int(elapsed)} s")
                    sys.stderr.flush()
                    frame += 1
            sys.stderr.write("\rExifTool: completado".ljust(60) + "\n")
            sys.stderr.flush()
            result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
        if result.returncode not in (0, 1):
            detail = result.stderr.strip() or f"código de salida {result.returncode}"
            return {}, f"ExifTool terminó con un aviso: {detail}"
        parsed = json.loads(result.stdout or "[]")
        metadata: dict[str, dict[str, Any]] = {}
        for record in parsed:
            source = record.pop("SourceFile", None)
            if source:
                metadata[str(Path(source).resolve())] = record
        warning = result.stderr.strip() or None
        return metadata, (f"Aviso de ExifTool: {warning}" if warning else None)
    except subprocess.TimeoutExpired:
        if progress:
            sys.stderr.write("\rExifTool: tiempo límite alcanzado".ljust(60) + "\n")
        return {}, "ExifTool excedió el límite de tiempo de 180 segundos."
    except (OSError, json.JSONDecodeError) as exc:
        return {}, f"No se pudieron leer metadatos incrustados con ExifTool: {exc}"


def render_text(records: list[dict[str, Any]], warning: str | None, errors: list[str]) -> str:
    lines: list[str] = []
    for index, record in enumerate(records):
        if index:
            lines.append("")
        basic = record["metadatos_basicos"]
        lines.append(f"Archivo: {basic['archivo']}")
        lines.append(f"  Tipo: {basic['tipo_mime_estimado']} | Tamaño: {basic['tamaño_legible']}")
        lines.append(f"  Modificado: {basic['modificado']} | Permisos: {basic['permisos']}")
        embedded = record.get("metadatos_incrustados", {})
        if embedded:
            lines.append("  Metadatos incrustados:")
            for key, value in embedded.items():
                lines.append(f"    {key}: {json.dumps(value, ensure_ascii=False)}")
        else:
            lines.append("  Metadatos incrustados: no disponibles")
        forensic = record.get("analisis_forense")
        if forensic:
            lines.append("  Análisis forense estático:")
            lines.extend("    " + line for line in json.dumps(forensic, ensure_ascii=False, indent=2).splitlines())
    if warning:
        lines.extend(["", f"Aviso: {warning}"])
    if errors:
        lines.extend(["", "Errores:", *[f"  - {error}" for error in errors]])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extrae metadatos y, opcionalmente, realiza análisis forense estático sin ejecutar archivos.",
        epilog="Ejemplos: %(prog)s --forense biblioteca.so | %(prog)s -r ./muestras --forense --json -o informe.json",
    )
    parser.add_argument("rutas", nargs="+", help="Uno o más archivos o directorios")
    parser.add_argument("-r", "--recursive", action="store_true", help="Recorrer subdirectorios")
    parser.add_argument("--json", action="store_true", help="Imprimir el resultado en JSON")
    parser.add_argument("-o", "--output", metavar="ARCHIVO", help="Guardar el resultado en un archivo (por defecto stdout)")
    parser.add_argument("--sin-incrustados", action="store_true", help="No ejecutar ExifTool aunque esté instalado")
    parser.add_argument("--progress", action="store_true", help="Mostrar avance por fase en stderr; la salida JSON permanece limpia")
    parser.add_argument("--forense", action="store_true", help="Añadir hashes, entropía y análisis estático de JAR/ZIP, ELF/.so, PE (.exe/.dll), .rc y scripts (.py/.sh/.ps1/.bat)")
    parser.add_argument("--rules", metavar="JSON", help="Cargar reglas heurísticas personalizadas desde un JSON (activa --forense)")
    args = parser.parse_args()

    files, errors = collect_files(args.rutas, args.recursive)
    custom_rules, rule_errors = load_custom_rules(args.rules)
    errors.extend(rule_errors)
    if args.rules:
        args.forense = True
    records: list[dict[str, Any]] = []
    for index, path in enumerate(files, 1):
        try:
            records.append({"metadatos_basicos": basic_metadata(path), "metadatos_incrustados": {}})
        except OSError as exc:
            errors.append(f"No se pudieron leer los metadatos de {path}: {exc}")
        if args.progress:
            _progress_bar("Metadatos básicos", index, len(files), path.name)

    embedded: dict[str, dict[str, Any]] = {}
    warning: str | None = None
    if not args.sin_incrustados:
        embedded, warning = extract_embedded(files, progress=args.progress)
        for record in records:
            full_path = record["metadatos_basicos"]["archivo"]
            record["metadatos_incrustados"] = embedded.get(full_path, {})

    if args.forense:
        for index, (path, record) in enumerate(zip(files, records), 1):
            try:
                record["analisis_forense"] = forensic_analysis(path, custom_rules)
            except (OSError, PermissionError) as exc:
                errors.append(f"No se pudo analizar forensemente {path}: {exc}")
            if args.progress:
                _progress_bar("Análisis forense", index, len(records), path.name)

    if args.json:
        output = json.dumps({"archivos": records, "aviso": warning, "errores": errors}, ensure_ascii=False, indent=2)
    else:
        output = render_text(records, warning, errors)
        if not output:
            output = "No se encontraron archivos para procesar."

    if args.output:
        destination = Path(args.output).expanduser()
        try:
            destination.write_text(output + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"No se pudo guardar {destination}: {exc}", file=sys.stderr)
            return 2
    else:
        print(output)
    if args.progress:
        print(f"Revisión completada: {len(records)} archivo(s), {len(errors)} error(es).", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
