#!/usr/bin/env python3
"""Reconstrucción de flujos y decodificación de ofuscación (análisis estático).

Complementa el análisis línea por línea de ``extract_metadata.py``:
sigue asignaciones y concatenaciones de cadenas a través de varias líneas,
definiciones y llamadas a funciones, y rastrea datos (taint) desde fuentes
(``input``, ``sys.argv``, lectura de archivos, variables de entorno) hasta
sumideros (``eval``, ``exec``, ``os.system``, ``subprocess``, escritura de
archivos, ...), con la cadena de líneas que forma cada flujo.

También decodifica ofuscación en capas (máx. 3) sobre los literales que
llegan a un sumidero: base64, hexadecimal, ``chr()``, escapes unicode,
rot13, cadenas invertidas y concatenación con ``+`` / ``join``.

Análisis puramente estático: nunca ejecuta el código analizado, nunca
llama a ``eval``/``exec`` con datos de los archivos, no hace red.
Una coincidencia no demuestra por sí sola que un archivo sea malicioso;
es un indicador para revisión contextual.
"""
from __future__ import annotations

import ast
import base64
import binascii
import codecs
import re
from typing import Any

MAX_DECODE_DEPTH = 3
MAX_CHAIN_LINES = 40

SOURCES = frozenset({
    "input", "sys.argv", "sys.stdin", "os.environ", "os.getenv",
    "open", "Path.read_text", "Path.read_bytes",
})

SINKS = {
    "eval": "high",
    "exec": "high",
    "compile": "medium",
    "__import__": "medium",
    "importlib.import_module": "medium",
    "os.system": "high",
    "os.popen": "high",
    "os.execv": "high",
    "os.execl": "high",
    "os.execve": "high",
    "os.spawnl": "high",
    "os.spawnlp": "high",
    "os.spawnv": "high",
    "os.spawnvp": "high",
    "subprocess.Popen": "high",
    "subprocess.call": "high",
    "subprocess.run": "high",
    "subprocess.check_output": "high",
    "subprocess.check_call": "high",
    "subprocess.getoutput": "high",
    "open": "medium",          # solo en modo escritura
    "Path.write_text": "medium",
    "Path.write_bytes": "medium",
}

# Palabras que hacen plausible una decodificación ambigua (rot13, inversión):
# sin ellas, cualquier cadena rot13/invertida "decodificaría" a otra cadena.
_MARKERS = (
    "eval", "exec", "import", "os.", "sys.", "subprocess", "system",
    "shell", "cmd", "http", "socket", "open(", "print", "popen",
    "b64decode", "base64", "getattr", "compile", "urllib", "requests",
)


def dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return dotted_name(node.func)
    return ""


def _is_printable(text: str) -> bool:
    if not text:
        return False
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\t")
    return printable / len(text) >= 0.95


def _looks_like_code(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in _MARKERS)


def _try_base64(value: str) -> str | None:
    candidate = re.sub(r"\s+", "", value)
    if len(candidate) < 8 or len(candidate) % 4 != 0:
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", candidate):
        return None
    try:
        decoded = base64.b64decode(candidate, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if text == value or not _is_printable(text):
        return None
    return text


def _try_hex(value: str) -> str | None:
    candidate = re.sub(r"\s+", "", value)
    if len(candidate) < 4 or len(candidate) % 2 != 0:
        return None
    if not re.fullmatch(r"[0-9a-fA-F]+", candidate):
        return None
    try:
        text = bytes.fromhex(candidate).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    if text == value or not _is_printable(text):
        return None
    return text


def _try_unicode_escape(value: str) -> str | None:
    if "\\" not in value or not re.search(r"\\(u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|n|t|\\|')", value):
        return None
    try:
        text = codecs.decode(value, "unicode_escape")
    except (ValueError, UnicodeDecodeError):
        return None
    if text == value or not _is_printable(text):
        return None
    return text


def _try_rot13(value: str) -> str | None:
    if not re.search(r"[A-Za-z]{4,}", value):
        return None
    text = codecs.decode(value, "rot_13")
    if text == value or not _looks_like_code(text):
        return None
    return text


def _try_reversed(value: str) -> str | None:
    text = value[::-1]
    if text == value or not _looks_like_code(text):
        return None
    return text


_DECODERS = (
    ("base64", _try_base64),
    ("hex", _try_hex),
    ("unicode-escape", _try_unicode_escape),
    ("rot13", _try_rot13),
    ("invertida", _try_reversed),
)


def decode_layers(value: str, max_depth: int = MAX_DECODE_DEPTH) -> list[dict[str, Any]]:
    """Decodifica un literal en capas (máx. ``max_depth``).

    Cada capa se acepta solo si el resultado es imprimible y distinto, y
    para las técnicas ambiguas (rot13, inversión) solo si el resultado
    parece código. Devuelve la lista de capas aplicadas, en orden.
    """
    layers: list[dict[str, Any]] = []
    current = value
    for depth in range(1, max_depth + 1):
        applied = None
        for name, decoder in _DECODERS:
            try:
                result = decoder(current)
            except Exception:
                result = None
            if result is not None:
                applied = (name, result)
                break
        if applied is None:
            break
        name, result = applied
        layers.append({"capa": depth, "tecnica": name, "resultado": result[:500]})
        current = result
    return layers


class _Value:
    """Valor simbólico de una expresión: cadena conocida o desconocida."""

    __slots__ = ("value", "tainted", "lines", "sources", "steps")

    def __init__(self, value: str | None = None, tainted: bool = False,
                 lines: set[int] | None = None, sources: list[dict[str, Any]] | None = None,
                 steps: list[dict[str, Any]] | None = None):
        self.value = value
        self.tainted = tainted
        self.lines: set[int] = set(lines or ())
        self.sources: list[dict[str, Any]] = list(sources or ())
        self.steps: list[dict[str, Any]] = list(steps or ())

    def merge(self, other: "_Value") -> "_Value":
        value = self.value
        if value is None:
            value = other.value
        elif other.value is not None and other.value != value:
            value = None  # dos valores distintos: ya no es un literal único
        return _Value(value, self.tainted or other.tainted,
                      self.lines | other.lines, self.sources + other.sources,
                      self.steps + other.steps)

    @classmethod
    def unknown(cls, tainted: bool = False, lines: set[int] | None = None,
                sources: list[dict[str, Any]] | None = None) -> "_Value":
        return cls(None, tainted, lines, sources)


class _Resolver:
    """Resuelve expresiones a valores simbólicos dentro de un entorno."""

    def __init__(self, source_lines: list[str], assignments: dict[str, list[tuple[int, ast.AST]]],
                 functions: dict[str, ast.FunctionDef], call_taint: dict[str, list[bool]],
                 depth: int = 0):
        self.lines = source_lines
        self.assignments = assignments
        self.functions = functions
        self.call_taint = call_taint
        self.depth = depth

    # -- entorno ---------------------------------------------------------
    def lookup(self, name: str, before_line: int) -> _Value | None:
        """Última asignación a ``name`` anterior a ``before_line`` (o la última)."""
        candidates = self.assignments.get(name, [])
        usable = [item for item in candidates if item[0] <= before_line] or candidates
        if not usable:
            return None
        lineno, expr = usable[-1]
        return self.resolve(expr, seen=frozenset({name}), before_line=lineno)

    # -- resolución ------------------------------------------------------
    def resolve(self, node: ast.AST, seen: frozenset[str] | None = None,
                before_line: int = 10 ** 9) -> _Value:
        seen = seen or frozenset()
        lines = {getattr(node, "lineno", 0)} if hasattr(node, "lineno") else set()

        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                return _Value(node.value, lines=lines)
            if isinstance(node.value, bytes):
                try:
                    return _Value(node.value.decode("utf-8"), lines=lines)
                except UnicodeDecodeError:
                    return _Value.unknown(lines=lines)
            if isinstance(node.value, (int, float, bool)):
                return _Value(str(node.value), lines=lines)
            return _Value.unknown(lines=lines)

        if isinstance(node, ast.Name):
            if node.id in seen:
                return _Value.unknown(lines=lines)
            if node.id in self.call_taint:
                # Parámetro de función: contaminado si algún llamador lo contamina.
                return _Value.unknown(tainted=any(self.call_taint[node.id]), lines=lines)
            found = self.lookup(node.id, before_line)
            if found is None:
                return _Value.unknown(lines=lines)
            found.lines |= lines
            return found

        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self.resolve(node.left, seen, before_line)
            right = self.resolve(node.right, seen, before_line)
            value = None
            if left.value is not None and right.value is not None:
                value = left.value + right.value
            return _Value(value, left.tainted or right.tainted,
                          left.lines | right.lines, left.sources + right.sources)

        if isinstance(node, ast.JoinedStr):
            merged = _Value("", lines=lines)
            for part in node.values:
                if isinstance(part, ast.FormattedValue):
                    merged = merged.merge(self.resolve(part.value, seen, before_line))
                elif isinstance(part, ast.Constant) and isinstance(part.value, str):
                    merged = merged.merge(_Value(part.value, lines=lines))
            return merged

        if isinstance(node, (ast.List, ast.Tuple)):
            merged = _Value.unknown(lines=lines)
            for elt in node.elts:
                merged = merged.merge(self.resolve(elt, seen, before_line))
            return merged

        if isinstance(node, ast.Subscript):
            name = dotted_name(node.value)
            if name in ("sys.argv",):
                return _Value.unknown(tainted=True, lines=lines,
                                     sources=[{"linea": node.lineno, "tipo": "fuente", "detalle": "sys.argv"}])
            if name in ("os.environ",):
                return _Value.unknown(tainted=True, lines=lines,
                                     sources=[{"linea": node.lineno, "tipo": "fuente", "detalle": "os.environ"}])
            base = self.resolve(node.value, seen, before_line)
            if base.value is not None:
                try:
                    sliced = eval_slice(base.value, node.slice)  # noqa: S307 - solo sobre el literal ya resuelto
                except Exception:
                    sliced = None
                if sliced is not None:
                    return _Value(sliced, base.tainted, base.lines | lines, base.sources)
            return _Value.unknown(tainted=base.tainted, lines=base.lines | lines, sources=base.sources)

        if isinstance(node, ast.Attribute):
            # open(...).read / Path.read_text / sys.stdin.read -> fuente
            if node.attr in ("read", "readline", "readlines", "read_text", "read_bytes"):
                base_name = dotted_name(node.value)
                if base_name in ("sys.stdin",) or _is_file_read(node.value):
                    return _Value.unknown(tainted=True, lines=lines,
                                         sources=[{"linea": node.lineno, "tipo": "fuente", "detalle": base_name or "lectura de archivo"}])
            base = self.resolve(node.value, seen, before_line)
            return _Value.unknown(tainted=base.tainted, lines=base.lines | lines, sources=base.sources)

        if isinstance(node, ast.Call):
            return self._resolve_call(node, seen, before_line)

        if isinstance(node, ast.IfExp):
            return self.resolve(node.body, seen, before_line).merge(
                self.resolve(node.orelse, seen, before_line))

        return _Value.unknown(lines=lines)

    def _resolve_call(self, node: ast.Call, seen: frozenset[str], before_line: int) -> _Value:
        name = dotted_name(node.func)
        lines = {node.lineno}
        args = [self.resolve(arg, seen, before_line) for arg in node.args]
        tainted = any(arg.tainted for arg in args)

        if name == "input":
            return _Value.unknown(tainted=True, lines=lines,
                                 sources=[{"linea": node.lineno, "tipo": "fuente", "detalle": "input()"}])
        if name in ("os.getenv", "os.environ.get"):
            return _Value.unknown(tainted=True, lines=lines,
                                 sources=[{"linea": node.lineno, "tipo": "fuente", "detalle": name}])
        if name in ("base64.b64decode", "base64.b32decode", "base64.b16decode", "binascii.unhexlify"):
            if args and args[0].value is not None:
                raw = args[0].value
                try:
                    if "b64" in name:
                        decoded = base64.b64decode(raw).decode("utf-8")
                        technique = "base64"
                    elif "b32" in name:
                        decoded = base64.b32decode(raw).decode("utf-8")
                        technique = "base32"
                    elif "b16" in name:
                        decoded = base64.b16decode(raw).decode("utf-8")
                        technique = "base16"
                    else:
                        decoded = binascii.unhexlify(raw).decode("utf-8")
                        technique = "hex"
                except Exception:
                    return _Value.unknown(tainted=tainted, lines=lines, sources=args[0].sources)
                steps = args[0].steps + [{"capa": len(args[0].steps) + 1, "tecnica": technique, "resultado": decoded[:500]}]
                return _Value(decoded, tainted, args[0].lines | lines, args[0].sources, steps)
            return _Value.unknown(tainted=tainted, lines=lines,
                                  sources=list(args[0].sources) if args else [])
        if name in ("bytes.fromhex",):
            if args and args[0].value is not None:
                try:
                    decoded = bytes.fromhex(args[0].value).decode("utf-8")
                except Exception:
                    return _Value.unknown(tainted=tainted, lines=lines)
                return _Value(decoded, tainted, args[0].lines | lines, args[0].sources,
                              args[0].steps + [{"capa": len(args[0].steps) + 1, "tecnica": "hex", "resultado": decoded[:500]}])
            return _Value.unknown(tainted=tainted, lines=lines)
        if name == "chr":
            if args and args[0].value is not None:
                try:
                    return _Value(chr(int(args[0].value)), tainted, args[0].lines | lines, args[0].sources)
                except (ValueError, TypeError):
                    pass
            return _Value.unknown(tainted=tainted, lines=lines)
        if name == "str":
            if args and args[0].value is not None:
                return _Value(args[0].value, tainted, args[0].lines | lines, args[0].sources)
            return _Value.unknown(tainted=tainted, lines=lines)
        if name == "reversed":
            if args and args[0].value is not None:
                text = args[0].value[::-1]
                return _Value(text, tainted, args[0].lines | lines, args[0].sources,
                              args[0].steps + [{"capa": len(args[0].steps) + 1, "tecnica": "invertida", "resultado": text[:500]}])
            return _Value.unknown(tainted=tainted, lines=lines)
        if name == "codecs.decode":
            if len(args) >= 2 and args[0].value is not None and args[1].value in ("rot_13", "rot13"):
                text = codecs.decode(args[0].value, "rot_13")
                return _Value(text, tainted, args[0].lines | lines, args[0].sources,
                              args[0].steps + [{"capa": len(args[0].steps) + 1, "tecnica": "rot13", "resultado": text[:500]}])
            if args and args[0].value is not None:
                return _Value(args[0].value, tainted, args[0].lines | lines, args[0].sources)
            return _Value.unknown(tainted=tainted, lines=lines)
        if (name == "join" or name.endswith(".join")) and args:
            sep = self.resolve(node.func.value, seen, before_line) if isinstance(node.func, ast.Attribute) else _Value("")
            parts = args[0]
            if isinstance(node.args[0], (ast.List, ast.Tuple)):
                values = [self.resolve(elt, seen, before_line) for elt in node.args[0].elts]
                text = None
                if all(v.value is not None for v in values):
                    text = (sep.value or "").join(v.value for v in values)
                merged = _Value.unknown(lines=lines)
                for v in values:
                    merged = merged.merge(v)
                return _Value(text, merged.tainted, merged.lines | lines, merged.sources)
            if parts.value is not None:
                return _Value(parts.value, tainted, parts.lines | lines, parts.sources)
            return _Value.unknown(tainted=tainted, lines=lines)
        if name in self.functions and self.depth < 3:
            func = self.functions[name]
            bindings: dict[str, list[tuple[int, ast.AST]]] = {}
            for param, arg in zip([a.arg for a in func.args.args], node.args):
                bindings[param] = [(node.lineno, arg)]
            sub = _Resolver(self.lines, {**self.assignments, **bindings},
                            self.functions, self.call_taint, depth=self.depth + 1)
            for ret in [n for n in ast.walk(func) if isinstance(n, ast.Return) and n.value is not None]:
                resolved = sub.resolve(ret.value, seen, before_line)
                resolved.lines |= lines
                return resolved
            return _Value.unknown(tainted=tainted, lines=lines)
        if _is_file_read(node):
            return _Value.unknown(tainted=True, lines=lines,
                                 sources=[{"linea": node.lineno, "tipo": "fuente", "detalle": "lectura de archivo"}])
        return _Value.unknown(tainted=tainted, lines=lines,
                              sources=[s for a in args for s in a.sources])


def _is_file_read(node: ast.AST) -> bool:
    """True si el nodo es open(...) o Path(...).open(...)."""
    if isinstance(node, ast.Call):
        return dotted_name(node.func) in ("open", "Path.open", "io.open")
    return False


def eval_slice(value: str, slice_node: ast.AST) -> str | None:
    """Aplica un slice de AST a un literal ya resuelto (sin ejecutar código)."""
    if isinstance(slice_node, ast.Slice):
        lower = _slice_bound(slice_node.lower)
        upper = _slice_bound(slice_node.upper)
        step = _slice_bound(slice_node.step)
        try:
            return value[slice(lower, upper, step)]
        except (TypeError, ValueError):
            return None
    if isinstance(slice_node, ast.Constant) and isinstance(slice_node.value, int):
        try:
            return value[slice_node.value]
        except IndexError:
            return None
    return None


def _slice_bound(node: ast.AST | None) -> int | None:
    if node is None:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub) and isinstance(node.operand, ast.Constant):
        return -node.operand.value
    return None


def _is_write_open(call: ast.Call) -> bool:
    modes = []
    if len(call.args) >= 2 and isinstance(call.args[1], ast.Constant):
        modes.append(str(call.args[1].value))
    for kw in call.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
            modes.append(str(kw.value.value))
    return any(any(ch in mode for ch in ("w", "a", "x", "+")) for mode in modes)


def analyze_flows(source: str, filename: str = "<desconocido>") -> dict[str, Any]:
    """Reconstruye flujos fuente -> sumidero en código Python.

    Devuelve un dict JSON-serializable con ``flujos`` y ``resumen``.
    Nunca ejecuta el código analizado.
    """
    lines = source.splitlines()
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as exc:
        return {"flujos": [], "resumen": {"flujos": 0, "con_fuente": 0, "con_decodificacion": 0},
                "error": f"no se pudo parsear: {exc}"}

    assignments: dict[str, list[tuple[int, ast.AST]]] = {}
    functions: dict[str, ast.FunctionDef] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            functions[node.name] = node
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assignments.setdefault(target.id, []).append((node.lineno, node.value))
                elif isinstance(target, ast.Tuple):
                    for elt in target.elts:
                        if isinstance(elt, ast.Name):
                            assignments.setdefault(elt.id, []).append((node.lineno, node.value))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
            assignments.setdefault(node.target.id, []).append((node.lineno, node.value))
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
            # x += "y"  ->  x = x + "y"
            combined = ast.BinOp(left=ast.Name(id=node.target.id, ctx=ast.Load()),
                                 op=ast.Add(), right=node.value)
            ast.copy_location(combined, node)
            assignments.setdefault(node.target.id, []).append((node.lineno, combined))

    # Contaminación de parámetros por llamador: si algún llamador pasa un
    # argumento contaminado, el parámetro se considera contaminado.
    call_taint: dict[str, list[bool]] = {}
    probe = _Resolver(lines, assignments, functions, {})
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            callee = dotted_name(node.func)
            if callee in functions:
                func = functions[callee]
                for param, arg in zip([a.arg for a in func.args.args], node.args):
                    call_taint.setdefault(param, []).append(
                        probe.resolve(arg, before_line=node.lineno).tainted)

    resolver = _Resolver(lines, assignments, functions, call_taint)
    flows: list[dict[str, Any]] = []
    seen_sinks: set[tuple[str, int, str]] = set()

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = dotted_name(node.func)
        severity = SINKS.get(name)
        if severity is None:
            continue
        if name == "open" and not _is_write_open(node):
            continue  # open() de lectura es fuente, no sumidero
        if not node.args and not node.keywords:
            continue
        # Resolver el primer argumento (el que lleva el dato) y los demás.
        arg_values = [resolver.resolve(arg, before_line=node.lineno) for arg in node.args]
        if not arg_values:
            continue
        main_arg = arg_values[0]
        for extra in arg_values[1:]:
            main_arg = main_arg.merge(extra)
        # Decodificación en capas sobre el literal resuelto (si lo hay).
        layers: list[dict[str, Any]] = list(main_arg.steps)
        decoded = main_arg.value
        if decoded is not None and not layers:
            layers = decode_layers(decoded)
            if layers:
                decoded = layers[-1]["resultado"]
        elif layers:
            decoded = layers[-1]["resultado"]
        tainted = main_arg.tainted
        sources = main_arg.sources
        if not tainted and not layers and main_arg.value is None:
            continue  # sumidero sin dato rastreable: no es un flujo
        key = (name, node.lineno, decoded or "")
        if key in seen_sinks:
            continue
        seen_sinks.add(key)

        # Cadena de evidencia: líneas de asignación/fuente + sumidero.
        chain: list[dict[str, Any]] = []
        for lineno in sorted(main_arg.lines):
            if lineno == node.lineno:
                continue  # la línea del sumidero se añade al final como tal
            if 1 <= lineno <= len(lines):
                chain.append({"linea": lineno, "codigo": lines[lineno - 1].strip()[:200],
                              "tipo": "fuente" if any(s["linea"] == lineno for s in sources) else "asignacion"})
        for src in sources:
            if src["linea"] not in [c["linea"] for c in chain]:
                chain.append({"linea": src["linea"],
                              "codigo": lines[src["linea"] - 1].strip()[:200] if 1 <= src["linea"] <= len(lines) else "",
                              "tipo": "fuente", "detalle": src["detalle"]})
        chain = sorted(chain, key=lambda c: c["linea"])[:MAX_CHAIN_LINES]
        chain.append({"linea": node.lineno,
                      "codigo": lines[node.lineno - 1].strip()[:200] if 1 <= node.lineno <= len(lines) else "",
                      "tipo": "sumidero", "detalle": name})
        if tainted and layers:
            sev = "high"
        elif tainted:
            sev = "high" if severity == "high" else "medium"
        elif layers:
            sev = "high" if severity == "high" else "medium"
        else:
            sev = "low"
        flows.append({
            "sumidero": name,
            "linea_sumidero": node.lineno,
            "argumento": (decoded or "")[:500],
            "argumento_conocido": main_arg.value is not None,
            "contaminado": tainted,
            "fuente": sources[0]["detalle"] if sources else None,
            "capas_decodificacion": layers,
            "cadena": chain,
            "severidad": sev,
        })

    flows.sort(key=lambda f: f["linea_sumidero"])
    return {
        "flujos": flows,
        "resumen": {
            "flujos": len(flows),
            "con_fuente": sum(1 for f in flows if f["contaminado"]),
            "con_decodificacion": sum(1 for f in flows if f["capas_decodificacion"]),
        },
        "nota": "Análisis estático: un flujo es un indicador para revisión contextual, no un veredicto de malware.",
    }


def analyze_flow_file(path: str) -> dict[str, Any]:
    """Analiza un archivo Python desde disco (solo lectura, sin ejecutar)."""
    with open(path, encoding="utf-8-sig", errors="replace") as handle:
        return analyze_flows(handle.read(), filename=path)
