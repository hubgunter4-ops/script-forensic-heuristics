#!/usr/bin/env python3
"""Tests de flow_analysis con fixtures inventadas (nunca se ejecutan).

El analizador solo parsea AST; ningún fixture se ejecuta, y ningún test
llama a eval/exec con datos de los fixtures.
"""
import base64
import codecs
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from flow_analysis import analyze_flows, decode_layers


def payload_b64(text: str, layers: int = 1) -> str:
    value = text
    for _ in range(layers):
        value = base64.b64encode(value.encode()).decode()
    return value


class ConcatenationFlowTests(unittest.TestCase):
    def test_flujo_concatenacion_en_3_lineas_hasta_eval(self):
        source = (
            'a = "ev"\n'
            'b = a + "al"\n'
            'c = b + "(x)"\n'
            'eval(c)\n'
        )
        result = analyze_flows(source)
        self.assertEqual(result["resumen"]["flujos"], 1)
        flow = result["flujos"][0]
        self.assertEqual(flow["sumidero"], "eval")
        self.assertEqual(flow["linea_sumidero"], 4)
        self.assertEqual(flow["argumento"], "eval(x)")
        self.assertTrue(flow["argumento_conocido"])
        self.assertEqual([c["linea"] for c in flow["cadena"]], [1, 2, 3, 4])

    def test_rotacion_de_variables(self):
        source = (
            'x = "ev"\n'
            'y = x\n'
            'x = y + "al"\n'
            'z = x\n'
            'eval(z)\n'
        )
        result = analyze_flows(source)
        self.assertEqual(result["resumen"]["flujos"], 1)
        self.assertEqual(result["flujos"][0]["argumento"], "eval")
        self.assertEqual(result["flujos"][0]["linea_sumidero"], 5)

    def test_taint_desde_input_hasta_os_system(self):
        source = (
            'dato = input("cmd: ")\n'
            'cmd = dato + " --help"\n'
            'import os\n'
            'os.system(cmd)\n'
        )
        result = analyze_flows(source)
        self.assertEqual(result["resumen"]["flujos"], 1)
        flow = result["flujos"][0]
        self.assertEqual(flow["sumidero"], "os.system")
        self.assertTrue(flow["contaminado"])
        self.assertEqual(flow["fuente"], "input()")
        self.assertEqual(flow["severidad"], "high")
        self.assertEqual(result["resumen"]["con_fuente"], 1)

    def test_taint_desde_argv_hasta_subprocess(self):
        source = (
            'import sys, subprocess\n'
            'cmd = sys.argv[1]\n'
            'subprocess.run(cmd, shell=True)\n'
        )
        result = analyze_flows(source)
        self.assertEqual(result["resumen"]["flujos"], 1)
        self.assertTrue(result["flujos"][0]["contaminado"])
        self.assertEqual(result["flujos"][0]["fuente"], "sys.argv")


class DecodingTests(unittest.TestCase):
    def test_base64_en_2_capas_hasta_eval(self):
        inner = payload_b64("print('ok')", layers=2)
        source = (
            'import base64\n'
            f'x = base64.b64decode("{inner}")\n'
            'y = base64.b64decode(x)\n'
            'eval(y)\n'
        )
        result = analyze_flows(source)
        self.assertEqual(result["resumen"]["flujos"], 1)
        flow = result["flujos"][0]
        self.assertEqual(flow["argumento"], "print('ok')")
        self.assertGreaterEqual(len(flow["capas_decodificacion"]), 2)
        self.assertEqual(result["resumen"]["con_decodificacion"], 1)

    def test_decode_layers_limite_3(self):
        value = payload_b64("print('ok')", layers=4)
        layers = decode_layers(value)
        self.assertEqual(len(layers), 3)
        self.assertEqual(layers[0]["tecnica"], "base64")
        self.assertEqual(layers[2]["capa"], 3)

    def test_decode_layers_hex_y_chr(self):
        self.assertEqual(decode_layers("7072696e742829")[0]["tecnica"], "hex")
        self.assertEqual(decode_layers("7072696e742829")[0]["resultado"], "print()")

    def test_decode_layers_rot13_con_marcador(self):
        encoded = codecs.encode("eval(x)", "rot_13")
        layers = decode_layers(encoded)
        self.assertTrue(any(l["tecnica"] == "rot13" and l["resultado"] == "eval(x)" for l in layers))

    def test_decode_layers_no_fuerza_rot13_sin_marcador(self):
        self.assertEqual(decode_layers("hello world"), [])

    def test_chr_y_join_hasta_eval(self):
        source = (
            'a = "".join([chr(101), chr(118), chr(97), chr(108)])\n'
            'eval(a)\n'
        )
        result = analyze_flows(source)
        self.assertEqual(result["resumen"]["flujos"], 1)
        self.assertEqual(result["flujos"][0]["argumento"], "eval")

    def test_cadena_invertida_por_slice(self):
        source = (
            'a = "lave"[::-1]\n'
            'eval(a)\n'
        )
        result = analyze_flows(source)
        self.assertEqual(result["resumen"]["flujos"], 1)
        self.assertEqual(result["flujos"][0]["argumento"], "eval")


class FalsePositiveTests(unittest.TestCase):
    def test_base64_inocua_sin_sumidero_no_se_marca(self):
        source = (
            'import base64\n'
            'dato = base64.b64decode("aGVsbG8=")\n'
            'print(dato)\n'
        )
        result = analyze_flows(source)
        self.assertEqual(result["resumen"]["flujos"], 0)
        self.assertEqual(result["flujos"], [])

    def test_print_de_literal_no_es_flujo(self):
        result = analyze_flows('x = "hola"\nprint(x)\n')
        self.assertEqual(result["resumen"]["flujos"], 0)

    def test_open_lectura_no_es_sumidero(self):
        source = 'f = open("datos.txt")\ndata = f.read()\nprint(data)\n'
        result = analyze_flows(source)
        self.assertEqual(result["resumen"]["flujos"], 0)

    def test_codigo_sin_sintaxis_no_rompe(self):
        result = analyze_flows("def rota(:\n")
        self.assertEqual(result["resumen"]["flujos"], 0)
        self.assertIn("error", result)

    def test_eval_con_literal_inocuo_se_marca_como_bajo(self):
        # eval de un literal conocido sin fuente ni ofuscación: se reporta
        # como flujo de severidad baja, no se oculta.
        result = analyze_flows('eval("1 + 1")\n')
        self.assertEqual(result["resumen"]["flujos"], 1)
        self.assertEqual(result["flujos"][0]["severidad"], "low")


class FunctionFlowTests(unittest.TestCase):
    def test_flujo_a_traves_de_funcion(self):
        source = (
            'def lanzar(cmd):\n'
            '    import os\n'
            '    os.system(cmd)\n'
            'dato = input("cmd: ")\n'
            'lanzar(dato)\n'
        )
        result = analyze_flows(source)
        self.assertEqual(result["resumen"]["flujos"], 1)
        self.assertTrue(result["flujos"][0]["contaminado"])

    def test_funcion_que_devuelve_cadena_hasta_eval(self):
        source = (
            'def hacer():\n'
            '    return "ev" + "al"\n'
            'eval(hacer())\n'
        )
        result = analyze_flows(source)
        self.assertEqual(result["resumen"]["flujos"], 1)
        self.assertEqual(result["flujos"][0]["argumento"], "eval")


if __name__ == "__main__":
    unittest.main()
