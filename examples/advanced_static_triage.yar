/*
 * Reglas de triaje estático para formatos contemplados por script-forensic-heuristics.
 * Una coincidencia indica un patrón que merece revisión; no demuestra malware.
 * No ejecutar archivos sospechosos. Ajustar reglas según corpus y falsos positivos locales.
 */

rule Script_Python_Suspicious_Download_And_Execution
{
    meta:
        description = "Python: descarga de contenido junto con ejecución dinámica"
        confidence = "medium"
        scope = "Python source or bytecode-like text"
    strings:
        $py_urlopen = "urlopen(" ascii nocase
        $py_requests = "requests.get(" ascii nocase
        $py_urllib = "urllib.request" ascii nocase
        $py_exec = "exec(" ascii nocase
        $py_eval = "eval(" ascii nocase
        $py_b64 = "base64.b64decode" ascii nocase
        $py_subprocess = "subprocess.Popen" ascii nocase
    condition:
        filesize < 5MB and
        (1 of ($py_urlopen, $py_requests, $py_urllib)) and
        (1 of ($py_exec, $py_eval, $py_subprocess) or $py_b64)
}

rule Script_Shell_Remote_Pipe_Execution
{
    meta:
        description = "Shell: descarga remota canalizada a intérprete o shell"
        confidence = "medium"
        scope = "sh, bash, zsh"
    strings:
        $curl = "curl " ascii nocase
        $wget = "wget " ascii nocase
        $pipe_sh = "| sh" ascii nocase
        $pipe_bash = "| bash" ascii nocase
        $pipe_shell = "|$SHELL" ascii nocase
        $dev_tcp = "/dev/tcp/" ascii nocase
        $nc = "nc -e" ascii nocase
    condition:
        filesize < 5MB and
        ((1 of ($curl, $wget) and 1 of ($pipe_sh, $pipe_bash, $pipe_shell)) or
         ($dev_tcp and $nc))
}

rule Script_PowerShell_Encoded_or_Download_Execution
{
    meta:
        description = "PowerShell: argumentos codificados o descarga seguida de ejecución"
        confidence = "medium"
        scope = "PowerShell script"
    strings:
        $enc1 = "-EncodedCommand" ascii nocase
        $enc2 = "-enc " ascii nocase
        $dl1 = "DownloadString(" ascii nocase
        $dl2 = "Invoke-WebRequest" ascii nocase
        $iex = "Invoke-Expression" ascii nocase
        $bypass = "-ExecutionPolicy Bypass" ascii nocase
        $frombase64 = "FromBase64String(" ascii nocase
    condition:
        filesize < 5MB and
        (($enc1 or $enc2) or
         ((1 of ($dl1, $dl2)) and ($iex or $frombase64 or $bypass)))
}

rule Script_Windows_Batch_Suspicious_Persistence_or_Download
{
    meta:
        description = "Batch: descarga remota o cambios de persistencia/defensa"
        confidence = "low"
        scope = ".bat and .cmd"
    strings:
        $bits = "bitsadmin " ascii nocase
        $certutil = "certutil -urlcache" ascii nocase
        $curl = "curl " ascii nocase
        $reg_run = "\\Run" ascii nocase
        $schtasks = "schtasks /create" ascii nocase
        $defender = "Add-MpPreference" ascii nocase
        $encoded = "-enc " ascii nocase
    condition:
        filesize < 5MB and
        ((1 of ($bits, $certutil, $curl) and 1 of ($reg_run, $schtasks, $encoded)) or
         ($defender and 1 of ($reg_run, $schtasks)))
}

rule Script_Ruby_Download_and_Dynamic_Evaluation
{
    meta:
        description = "Ruby: acceso remoto combinado con eval o carga dinámica"
        confidence = "medium"
        scope = "Ruby source"
    strings:
        $uri = "URI.open(" ascii nocase
        $openuri = "open-uri" ascii nocase
        $nethttp = "Net::HTTP" ascii nocase
        $eval = "eval(" ascii nocase
        $exec = "exec(" ascii nocase
        $system = "system(" ascii nocase
        $require = "require 'base64'" ascii nocase
    condition:
        filesize < 5MB and
        (1 of ($uri, $openuri, $nethttp)) and
        (1 of ($eval, $exec, $system, $require))
}

rule Binary_ELF_Suspicious_Embedded_Indicators
{
    meta:
        description = "ELF: formato ejecutable con cadenas de acceso remoto o ejecución de shell"
        confidence = "low"
        scope = "ELF binaries and shared objects"
    strings:
        $elf = { 7F 45 4C 46 }
        $sh = "/bin/sh" ascii
        $bash = "/bin/bash" ascii
        $wget = "wget " ascii nocase
        $curl = "curl " ascii nocase
        $devtcp = "/dev/tcp/" ascii
        $crypt = "-----BEGIN OPENSSH PRIVATE KEY-----" ascii
    condition:
        $elf at 0 and filesize < 100MB and 2 of ($sh, $bash, $wget, $curl, $devtcp, $crypt)
}

rule Binary_PE_Suspicious_Embedded_Indicators
{
    meta:
        description = "PE: ejecutable Windows con indicadores de descarga, persistencia o evasión"
        confidence = "low"
        scope = "Windows PE executable or DLL"
    strings:
        $mz = { 4D 5A }
        $url = "http" ascii nocase
        $powershell = "powershell" ascii nocase
        $schtasks = "schtasks" ascii nocase
        $runkey = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide nocase
        $amsi = "AmsiScanBuffer" ascii nocase
        $virtualalloc = "VirtualAlloc" ascii
        $writeprocess = "WriteProcessMemory" ascii
    condition:
        $mz at 0 and filesize < 200MB and
        (2 of ($url, $powershell, $schtasks, $runkey, $amsi, $virtualalloc, $writeprocess))
}

rule Archive_ZIP_or_JAR_Suspicious_Manifest_or_Payload_Name
{
    meta:
        description = "ZIP/JAR: nombres de miembros sugerentes de carga o ejecución"
        confidence = "low"
        scope = "ZIP/JAR archive bytes; YARA does not unpack members automatically"
    strings:
        $zip_local = { 50 4B 03 04 }
        $manifest = "META-INF/MANIFEST.MF" ascii nocase
        $class = ".class" ascii nocase
        $script = "payload.sh" ascii nocase
        $ps1 = "payload.ps1" ascii nocase
        $jar = "Class-Path:" ascii nocase
        $traversal = "../" ascii
    condition:
        $zip_local at 0 and filesize < 500MB and
        (1 of ($script, $ps1, $traversal) or ($manifest and $class and $jar))
}

rule Windows_RC_Resource_Suspicious_Embedded_Command
{
    meta:
        description = "Recurso Windows .rc: referencias a comandos o carga ejecutable"
        confidence = "low"
        scope = "Windows resource script text"
    strings:
        $rc_type = "RCDATA" ascii nocase
        $rc_icon = "ICON" ascii nocase
        $cmd = "cmd.exe" ascii nocase
        $powershell = "powershell.exe" ascii nocase
        $url = "https://" ascii nocase
        $url2 = "http://" ascii nocase
        $mZ = { 4D 5A }
    condition:
        filesize < 20MB and
        ((1 of ($rc_type, $rc_icon) and 1 of ($cmd, $powershell, $url, $url2)) or
         ($mZ and 1 of ($cmd, $powershell, $url, $url2)))
}
