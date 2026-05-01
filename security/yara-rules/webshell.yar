/*
 * webshell.yar — YARA Web Shell Detection Rules
 * Member B — Upload Pipeline & Security
 *
 * Purpose:
 *   Detect PHP, ASP, JSP, and polyglot web shells in uploaded files.
 *   Web shells are the most critical upload threat — they allow remote
 *   code execution if served by a web server.
 *
 * Hot-reload: signal clamd after editing:
 *   kill -USR2 $(cat /run/clamav/clamd.pid)
 *
 * A match quarantines the file immediately via scan.service.js.
 * Storage is outside web root (Member B) so shells cannot be executed
 * even if one bypasses detection — defence in depth.
 */

// ─────────────────────────────────────────────────────────────────────────────
// RULE 1: PHP web shell — generic eval-based shells
// ─────────────────────────────────────────────────────────────────────────────
rule Webshell_PHP_Eval
{
    meta:
        description = "Detects PHP eval-based web shells"
        severity    = "CRITICAL"
        category    = "webshell"
        author      = "SecureVault Security Team"

    strings:
        $php_tag   = "<?php"  nocase ascii
        $php_tag2  = "<?"     ascii

        $eval1 = /eval\s*\(\s*base64_decode/    nocase ascii
        $eval2 = /eval\s*\(\s*gzinflate/        nocase ascii
        $eval3 = /eval\s*\(\s*gzuncompress/     nocase ascii
        $eval4 = /eval\s*\(\s*str_rot13/        nocase ascii
        $eval5 = /eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase ascii
        $eval6 = /eval\s*\(\s*stripslashes/     nocase ascii
        $eval7 = /assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase ascii
        $eval8 = /preg_replace\s*\(.+\/e['"]/   nocase ascii

    condition:
        ($php_tag or $php_tag2) and any of ($eval*)
}

// ─────────────────────────────────────────────────────────────────────────────
// RULE 2: PHP web shell — system command execution
// ─────────────────────────────────────────────────────────────────────────────
rule Webshell_PHP_CommandExecution
{
    meta:
        description = "Detects PHP web shells that execute system commands"
        severity    = "CRITICAL"
        category    = "webshell"
        author      = "SecureVault Security Team"

    strings:
        $php_tag = "<?php" nocase ascii

        // Command execution functions
        $cmd1 = /system\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase ascii
        $cmd2 = /exec\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/   nocase ascii
        $cmd3 = /shell_exec\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase ascii
        $cmd4 = /passthru\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase ascii
        $cmd5 = /popen\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/  nocase ascii
        $cmd6 = /proc_open\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase ascii
        $cmd7 = /`\$_(GET|POST|REQUEST|COOKIE)/              nocase ascii

        // Obfuscated input handling
        $inp1 = "$_GET["    ascii
        $inp2 = "$_POST["   ascii
        $inp3 = "$_REQUEST["ascii
        $inp4 = "$_COOKIE[" ascii

    condition:
        $php_tag and (any of ($cmd*)) and (any of ($inp*))
}

// ─────────────────────────────────────────────────────────────────────────────
// RULE 3: PHP web shell — file manager / filesystem access
// ─────────────────────────────────────────────────────────────────────────────
rule Webshell_PHP_FileManager
{
    meta:
        description = "Detects PHP-based file manager web shells"
        severity    = "HIGH"
        category    = "webshell"
        author      = "SecureVault Security Team"

    strings:
        $php_tag = "<?php" nocase ascii

        $fm1 = "file_put_contents" nocase ascii
        $fm2 = "fwrite"            nocase ascii
        $fm3 = "move_uploaded_file" nocase ascii
        $fm4 = "copy("             nocase ascii
        $fm5 = "unlink("           nocase ascii
        $fm6 = "rmdir("            nocase ascii
        $fm7 = "mkdir("            nocase ascii
        $fm8 = "chmod("            nocase ascii
        $fm9 = "chown("            nocase ascii

        $inp1 = "$_GET["    ascii
        $inp2 = "$_POST["   ascii
        $inp3 = "$_REQUEST["ascii

    condition:
        $php_tag and
        3 of ($fm*) and
        any of ($inp*)
}

// ─────────────────────────────────────────────────────────────────────────────
// RULE 4: ASP / ASPX web shell
// ─────────────────────────────────────────────────────────────────────────────
rule Webshell_ASP_CommandExecution
{
    meta:
        description = "Detects ASP/ASPX web shells executing system commands"
        severity    = "CRITICAL"
        category    = "webshell"
        author      = "SecureVault Security Team"

    strings:
        $asp_tag1 = "<%"          ascii
        $asp_tag2 = "<script runat" nocase ascii

        $cmd1 = "cmd.exe"         nocase wide ascii
        $cmd2 = "WScript.Shell"   nocase wide ascii
        $cmd3 = "Shell.Exec"      nocase wide ascii
        $cmd4 = "CreateObject"    nocase wide ascii
        $cmd5 = "Process.Start"   nocase wide ascii
        $cmd6 = "Runtime.exec"    nocase wide ascii

        $req1 = "Request.QueryString" nocase ascii
        $req2 = "Request.Form"        nocase ascii
        $req3 = "Request("            nocase ascii

    condition:
        ($asp_tag1 or $asp_tag2) and
        (any of ($cmd*)) and
        (any of ($req*))
}

// ─────────────────────────────────────────────────────────────────────────────
// RULE 5: JSP web shell
// ─────────────────────────────────────────────────────────────────────────────
rule Webshell_JSP_CommandExecution
{
    meta:
        description = "Detects JSP web shells executing system commands"
        severity    = "CRITICAL"
        category    = "webshell"
        author      = "SecureVault Security Team"

    strings:
        $jsp1 = "<%@"        ascii
        $jsp2 = "<jsp:"      nocase ascii
        $jsp3 = "<%!"        ascii

        $cmd1 = "Runtime.getRuntime().exec" nocase ascii
        $cmd2 = "ProcessBuilder"            nocase ascii
        $cmd3 = "getParameter("             nocase ascii
        $cmd4 = "request.getParameter"      nocase ascii
        $cmd5 = "Runtime.exec"              nocase ascii

        $import1 = "java.io.InputStream"    ascii
        $import2 = "java.lang.Runtime"      ascii
        $import3 = "java.lang.ProcessBuilder" ascii

    condition:
        ($jsp1 or $jsp2 or $jsp3) and
        (any of ($cmd*)) and
        (any of ($import*))
}

// ─────────────────────────────────────────────────────────────────────────────
// RULE 6: Obfuscated PHP shell — character encoding tricks
// ─────────────────────────────────────────────────────────────────────────────
rule Webshell_PHP_Obfuscated
{
    meta:
        description = "Detects heavily obfuscated PHP web shells using encoding tricks"
        severity    = "HIGH"
        category    = "webshell"
        author      = "SecureVault Security Team"

    strings:
        $php_tag = "<?php" nocase ascii

        // Obfuscation patterns
        $ob1 = /\$[a-zA-Z_]{1,20}\s*=\s*str_rot13/ nocase ascii
        $ob2 = /\$[a-zA-Z_]{1,20}\s*=\s*base64_decode/ nocase ascii
        $ob3 = /\$[a-zA-Z_]{1,20}\s*=\s*gzinflate/ nocase ascii
        $ob4 = /\$[a-zA-Z_]{1,20}\s*=\s*gzuncompress/ nocase ascii
        $ob5 = /chr\(\d+\)\.chr\(\d+\)\.chr\(\d+\)/ ascii
        $ob6 = /\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}/ ascii

        // Suspicious variable function call
        $dyn1 = /\$[a-zA-Z_]{1,20}\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase ascii

    condition:
        $php_tag and
        (2 of ($ob*) or $dyn1)
}

// ─────────────────────────────────────────────────────────────────────────────
// RULE 7: Polyglot file — valid image AND valid PHP
// Targets: JPEG/PNG/GIF files with embedded PHP code (polyglot attack)
// This rule complements the magic-byte check in magicByte.service.js
// ─────────────────────────────────────────────────────────────────────────────
rule Webshell_Polyglot_ImagePHP
{
    meta:
        description = "Detects polyglot files that are valid images AND contain PHP web shell code"
        severity    = "CRITICAL"
        category    = "webshell"
        author      = "SecureVault Security Team"

    strings:
        // Image magic bytes
        $jpeg = { FF D8 FF }
        $png  = { 89 50 4E 47 0D 0A 1A 0A }
        $gif  = { 47 49 46 38 }

        // PHP code embedded anywhere in file
        $php_tag = "<?php" nocase ascii
        $php_short = "<?" ascii

        // Shell indicators
        $shell1 = "eval("    nocase ascii
        $shell2 = "system("  nocase ascii
        $shell3 = "exec("    nocase ascii
        $shell4 = "passthru(" nocase ascii
        $shell5 = "base64_decode(" nocase ascii

    condition:
        ($jpeg at 0 or $png at 0 or $gif at 0) and
        ($php_tag or $php_short) and
        any of ($shell*)
}

// ─────────────────────────────────────────────────────────────────────────────
// RULE 8: Generic web shell keywords — catch-all
// ─────────────────────────────────────────────────────────────────────────────
rule Webshell_Generic_Keywords
{
    meta:
        description = "Generic catch-all for common web shell indicator keywords"
        severity    = "MEDIUM"
        category    = "webshell"
        author      = "SecureVault Security Team"

    strings:
        $kw1  = "c99shell"         nocase ascii
        $kw2  = "r57shell"         nocase ascii
        $kw3  = "b374k"            nocase ascii
        $kw4  = "wso shell"        nocase ascii
        $kw5  = "FilesMan"         nocase ascii
        $kw6  = "webshell"         nocase ascii
        $kw7  = "Web Shell"        nocase ascii
        $kw8  = "Antak-WebShell"   nocase ascii
        $kw9  = "China Chopper"    nocase ascii
        $kw10 = "laudanum"         nocase ascii

    condition:
        any of ($kw*)
}
