
rule Unittest
{
    strings:
	$s1 = "Hello Reflash!"

    condition:
        all of them
}

rule LoadBytes_MethodClosure
{
    strings:
	$s1 = "builtin.as$0::MethodClosure:loadBytes"

    condition:
        all of them
}

rule ExternalInterface
{
    strings:
	$s1 = "flash.external::ExternalInterface"

    condition:
        all of them
}

rule Embedded_SWF
{
    strings:
	$s1 = "loadBytes"
        $f1 = "CWS"
        $f2 = "ZWS"

    condition:
        $s1 and ($f1 or $f2)
}

rule Capabilities_isDebugger
{
    strings:
	$s1 = "flash.system::Capabilities"
	$s2 = "isDebugger"

    condition:
        all of them
}

rule RIG_EK_shellcode
{
    strings:
        $b = {60 eb 11 58 b9 ?? ?? 00 00 49 80 34 08 ?? 85 c9 75 f7 ff e0 e8 ea ff ff ff}

    condition:
        all of them
}


rule Neutrino_EK_shellcode
{
    strings:
        $b = {eb 12 58 31 c9 66 b9 ?? ?? 49 80 34 08 ?? 85 c9 75 f7 ff e0 e8 e9 ff ff ff}

    condition:
        all of them
}

rule Angler_EK_shellcode
{
    strings:
        $a = "\xe8\x0d\x00\x00\x00CreateThread"
        $b = "\xe8\x14\x00\x00\x00WaitForSingleObject"
        $c = "\xe8\x0d\x00\x00\x00LoadLibraryA"
        $d = "\xe8\x0d\x00\x00\x00VirtualAlloc"
        $e = "\xe8\x17\x00\x00\x00CreateProcessInternalW"
    condition:
        all of them
}


rule Shellcode_API_resolver
{
    strings:
         $a = {64 A1 30 00 00 00 53 8B 40 0C 55 56 8B 70 0C 57 89 4C 24 18}
         $b = {89 4C 24 18}
         $c = {8B ?? 10 78}
         $d = {89 ?? 24 10}
         $e = {C1 C9 0D}
         $f = {3C 61 0F BE C0 7C 03 83 C1 E0}

    condition:
        all of them
}

rule Shellcode_API_resolver_2
{
    strings:
         $a={ E8 FF 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63}
    condition:
        all of them
}
