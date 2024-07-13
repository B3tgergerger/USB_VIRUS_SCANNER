rule ExampleRule
{
    meta:
        description = "This rule detects a specific threat"
    strings:
        $a = {6A 40 68 00 30 00 00 6A 14 8D 91}
        $b = "malicious_string"
    condition:
        $a or $b
}

rule EICAR_Test_File
{
    meta:
        description = "This rule detects the EICAR test file"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}
