rule TrollAgent_Kimsuky_Stealer
{
meta:
description = "Detect TrollAgent Stealer"
author = "Aziz Farghly"
date = "2024-05-16"
version = "1.0"
strings:
$ex1 = "rollbackHookTrampoline" wide ascii
$ex2 = "preUpdateHookTrampoline" wide ascii
$ex3 = "compareTrampoline" wide ascii
$ex4 = "doneTrampoline" wide ascii
$ex5 = "authorizerTrampoline" wide ascii
condition:
uint16(0) == 0x5a4d and
pe.characteristics & pe.DLL and
all of them and
pe.number_of_exports > 11 and
for any i in (0 .. pe.number_of_sections) : (
pe.sections[i].name == ".vmp0" or
pe.sections[i].name == ".vmp1"
)
}
