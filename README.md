# Generate PowerShell Encoded Command

## Description

This tool is a python script to generates PowerShell encoded command, to execute script without writing on the disk (execute in memory).

## Requirements

 - Python
 - Python Standard Library

## Install

```bash
git clone https://github.com/mauricelambert/GeneratePowerShellEncodedCommand.git
cd GeneratePowerShellEncodedCommand
```

## Usages

```
~# python generate_powersehll_command.py
gci -rec -file | Where-Object {$_.FullName -Match '.*\.csv$'} | Select-Object -Property FullName,Length | Export-Csv -Path .\csvs.csv
^Z
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Unrestricted -EncodedCommand ZwBjAGkAIAAtAHIAZQBjACAALQBmAGkAbABlACAAfAAgAFcAaABlAHIAZQAtAE8AYgBqAGUAYwB0ACAAewAkAF8ALgBGAHUAbABsAE4AYQBtAGUAIAAtAE0AYQB0AGMAaAAgACIALgAqAFwALgBjAHMAdgAkACIAfQAgAHwAIABTAGUAbABlAGMAdAAtAE8AYgBqAGUAYwB0ACAALQBQAHIAbwBwAGUAcgB0AHkAIABGAHUAbABsAE4AYQBtAGUALABMAGUAbgBnAHQAaAAgAHwAIABFAHgAcABvAHIAdAAtAEMAcwB2ACAALQBQAGEAdABoACAALgBcAGMAcwB2AHMALgBjAHMAdgAKAA==

~# python generate_powersehll_command.py -f
gci -rec -file | Where-Object {$_.FullName -Match ".*\.csv$"} | Select-Object -Property FullName,Length | Export-Csv -Path .\csvs.csv
^Z
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Unrestricted -EncodedCommand ZwBjAGkAIAAtAHIAZQBjACAALQBmAGkAbABlACAAfAAgAFcAaABlAHIAZQAtAE8AYgBqAGUAYwB0ACAAewAkAF8ALgBGAHUAbABsAE4AYQBtAGUAIAAtAE0AYQB0AGMAaAAgACIALgAqAFwALgBjAHMAdgAkACIAfQAgAHwAIABTAGUAbABlAGMAdAAtAE8AYgBqAGUAYwB0ACAALQBQAHIAbwBwAGUAcgB0AHkAIABGAHUAbABsAE4AYQBtAGUALABMAGUAbgBnAHQAaAAgAHwAIABFAHgAcABvAHIAdAAtAEMAcwB2ACAALQBQAGEAdABoACAALgBcAGMAcwB2AHMALgBjAHMAdgAKAA==

~# echo "gci -rec -file | Where-Object {$_.FullName -Match '.*\.csv$'} | Select-Object -Property FullName,Length | Export-Csv -Path .\csvs.csv" > script.ps1
~# python generate_powersehll_command.py -f script.ps1
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Unrestricted -EncodedCommand IgBnAGMAaQAgAC0AcgBlAGMAIAAtAGYAaQBsAGUAIAB8ACAAVwBoAGUAcgBlAC0ATwBiAGoAZQBjAHQAIAB7ACQAXwAuAEYAdQBsAGwATgBhAG0AZQAgAC0ATQBhAHQAYwBoACAAJwAuACoAXAAuAGMAcwB2ACQAJwB9ACAAfAAgAFMAZQBsAGUAYwB0AC0ATwBiAGoAZQBjAHQAIAAtAFAAcgBvAHAAZQByAHQAeQAgAEYAdQBsAGwATgBhAG0AZQAsAEwAZQBuAGcAdABoACAAfAAgAEUAeABwAG8AcgB0AC0AQwBzAHYAIAAtAFAAYQB0AGgAIAAuAFwAYwBzAHYAcwAuAGMAcwB2ACIAIAAKAA==

~# python generate_powersehll_command.py -f script.ps1 -p
C:\Windows\System32\cmd.exe /c C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Unrestricted -EncodedCommand IgBnAGMAaQAgAC0AcgBlAGMAIAAtAGYAaQBsAGUAIAB8ACAAVwBoAGUAcgBlAC0ATwBiAGoAZQBjAHQAIAB7ACQAXwAuAEYAdQBsAGwATgBhAG0AZQAgAC0ATQBhAHQAYwBoACAAJwAuACoAXAAuAGMAcwB2ACQAJwB9ACAAfAAgAFMAZQBsAGUAYwB0AC0ATwBiAGoAZQBjAHQAIAAtAFAAcgBvAHAAZQByAHQAeQAgAEYAdQBsAGwATgBhAG0AZQAsAEwAZQBuAGcAdABoACAAfAAgAEUAeABwAG8AcgB0AC0AQwBzAHYAIAAtAFAAYQB0AGgAIAAuAFwAYwBzAHYAcwAuAGMAcwB2ACIAIAAKAA==

~# python generate_powersehll_command.py -i secrets1 secrets2 -i secrets3
$password1 = Read-Host "My secret 1 (not in parameters, not in powershell history, not in logs)"
$password2 = Read-Host "My secret 2 (not in parameters, not in powershell history, not in logs)"
$password3 = Read-Host "My secret 3 (not in parameters, not in powershell history, not in logs)"
echo "$password1 $password2 $password3"
^Z
(echo secrets1 & echo secrets2 & echo secrets3) | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Unrestricted -EncodedCommand JABwAGEAcwBzAHcAbwByAGQAMQAgAD0AIABSAGUAYQBkAC0ASABvAHMAdAAgACIATQB5ACAAcwBlAGMAcgBlAHQAIAAxACAAKABuAG8AdAAgAGkAbgAgAHAAYQByAGEAbQBlAHQAZQByAHMALAAgAG4AbwB0ACAAaQBuACAAcABvAHcAZQByAHMAaABlAGwAbAAgAGgAaQBzAHQAbwByAHkALAAgAG4AbwB0ACAAaQBuACAAbABvAGcAcwApACIACgAkAHAAYQBzAHMAdwBvAHIAZAAyACAAPQAgAFIAZQBhAGQALQBIAG8AcwB0ACAAIgBNAHkAIABzAGUAYwByAGUAdAAgADIAIAAoAG4AbwB0ACAAaQBuACAAcABhAHIAYQBtAGUAdABlAHIAcwAsACAAbgBvAHQAIABpAG4AIABwAG8AdwBlAHIAcwBoAGUAbABsACAAaABpAHMAdABvAHIAeQAsACAAbgBvAHQAIABpAG4AIABsAG8AZwBzACkAIgAKACQAcABhAHMAcwB3AG8AcgBkADMAIAA9ACAAUgBlAGEAZAAtAEgAbwBzAHQAIAAiAE0AeQAgAHMAZQBjAHIAZQB0ACAAMwAgACgAbgBvAHQAIABpAG4AIABwAGEAcgBhAG0AZQB0AGUAcgBzACwAIABuAG8AdAAgAGkAbgAgAHAAbwB3AGUAcgBzAGgAZQBsAGwAIABoAGkAcwB0AG8AcgB5ACwAIABuAG8AdAAgAGkAbgAgAGwAbwBnAHMAKQAiAAoAZQBjAGgAbwAgACIAJABwAGEAcwBzAHcAbwByAGQAMQAgACQAcABhAHMAcwB3AG8AcgBkADIAIAAkAHAAYQBzAHMAdwBvAHIAZAAzACIACgA=

~# (echo secrets1 & echo secrets2 & echo secrets3) | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Unrestricted -EncodedCommand JABwAGEAcwBzAHcAbwByAGQAMQAgAD0AIABSAGUAYQBkAC0ASABvAHMAdAAgACIATQB5ACAAcwBlAGMAcgBlAHQAIAAxACAAKABuAG8AdAAgAGkAbgAgAHAAYQByAGEAbQBlAHQAZQByAHMALAAgAG4AbwB0ACAAaQBuACAAcABvAHcAZQByAHMAaABlAGwAbAAgAGgAaQBzAHQAbwByAHkALAAgAG4AbwB0ACAAaQBuACAAbABvAGcAcwApACIACgAkAHAAYQBzAHMAdwBvAHIAZAAyACAAPQAgAFIAZQBhAGQALQBIAG8AcwB0ACAAIgBNAHkAIABzAGUAYwByAGUAdAAgADIAIAAoAG4AbwB0ACAAaQBuACAAcABhAHIAYQBtAGUAdABlAHIAcwAsACAAbgBvAHQAIABpAG4AIABwAG8AdwBlAHIAcwBoAGUAbABsACAAaABpAHMAdABvAHIAeQAsACAAbgBvAHQAIABpAG4AIABsAG8AZwBzACkAIgAKACQAcABhAHMAcwB3AG8AcgBkADMAIAA9ACAAUgBlAGEAZAAtAEgAbwBzAHQAIAAiAE0AeQAgAHMAZQBjAHIAZQB0ACAAMwAgACgAbgBvAHQAIABpAG4AIABwAGEAcgBhAG0AZQB0AGUAcgBzACwAIABuAG8AdAAgAGkAbgAgAHAAbwB3AGUAcgBzAGgAZQBsAGwAIABoAGkAcwB0AG8AcgB5ACwAIABuAG8AdAAgAGkAbgAgAGwAbwBnAHMAKQAiAAoAZQBjAGgAbwAgACIAJABwAGEAcwBzAHcAbwByAGQAMQAgACQAcABhAHMAcwB3AG8AcgBkADIAIAAkAHAAYQBzAHMAdwBvAHIAZAAzACIACgA=
My secret 1 (not in parameters, not in powershell history, not in logs): secrets1
My secret 2 (not in parameters, not in powershell history, not in logs): secrets2
My secret 3 (not in parameters, not in powershell history, not in logs): secrets3
secrets1  secrets2  secrets3

~# 
```

## Licence

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
