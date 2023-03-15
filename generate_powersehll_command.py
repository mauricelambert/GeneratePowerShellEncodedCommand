#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This tool encodes PowerShell script to execute it in single command line (in memory).
#    Copyright (C) 2023  Maurice Lambert

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

from sys import argv, stdin, stderr, exit, stdout
from argparse import ArgumentParser, FileType
from base64 import b64encode

parser = ArgumentParser(description="This script generates a powershell command to execute script with only one command line (in memory).")
parser.add_argument('-f', '--file', default=stdin, const=stdin, type=FileType(), nargs="?", help="Filename of the script to encode or stdin")
parser.add_argument('-i', '--inputs', nargs="+", action="extend", help="Inputs to read in your powershell.")
parser.add_argument('-p', '--as-process', action="store_true", help="Start this command as single process.")
arguments = parser.parse_args()

script = arguments.file.read()
arguments.file.close()

if arguments.as_process:
	stdout.write(r'C:\Windows\System32\cmd.exe /c ')

if arguments.inputs:
	inputs = '(echo ' + ' & echo '.join(arguments.inputs) + ') | '
	stdout.write(inputs)

print(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Unrestricted -EncodedCommand", b64encode(script.encode('utf-16-le')).decode())
exit(0)