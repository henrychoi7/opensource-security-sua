#!/usr/bin/env python3

"""

Picocrypt v1.11
Dependencies: argon2-cffi, pycryptodome, reedsolo, tkinterdnd2
Copyright (c) Evan Su (https://evansu.cc)
Released under a GNU GPL v3 License
https://github.com/HACKERALERT/Picocrypt

~ In cryptography we trust ~

"""

# Imports
from tkinter import filedialog,messagebox
from threading import Thread
from datetime import datetime
from argon2.low_level import hash_secret_raw,Type
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Hash import SHA3_512 as sha3_512
from secrets import compare_digest
from os import urandom,fsync,remove,system
from os.path import getsize,expanduser,isdir
from os.path import dirname,abspath,realpath
from os.path import join as pathJoin
from os.path import split as pathSplit
from tkinterdnd2 import TkinterDnD,DND_FILES
from zipfile import ZipFile
from pathlib import Path
from shutil import rmtree
import sys
import tkinter
import tkinter.ttk
import tkinter.scrolledtext
import webbrowser
import platform
from reedsolo import RSCodec,ReedSolomonError

# Tk/Tcl is a little barbaric, so I'm disabling
# high DPI so it doesn't scale bad and look horrible
try:
	from ctypes import windll
	windll.shcore.SetProcessDpiAwareness(0)
except:
	pass

# Global variables and strings
rootDir = dirname(realpath(__file__))
inputFile = ""
outputFile = ""
outputPath = ""
password = ""
ad = ""
kept = False
working = False
gMode = None
headerRsc = False
allFiles = False
draggedFolderPaths = False
files = False
adString = "File metadata (used to store some text along with the file):"
compressingNotice = "Compressing files together..."
passwordNotice = "Error. The provided password is incorrect."
corruptedNotice = "Error. The input file is corrupted."
veryCorruptedNotice = "Error. The input file and header keys are badly corrupted."
modifiedNotice = "Error. The input file has been intentionally modified."
kCorruptedNotice = "The input file is corrupted, but the output has been kept."
kModifiedNotice = "The input file has been intentionally modified, but the output has been kept."
kVeryCorruptedNotice = "The input file is badly corrupted, but the output has been kept."
derivingNotice = "Deriving key (takes a few seconds)..."
keepNotice = "Keep decrypted output even if it's corrupted or modified"
eraseNotice = "Securely erase and delete original file"
erasingNotice = "Securely erasing original file(s)..."
overwriteNotice = "Output file already exists. Would you like to overwrite it?"
cancelNotice = "Exiting now will lead to broken output. Are you sure?"
rsNotice = "Prevent corruption using Reed-Solomon"
rscNotice = "Creating Reed-Solomon tables..."
unknownErrorNotice = "Unknown error occured. Please try again."
