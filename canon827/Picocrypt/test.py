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

# Create root Tk
tk = TkinterDnD.Tk()
tk.geometry("480x470")
tk.title("Picocrypt")
if platform.system()=="Darwin":
	tk.configure(background="#edeced")
else:
	tk.configure(background="#ffffff")
tk.resizable(0,0)

# Try setting window icon if included with Picocrypt
try:
	favicon = tkinter.PhotoImage(file="./key.png")
	tk.iconphoto(False,favicon)
except:
	pass

# Some styling
s = tkinter.ttk.Style()
s.configure("TCheckbutton",background="#ffffff")

# Event when user drags file(s) and folder(s) into window
def inputSelected(draggedFile):
	global inputFile,working,headerRsc,allFiles,draggedFolderPaths,files
	resetUI()
	dummy.focus()
	status.config(cursor="")
	status.bind("<Button-1>",lambda e:None)

	# Use try to handle errors
	try:
		# Create list of input files
		allFiles = []
		files = []
		draggedFolderPaths = []
		suffix = ""
		tmp = [i for i in draggedFile]
		res = []
		within = False
		tmpName = ""

		"""
		The next for loop parses data return by tkinterdnd2's file drop method.
		When files and folders are dragged, the output (the 'draggedFile' parameter)
		will contain the dropped files/folders and will look something like this:
		
		A single file/folder: "C:\Foo\Bar.txt"
		A single file/folder with a space in path: "{C:\Foo Bar\Lorem.txt}"
		Multiple files/folders: "C:\Foo\Bar1.txt C:\Foo\Ba2.txt"
		Multiple files/folders with spaces in paths: 
			- "C:\Foo\Bar1.txt {C:\Foo Bar\Lorem.txt}"
			- "{C:\Foo Bar\Lorem.txt} C:\Foo\Bar1.txt"
			- "{C:\Foo Bar\Lorem1.txt} {C:\Foo Bar\Lorem2.txt}"
		"""
		for i in tmp:
			if i=="{":
				within = True
			elif i=="}":
				within = False
				res.append(tmpName)
				tmpName = ""
			else:
				if i==" " and not within:
					if tmpName!="":
						res.append(tmpName)
					tmpName = ""
				else:
					tmpName += i
		if tmpName:
			res.append(tmpName)

		allFiles = []
		files = []

		# Check each thing dragged by user
		for i in res:
			# If there is a directory, recursively add all files to 'allFiles'
			if isdir(i):
				# Record the directory for secure wipe (if necessary)
				draggedFolderPaths.append(i)
				tmp = Path(i).rglob("*")
				for p in tmp:
					allFiles.append(abspath(p))
			# Just a file, add it to files
			else:
				files.append(i)

		# If there's only one file, set it as input file
		if len(files)==1 and len(allFiles)==0:
			inputFile = files[0]
			files = []
		else:
			inputFile = ""

		# Decide if encrypting or decrypting
		if inputFile.endswith(".pcv"):
			suffix = " (will decrypt)"
			fin = open(inputFile,"rb")

			# Read file metadata (a little complex)
			tmp = fin.read(139)
			reedsolo = False
			if tmp[0]==43:
				reedsolo = True
				tmp = tmp[1:]
			else:
				tmp = tmp[:-1]
			tmp = bytes(headerRsc.decode(tmp)[0])
			tmp = tmp.replace(b"+",b"")
			tmp = int(tmp.decode("utf-8"))
			if not reedsolo:
				fin.seek(138)
			ad = fin.read(tmp)
			try:
				ad = bytes(headerRsc.decode(ad)[0])
			except ReedSolomonError:
				ad = b"Error decoding file metadata."
			ad = ad.decode("utf-8")
			fin.close()

			# Insert the metadata into its text box
			adArea["state"] = "normal"
			adArea.delete("1.0",tkinter.END)
			adArea.insert("1.0",ad)
			adArea["state"] = "disabled"

			# Update UI
			adLabelString.set("File metadata (read only):")
			keepBtn["state"] = "normal"
			eraseBtn["state"] = "disabled"
			rsBtn["state"] = "disabled"
			cpasswordInput["state"] = "normal"
			cpasswordInput.delete(0,"end")
			cpasswordInput["state"] = "disabled"
			cpasswordString.set("Confirm password (N/A):")
		else:
			# Update the UI
			eraseBtn["state"] = "normal"
			keepBtn["state"] = "disabled"
			rsBtn["state"] = "normal"
			adArea["state"] = "normal"
			adArea.delete("1.0",tkinter.END)
			suffix = " (will encrypt)"
			adLabelString.set(adString)
			cpasswordInput["state"] = "normal"
			cpasswordInput.delete(0,"end")
			cpasswordString.set("Confirm password:")
			cpasswordLabel["state"] = "normal"
			adLabel["state"] = "normal"

		nFiles = len(files)
		nFolders = len(draggedFolderPaths)

		# Show selected file(s) and folder(s)
		if (allFiles or files) and not draggedFolderPaths:
			inputString.set(f"{nFiles} files selected (will encrypt).")
		elif draggedFolderPaths and not files:
			inputString.set(f"{nFolders} folder{'s' if nFolders!=1 else ''} selected (will encrypt).")
		elif draggedFolderPaths and (allFiles or files):
			inputString.set(
				f"{nFiles} file{'s' if nFiles!=1 else ''} and "+
				f"{nFolders} folder{'s' if nFolders!=1 else ''} selected (will encrypt)."
			)
		else:
			inputString.set(inputFile.split("/")[-1]+suffix)

		# Enable password box, etc.
		passwordInput["state"] = "normal"
		passwordInput.delete(0,"end")
		passwordLabel["state"] = "normal"
		startBtn["state"] = "normal"
		statusString.set("Ready.")
		status["state"] = "enabled"
		progress["value"] = 0

	# File decode error
	except UnicodeDecodeError:
		statusString.set(corruptedNotice)
		progress["value"] = 100

	# No file(s) selected, do nothing
	except:
		inputString.set("Drag and drop file(s) and folder(s) into this window.")
		resetUI()