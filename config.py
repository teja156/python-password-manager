import os
import sys
import string
import random
import hashlib
from getpass import getpass

from utils.dbconfig import dbconfig

from rich import print as printc
from rich.console import Console

console = Console()

def checkConfig():
	db = dbconfig()
	cursor = db.cursor()
	query = "SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA  WHERE SCHEMA_NAME = 'pm'"
	cursor.execute(query)
	if len(cursor.fetchall())!=0:
		return True
	return False


def generateDeviceSecret(length=10):
	return ''.join(random.choices(string.ascii_uppercase + string.digits, k = length))


def config():
	if checkConfig():
		printc("[red][!] Already Configured! [/red]")
		sys.exit(0)

	printc("[green][+] Creating new config [/green]")

	# Create database
	db = dbconfig()
	cursor = db.cursor()
	try:
		cursor.execute("CREATE DATABASE pm")
	except Exception as e:
		printc("[red][!] An error occurred while trying to create db. Check if database with name 'pm' already exists - if it does, delete it and try again.")
		console.print_exception(show_locals=True)
		sys.exit(0)

	printc("[green][+][/green] Database 'pm' created")

	# Create tables
	query = "CREATE TABLE pm.secrets (masterkey_hash TEXT NOT NULL, device_secret TEXT NOT NULL)"
	res = cursor.execute(query)
	printc("[green][+][/green] Table 'secrets' created ")

	query = "CREATE TABLE pm.entries (sitename TEXT NOT NULL, siteurl TEXT NOT NULL, email TEXT, username TEXT, password TEXT NOT NULL)"
	res = cursor.execute(query)
	printc("[green][+][/green] Table 'entries' created ")


	mp = ""
	printc("[green][+] A [bold]MASTER PASSWORD[/bold] is the only password you will need to remember in-order to access all your other passwords. Choosing a strong [bold]MASTER PASSWORD[/bold] is essential because all your other passwords will be [bold]encrypted[/bold] with a key that is derived from your [bold]MASTER PASSWORD[/bold]. Therefore, please choose a strong one that has upper and lower case characters, numbers and also special characters. Remember your [bold]MASTER PASSWORD[/bold] because it won't be stored anywhere by this program, and you also cannot change it once chosen. [/green]\n")

	while 1:
		mp = getpass("Choose a MASTER PASSWORD: ")
		if mp == getpass("Re-type: ") and mp!="":
			break
		printc("[yellow][-] Please try again.[/yellow]")

	# Hash the MASTER PASSWORD
	hashed_mp = hashlib.sha256(mp.encode()).hexdigest()
	printc("[green][+][/green] Generated hash of MASTER PASSWORD")


	# Generate a device secret
	ds = generateDeviceSecret()
	printc("[green][+][/green] Device Secret generated")

	# Add them to db
	query = "INSERT INTO pm.secrets (masterkey_hash, device_secret) values (%s, %s)"
	val = (hashed_mp, ds)
	cursor.execute(query, val)
	db.commit()

	printc("[green][+][/green] Added to the database")

	printc("[green][+] Configuration done![/green]")

	db.close()



config()