#!/usr/bin/python3
import sys
def convert_name(userfile):
	f = open(userfile, 'r')
	for line in f.readlines():
		data = "".join(line.split('\n'))
		names = data.split(' ')
		first_letter = names[0][0]
		first_name = names[0]
		lastname = names[1]
		print(f'{first_name}.{lastname}')
		print(f'{first_letter}{lastname}')
		print(f'{first_letter}.{lastname}')
		print(f'{first_letter}a{lastname}')


if __name__ == '__main__' :
	try:
		namelist = sys.argv[1].strip()
	except IndexError:
		print("[-] Usage: ./convert-name.py <list-of-names>")
		exit(-1)

	convert_name(namelist)
	