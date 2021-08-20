#!/usr/bin/env python
# -*- coding: utf-8 -*- 

# Názov súboru:	interpret.py
# Meno autora:	Damián Sova (xsovad06)
# Dátum:		14.4.2020
# Popis:		Interpret jazyka IPPcode20

# Importovanie kniznic potrebnych na interpretaciu
import sys
import xml.etree.ElementTree as ET
import getopt
import re
import itertools

# Sprava vypisana po spusteni skriptu s parametrom "--help"
help_message = '''Progam načíta XML reprezentáciu programu zo vstupného súboru, ktorý potom interpretuje.\n
Parametre skriptu:
\t--help  vypíše pomocnú správu
\t--source=file   vstupný súbor s XML kódom
\t--input=file   vstupný súbor so vstupmi pre reprezentáciu zdrojového kódu'''

# fukcia na spracovanie vstupnych parametrov
def process_program_arguments():
	# Nacitanie vstupnych parametrov
	try:
		opts, args = getopt.getopt(sys.argv[1:], "", ['help', 'source=', 'input='])
	except getopt.GetoptError:
		sys.exit(Errors.wrong_argument)
	
	# Obstaranie prave jedneho vstupneho parametru
	if len(opts) == 0:
		return None, None

	# Obstaranie prave jedneho vstupneho parametru
	elif len(opts) == 1:
		if opts[0][0] == "--help":
			print(help_message)
			sys.exit(0)
		
		elif opts[0][0] == "--source":
			return opts[0][1], None

		elif opts[0][0] == "--input":
			return None, opts[0][1]

	# Obstaranie prave dvoch vstupnych parametrov
	elif len(opts) == 2:
		if opts[0][0] == "--source" and opts[1][0] == "--input":
			return opts[0][1], opts[1][1]

		elif opts[0][0] == "--input" and opts[1][0] == "--source":
			return opts[1][1], opts[0][1] 
	
	else:
		sys.exit(Errors.wrong_argument)

# Funkcia otvara, testuje vstupny subor a nahra source code do stringu
def open_source_file(source_file):
	string = ""
	
	# Nacitanie zo STDIN
	if source_file == None:
		source = sys.stdin.readlines()
		for line in source:
			string += line

	# Otvorenie suboru so vstupnym kodom
	else:
		try:
			with open(source_file, "r") as s_file:
				for line in s_file:
					string += line
		except Exception:
			sys.exit(Errors.input_file)
	
	return string

# Funkcia na ulozenie vsetkych navesti v programe
def labels_process(instructions):
	i = 0
	global instruction_order

	# Hladanie instrukcie LABEL a jej nasledne vykonanie
	while i < len(instructions):
		if instructions[i].attrib["opcode"] == "LABEL":
			instruction_order = i
			instruction = Instruction(instructions[i])
			instruction.instr_exetuce()
		
		i = i + 1

# Trieda s chybovymi kodmi
class Errors:
	wrong_argument = 10
	input_file = 11
	output_file = 12
	xml_structure = 31
	xml_syntax = 32
	semantic = 52
	operands_type = 53
	non_exists_var = 54
	non_exists_frame = 55
	missing_value = 56
	bad_value = 57
	work_with_string = 58
	internal = 99

# Trieda na spracovanie xml kodu a naplnenie pola instrukcii
class Xml_Parser:
	def parse(self, string_xml):
		# Nacitanie XML srtruktury do premennej program
		try:
			program = ET.fromstring(string_xml)
		except ET.ParseError:
			sys.exit(Errors.xml_syntax)
		
		# Kontrola typu elementu a jeho atributov
		if program.tag != 'program' or len(program.attrib) > 3 or program.attrib.get('language') != 'IPPcode20':
			sys.exit(Errors.xml_syntax)

		# Zistenie maxialneho poradoveho cisla instrukcie
		max_order_number = 1
		for instruction in program:
			if instruction.tag == 'instruction':
				
				# Chybajuci atribut
				if len(instruction.attrib) != 2:
					sys.exit(Errors.xml_syntax)

				# Cbybny typ poradoveho cisla funckie
				if not instruction.attrib["order"].isdigit():
					sys.exit(Errors.xml_syntax)

				order_number = int(instruction.attrib["order"])
				if order_number > max_order_number:
					max_order_number = order_number

		# Deklarovanie zoznamu pre usporiadanie poradia instrukcii
		ordered_instructions = [None] * max_order_number
		# Deklarovanie zoznamu usporiadanych instrukcii iducich za sebou bez medzier
		instructions = [None] * (len(program))

		# Zoradovanie podla poradoveho cisla instrukcie
		for instruction in program:

			# Kontrola opercneho kodu
			if instruction.tag == 'instruction':
				opcode = instruction.attrib["opcode"]

				# Povolene instrukcie
				if opcode == "DEFVAR":
					pass
				elif opcode == "ADD":
					pass
				elif opcode == "SUB":
					pass
				elif opcode == "MUL":
					pass
				elif opcode == "IDIV":
					pass
				elif opcode == "WRITE":
					pass
				elif opcode == "MOVE":
					pass
				elif opcode == "PUSHS":
					pass
				elif opcode == "POPS":
					pass
				elif opcode == "STRLEN":
					pass
				elif opcode == "CONCAT":
					pass
				elif opcode == "GETCHAR":
					pass
				elif opcode == "SETCHAR":
					pass
				elif opcode == "TYPE":
					pass
				elif opcode == "AND":
					pass
				elif opcode == "OR":
					pass
				elif opcode == "NOT":
					pass
				elif opcode == "LT":
					pass
				elif opcode == "EQ":
					pass
				elif opcode == "GT":
					pass
				elif opcode == "INT2CHAR":
					pass
				elif opcode == "STRI2INT":
					pass
				elif opcode == "READ":
					pass
				elif opcode == "LABEL":
					pass
				elif opcode == "JUMP":
					pass
				elif opcode == "JUMPIFEQ":
					pass
				elif opcode == "JUMPIFNEQ":
					pass
				elif opcode == "CREATEFRAME":
					pass
				elif opcode == "PUSHFRAME":
					pass
				elif opcode == "POPFRAME":
					pass
				elif opcode == "CALL":
					pass
				elif opcode == "RETURN":
					pass
				elif opcode == "DPRINT":
					pass
				elif opcode == "BREAK":
					pass
				elif opcode == "EXIT":
					pass
				else:
					sys.exit(Errors.xml_syntax)

				order_number = int(instruction.attrib["order"]) - 1
				
				# Instrukcia s duplicitnym poradovym cislom
				if ordered_instructions[order_number] != None:
					sys.exit(Errors.xml_syntax)

				# Ulozenie instrukcie na poziciu poradoveho cisla instrukcie
				ordered_instructions[order_number] = instruction
			
			else:
				sys.exit(Errors.xml_syntax)

		instruction_order = 0

		# Zoradenie za seba, bez medzier
		for instruction in ordered_instructions:
			if instruction is None:
				continue

			else:
				instructions[instruction_order] = instruction
				instruction_order = instruction_order + 1
		
		return instructions, len(instructions)

# Trieda na pracu s ramcami ako: GF(globalny ramec), LF(lokalny ramec), TF(docastny ramec)
class Frames:
	global_frame = {}
	local_frame = None
	temporary_frame = None
	stack = []
	
	# Pridanie premennej do ramce
	@classmethod
	def add(cls, frame_type, name):
		frame = cls.__identifyFrame(frame_type)

		if name in frame:
			sys.exit(Errors.xml_syntax)
		frame[name] = None

	# Nastavenie hodnoty premennej ulozenej v ramci
	@classmethod
	def set(cls, frame_type, name, value):
		frame = cls.__identifyFrame(frame_type)

		if name not in frame:
			sys.exit(Errors.non_exists_var)
		
		if type(value) == Var:
			value = value.getValue()
		
		frame[name] = value
		
	# Vrati hodnotu premennej ulozenej v ramci
	@classmethod
	def get(cls, frame_type, name):
		frame = cls.__identifyFrame(frame_type)

		if name not in frame:
			sys.exit(Errors.non_exists_var)
		
		value = frame[name]
		
		if value == None:
			sys.exit(Errors.missing_value)

		return value
	
	# Vrati hodnotu premennej ulozenej v ramci, pri neinicializovanej prem. nie je error
	@classmethod
	def get_without_missing_value(cls, frame_type, name):
		frame = cls.__identifyFrame(frame_type)

		if name not in frame:
			sys.exit(Errors.non_exists_var)
		
		value = frame[name]
		
		if value == None:
			value = ''

		return value


	# Vrati ramec podla parametru frame_type
	@classmethod
	def __identifyFrame(cls, frame_type):
		if frame_type == "GF":
			frame = cls.global_frame
			
		elif frame_type == "LF":
			frame = cls.local_frame
			
		elif frame_type == "TF":
			frame = cls.temporary_frame
		
		else:
			sys.exit(Errors.xml_syntax)

		if frame == None:
			sys.exit(Errors.non_exists_frame)

		return frame

# Trieda na pracu s navestiami
class Labels:
	labels = {}

	# Funkcia na pridanie navestia do slovnika
	@classmethod
	def add_label(cls, name):
		name = str(name)
	
		if name in cls.labels:
			sys.exit(Errors.semantic)
		global instruction_order
		cls.labels[name] = instruction_order
	
	# Funkcia vykona skok na dane navestie
	@classmethod
	def jump(cls, name):
		name = str(name)
		
		if name not in cls.labels:
			sys.exit(Errors.semantic)
		global instruction_order
		instruction_order = cls.labels[name]

# Trieda reprezentujuca ADT zasobnik
class Stack:
	def __init__(self):
		self.stack = []
	
	# Funkcia vyhodi poslednu polozku zo zasobnika
	def pop(self):
		if len(self.stack) == 0:
			sys.exit(Errors.missing_value)

		return self.stack.pop()
	
	# Funkcia prida polozku na koniec zasoniku
	def push(self, value):
		self.stack.append(value)

# Trieda na pracu s premennymi a ich hodnotami
class Var:
	def __init__(self, frame_type, name):
		self.name = name
		self.frame_type = frame_type

# Fiktivna trieda
class Symb:
	pass

# Hlavna trieda na interpretaciu zdrojoveho kodu obsahuje operacny kod instrukcie, jej ulozene argumenty
# Obsahuje implementaciu jednotlivych instrukcii jazyka IPPcode20
class Instruction:
	def __init__(self, xml_element):
		self.opcode = xml_element.attrib["opcode"]
		self.arguments, self.arguments_count = self.process_arguments(xml_element)
		
	# Spracuje a vrati argumenty intrukcie ulozene v slovniku
	def process_arguments(self, xml_element):
		arguments = {}
		arguments_count = len(xml_element)
		
		# Povoleny pocet argumentov instrukcie v intervale < 0 , 3 >
		if arguments_count < 0 or 3 < arguments_count:
			sys.exit(Errors.xml_syntax)
		arg1 = arg2 = arg3 = 0
		
		# Deklaracia slovnikov pre spracovanie argumentov
		attributes1 = {}
		attributes2 = {}
		attributes3 = {}

		# Naplnenie slovnika s argumentmi instrukcie
		for arg in xml_element:
			
			# Spracovanie prveho argumentu instrukcie
			if arg.tag == 'arg1' and arg1 == 0:
				attributes1["type"] = arg.attrib["type"]
				
				# Spracuje atributy premennej, ramec a meno
				if attributes1["type"] == "var":
					try:
						frame, name = arg.text.split('@')
					except ValueError:
						sys.exit(Errors.xml_syntax)

					# Kontrola formatu mena premennej, porovnavanie regularnym vyrazom
					if True != (re.match(r"^([a-zA-Z]|-|[_$&%*])([a-zA-Z]|-|[_$&%*]|[0-9]+)*$$", name) is not None):
						sys.exit(Errors.xml_syntax)

					attributes1["frame"] = frame
					attributes1["value"] = name

				# Spracuje hodnotu argumentu typu INT
				elif attributes1["type"] == "int":
					
					# Kontrola formatu hodnoty typu INT, porovnavanie regularnym vyrazom
					if True != (re.match(r"^[\x2B\x2D]?[0-9]+$", arg.text) is not None): 
						sys.exit(Errors.xml_syntax)

					attributes1["value"] = int(arg.text)

				# Spracuje hodnotu argumentu typu STRING
				elif attributes1["type"] == "string":
					
					# Kontrola formatu mena premennej, porovnavanie regularnym vyrazom
					if True != (re.match(r"^([a-zA-Z\u0021\u0022\u0024-\u005B\u005D-\uFFFF|(\\\\[0-90-90-9])*$", arg.text) is not None): 
						sys.exit(Errors.xml_syntax)
					
					# Odstrani escape sekvenice a ulozi do slovnika
					attributes1["value"] = self.unmake_escape_sequence(arg.text)

				# Spracuje hodnotu argumentu typu BOOL
				elif attributes1["type"] == "bool":
					
					# Kontrola formatu hodnoty typu BOOL, porovnavanie retazcom
					if arg.text == 'true':
						attributes1["value"] = True

					elif arg.text == 'false':
						attributes1["value"] = False
					
					else:
						sys.exit(Errors.xml_syntax)

				# Spracuje hodnotu argumentu typu LABEL
				elif attributes1["type"] == "label":
					
					# Kontrola formatu mena navestia, porovnavanie regularnym vyrazom
					if True != (re.match(r"^([a-zA-Z\u0021\u0022\u0024-\u005B\u005D-\uFFFF|(\\\\[0-90-90-9])*$", arg.text) is not None): 
						sys.exit(Errors.xml_syntax)

					attributes1["value"] = arg.text

				# Spracuje hodnotu argumentu typu NIL
				elif attributes1["type"] == "nil":
					
					# Kontrola formatu hodnoty typu BOOL, porovnavanie retazcom
					if arg.text != "nil":
						sys.exit(Errors.xml_syntax)

					attributes1["value"] = arg.text

				# Spracuje hodnotu argumentu typu TYPE
				elif attributes1["type"] == "type":
					
					# Kontrola formatu hodnoty typu TYPE, porovnavanie retazcom
					if arg.text == "int" or arg.text == "string" or arg.text == "bool":
						attributes1["value"] = arg.text
						
					else:
						sys.exit(Errors.xml_syntax)

				# Nepovoleny typ argumentu
				else:
					sys.exit(Errors.xml_syntax)

				arguments['arg1'] = attributes1
				arg1 += 1
			
			# Spracovanie druheho argumentu instrukcie
			elif arg.tag == 'arg2' and arg2 == 0:
				attributes2["type"] = arg.attrib["type"]
				
				# Spracuje atributy premennej, ramec a meno
				if attributes2["type"] == "var":
					try:
						frame, name = arg.text.split('@')
					except ValueError:
						sys.exit(Errors.xml_syntax)
					
					# Kontrola formatu mena premennej, porovnavanie regularnym vyrazom
					if True != (re.match(r"^([a-zA-Z]|-|[_$&%*])([a-zA-Z]|-|[_$&%*]|[0-9]+)*$$", name) is not None):
						sys.exit(Errors.xml_syntax)

					attributes2["frame"] = frame
					attributes2["value"] = name

				# Spracuje hodnotu argumentu typu INT
				elif attributes2["type"] == "int":
					
					# Kontrola formatu hodnoty typu INT, porovnavanie regularnym vyrazom
					if True != (re.match(r"^[\x2B\x2D]?[0-9]+$", arg.text) is not None): 
						sys.exit(Errors.xml_syntax)

					attributes2["value"] = int(arg.text)

				# Spracuje hodnotu argumentu typu STRING
				elif attributes2["type"] == "string":
					
					# Kontrola formatu mena premennej, porovnavanie regularnym vyrazom
					if True != (re.match(r"^([a-zA-Z\u0021\u0022\u0024-\u005B\u005D-\uFFFF|(\\\\[0-90-90-9])*$", arg.text) is not None): 
						sys.exit(Errors.xml_syntax)

					# Odstrani escape sekvenice a ulozi do slovnika
					attributes2["value"] = self.unmake_escape_sequence(arg.text)

				# Spracuje hodnotu argumentu typu BOOL
				elif attributes2["type"] == "bool":
					
					# Kontrola formatu hodnoty typu BOOL, porovnavanie retazcom
					if arg.text == 'true':
						attributes2["value"] = True

					elif arg.text == 'false':
						attributes2["value"] = False
					
					else:
						sys.exit(Errors.xml_syntax)

				# Spracuje hodnotu argumentu typu LABEL
				elif attributes2["type"] == "label":
					
					# Kontrola formatu mena navestia, porovnavanie regularnym vyrazom
					if True != (re.match(r"^([a-zA-Z\u0021\u0022\u0024-\u005B\u005D-\uFFFF|(\\\\[0-90-90-9])*$", arg.text) is not None): 
						sys.exit(Errors.xml_syntax)

					attributes2["value"] = arg.text

				# Spracuje hodnotu argumentu typu NIL
				elif attributes2["type"] == "nil":
					
					# Kontrola formatu hodnoty typu BOOL, porovnavanie retazcom
					if arg.text != "nil":
						sys.exit(Errors.xml_syntax)

					attributes2["value"] = arg.text
				
				# Spracuje hodnotu argumentu typu TYPE
				elif attributes2["type"] == "type":
					
					# Kontrola formatu hodnoty typu TYPE, porovnavanie retazcom
					if arg.text == "int" or arg.text == "string" or arg.text == "bool":
						attributes2["value"] = arg.text
						
					else:
						sys.exit(Errors.xml_syntax)

				# Nepovoleny typ argumentu
				else:
					sys.exit(Errors.xml_syntax)

				arguments['arg2'] = attributes2
				arg2 += 1

			# Spracovanie tretieho argumentu instrukcie
			elif arg.tag == 'arg3' and arg3 == 0:
				attributes3["type"] = arg.attrib["type"]
				
				# Spracuje atributy premennej, ramec a meno
				if attributes3["type"] == "var":
					try:
						frame, name = arg.text.split('@')
					except ValueError:
						sys.exit(Errors.xml_syntax)
					
					# Kontrola formatu mena premennej, porovnavanie regularnym vyrazom
					if True != (re.match(r"^([a-zA-Z]|-|[_$&%*])([a-zA-Z]|-|[_$&%*]|[0-9]+)*$$", name) is not None):
						sys.exit(Errors.xml_syntax)

					attributes3["frame"] = frame
					attributes3["value"] = name

				# Spracuje hodnotu argumentu typu INT
				elif attributes3["type"] == "int":
					
					# Kontrola formatu hodnoty typu INT, porovnavanie regularnym vyrazom
					if True != (re.match(r"^[\x2B\x2D]?[0-9]+$", arg.text) is not None): 
						sys.exit(Errors.xml_syntax)

					attributes3["value"] = int(arg.text)

				# Spracuje hodnotu argumentu typu STRING
				elif attributes3["type"] == "string":
					
					# Kontrola formatu mena premennej, porovnavanie regularnym vyrazom
					if True != (re.match(r"^([a-zA-Z\u0021\u0022\u0024-\u005B\u005D-\uFFFF|(\\\\[0-90-90-9])*$", arg.text) is not None): 
						sys.exit(Errors.xml_syntax)

					# Odstrani escape sekvenice a ulozi do slovnika
					attributes3["value"] = self.unmake_escape_sequence(arg.text)

				# Spracuje hodnotu argumentu typu BOOL
				elif attributes3["type"] == "bool":
					
					# Kontrola formatu hodnoty typu BOOL, porovnavanie retazcom
					if arg.text == 'true':
						attributes3["value"] = True

					elif arg.text == 'false':
						attributes3["value"] = False
					
					else:
						sys.exit(Errors.xml_syntax)

				# Spracuje hodnotu argumentu typu LABEL
				elif attributes3["type"] == "label":
					
					# Kontrola formatu mena navestia, porovnavanie regularnym vyrazom
					if True != (re.match(r"^([a-zA-Z\u0021\u0022\u0024-\u005B\u005D-\uFFFF|(\\\\[0-90-90-9])*$", arg.text) is not None): 
						sys.exit(Errors.xml_syntax)

					attributes3["value"] = arg.text

				# Spracuje hodnotu argumentu typu NIL
				elif attributes3["type"] == "nil":
					
					# Kontrola formatu hodnoty typu BOOL, porovnavanie retazcom
					if arg.text != "nil":
						sys.exit(Errors.xml_syntax)

					attributes3["value"] = arg.text
				
				# Spracuje hodnotu argumentu typu TYPE
				elif attributes3["type"] == "type":
					# Kontrola formatu hodnoty typu TYPE, porovnavanie retazcom
					if arg.text == "int" or arg.text == "string" or arg.text == "bool":
						attributes2["value"] = arg.text
						
					else:
						sys.exit(Errors.xml_syntax)

				# Nepovoleny typ argumentu
				else:
					sys.exit(Errors.xml_syntax)

				arguments['arg3'] = attributes3
				arg3 += 1
			
			# Inak je to syntakticka chyba
			else:
				sys.exit(Errors.xml_syntax)

		# Nepovolena kombinacia argumentov
		if len(attributes1) == 0 and (len(attributes2) != 0 or len(attributes3) != 0):
			sys.exit(Errors.xml_syntax)

		# Nepovolena kombinacia argumentov
		if len(attributes2) == 0 and len(attributes3) != 0:
			sys.exit(Errors.xml_syntax)

		# Vracia slovnik so spravocanymi argumentmi a pocet argumentov
		return arguments, arguments_count
	
	# Pomocna funkcia na odstranenie escape sekvencii
	def unmake_escape_sequence(self,string):
		string = re.sub(r"\x5c([0-9][0-9][0-9])", lambda w: chr(int(w.group(1))), string)
		return string

	# Funkcia kontroluje typy argumentov porovnamanim ulozenych s ocakavanymi
	def arguments_control(self, expected_arg_number, *expected_arguments_type):
		if self.arguments_count != expected_arg_number:
			sys.exit(Errors.xml_syntax)
		elif expected_arg_number == 0:
			return
		
		# Vytvori zoznam ocakavanych argumentov
		expected_arguments_type = list(expected_arguments_type)
		# Spracuje slovnik do pola podla poloziek
		#arg_index = list(self.arguments)
		# Porovnavanie typu argumentu s ocakavanym typom
		for i in range(expected_arg_number):
			# Virtualny typ Symb nahradime moznostami jeho reprezentacie
			if expected_arguments_type[i] == Symb:
				expected_arguments_type[i] = ["var", "int", "string", "bool", "nil"]
			
			arg_index = 'arg' + str(i + 1)
			arg_type = self.arguments[arg_index]["type"]
			# Kontrola ak je ocakavany jediny typ 
			if type(expected_arguments_type[i]) != list:
				if arg_type != expected_arguments_type[i]:
					sys.exit(Errors.operands_type)
			
			# Kontrola ak su ocakavane viacere typy
			elif type(expected_arguments_type[i]) == list:
				if arg_type not in expected_arguments_type[i]:
					sys.exit(Errors.operands_type)

##########################################################################
#                    Telo instrukcii jazyka IPPcode20                    #
##########################################################################

	# Telo instrukcie MOVE z jazyka IPPcode20
	def Instr_Move(self):
		self.arguments_control(2,'var', Symb)
		
		# Ziska hodnotu z ulozenej premennej
		if self.arguments["arg2"]["type"] == 'var':
			value =  Frames.get(self.arguments["arg2"]["frame"], self.arguments["arg2"]["value"])
		# Ziska hodnotu z arkumentu instrukcie
		else:
			value = self.arguments["arg2"]["value"]

		# Ulozenie hodnoty do premennej v 1. argumnte
		Frames.set(self.arguments["arg1"]["frame"], self.arguments["arg1"]["value"], value)


	# Telo instrukcie CREATEFRAME z jazyka IPPcode20
	def Instr_CreateFrame(self):
		self.arguments_control(0)

		# Vytvori docasny ramec
		Frames.temporary_frame = {}
		
		
	# Telo instrukcie PUSHFRAME z jazyka IPPcode20
	def Instr_PushFrame(self):
		self.arguments_control(0)

		if Frames.temporary_frame == None:
			sys.exit(Errors.non_exists_frame)

		# Presunie ramec na zasobnik ramcov
		Frames.stack.append(Frames.temporary_frame)

		# Nastavi pristup k ramcu cez LF(lokany ramec), vrchol zasobniku
		Frames.local_frame = Frames.stack[-1]

		# Nastavi TF na nedefinovany
		Frames.temporary_frame = None


	# Telo instrukcie POPFRAME z jazyka IPPcode20
	def Instr_PopFrame(self):
		self.arguments_control(0)

		if Frames.local_frame == None:
			sys.exit(Errors.non_exists_frame)

		# Nastavi TF na hodnotu vrcholu zasobniku
		Frames.temporary_frame = Frames.stack.pop()

		# Nastavi LF na nedefinovany
		Frames.local_frame = None


	# Telo instrukcie RETURN z jazyka IPPcode20
	def Instr_Return(self):
		self.arguments_control(0)
		
		# Spristupnenie globalnych premennych
		global stack_for_call
		global instruction_order

		# Nastavenie podaroveho cisla instrukcie na cislo z vrcholu zasobniku volani
		instruction_order = stack_for_call.pop()


	# Telo instrukcie BREAK z jazyka IPPcode20
	def Instr_Break(self):
		self.arguments_control(0)
		global instruction_order

		sys.stderr.write("Instrukcia c.{0}, GF: {1}, LF: {2}, TF: {3}".format(instruction_order, Frames.global_frame, Frames.local_frame, Frames.temporary_frame))
		sys.stderr.write("\n")

	# Telo instrukcie DEFVAR z jazyka IPPcode20
	def Instr_Defvar(self):
		self.arguments_control(1, 'var')

		# Prida premennu do daneho ramca
		Frames.add(self.arguments["arg1"]["frame"], self.arguments["arg1"]["value"])


	# Telo instrukcie CALL z jazyka IPPcode20
	def Instr_Call(self):
		
		# Spristupnenie globalnych premennych
		global stack_for_call
		global instruction_order

		# Ulozenie poradoveho cisla instrukcie na zasobnik volani
		stack_for_call.push(instruction_order)
		self.Instr_Jump()

	# Telo instrukcie PUSHS z jazyka IPPcode20
	def Instr_Pushs(self):
		self.arguments_control(1, Symb)

		# Spristupnenie globalnej premennej
		global value_stack

		# Vlozi hodnotu na vrchol datoveho zasobniku
		value_stack.push(self.arguments["arg1"]["value"])


	# Telo instrukcie POPS z jazyka IPPcode20
	def Instr_Pops(self):
		self.arguments_control(1, 'var')

		# Spristupnenie globalnej premennej
		global value_stack

		# Ulozi hodnotu do premennej
		Frames.set(self.arguments["arg1"]["frame"], self.arguments["arg1"]["value"], value_stack.pop())


	# Telo instrukcie ADD z jazyka IPPcode20
	def Instr_Add(self):
		self.arguments_control(3,'var', ['int', 'var'], ['int', 'var'])

		# Ziskanie hodnoty 1 operandu
		if self.arguments["arg2"]["type"] == 'var':
			operand1 = Frames.get(self.arguments["arg2"]["frame"], self.arguments["arg2"]["value"])
		else:
			operand1 = self.arguments["arg2"]["value"]
		
		# Ziskanie hodnoty 2 operandu
		if self.arguments["arg3"]["type"] == 'var':
			operand2 = Frames.get(self.arguments["arg3"]["frame"], self.arguments["arg3"]["value"])
		else:
			operand2 = self.arguments["arg3"]["value"]

		# Ulozenie hodnoty do premennej
		Frames.set(self.arguments["arg1"]["frame"], self.arguments["arg1"]["value"], operand1 + operand2)

	# Telo instrukcie SUB z jazyka IPPcode20
	def Instr_Sub(self):
		self.arguments_control(3,'var', ['int', 'var'], ['int', 'var'])

		# Ziskanie hodnoty 1 operandu
		if self.arguments["arg2"]["type"] == 'var':
			operand1 = Frames.get(self.arguments["arg2"]["frame"], self.arguments["arg2"]["value"])
		else:
			operand1 = self.arguments["arg2"]["value"]
		
		# Ziskanie hodnoty 2 operandu
		if self.arguments["arg3"]["type"] == 'var':
			operand2 = Frames.get(self.arguments["arg3"]["frame"], self.arguments["arg3"]["value"])
		else:
			operand2 = self.arguments["arg3"]["value"]

		# Ulozenie hodnoty do premennej
		Frames.set(self.arguments["arg1"]["frame"], self.arguments["arg1"]["value"], operand1 - operand2)


	# Telo instrukcie MUL z jazyka IPPcode20
	def Instr_Mul(self):
		self.arguments_control(3,'var', ['int', 'var'], ['int', 'var'])

		# Ziskanie hodnoty 1 operandu
		if self.arguments["arg2"]["type"] == 'var':
			operand1 = Frames.get(self.arguments["arg2"]["frame"], self.arguments["arg2"]["value"])
		else:
			operand1 = self.arguments["arg2"]["value"]
		
		# Ziskanie hodnoty 2 operandu
		if self.arguments["arg3"]["type"] == 'var':
			operand2 = Frames.get(self.arguments["arg3"]["frame"], self.arguments["arg3"]["value"])
		else:
			operand2 = self.arguments["arg3"]["value"]

		# Ulozenie hodnoty do premennej
		Frames.set(self.arguments["arg1"]["frame"], self.arguments["arg1"]["value"], operand1 * operand2)
		

	# Telo instrukcie IDIV z jazyka IPPcode20
	def Instr_IDiv(self):
		self.arguments_control(3,'var', ['int', 'var'], ['int', 'var'])

		# Ziskanie hodnoty 1 operandu
		if self.arguments["arg2"]["type"] == 'var':
			operand1 = Frames.get(self.arguments["arg2"]["frame"], self.arguments["arg2"]["value"])
		else:
			operand1 = self.arguments["arg2"]["value"]
		
		# Ziskanie hodnoty 2 operandu
		if self.arguments["arg3"]["type"] == 'var':
			operand2 = Frames.get(self.arguments["arg3"]["frame"], self.arguments["arg3"]["value"])
		else:
			operand2 = self.arguments["arg3"]["value"]

		# Delenie nulou
		if operand2 == 0:
			sys.exit(Errors.bad_value)

		# Ulozenie hodnoty do premennej
		Frames.set(self.arguments["arg1"]["frame"], self.arguments["arg1"]["value"], operand1 // operand2)


	# Telo instrukcie LT z jazyka IPPcode20
	def Instr_LT(self):
		self.arguments_control(3,'var', Symb, Symb)

		# Ziskanie hodnoty 1 operandu
		if self.arguments["arg2"]["type"] == 'var':
			operand1 = Frames.get(self.arguments["arg2"]["frame"], self.arguments["arg2"]["value"])
		else:
			operand1 = self.arguments["arg2"]["value"]
		
		# Ziskanie hodnoty 2 operandu
		if self.arguments["arg3"]["type"] == 'var':
			operand2 = Frames.get(self.arguments["arg3"]["frame"], self.arguments["arg3"]["value"])
		else:
			operand2 = self.arguments["arg3"]["value"]

		# Rovnake typy oerandov
		if type(operand1) != type(operand2):
			sys.exit(Errors.operands_type)

		# Ulozenie hodnoty do premennej
		Frames.set(self.arguments["arg1"]["frame"], self.arguments["arg1"]["value"], operand1 < operand2)

	# Telo instrukcie GT z jazyka IPPcode20
	def Instr_GT(self):
		self.arguments_control(3,'var', Symb, Symb)

		# Ziskanie hodnoty 1 operandu
		if self.arguments["arg2"]["type"] == 'var':
			operand1 = Frames.get(self.arguments["arg2"]["frame"], self.arguments["arg2"]["value"])
		else:
			operand1 = self.arguments["arg2"]["value"]
		
		# Ziskanie hodnoty 2 operandu
		if self.arguments["arg3"]["type"] == 'var':
			operand2 = Frames.get(self.arguments["arg3"]["frame"], self.arguments["arg3"]["value"])
		else:
			operand2 = self.arguments["arg3"]["value"]

		# Rovnake typy oerandov
		if type(operand1) != type(operand2):
			sys.exit(Errors.operands_type)

		# Ulozenie hodnoty do premennej
		Frames.set(self.arguments["arg1"]["frame"], self.arguments["arg1"]["value"], operand1 > operand2)
		

	# Telo instrukcie EQ z jazyka IPPcode20
	def Instr_EQ(self):
		self.arguments_control(3,'var', Symb, Symb)

		# Ziskanie hodnoty 1 operandu
		if self.arguments["arg2"]["type"] == 'var':
			operand1 = Frames.get(self.arguments["arg2"]["frame"], self.arguments["arg2"]["value"])
		else:
			operand1 = self.arguments["arg2"]["value"]
		
		# Ziskanie hodnoty 2 operandu
		if self.arguments["arg3"]["type"] == 'var':
			operand2 = Frames.get(self.arguments["arg3"]["frame"], self.arguments["arg3"]["value"])
		else:
			operand2 = self.arguments["arg3"]["value"]

		# Rovnake typy oerandov
		if type(operand1) != type(operand2):
			sys.exit(Errors.operands_type)

		# Ulozenie hodnoty do premennej
		Frames.set(self.arguments["arg1"]["frame"], self.arguments["arg1"]["value"], operand1 == operand2)
		

	# Telo instrukcie AND z jazyka IPPcode20
	def Instr_And(self):
		self.arguments_control(3,'var', ['bool', 'var'], ['bool', 'var'])

		# Ziskanie hodnoty 1 operandu
		if self.arguments["arg2"]["type"] == 'var':
			operand1 = Frames.get(self.arguments["arg2"]["frame"], self.arguments["arg2"]["value"])
		else:
			operand1 = self.arguments["arg2"]["value"]
		
		# Ziskanie hodnoty 2 operandu
		if self.arguments["arg3"]["type"] == 'var':
			operand2 = Frames.get(self.arguments["arg3"]["frame"], self.arguments["arg3"]["value"])
		else:
			operand2 = self.arguments["arg3"]["value"]

		# Rovnake typy oerandov
		if type(operand1) != type(operand2):
			sys.exit(Errors.operands_type)

		# Ulozenie hodnoty do premennej
		Frames.set(self.arguments["arg1"]["frame"], self.arguments["arg1"]["value"], operand1 and operand2)
		

	# Telo instrukcie OR z jazyka IPPcode20
	def Instr_Or(self):
		self.arguments_control(3,'var', ['bool', 'var'], ['bool', 'var'])

		# Ziskanie hodnoty 1 operandu
		if self.arguments["arg2"]["type"] == 'var':
			operand1 = Frames.get(self.arguments["arg2"]["frame"], self.arguments["arg2"]["value"])
		else:
			operand1 = self.arguments["arg2"]["value"]
		
		# Ziskanie hodnoty 2 operandu
		if self.arguments["arg3"]["type"] == 'var':
			operand2 = Frames.get(self.arguments["arg3"]["frame"], self.arguments["arg3"]["value"])
		else:
			operand2 = self.arguments["arg3"]["value"]

		# Rovnake typy oerandov
		if type(operand1) != type(operand2):
			sys.exit(Errors.operands_type)

		# Ulozenie hodnoty do premennej
		Frames.set(self.arguments["arg1"]["frame"], self.arguments["arg1"]["value"], operand1 or operand2)
		

	# Telo instrukcie NOT z jazyka IPPcode20
	def Instr_Not(self):
		self.arguments_control(2,'var', ['bool', 'var'])

		# Ziskanie hodnoty 1 operandu
		if self.arguments["arg2"]["type"] == 'var':
			operand1 = Frames.get(self.arguments["arg2"]["frame"], self.arguments["arg2"]["value"])
		else:
			operand1 = self.arguments["arg2"]["value"]

		# Rovnake typy oerandov
		if type(operand1) != bool:
			sys.exit(Errors.operands_type)

		# Ulozenie hodnoty do premennej
		Frames.set(self.arguments["arg1"]["frame"], self.arguments["arg1"]["value"], not operand1)
		

	# Telo instrukcie INTTOCHAR z jazyka IPPcode20
	def Instr_IntToChar(self):
		self.arguments_control(2,'var', ['int', 'var'])
		
		# Ziskanie hodnoty 1 operandu
		if self.arguments["arg2"]["type"] == 'var':
			value = Frames.get(self.arguments["arg2"]["frame"], self.arguments["arg2"]["value"])
		else:
			value = self.arguments["arg2"]["value"]

		# Ulozenie hodnoty do premennej
		try:
			Frames.set(self.arguments["arg1"]["frame"], self.arguments["arg1"]["value"], chr(value))
		except ValueError:
			sys.exit(Errors.work_with_string)


	# Telo instrukcie STRINGTOINT z jazyka IPPcode20
	def Instr_StringToInt(self):
		# Funkcia Getchar vykona ulozenie znaku z retazca
		self.Instr_GetChar()

		# ASCII hodnota daneho znaku
		value = ord(Frames.get(self.arguments["arg1"]["frame"], self.arguments["arg1"]["value"]))

		# Ulozenie hodnoty do premennej
		Frames.set(self.arguments["arg1"]["frame"], self.arguments["arg1"]["value"], value)


	# Telo instrukcie READ z jazyka IPPcode20
	def Instr_Read(self):
		self.arguments_control(2,'var', 'type')

		# Otvorenie suboru pre input instrukcie
		global input_file
		if input_file != None:
			try:
				with open(input_file, "r") as i_file:
					string_input = i_file.readline()
			except Exception:
				sys.exit(Errors.input_file)

		else:
			string_input = input()

		# Ulozi do premenne hodnotu pretypovanu na INT
		if self.arguments["arg2"]["value"] == 'int':
			string_input = int(string_input)
		
		# Ulozi do premennej retzec zo vstupu
		elif self.arguments["arg2"]["value"] == 'string':
			pass
		
		# Ulozi do premenne hodnotu typu BOOL
		elif self.arguments["arg2"]["value"] == 'bool':
			if string_input == 'True' or string_input == 'true':
				string_input = True
			elif string_input == 'False' or string_input == 'false':
				string_input = False
			else:
				sys.exit(Errors.xml_syntax)
		
		# Ulozenie hodnoty zo string_input do premennej
		Frames.set(self.arguments["arg1"]["frame"], self.arguments["arg1"]["value"], string_input)


	# Telo instrukcie WRITE z jazyka IPPcode20
	def Instr_Write(self):
		self.arguments_control(1, Symb)

		# Ziska hodnotu z premennej
		if self.arguments["arg1"]["type"] == 'var':
			value = Frames.get(self.arguments["arg1"]["frame"], self.arguments["arg1"]["value"])
		
		# True = 'true', False = 'false'
		elif self.arguments["arg1"]["type"] == 'bool':
			if self.arguments["arg1"]["value"] == True:
				value = 'true'
			else:
				value = 'false'

		# NIL == ''
		elif self.arguments["arg1"]["type"] == 'nil':
			value = ''
		# Hodnota argumentu
		else:
			value = self.arguments["arg1"]["value"]
		
		value = str(value)

		# Vypis hodnoty na STDOUT
		print(value, end= '')

	# Telo instrukcie EXIT z jazyka IPPcode20
	def Instr_Exit(self):
		self.arguments_control(1, ['int', 'var'])

		# Ziska hodnotu z premennej
		if self.arguments["arg1"]["type"] == 'var':
			value = int(Frames.get(self.arguments["arg1"]["frame"], self.arguments["arg1"]["value"]))
		
		else:
			value = self.arguments["arg1"]["value"]
		
		# Nepovolena hodnota
		if 0 > value or value > 49:
			sys.exit(Errors.bad_value)

		# Ukoncenie skriptu s danou hodnotou
		sys.exit(value)


	# Telo instrukcie CONCAT z jazyka IPPcode20
	def Instr_Concat(self):
		self.arguments_control(3,'var', ['string', 'var'], ['string', 'var'])

		# Ziskanie hodnoty 1 operandu
		if self.arguments["arg2"]["type"] == 'var':
			operand1 = Frames.get(self.arguments["arg2"]["frame"], self.arguments["arg2"]["value"])
		else:
			operand1 = self.arguments["arg2"]["value"]
		
		# Ziskanie hodnoty 2 operandu
		if self.arguments["arg3"]["type"] == 'var':
			operand2 = Frames.get(self.arguments["arg3"]["frame"], self.arguments["arg3"]["value"])
		else:
			operand2 = self.arguments["arg3"]["value"]

		# Rovnake typy oerandov
		if type(operand1) != type(operand2):
			sys.exit(Errors.operands_type)

		# Ulozenie hodnoty do premennej
		Frames.set(self.arguments["arg1"]["frame"], self.arguments["arg1"]["value"], operand1 + operand2)
		

	# Telo instrukcie STRLEN z jazyka IPPcode20
	def Instr_StrLen(self):
		self.arguments_control(2,'var', ['string', 'var'])

		# Ziskanie hodnoty 1 operandu
		if self.arguments["arg2"]["type"] == 'var':
			operand1 = Frames.get(self.arguments["arg2"]["frame"], self.arguments["arg2"]["value"])
		else:
			operand1 = self.arguments["arg2"]["value"]

		# Typ string
		if type(operand1) != str:
			sys.exit(Errors.operands_type)

		# Ulozenie hodnoty do premennej
		Frames.set(self.arguments["arg1"]["frame"], self.arguments["arg1"]["value"], len(operand1))
		

	# Telo instrukcie GETCHAR z jazyka IPPcode20
	def Instr_GetChar(self):
		self.arguments_control(3,'var', ['string', 'var'], ['int', 'var'])

		position = self.arguments["arg3"]["value"]
		
		# Index mimo retazca
		if position >= len(self.arguments["arg2"]["value"]):
			sys.exit(Errors.work_with_string)
		
		# Hodnota znaku v retazci na pozicii hodnoty 3 argumentu 
		value = self.arguments["arg2"]["value"][position]
		
		# Ulozenie hodnoty do premennej
		Frames.set(self.arguments["arg1"]["frame"], self.arguments["arg1"]["value"], value)


	# Telo instrukcie SETCHAR z jazyka IPPcode20
	def Instr_SetChar(self):
		self.arguments_control(2,'var', ['int', 'var'], ['int', 'var'])

		string = Frames.get(self.arguments["arg1"]["frame"], self.arguments["arg1"]["value"])
		position = self.arguments["arg2"]["value"]
		character = self.arguments["arg3"]["value"]
		
		# Index mimo retzec
		if position >= len(string):
			sys.exit(Errors.work_with_string)
		
		# Prazdny retazec
		if len(character) == 0:
			sys.exit(Errors.work_with_string)
		
		# Vymena znaku na danej pozici danym znakom
		value = string[:position] + character[0] + string[position+1:]
		
		# Ulozenie hodnoty do premennej
		Frames.set(self.arguments["arg1"]["frame"], self.arguments["arg1"]["value"], value)


	# Telo instrukcie TYPE z jazyka IPPcode20
	def Instr_Type(self):
		self.arguments_control(2,'var', Symb)

		# Ziskanie hodnoty premennej
		if self.arguments["arg2"]["type"] == 'var':
			value = Frames.get_without_missing_value(self.arguments["arg2"]["frame"], self.arguments["arg2"]["value"])
			
			# Prekonvertovanie typu na odpovedajuci retazec
			if type(value) == bool:
				symb_type = 'bool'
			elif type(value) == str:
				symb_type = 'string'
			elif type(value) == int:
				symb_type = 'int'

		else:
			symb_type = self.arguments["arg2"]["type"]
	
		# Ulozenie hodnoty do premennej
		Frames.set(self.arguments["arg1"]["frame"], self.arguments["arg1"]["value"], symb_type)


	# Telo instrukcie LABEL z jazyka IPPcode20
	def Instr_Label(self):
		self.arguments_control(1,'label')
		
		# Ulozenie navestia
		Labels.add_label(self.arguments["arg1"]["value"])


	# Telo instrukcie JUMP z jazyka IPPcode20
	def Instr_Jump(self):
		self.arguments_control(1,'label')
		
		# Zmeni poradove cislo instrukcie na poradove cislo navestia 
		Labels.jump(self.arguments["arg1"]["value"])

	# Telo instrukcie JUMPIFEQ z jazyka IPPcode20
	def Instr_JumpIfEq(self):
		self.arguments_control(3,'label', Symb, Symb)

		# Ziskanie hodnoty premennej
		if self.arguments["arg2"]["type"] == 'var':
			value1 = Frames.get(self.arguments["arg2"]["frame"], self.arguments["arg2"]["value"])
			
			# Prekonvertovanie typu na odpovedajuci retazec
			if type(value1) == bool:
				symb_type1 = 'bool'
			elif type(value1) == str:
				symb_type1 = 'string'
			elif type(value1) == int:
				symb_type1 = 'int'

		else:
			symb_type1 = self.arguments["arg2"]["type"]
			value1 = self.arguments["arg2"]["value"]

		# Ziskanie hodnoty premennej
		if self.arguments["arg3"]["type"] == 'var':
			value2 = Frames.get(self.arguments["arg3"]["frame"], self.arguments["arg3"]["value"])
			
			# Prekonvertovanie typu na odpovedajuci retazec
			if type(value2) == bool:
				symb_type2 = 'bool'
			elif type(value2) == str:
				symb_type2 = 'string'
			elif type(value2) == int:
				symb_type2 = 'int'

		else:
			symb_type2 = self.arguments["arg3"]["type"]
			value2 = self.arguments["arg3"]["value"]

		# Skoci pri zhodnosti typov aj hodnot
		if symb_type1 == symb_type2 and value1 == value2:
			# Zmeni poradove cislo instrukcie na poradove cislo navestia 
			
			Labels.jump(self.arguments["arg1"]["value"])

		# Nerovnost typov, NIL je povoleny
		elif symb_type1 != symb_type2:
			if symb_type1 == 'nil' or symb_type2 == 'nil':
				pass
			else:
				sys.exit(Errors.operands_type)


	# Telo instrukcie JUMPIFNOTEQ z jazyka IPPcode20
	def Instr_JumpIfNotEq(self):
		self.arguments_control(3,'label', Symb, Symb)

		# Ziskanie hodnoty premennej
		if self.arguments["arg2"]["type"] == 'var':
			value1 = Frames.get(self.arguments["arg2"]["frame"], self.arguments["arg2"]["value"])
			
			# Prekonvertovanie typu na odpovedajuci retazec
			if type(value1) == bool:
				symb_type1 = 'bool'
			elif type(value1) == str:
				symb_type1 = 'string'
			elif type(value1) == int:
				symb_type1 = 'int'

		else:
			symb_type1 = self.arguments["arg2"]["type"]
			value1 = self.arguments["arg2"]["value"]

		# Ziskanie hodnoty premennej
		if self.arguments["arg3"]["type"] == 'var':
			value2 = Frames.get(self.arguments["arg3"]["frame"], self.arguments["arg3"]["value"])
			
			# Prekonvertovanie typu na odpovedajuci retazec
			if type(value2) == bool:
				symb_type2 = 'bool'
			elif type(value2) == str:
				symb_type2 = 'string'
			elif type(value2) == int:
				symb_type2 = 'int'

		else:
			symb_type2 = self.arguments["arg3"]["type"]
			value2 = self.arguments["arg3"]["value"]

		# Skoci pri zhodnosti typov a nerovnosti hodnot
		if symb_type1 == symb_type2 and value1 != value2:
			# Zmeni poradove cislo instrukcie na poradove cislo navestia 
			Labels.jump(self.arguments["arg1"]["value"])

		# Nerovnost typov, NIL je povoleny
		elif symb_type1 != symb_type2:
			if symb_type1 == 'nil' or symb_type2 == 'nil':
				pass
			else:
				sys.exit(Errors.operands_type)
		

	# Telo instrukcie Dprint z jazyka IPPcode20
	def Instr_Dprint(self):
		self.arguments_control(1, Symb)

		if self.arguments["arg1"]["type"] == 'var':
			value = Frames.get(self.arguments["arg1"]["frame"], self.arguments["arg1"]["value"])
		
		else:
			value = self.arguments["arg1"]["value"]

		if value == None:
			value = ''
		sys.stderr.write(value)
		sys.stderr.write("\n")

	# Funkcia hozhoduje na zaklade operacneho kodu, aka instrukcia sa ma vykonat
	def instr_exetuce(self):
		if self.opcode == "DEFVAR":
			self.Instr_Defvar()
		elif self.opcode == "ADD":
			self.Instr_Add()
		elif self.opcode == "SUB":
			self.Instr_Sub()
		elif self.opcode == "MUL":
			self.Instr_Mul()
		elif self.opcode == "IDIV":
			self.Instr_IDiv()
		elif self.opcode == "WRITE":
			self.Instr_Write()
		elif self.opcode == "MOVE":
			self.Instr_Move()
		elif self.opcode == "PUSHS":
			self.Instr_Pushs()
		elif self.opcode == "POPS":
			self.Instr_Pops()
		elif self.opcode == "STRLEN":
			self.Instr_StrLen()
		elif self.opcode == "CONCAT":
			self.Instr_Concat()
		elif self.opcode == "GETCHAR":
			self.Instr_GetChar()
		elif self.opcode == "SETCHAR":
			self.Instr_SetChar()
		elif self.opcode == "TYPE":
			self.Instr_Type()
		elif self.opcode == "AND":
			self.Instr_And()
		elif self.opcode == "OR":
			self.Instr_Or()
		elif self.opcode == "NOT":
			self.Instr_Not()
		elif self.opcode == "LT":
			self.Instr_LT()
		elif self.opcode == "EQ":
			self.Instr_EQ()
		elif self.opcode == "GT":
			self.Instr_GT()
		elif self.opcode == "INT2CHAR":
			self.Instr_IntToChar()
		elif self.opcode == "STRI2INT":
			self.Instr_StringToInt()
		elif self.opcode == "READ":
			self.Instr_Read()
		elif self.opcode == "LABEL":
			self.Instr_Label()
		elif self.opcode == "JUMP":
			self.Instr_Jump()
		elif self.opcode == "JUMPIFEQ":
			self.Instr_JumpIfEq()
		elif self.opcode == "JUMPIFNEQ":
			self.Instr_JumpIfNotEq()
		elif self.opcode == "CREATEFRAME":
			self.Instr_CreateFrame()
		elif self.opcode == "PUSHFRAME":
			self.Instr_PushFrame()
		elif self.opcode == "POPFRAME":
			self.Instr_PopFrame()
		elif self.opcode == "CALL":
			self.Instr_Call()
		elif self.opcode == "RETURN":
			self.Instr_Return()
		elif self.opcode == "EXIT":
			self.Instr_Exit()
		elif self.opcode == "Dprint":
			self.Instr_Dprint()
		elif self.opcode == "BREAK":
			self.Instr_Break()

################################################################################
#           Hlavne telo skriptu, volanie a vyuzivanie funkcii a tried          #
################################################################################

# Premenna urcujuca poradove cislo aktualnej instrukcie 
# Zasobnik na ukladanie hodnot
# Zasobnik pre funkcie Call a Return
instruction_order = 1 
value_stack = Stack()
stack_for_call = Stack()

# Spracovanie vstupnych argumentov skriptu, otvorenie a nacitanie suborov so vstupmi 
source_file, input_file = process_program_arguments()
string = open_source_file(source_file)

# Inicializacia triedneho objektu a nasledne spravocanieinstrukcii do pola
parser = Xml_Parser()
instructions, instructions_count = parser.parse(string)

# Najdenie a ulozenie vsetkych navesti v programe
labels_process(instructions)
instruction_order = 1

# Vykonanie vsetkych instrukcii
while instruction_order <= instructions_count:
	# vyberie aktualnu instrukciu
	xml_instruction = instructions[instruction_order-1]
	
	# Preskoci popredu spracovane instrukcie Label
	if xml_instruction.attrib["opcode"] == "LABEL":
		instruction_order = instruction_order + 1
		continue
	
	# Volanie triedy Instruction() pre vytvorenie instacie instrukcie a jej vykonanie 
	instruction = Instruction(xml_instruction)
	instruction.instr_exetuce()
	instruction_order = instruction_order + 1

# Uspesne ukoncenie skriptu
sys.exit(0)