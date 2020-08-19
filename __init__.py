from binaryninja import *
from multiprocessing import *


def get_address_from_sig(bv, sigList):
	br = BinaryReader(bv)

	result = 0

	length = len(sigList) - 1

	for search_func in bv.functions:
		br.seek(search_func.start)

		while bv.get_functions_containing(br.offset + length) != None and search_func in bv.get_functions_containing(br.offset + length):
			found = True
			counter = 0
			for entry in sigList:
				byte = br.read8()
				counter += 1
				if entry != byte and entry != '?':
					found = False
					break

			br.offset -= counter

			if found:
				result = br.offset
				break

			br.offset += bv.get_instruction_length(br.offset)

		if result != 0:
			break

	return result

def test_address_for_sig(bv, addr, sigList):
	br = BinaryReader(bv)

	length = len(sigList) - 1

	br.seek(addr)

	containing = bv.get_functions_containing(br.offset + length)

	if containing == None or len(containing) == 0:
		return False

	found = True
	for entry in sigList:
		byte = br.read8()
		if entry != byte and entry != '?':
			found = False
			break

	return found

def get_amount_of_hits(bv, sigList):
	br = BinaryReader(bv)

	result = 0

	if len(sigList) == 0:
		return result

	sigLen = len(sigList) - 1

	for search_func in bv.functions:
		br.seek(search_func.start)

		while bv.get_functions_containing(br.offset + sigLen) != None and search_func in bv.get_functions_containing(br.offset + sigLen):
			found = True
			counter = 0
			for entry in sigList:
				byte = br.read8()
				counter += 1
				if entry != byte and entry != '?':
					found = False
					break

			br.offset -= counter

			if found:
				result += 1

			br.offset += bv.get_instruction_length(br.offset)

	return result

def get_addr_of_hits(bv, sigList):
	br = BinaryReader(bv)

	result = []

	if len(sigList) == 0:
		return result

	sigLen = len(sigList) - 1

	for search_func in bv.functions:
		br.seek(search_func.start)

		while bv.get_functions_containing(br.offset + sigLen) != None and search_func in bv.get_functions_containing(br.offset + sigLen):
			found = True
			counter = 0
			for entry in sigList:
				byte = br.read8()
				counter += 1
				if entry != byte and entry != '?':
					found = False
					break

			br.offset -= counter

			if found:
				result.append(br.offset)

			br.offset += bv.get_instruction_length(br.offset)

			if bv.get_instruction_length(br.offset) == 0:
				break

	return result

def SigMakerFind(bv):
	f = Finder(bv)
	f.start()

class Finder(BackgroundTaskThread):
	def __init__(self, bv):
		BackgroundTaskThread.__init__(self, "Finding Signature...", True)
		self.bv = bv

	def run(self):
		user_input = get_text_line_input("Find Signature\t\t\t\t\t", "SigMaker")

		if user_input == None:
			return

		sig = user_input.split(" ".encode())

		sigList = []

		for value in sig:
			if value == '?' or value == b'?' or value == b'?\n':
				sigList.append('?')
			elif value != '?' and value != '':
				sigList.append(int(value,16))

		result = get_address_from_sig(self.bv, sigList)

		if result != 0:
			new_result = result
			print('Found:\t' + convert_to_hex_string(new_result) + '\nInside:\t' + convert_to_hex_string(self.bv.get_functions_containing(new_result)[0].start) + '\nHits:\t' + convert_to_hex_string(get_amount_of_hits(self.bv,sigList))) #+ )
			print('\nSignature:\t' + user_input.decode())
			res = show_message_box("Search result",'Address:\t' + convert_to_hex_string(new_result) + '\n' + 'Function:\t' + convert_to_hex_string(self.bv.get_functions_containing(new_result)[0].start) + '\nWant to jump to the address?', MessageBoxButtonSet.YesNoButtonSet, MessageBoxIcon.InformationIcon)
			if res == MessageBoxButtonResult.YesButton:
				self.bv.file.navigate(self.bv.file.view, new_result)
		else:
			print('Found:\t' + 'None' + '\nInside:\t' + 'None' + '\nSignature:\t' + user_input.decode())
			show_message_box("Search result",'Address:\t' + 'NONE' + '\n' + 'Function:\t' + 'NONE' + '\n', MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.InformationIcon)


def get_instruction_sig(bv, func, addr):
	const = func.get_constants_referenced_by(addr)
	length = bv.get_instruction_length(addr)

	br = BinaryReader(bv)

	br.seek(addr)

	sig = []

	if len(const) == 0:
		for x in range(length):
			sig.append(br.read8())
	elif len(const) > 0:
		br.offset += length
		new_delta = 0
		for cur_const in const:
			if cur_const.pointer:
				new_delta += 4
			else:
				br.offset -= new_delta + 1
				if const[0].value == br.read8():
					new_delta += 1
				else:
					br.offset -= new_delta + 4
					if const[0].value == br.read32():
						new_delta += 4

		br.offset = addr
		for x in range(length - new_delta):
			sig.append(br.read8())
		for x in range(new_delta):
			sig.append('?')


	return sig

def get_sig_from_address(bv, addr, first_try = True):

	sigList = []

	length = len(sigList) - 1

	if addr == None:
		return sigList

	offset = addr

	org_func = bv.get_functions_containing(offset)

	if len(org_func) == 0:
		return sigList

	sigList.extend(get_instruction_sig(bv, org_func[0], offset))

	if len([x for x in sigList if x != '?']) < 4:
		offset += bv.get_instruction_length(offset)
		sigList.extend(get_instruction_sig(bv, org_func[0], offset))

	hitList = get_addr_of_hits(bv, sigList)

	while len(hitList) > 1:
		offset += bv.get_instruction_length(offset)

		containing = bv.get_functions_containing(offset + 1)

		if  containing == None or len(containing) == 0 or containing[0] != org_func[0] and first_try:
			return get_sig_from_address(bv, org_func[0].start, False)
		elif not first_try:
			return []

		if len(sigList) > 48 and first_try:
			return get_sig_from_address(bv, org_func[0].start, False)
		elif not first_try:
			return []

		sigList.extend(get_instruction_sig(bv, org_func[0], offset))

		for hit in hitList:
			if hit == addr:
				continue
			if not test_address_for_sig(bv, hit, sigList):
				hitList = [x for x in hitList if x != hit]


	return sigList

def convert_to_hex_string(value):
	str_value = (hex(value).rstrip("L").lstrip("0x").upper() or "0")
	if len(str_value) == 1:
		return '0' + str_value
	else:
		return str_value

def convert_to_string(sigList):

	if len(sigList) == 0:
		return "NONE"

	str_sig = ""
	count = 0
	for entry in sigList:
		if entry != '?':
			str_sig += convert_to_hex_string(entry)
		else:
			str_sig += entry
		count += 1
		if count != len(sigList):
			str_sig += ' '

	return str_sig

def SigMakerCreate(bv, addr):
	#show_message_box("Create Signature","It can take a while for the plugin to finish.\nThe search will run in the background but you can cancel it at any time.\nPress 'OK' if you want to start.", MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.InformationIcon)

	c = Creator(addr, bv)
	c.start()


class Creator(BackgroundTaskThread):
	def __init__(self, addr, bv):
		BackgroundTaskThread.__init__(self, "Creating Signature...", True)
		self.addr = addr
		self.bv = bv

	def run(self):
		sigList = get_sig_from_address(self.bv, self.addr)

		str_sig = convert_to_string(sigList)
		print('Created Signature:\t\n')
		print(str_sig)
		show_message_box("Created Signature",'Address:\t' + convert_to_hex_string(get_address_from_sig(self.bv, sigList)) + '\n' + 'Signature:\t' + str_sig + '\n', MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.InformationIcon)


PluginCommand.register("Find Signature", "", SigMakerFind)
PluginCommand.register_for_address("Create Signature", "", SigMakerCreate)
