def ROL(data):
    if len(data)<10:
        data=data[:2:]+'0'*(10-len(data))+data[2::]
    parse = data[2::]
    parse = parse[2:4:]+parse[0:2:]+parse[6:8:]+parse[4:6:]
    return int(parse,16)

def itob(data):
    return int(data).to_bytes(4,byteorder='big')

def btoi(data):
    return int.from_bytes(data,byteorder='big')


# target file open
f = open('./NOTEPAD.exe','rb+')

# find e_lfanew
f.seek(0x3C)
e_lfanew = f.read(4)[::-1]

# get StubCode
DOS_STUB = []
for i in range(4):
    DOS_STUB.append(f.read(4))


# Check Infected
if DOS_STUB[0][::-1].hex() != 'deadc0de':
    print("NOT Infected!")
    
else:
    print("STUBCODE : "+DOS_STUB[0][::-1].hex())

    # Change StubCode
    edit_stub = itob(0x0e1fba0e)
    f.seek(0x40)
    f.write(edit_stub)
    print("Change StubCode Successful!")

    # Get Key
    key1 = btoi(DOS_STUB[2][::-1])
    key2 = btoi(DOS_STUB[3][::-1])
    
    # Move to Optional Header and Find Number of Sections
    f.seek(btoi(e_lfanew)+6)
    NumberOfSections = f.read(2)[::-1]
    
    # Find Address of Entry Point 
    f.seek(btoi(e_lfanew)+0x28)
    EntryPoint = f.read(4)[::-1]

    # Find Size of Image
    f.seek(btoi(e_lfanew)+0x50)
    SizeOfImage = btoi(f.read(4)[::-1])
    print("Infected Size of Image : " + hex(SizeOfImage))
    SizeOfImage -= 0x1000
    print("Original Size of Image : " + hex(SizeOfImage))
    f.seek(btoi(e_lfanew)+0x50)
    SizeOfImage = int(SizeOfImage).to_bytes(4,byteorder='little')
    f.write(SizeOfImage)
    print("RESTORE SizeOfImage!!!\n\n\n")




    
    # Move to First Section and Find Section Virtual Size
    f.seek(btoi(e_lfanew)+0xF8+0xC)
    text_RVA = f.read(4)[::-1]
    
    # Find First Section's Size of Raw Data
    f.seek(btoi(e_lfanew)+0xF8+0x10)
    text_Size_RD = f.read(4)[::-1]
    print("First Section's Size of Raw Data : " + text_Size_RD.hex())

    # Find First Section's Pointer to Raw Data
    text_Pointer=f.read(4)[::-1]  
    print("First Section's Pointer to Raw Data : " + text_Pointer.hex())
    
    # Real Address Entry Point
    RealEP = btoi(EntryPoint) - btoi(text_RVA) + btoi(text_Pointer)
    print("Real Address Entry Point : " + hex(RealEP))
    
    
    # Find Last Section
    last_section_header = btoi(e_lfanew)+0xF8+(btoi(NumberOfSections)-1)*0x28

    # Find Last Section's Virtual Size -> RVA -> Size of Raw Data (Malware expands the size of Last Section's Virtual Size and Pointer to RawData by 0x1000)
    f.seek(last_section_header+8)
    last_section_virtualSize = btoi(f.read(4)[::-1]) - 0x1000
    last_section_RVA = f.read(4)
    last_section_pointer2RawData = btoi(f.read(4)[::-1]) - 0x1000
    
    f.seek(last_section_header+8)
    f.write(int(last_section_virtualSize).to_bytes(4,byteorder='little'))
    last_section_RVA = f.read(4)
    f.write(int(last_section_pointer2RawData).to_bytes(4,byteorder='little'))

    print("RESTORE LAST SECTION'S VirtualSize and Pointer to RawData!!!\n\n")

    # Find File End 
    file_end = last_section_virtualSize+last_section_pointer2RawData
    backup_point = file_end+0x822
    
    print("last_section_header : "+hex(last_section_header))
    print("file_end : "+hex(file_end))
    print("backup_point : "+hex(backup_point))
    

    # Move To Backup Point
    f.seek(backup_point)
    backup_memory = b''
    
    # Decrypt Backup Memory By Key1 and Key2 (Size 0x70 = 0x1c*4)
    for i in range(0x1C):
        f.seek(backup_point+4*i)
        data = btoi(f.read(4)[::-1])
        data^=key2
        data = 0xFFFFFFFF-data+1
        data^=key1
        data = ROL(hex(data))
        backup_memory+=itob(data)

    # Restore Backup Memory(EntryPoint)
    f.seek(RealEP)
    f.write(backup_memory)
    f.seek(file_end)

    # Remove Infected Code
    for i in range(0x1000):
        f.write(b'00')
    f.close()

    print("Success!")
