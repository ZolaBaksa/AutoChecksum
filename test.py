import os
import re
import sys

micom_info = sys.argv[1]

# Micom 빈 영역을 0xFF로 채운 0x80000 바이트의 배열 생성
if micom_info == 'TMPM3H':
    bin_data = bytearray([0xFF] * 0x80000)
    hex_line = ":08FEF000"
elif micom_info == 'TMPM380':
    bin_data = bytearray([0xFF] * 0x40000)
    hex_line = ":04FFEC00"
elif micom_info == 'TMPM383':
    bin_data = bytearray([0xFF] * 0x20000)
    hex_line = ":08FEF000"
elif micom_info == 'RF1308':
    bin_data = bytearray([0xFF] * 0x80000)
    hex_line = ":08000000"

target_dir = sys.argv[2]
target_hex = sys.argv[3]

def hex_to_bin(hex_file, bin_file):
    print("hex_to_bin road")
    with open(hex_file, 'r') as f:
        b_address = int("00", 16)
        for line in f:
            if line.startswith(':'):
                # HEX 레코드 파싱
                length = int(line[1:3], 16)
                address = int(line[3:7], 16)
                record_type = int(line[7:9], 16)

                checksum = int(line[9 + length * 2:9 + length * 2 + 2], 16)
                # 데이터가 있는 경우
                if record_type == 0:  # 데이터 레코드
                    data = bytes.fromhex(line[9:9 + length * 2])
                    bin_data[(b_address+address):(b_address+address) + length] = data
                elif record_type == 4:  # 주소 레코드
                    if micom_info == 'RF1308':
                        data = int(line[9:9 + length * 2], 16) - int('FFF8', 16)
                    else:
                        data = int(line[9:9 + length * 2], 16)
                    b_address = data << 16

    # .bin 파일로 저장
    with open(bin_file, 'wb') as f:
        f.write(bin_data)

    return bin_data

def calculate_byte_sum(bin_data):
    return sum(bin_data)

hex_file = f"{target_dir}\\{target_hex}"  # 입력 HEX 파일 경로
bin_file = f"{target_dir}\\{os.path.splitext(target_hex)[0]}.bin"  # 출력 BIN 파일 경로

bin_data = hex_to_bin(hex_file, bin_file)
byte_sum = calculate_byte_sum(bin_data)

if micom_info == 'TMPM380':
    byte_sum = 0x0000FFFF & byte_sum
    print(f'바이트 합: 0x{byte_sum:04X}')  # 16진수로 출력
else:
    print(f'바이트 합: 0x{byte_sum:08X}')  # 16진수로 출력

def update_define_value(file_path, csum_define, new_value):
    # 1. 특정 파일을 'utf-8' 형식으로 연다.
    print("update_define_value road")
    with open(file_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()
        print(f"csum_define : {csum_define}")

    if not lines:
        print("Error: The file is empty.")
        return ""

    # 2. '#define SW_CSUM' 으로 시작하는 위치를 찾는다.
    define_pattern = re.compile(r'^#define\s+' + csum_define)
    define_pattern_saa = re.compile(r'^#define\s+SW_PNO')
    print("here is the point")
    saa = ""
    matched = False
    for i, line in enumerate(lines):
        print(f"Checking line {i}: {line.strip()}")
        if micom_info == 'TMPM3H' and define_pattern_saa.match(line):
            saa = line[-9:-1]
            print(f"Found SW_PNO: {saa}")
        if define_pattern.match(line):
            print(f"Found {csum_define} at line {i}: {line.strip()}")
            # 3. 해당 라인을 '#define {csum_define} ' 에 변수의 값을 '0x' 로 시작하고 대문자로 표현된 16진수 값으로 기록한다.
            lines[i] = f'#define {csum_define}\t{new_value}\n'
            matched = True
            break

    if not matched:
        print(f"Error: No matching line found for #define {csum_define} in the file.")
        return saa

    # 변경된 내용을 파일에 다시 쓴다.
    with open(file_path, 'w', encoding='utf-8') as file:
        file.writelines(lines)
    return saa

ts = len(sys.argv)
print(ts)
print(sys.argv)
print(f"I'm here 104")

pjt_dir = sys.argv[4]
csum_src = sys.argv[5]
csum_define = sys.argv[6]

csum_file = f'{pjt_dir}\\{csum_src}'

if micom_info == 'TMPM380':
    new_csum = '0x' + f'{byte_sum:04X}'
else:
    new_csum = '0x' + f'{byte_sum:08X}'
new_saa = update_define_value(csum_file, csum_define, new_csum)

def modify_hex_line(line):
    # 행의 구조 파악
    if not line.startswith(hex_line):
        return line

    if micom_info == 'TMPM3H' or micom_info == 'RF1308':
        # 데이터 추출
        data = line[9:41]  # :10FEF800 이후의 데이터 (16바이트)

        # CSUM 계산
        csum = byte_sum

        # FFFFFFFF에서 CSUM을 뺀 값 계산
        ffffffff_minus_csum = 0xFFFFFFFF - byte_sum

        # 결과 생성
        csum_hex = f'{csum:08X}'
        csum_hex = f'{csum_hex[-2:]}{csum_hex[-4:-2]}{csum_hex[-6:-4]}{csum_hex[-8:-6]}'
        ffffffff_minus_csum_hex = f'{ffffffff_minus_csum:08X}'
        ffffffff_minus_csum_hex = f'{ffffffff_minus_csum_hex[-2:]}{ffffffff_minus_csum_hex[-4:-2]}{ffffffff_minus_csum_hex[-6:-4]}{ffffffff_minus_csum_hex[-8:-6]}'
        # 새로운 데이터 생성
        new_data = f'{csum_hex}{ffffffff_minus_csum_hex}'

        # 새로운 행 생성
        new_line = f'{hex_line}{new_data}{line[25:]}'
    elif micom_info == 'TMPM380':
        # 데이터 추출
        data = line[9:41]  # :10FEF800 이후의 데이터 (16바이트)

        # CSUM 계산
        csum = byte_sum

        # FFFFFFFF에서 CSUM을 뺀 값 계산
        ffff_minus_csum = 0xFFFF - byte_sum

        # 결과 생성
        csum_hex = f'{csum:04X}'
        csum_hex = f'{csum_hex[-2:]}{csum_hex[-4:-2]}'
        ffff_minus_csum_hex = f'{ffff_minus_csum:04X}'
        ffff_minus_csum_hex = f'{ffff_minus_csum_hex[-2:]}{ffff_minus_csum_hex[-4:-2]}'
        # 새로운 데이터 생성
        new_data = f'{ffff_minus_csum_hex}{csum_hex}'

        # 새로운 행 생성
        new_line = f'{hex_line}{new_data}{line[17:]}'
    print(new_line)
    return new_line

def process_hex_file(input_file, output_file):
    with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
        for line in infile:
            modified_line = modify_hex_line(line.strip())
            outfile.write(modified_line + '\n')

input_file = f"{target_dir}\\{target_hex}"
output_file = f'{target_dir}\\{os.path.splitext(target_hex)[0]}_{new_csum}_SAA{new_saa}.hex'
process_hex_file(input_file, output_file)