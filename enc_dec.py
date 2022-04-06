import bech32m
import sys
from colorama import init, Fore, Style

init(autoreset=True)  # Initializes colorama
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def validate_hrp(hrp):
    if hrp == "":
        print("HRP cannot be null/empty")
        return False

    if len(hrp) > 83:
        print("Invalid Length of HRP. Enter Valid HRP string of length between 1 and 83")
        return False

    for x in hrp:
        if ord(x) < 33 or ord(x) > 126:
            print("Invalid character in HRP. Character should have ASCII Value between 33 and 126(both inclusive")
            return False
        else:
            return True


def validate_str_for_encoding(hrp, input_str, input_format):
    if validate_hrp(hrp):

        if input_format == "hex":
            if bech32m.check_if_str_is_hex(input_str) or input_str == "":
                validated_str = bytes.fromhex(input_str.lower())
                return validated_str
            else:
                print("Invalid hex String")
                return False

        elif input_format == "b64":
            if bech32m.check_if_str_is_base64(input_str) or input_str == "":
                hex_str = bech32m.base64_to_hex(input_str)
                validated_str = bytes.fromhex(hex_str)
                return validated_str
            else:
                print("Invalid b64 String")
                return False

        elif input_format == "bin":
            if bech32m.check_if_str_is_bin(input_str) or input_str == "":
                validated_str = input_str
                return validated_str
            else:
                print("Invalid bin String")
                return False
        else:
            print("Invalid Input Format!!!. Input string should be in \"hex\", \"b64\" or \"bin\"")
            return None
    else:
        sys.exit(0)


def detect_errors(hrp, data_str):
    print("Checking for Corrections in Input String")
    for i in range(0, len(data_str)):
        check_char = data_str[i]

        for correct_char in range(0, 32):
            if correct_char == check_char:
                continue
            data_str[i] = correct_char
            spec = bech32m.bech32_verify_checksum(hrp, data_str)

            if spec == 1:
                final_ret = hrp + '1' + ''.join([CHARSET[d] for d in data_str])
                return final_ret

        data_str[i] = check_char


def print_corrections(input_str, correct_str):
    if correct_str is None:
        print("Correct Character Not Found. Possibly more than one incorrect character in input string")
        sys.exit(0)

    for i in range(len(input_str)):
        if input_str[i] == correct_str[i]:
            i += 1
        else:
            print("Incorrect Character Found:",
                  (Style.BRIGHT + Fore.WHITE + input_str[:i]) + (Style.BRIGHT + Fore.RED + input_str[i])
                  + (Style.BRIGHT + Fore.WHITE + input_str[i + 1:]))
            print("Correct Character is:", correct_str[i])
            print("Correct String is:",
                  (Style.BRIGHT + Fore.WHITE + correct_str[:i]) + (Style.BRIGHT + Fore.GREEN + correct_str[i])
                  + (Style.BRIGHT + Fore.WHITE + correct_str[i + 1:]))

            sys.exit(0)


def validate_str_for_decoding(input_str, input_format):
    if input_str == "":
        print("Input string cannot be empty for decoding")
        sys.exit(0)

    if input_format == "b64":
        if bech32m.check_if_str_is_base64(input_str):
            input_str = bech32m.hex_to_ascii(bech32m.base64_to_hex(input_str))
        else:
            print("Invalid b64 String")
            return False

    if input_format == "hex":
        if bech32m.check_if_str_is_hex(input_str):
            input_str = bech32m.hex_to_ascii(input_str)
        else:
            print("Invalid hex String")
            return False

    if input_format == "bin":
        if bech32m.check_if_str_is_bin(input_str):
            input_str = bech32m.hex_to_ascii(bech32m.raw_to_hex(input_str))
        else:
            print("Invalid bin String")
            return False

    for x in input_str:
        if ord(x) < 33 or ord(x) > 126:
            print("Invalid character in string. Character should have ASCII Value between 33 and 126(both inclusive)")
            sys.exit(0)

    bech32m_str = input_str.lower()
    pos = bech32m_str.rfind('1')

    if pos == -1:
        print("Separator not found in bech32m string")
        sys.exit(0)

    if pos < 1 or pos + 7 > len(bech32m_str) or len(bech32m_str) > 90:
        print("Invalid Length of bech32m string. Enter valid bech32m string")
        sys.exit(0)

    data_part = bech32m_str[pos + 1:]

    if len(data_part) < 6:
        print("Invalid Length of Data Part")
        sys.exit(0)

    if not all(x in CHARSET for x in data_part):
        print("Invalid character in Data Part of Bech32m String")
        sys.exit(0)

    hrp = bech32m_str[:pos]
    data = [CHARSET.find(x) for x in bech32m_str[pos + 1:]]
    spec = bech32m.bech32_verify_checksum(hrp, data)

    if spec is None:
        print("Checksum Failed")
        correct_str = detect_errors(hrp, data)
        print_corrections(input_str, correct_str)
    else:
        return hrp, data[:-6]


# to encode pure bech32m
def encode_pure_bech32m(hrp, input_str, in_format, out_format):
    if not validate_str_for_encoding(hrp.lower(), input_str, in_format):
        sys.exit(0)
    else:
        validated_str = validate_str_for_encoding(hrp.lower(), input_str, in_format)
        bits_converted = bech32m.convertbits(validated_str, 8, 5, True)
        combined = bits_converted + bech32m.bech32m_create_checksum(hrp.lower(), bits_converted)
        final_ret = hrp + '1' + ''.join([CHARSET[d] for d in combined])

        return bech32m.output_format_enc(final_ret, out_format)


def decode_pure_bech32m(hrp, str_to_decode, input_format, out_form):
    if validate_hrp(hrp):
        if not validate_str_for_decoding(str_to_decode, input_format):
            sys.exit(0)
        else:
            hrpgot, data = validate_str_for_decoding(str_to_decode, input_format)
            if hrpgot != hrp.lower():
                print("Invalid HRP provided for decoding, Does not match with HRP calculated from string")
                return None
            else:
                decoded_data = bech32m.convertbits(data[:], 5, 8, True)
                list_to_hex = ([hex(x).lstrip("0x") for x in decoded_data])
                decoded_str_in_hex = ''.join(map(str, list_to_hex))
                decoded_string_in_output_format = bech32m.output_format_dec(decoded_str_in_hex, out_form)

                return decoded_string_in_output_format
    else:
        sys.exit(0)



