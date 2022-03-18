import bech32m

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def validate_str_for_encoding(hrp,str,input_format):
    if(83 <len(hrp) < 1):
        print("Invalid Length of HRP. Enter Valid HRP string of length between 1 and 83")

    for x in hrp:
        if (ord(x) < 33 or ord(x) > 126):
            print("Invalid character in HRP. Character should have ASCII Value between 33 and 126(both inclusive")

    if input_format=="-hex":
        validated_str=bytes.fromhex(str)
    elif input_format=="ascii":
        hex_str=bech32m.ASCIItoHEX(str)
        validated_str=bytes.fromhex(hex_str)
    elif input_format=="-b64":
        hex_str= bech32m.base64_to_hex(str)
        validated_str=bytes.fromhex(hex_str)
    elif input_format=="raw":
        validated_str=str
    elif input_format=="-bin":
        validated_str=bech32m.bin_to_bytes(str)
    else:
        print("Invalid Input Format!!!. Input string should be in HEX, BASE64, ASCII or BIN")
        return None
    return validated_str

def validate_str_for_decoding(str):

    for x in str:
        if (ord(x) < 33 or ord(x) > 126):
            print("Invalid character in HRP. Character should have ASCII Value between 33 and 126(both inclusive")

    bech32m_str = str.lower()
    pos = bech32m_str.rfind('1')
    if pos < 1 or pos + 7 > len(str) or len(str) > 90:
        print("Invalid Length of bech32m string. Enter valid bech32m string")

    hrp =bech32m_str[:pos]
    data = [CHARSET.find(x) for x in bech32m_str[pos + 1:]]
    spec = bech32m.bech32_verify_checksum(hrp, data)

    if spec is None:
        print("Invalid Checksum")
        return None
    else:
        return (hrp, data[:-6])

#to encode pure bech32m
def encode_pure_bech32m(hrp, str, format):

    validated_str = validate_str_for_encoding(hrp, str, format)
    bits_converted = bech32m.convertbits(validated_str, 8, 5)
    combined = bits_converted + bech32m.bech32m_create_checksum(hrp, bits_converted)
    final_ret = hrp + '1' + ''.join([CHARSET[d] for d in combined])
    print("Encoded str=",final_ret)
    #if decode_pure_bech32m(hrp, final_ret) == None:
    #   return None
    return final_ret

def decode_pure_bech32m(hrp, str_to_decode, out_form,):
    hrpgot, data = validate_str_for_decoding(str_to_decode)

    if hrpgot != hrp:
        print("Invalid HRP provided for decoding, Does not match with HRP calculated from string")
        return None
    decoded_data = bech32m.convertbits(data[:], 5, 8, False)
    decoded_string_in_output_format = bech32m.output_format_fn(decoded_data, out_form)
    return decoded_string_in_output_format

def main():
    encode_pure_bech32m("abcdef","q83v", "-b64")
    encode_pure_bech32m("abcdef", b'\xab\xcd\xef', "raw")
    encode_pure_bech32m("abcdef", "101010111100110111101111", "-bin")  #raw bytes
    encode_pure_bech32m("abcdef", "abcdef", "-hex")
    encode_pure_bech32m("test", "766563746f72", "-hex")
    encode_pure_bech32m("a","", "-hex")
    encode_pure_bech32m("an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber1","", "-hex")
    encode_pure_bech32m("abcdef","ffbbcdeb38bdab49ca307b9ac5a928398a418820", "-hex")
    encode_pure_bech32m("?","", "-hex")
    encode_pure_bech32m("split", "c5f38b70305f519bf66d85fb6cf03058f3dde463ecd7918f2dc743918f2d", "-hex")  #case of unaligend input
    #encode_pure_bech32m("1","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc0")

    ascii_format=encode_pure_bech32m( "?","abczzzzzz", "ascii")
    print("ascii format=", ascii_format)

    base64data=encode_pure_bech32m("split","xfOLcDBfUZv2bYX7bPAwWPPd5GPs15GPLcdDkY8t", "-b64")
    print("base64 data=",base64data)

    str=bech32m.read_file("test.txt")
    encoded_data=encode_pure_bech32m("abcdef",str, "-hex")
    print("Encode from file=", encoded_data)

    bech32m.write_file("encoded_test.txt", encoded_data)



    print("\n\n\nDecode......")
    decode_pure_bech32m("test", "test1wejkxar0wg64ekuu","-hex")
    decode_pure_bech32m("abcdef", "abcdef140x77khk82w","-hex")
    decode_pure_bech32m("abcdef", "abcdef140x77khk82w", "-b64")
    decode_pure_bech32m("a", "a1lqfn3a", "-hex")
    decode_pure_bech32m("an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber1", "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6", "-hex")
    decode_pure_bech32m("abcdef", "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx", "-hex")
    decode_pure_bech32m("?", "?1v759aa", "-hex")
    decode_pure_bech32m("split", "split1checkupstagehandshakeupstreamerranterredcaperredlc445v", "-hex")
    #decode_pure_bech32m("1","11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8")

    str = bech32m.read_file("encoded_test.txt")
    decoded_data = decode_pure_bech32m("abcdef", str, "-hex")
    print("Decoded from file=", decoded_data)


if __name__=="__main__":
    main()


