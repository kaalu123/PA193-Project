import sys
import bech32m
import hashlib
import binascii

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def calc_hash(str_to_hash):
    sha256_1 = hashlib.sha256(str_to_hash)
    ripemd160 = hashlib.new("ripemd160")
    ripemd160.update(sha256_1.digest())
    str_hash = ripemd160.digest()
    return str_hash

def conv_and_encode(witprog, version, hrp):
    bits_converted = bech32m.convertbits(witprog, 8, 5)
    data = [version] + bits_converted
    combined = data + bech32m.bech32m_create_checksum(hrp, data)
    final_ret = hrp + '1' + ''.join([CHARSET[d] for d in combined])
    print(final_ret)
    if bech32m.decode(hrp, final_ret) == (None, None):
        return None
    return final_ret

#to encode any arbitrary string input
def encode_str(str):
    #str = input("Enter String to Encode:")
    hrp = "bc"
    #version = int(input("Enter Version:"))      Version input to be taken from user-Phase3
    version=1
    if version in range(1, 17):
        enc_data=bytes.fromhex(str)
        bytes_dt = calc_hash(enc_data)
        print(bytes_dt.hex())
        final_ret=conv_and_encode(bytes_dt,version, hrp)
        return final_ret
    else:
        print("Enter Valid version for bech32m encoding between 1 and 16")
        sys.exit()

'''''
to encode input given as scriptPubKey
'''

def encode_scriptPubkey(hrp,str_to_encode):
    str_unhex = binascii.unhexlify(str_to_encode)
    version = str_unhex[0] - 0x50 if str_unhex[0] else 0
    if version in range(1,17):
        prog = str_unhex[2:]
        final_ret=conv_and_encode(prog, version, hrp)
        print("Encoded scriptPubKey:")
        return final_ret
    else:
        print("version invalid for bech32m encoding:", version)

def decode_bech32(hrp, data):
    data, wit= bech32m.decode(hrp, data)
    wit_hex=([hex(x).lstrip("0x") for x in wit])
    decoded_str= ''.join(map(str, wit_hex))
    print("decoded str=", decoded_str)
    return decoded_str

def main():

    '''#arbitrary string
    encode_str("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")

    #scriptPunKey
    encode_scriptPubkey("bc", "5210751e76e8199196d454941c45d1b3a323")

    #bech32m
    decode_bech32("bc", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh")

    #bech32
    decode_bech32("bc", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")

    #str_to_encode = '512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
    #encode(str_to_encode)'''
    
    #encoded_string=encode_scriptPubkey("bc","38cfe55729af9362bd8e8ffb5c72268962fab01b")
    #print(encoded_string)

if __name__=="__main__":
    main()
    
