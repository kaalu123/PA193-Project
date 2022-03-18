#Reference :https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki

# Copyright (c) 2017, 2020 Pieter Wuille
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

"""The function bech32_polymod(),bech32_hrp_expand(),bech32_verify_checksum(), bech32m_create_checksum() & convertbits()
 have been taken from Reference implementation[1] and modified to cater for pure bech32m encoding/decoding only"""

import base64
import sys

BECH32M_CONST = 0x2bc830a3

def bech32_polymod(values):
    """Internal function that computes the Bech32 checksum."""
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk

def bech32_hrp_expand(hrp):
    """Expand the HRP into values for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_verify_checksum(hrp, data):
    """Verify a checksum given HRP and converted data characters."""
    const = bech32_polymod(bech32_hrp_expand(hrp) + data)
    if const == BECH32M_CONST:
        return 1
    else:
        print("Invalid checksum!!! address not bech32m encoded")
    return None

def bech32m_create_checksum(hrp, data):
    """Compute the checksum values given HRP and data."""
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ BECH32M_CONST
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def convertbits(data, frombits, tobits, pad=True):
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1

    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def check_if_str_is_hex(str):
    for char in str:
        if ((char < '0' or char > '9') and
                (char < 'A' or char > 'F')):
            print("Non Hex Character Entered in String")
            return False
        else:
            return True

def ASCIItoHEX(ascii):
    hexa = ""
    for i in range(len(ascii)):
        ch = ascii[i]
        in1 = ord(ch)
        part = hex(in1).lstrip("0x").rstrip("L")
        hexa += part
    return hexa

def base64_to_hex(base64_str):
    decoded_str = base64.b64decode(base64_str.encode('utf-8')).hex()
    return decoded_str

def hex_to_base64(hex_str):
    return base64.b64encode(bytes.fromhex(hex_str)).decode()

def bin_to_bytes(bin_str):
    return int(bin_str, 2).to_bytes((len(bin_str) + 7) // 8, byteorder='big')


def output_format_fn(decoded_str, out_format):
    list_to_hex = ([hex(x).lstrip("0x") for x in decoded_str])
    decoded_str_in_hex = ''.join(map(str, list_to_hex))

    if out_format == "hex":
        print("decoded_str_in_hex=", decoded_str_in_hex)
        return decoded_str_in_hex

    if out_format == "base64":
        print("decoded_str_in_base64=", hex_to_base64(decoded_str_in_hex))
        return hex_to_base64(decoded_str_in_hex)

def read_file(input_file_name):
    try:
        with open(input_file_name, 'r') as f:
            input_data = f.read()

        if not input_data:
            print("No Data found in file :" + input_file_name)
            return None
        else:
            return input_data

    except IOError as e:
        print("I/O error({0}): {1}".format(e.errno, e.strerror))

    except:  # handle other exceptions such as attribute errors
        print("Unexpected error:", sys.exc_info()[0])

def write_file(output_file_name, output_data):
    try:
        with open(output_file_name,'w') as f:
            f.write(output_data)

    except IOError as e:
        print("I/O error({0}): {1}".format(e.errno, e.strerror))

    except:  # handle other exceptions such as attribute errors
        print("Unexpected error:", sys.exc_info()[0])
