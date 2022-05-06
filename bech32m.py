# Reference :https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki

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
# FITNESS FOR A PARTICULAR PURPOSE AND NON INFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

"""The function bech32_polymod(),bech32_hrp_expand(),bech32_verify_checksum(), bech32m_create_checksum() & convertbits()
 have been taken from Reference implementation[1] and modified to cater for pure bech32m encoding/decoding only"""

import base64
import binascii
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


def check_if_str_is_base64(check_str):
    """check if given string is valid base64 string"""

    base64_charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    if check_str == "":
        return True

    elif type(check_str) is not str:
        print("Input given not a string. If input is raw bytes, select -bin as input format")
        return False

    elif len(check_str) % 4 != 0:
        print("Invalid length of base 64 string. Check input string and input format")
        return False

    elif not all(x in base64_charset for x in check_str):
        print("Non base64 Character Entered in String")
        return False

    else:
        return True


def check_if_str_is_hex(check_str):
    """
    check if given string is valid hexadecimal string
    :param check_str: string to be validated for hexadecimal encoding
    :return: true if string has valid hexadecimal encoding
    """

    hex_charset = "ABCDEFabcdef0123456789"
    if check_str == "":
        return True

    elif type(check_str) is not str:
        print("Input given not a string. If input is raw bytes, select \"bin\" as input format")
        return False

    elif len(check_str) % 2 != 0:
        print("Invalid Length of Hex String")
        return False

    elif not all(x in hex_charset for x in check_str):
        print("Non Hex Character Entered in String")
        return False

    else:
        return True


def check_if_str_is_bin(check_str):
    """
    check if input string has raw bytes
    :param check_str: string to be checked
    :return: true if string is raw bytes else false
    """
    return isinstance(check_str, bytes)


def ascii_to_hex(ascii_str):
    """
    convert any ascii string to hexadecimal
    :param ascii_str: ascii string to be converted to hex
    :return: hex encoded ascii string
    """

    hexa = ""
    for i in range(len(ascii_str)):
        ch = ascii_str[i]
        in1 = ord(ch)
        part = hex(in1).lstrip("0x").rstrip("L")
        hexa += part
    return hexa


def hex_to_ascii(hex_str):
    """
    convert hexadecimal string to ascii
    :param hex_str: hex string to be converted
    :return: ascii string
    """

    ascii_str = ""

    for i in range(0, len(hex_str), 2):
        data = hex_str[i: i + 2]
        one_char = chr(int(data, 16))
        ascii_str += one_char

    return ascii_str


def base64_to_hex(base64_str):
    """
    Convert base64 encoded string to hex string
    :param base64_str: base64 encoded string
    :return: hexadecimal string
    """

    decoded_str = base64.b64decode(base64_str.encode('utf-8')).hex()
    return decoded_str


def hex_to_base64(hex_str):
    """
    convert hex encoded string to base64 encoded string
    :param hex_str: hexadecimal string to be converted
    :return: base64 encoded string
    """

    decoded_str = base64.b64encode(bytes.fromhex(hex_str)).decode()
    return decoded_str


def hex_to_raw(hex_str):
    """
    convert hex string to raw bytes
    :param hex_str:
    :return: raw bytes
    """

    return binascii.unhexlify(hex_str)


def raw_to_hex(raw_str):
    """
    convert raw bytes to hex string
    :param raw_str: raw bytes
    :return: hexadecimal string
    """

    return binascii.hexlify(raw_str)


def str_to_base64(sample_string):
    """
    convert any ascii string to base64 encoding
    :param sample_string: ascii string to be encoded to base 64
    :return: base64 encoded string
    """

    sample_string_bytes = sample_string.encode()
    base64_bytes = base64.b64encode(sample_string_bytes)
    base64_string = base64_bytes.decode()
    return base64_string


def output_format_enc(bech32_str, out_format):
    """
    convert the encoded bech32m string to desired(hex/b64/bin) output format
    :param bech32_str: valid bech32m encoded string
    :param out_format: output format for encoded string
    :return: bech32m string encoded in output format (hex/b64/bin)
    """

    if out_format == "bech32m":
        return bech32_str

    elif out_format == "hex":
        return ascii_to_hex(bech32_str)

    elif out_format == "b64":
        return str_to_base64(bech32_str)

    elif out_format == "bin":
        raw_hex = ascii_to_hex(bech32_str)
        return hex_to_raw(raw_hex)

    else:
        print("Invalid Output Format. Please Specify hex, b64 or bin")
        sys.exit(0)


def output_format_dec(hex_str, out_format):
    """
    convert the decoded string to desired(hex/b64/bin) output format
    :param hex_str: hex string generated after decoding a bech32m string
    :param out_format: output format for decoded string
    :return: decoded string in required encoding (hex/b64/bin)
    """

    if out_format == "hex":
        return hex_str
    elif out_format == "b64":
        return hex_to_base64(hex_str)
    elif out_format == "bin":
        return hex_to_raw(hex_str)
    else:
        print("Invalid Output Format. Please Specify hex, b64 or bin")


def read_file(input_file_name, input_format):
    """
    read encoded/decoded string/bytes from file as per input format
    :param input_file_name: file name from which input string/bytes are to be read
    :param input_format: bin/hex/b64
    :return: string/bytes as per specified input format
    """

    try:

        if input_format == "bin":
            mode = "rb"
        else:
            mode = "r"
        with open(input_file_name, mode) as f:
            input_data = f.read()

        if not input_data:
            return ""
        else:
            return input_data

    except IOError as e:
        print("I/O error({0}): {1}".format(e.errno, e.strerror))
        return False


def write_file(output_file_name, output_data, output_format):
    """
    write encoded/decoded string/bytes to file as per output format
    :param output_file_name: file name to which string/bytes are to be written
    :param output_data:
    :param output_format:
    :return:
    """

    try:
        if output_format == "bin":
            mode = "wb"
        else:
            mode = "w"

        with open(output_file_name, mode) as f:
            f.write(output_data)

    except IOError as e:
        print("I/O error({0}): {1}".format(e.errno, e.strerror))
        sys.exit(0)
