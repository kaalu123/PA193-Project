import sys
import argparse
import bech32m
import enc_dec


def user_interface():
    """
    provides cli and stdin/stdout options to user for encoding/decoding
    :return: mode, hrp, input_string, infile, input_format, output_format, outfile
    """

    if len(sys.argv) > 1:
        my_parser = argparse.ArgumentParser(description='Bech32m Encoder/Decoder')
        my_parser.add_argument('m', type=str, help='encode/decode', choices=['enc', 'dec'])
        my_parser.add_argument('hrp', type=str, help='human readable part[ASCII]')
        group = my_parser.add_mutually_exclusive_group(required=True)
        group.add_argument('-s', type=str, help='input string to be encoded/decoded')
        group.add_argument('-inf', type=str, help='input file to read string to be encoded/decoded')
        my_parser.add_argument('-iform', type=str, choices=['hex', 'bin', 'b64'], help='input format')
        my_parser.add_argument('-oform', type=str, choices=['hex', 'bin', 'b64'], help='output format')
        my_parser.add_argument('-of', type=str, help='output file path to write encoded/decoded string')
        args = my_parser.parse_args()

        if args.s is not None and args.iform == "bin":
            args_s = args.s
            args_str = args_s.encode()
        else:
            args_str = args.s

        return args.m, args.hrp, args_str, args.inf, args.iform, args.oform, args.of

    if len(sys.argv) == 1:
        print("Default Interface Stdin Selected")

        #Enter Correct Mode
        mode = ""
        while mode not in ["enc", "dec"]:
            mode = input("Enter the mode [\"enc\" or \"dec\"]:")
            if mode not in ["enc", "dec"]:
                print("Enter Valid Mode [\"enc\" or \"dec\"]")

        #Enter and Validate HRP
        hrp = input("Enter HRP[valid ascii]:")
        while not enc_dec.validate_hrp(hrp):
            hrp = input("Enter HRP[valid ascii]:")

        #Enter and validate input format
        input_format = input("Enter Input Format[b64/bin/hex]"
                             "(Press Enter for Default[\"hex\" for \"enc\" and \"bech32m\" for \"dec\"]):")
        while input_format not in ["b64", "bin", "hex", ""]:
            input_format = input("Enter Valid Input Format[b64/bin/hex]"
                                 "(Press Enter for Default[\"hex\" for \"enc\" and \"bech32m\" for \"dec\"]):")

        #set default input format for enc/dec if not provided
        if mode == "enc" and input_format == "":
            input_format = "hex"
        if mode == "dec" and input_format == "":
            input_format = "bech32m"

        #read string/filename from stdin
        infile = input("Enter input file name ( or press enter to input string from \"stdin\"):")
        if not infile:                                                  #if filename is not provided, read string from stdin
            input_string = input("Enter the input string:")
            if not input_string and mode == "enc":
                print("Null String Entered")
            else:
                while not input_string and mode == "dec":
                    print("Empty String Cannot be decoded")
                    input_string = input("Enter the input string:")

            if input_format == "bin":
                #input_string = bytes(input_string, 'utf-8')
                input_string = input_string.encode()

        else:                                                          #if file name is provided read string from file
            while not bech32m.read_file(infile, input_format):
                infile = input("Enter input file name:")

            input_string = bech32m.read_file(infile, input_format)

        #validate input string with the input format provided, if string not in format ask for input string again
        if input_format == "b64":
            while not bech32m.check_if_str_is_base64(input_string):
                input_string = input("Enter Valid \"base64\" input string:")

        if input_format == "hex":
            while not bech32m.check_if_str_is_hex(input_string):
                input_string = input("Enter valid \"Hex\" input string:")

        if input_format == "bin":
            while not bech32m.check_if_str_is_bin(input_string):
                input_string_s = input("Enter valid \"bin\" input string:")
                #input_string = bytes(input_string_s, 'utf-8')
                input_string = input_string_s.encode()

        #input output format and validate
        output_format = input("Choose output Format[b64/bin/hex]"
                              " (Press Enter for Default[\"bech32m\" for \"enc\" and \"hex\" for \"dec\"]):")
        while output_format not in ["b64", "bin", "hex", ""]:
            output_format = input("Enter Valid Output Format[b64/bin/hex]"
                                  "(Press Enter for Default[\"hex\" for \"enc\" and \"bech32m\" for \"dec\"]):")

        #set default output format for enc/dec if not provided
        if mode == "enc" and output_format == "":
            output_format = "bech32m"
        if mode == "dec" and output_format == "":
            output_format = "hex"

        #input output file name if enc/dec data is to be written to a file
        outfile = input("Enter output file name (press enter to print output to \"stdout\") : ")

        return mode, hrp, input_string, infile, input_format, output_format, outfile


def main():
    mode, hrp, input_string, input_file, input_format, output_format, output_file = user_interface()

    if input_string is None:
        if not bech32m.read_file(input_file, input_format):
            sys.exit(0)
        else:
            input_string = bech32m.read_file(input_file, input_format)

    if mode == "enc":
        if input_format is None:
            input_format = "hex"
        if output_format is None:
            output_format = "bech32m"

        print("Mode:", mode, "HRP:", hrp, "Input String:", input_string, "Input Format:", input_format,
              "Output Format:", output_format)

        encoded_string = enc_dec.encode_pure_bech32m(hrp, input_string, input_format, output_format)

        if not output_file:
            print("\nEncoded String in {}".format(output_format[:].upper()), encoded_string)
            print("\n")
        else:
            bech32m.write_file(output_file, encoded_string, output_format)
            print("\nEncoded String in \"{}\" written to file :\"{}\"".format(output_format[:].upper(), output_file))
            print("\n")

    if mode == "dec":

        if input_format is None:
            input_format = "bech32m"
        if output_format is None:
            output_format = "hex"

        print("Mode:", mode, "HRP:", hrp, "Input String:", input_string, "Input Format:", input_format,
              "Output Format:", output_format, "Input File:", input_file, "Output File:", output_file)

        decoded_string = enc_dec.decode_pure_bech32m(hrp, input_string, input_format, output_format)

        if not output_file:
            print("Decoded String in \"{}\"".format(output_format[:].upper()), decoded_string)
            print("\n")
        else:
            bech32m.write_file(output_file, decoded_string, output_format)
            print("\nDecoded String in \"{}\" written to file :\"{}\"".format(output_format[:].upper(), output_file))
            print("\n")

if __name__ == "__main__":
    main()

