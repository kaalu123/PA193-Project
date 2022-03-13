import sys

def cli_functions():

    help = (open("help.txt", "r")).read()
    index = 0
    try:
        if(sys.argv[1] not in ["-enc","-dec"]):
            print(help)

        elif(sys.argv[1] == "-enc"):
            print("Encode Mode selected")
            mode = "-enc"
            index += 1

            if(sys.argv[2] not in ["-b64","-bin", "-hex"]):
                print("Type of input not specified. Quitting...")
                print(help)
                exit(0)
            else:
                str_format = sys.argv[2]
    #
                if(len(sys.argv)<4):
                    print("Command line or file input not selected. Defaulting to stdin")
                    index += 1
                    input_string = input("Enter string to encode : ")
                    outfile = input("Enter output file name (press enter for stdout) : ")
                    if (outfile == ""): outfile = "stdout"
                    return mode, str_format, input_string, outfile

                else:
                    if (sys.argv[3] == "-cli"):
                        input_string = sys.argv[4]
                        print("Input = " + input_string)

                    elif (sys.argv[3] == "-if"):
                        input_file = sys.argv[4]
                        print("File = " + input_file)
                        input_string = (open(input_file, "r").read())

                try:
                    x = sys.argv.index("-of")
                    outfile = sys.argv[x+1]
                except:
                    print("No output path selected. Defaulting to stdout")
                    outfile = "stdout"



        return mode, str_format, input_string, outfile

    except:
        print("Wrong Input!\n")
        exit(0)



if __name__== "__main__":
    mode, str_format, input_string, outfile = cli_functions()
    print("Mode " + mode +"\nFormat " + str_format + "\nInput " + input_string + "\nOutput path :" + outfile)