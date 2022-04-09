# PA193-Project
This is a simple bech32m encoding and decoding tool written in python.
The tool can be run from either CLI or STDIN


**CLI**

Usage: cli.py {enc,dec} hrp [-h] (-s S | -inf INF) [-iform {hex,bin,b64}] [-oform {hex,bin,b64}] [-of OF] 

positional arguments:
  {enc,dec}         mode to define the function of tool : encode/decode
  hrp                   human readable part
optional arguments:
  -h, --help            	show this help message and exit
  -s S                  		input string to be encoded/decoded*
  -inf INF              	input file to read string to be encoded/decoded*
  -iform {hex,bin,b64}  	input format@
  -oform {hex,bin,b64}  	output format$
  -of OF                	output file path to write encoded/decoded string #

** -s and -inf are part of mutually exclusive group i.e. only one of the optional argument can be used on cli to provide user input (also one of them is a required optional argument)
@ default input format for encoding mode is “hex” if no input format is specified. For decoding “bech32m” is default format if not specified which takes a valid bech32m encoded string as input.
$ default output format for encoding mode is “bech32m” and for “decoding” mode is “hex”
# output file name if not specified defaults to stdout


**STDIN**

User input is validated on entering the data on stdin and prompted to enter again in case of invalid input.

Usage: 		Default Interface Stdin Selected

Enter the mode ["enc" or "dec"]: <mode encoding/decoding>
Enter HRP[valid ascii]: <human readable part>
Enter Input Format[b64/bin/hex](Press Enter for Default["hex" for "enc" and "bech32m" for "dec"]):  <defaults same as CLI>
Enter input file name ( or press enter to input string from "stdin"): <filename which contains string to be encoded/decoded >
Enter the input string: <string to be encoded/decoded>
Choose output Format[b64/bin/hex] (Press Enter for Default["bech32m" for "enc" and "hex" for "dec"]):  <defaults same as CLI>
Enter output file name (press enter to print output to "stdout") :  <output file name to which encoded/decode data will be written.Defaults to stout if not specified>
  
**Error Detection and Correction**
  
The tool uses naive approach to detect errors in bech32m string input for decoding and suggest the correct string. This has been done by iterating over possible symbols from bech32m character set and checking for valid checksum after each iteration. The tool cannot error of more than one character. Also, the Human Readable Part is assumed to be correct in error detection and correction as same is validated first during decoding process. Colour coded characters are shown for error (red) and correction (green) for which colorama has been used. Example:

$ python cli.py dec test -s test1zy3rx9zgu9r
  
>Checksum Failed
  
>Checking for Corrections in Input String
  
>Incorrect Character Found: test1zy3rx9zgu9r
  
>Correct Character is: z
  
>Correct String is: test1zy3rxzzgu9r 

