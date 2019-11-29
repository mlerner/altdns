#!/usr/bin/env python
# released at BSides Canberra by @infosec_au and @nnwakelam
# <3 silvio

import argparse



def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("-i",
                        "--input",
                        help="List of subdomains input",
                        required=True)
    parser.add_argument("-o",
                        "--output",
                        help="Output location for altered subdomains",
                        required=True)
    parser.add_argument("-w",
                        "--wordlist",
                        help="List of words to alter the subdomains with",
                        required=False,
                        default="words.txt")
    parser.add_argument("-r",
                        "--resolve",
                        help="Resolve all altered subdomains",
                        action="store_true")
    parser.add_argument("-n",
                        "--add-number-suffix",
                        help="Add number suffix to every domain (0-9)",
                        action="store_true")
    parser.add_argument("-e",
                        "--ignore-existing",
                        help="Ignore existing domains in file",
                        action="store_true")
    parser.add_argument(
        "-d",
        "--dnsserver",
        help="IP address of resolver to use (overrides system default)",
        required=False)

    parser.add_argument("-s",
                        "--save",
                        help="File to save resolved altered subdomains to",
                        required=False)

    parser.add_argument("-t",
                        "--threads",
                        help="Amount of threads to run simultaneously",
                        required=False,
                        default="0")

    args = parser.parse_args()

    run(args.input, args.output, args.wordlist, args.resolve,
        args.add_number_suffix, args.ignore_existing, args.dnsserver,
        args.save, args.threads)


if __name__ == "__main__":
    main()
