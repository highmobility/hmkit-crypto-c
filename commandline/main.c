/*
The MIT License

Copyright (c) 2014- High-Mobility GmbH (https://high-mobility.com)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "commander.h"
#include "printer.h"


int main(int argc, char *argv[]) {
    char *name = argv[0];

    if (argc == 1) {
        print_help(name, true, NULL);
    }
    else {
        // Get the flags
        bool hasHelpFlag = false;
        bool hasVerFlag = false;

        for (int i = 1; i < argc; i++) {
            char *argument = argv[i];

            if ((strcmp(argument, "-h") == 0) || (strcmp(argument, "--help") == 0)) {
                hasHelpFlag = true;
            }
            else if ((strcmp(argument, "-v") == 0) || (strcmp(argument, "--ver") == 0)) {
                hasVerFlag = true;
            }
        }

        // Start going through the flags
        if (hasVerFlag) {
            printf("\n");
            printf("Cryptotool version 1.0\n");
            printf("\n");
        }
        else if (hasHelpFlag) {
            if (argc == 2) {
                print_help(name, true, NULL);
            }
            else {
                print_help(name, false, argv[1]);
            }
        }
        else {
            if (parse_command(argc, argv) != 0) {
                printf("\n");
                printf("ERROR:	Invalid input, please check --help for the command.\n");
                printf("\n");
            }
        }
    }

    return 0;
}
