#!/usr/bin/env python3

import os
import sys
import re
import string
import argparse


class Util:
    def __init__(self, splited_text, block_start, block_end):
        '''
            ### splited_text: should be splited by lines.
        '''
        self.splited_text = splited_text
        self.block_start = block_start
        self.block_end = block_end
        
        self.block_start_line = None
        self.block_end_line = None

        self.file_changed = False


    def get_splited_text(self):
        return self.splited_text


    @property
    def is_changed(self):
        return self.file_changed
    

    def find_block(self):
        for i, s in enumerate(self.splited_text):
            if self.block_start in s:  # define start of the block --> eg: authorize { ... }
                self.block_start_line = i
                break

        for j in range(self.block_start_line, len(self.splited_text)):
            if self.splited_text[j] == self.block_end:  # define end of the block --> eg: authorize { ... }
                self.block_end_line = j
                break


    def find_block2(self):
        for i, s in enumerate(self.splited_text):
            if self.block_start in s:
                self.block_start_line = i
                break
        else:
             raise Exception("Begining of block was not found.")

        curly_braces_counter = 0
        for j in range(self.block_start_line, len(self.splited_text)):
            if "{" in self.splited_text[j]:
                curly_braces_counter += 1

            if "}" in self.splited_text[j]:
                curly_braces_counter -= 1
            
            if curly_braces_counter <= 0:
                self.block_end_line = j
                break
        else:
            raise Exception("End of block was not found.")


    def get_regex(find_str):
        return re.compile(r'(\s*)' + r'([' + re.escape(string.punctuation) + r']*)' + r'\s*' + '(' + f'{find_str}' + ')$')  # r'[\p{P}\p{S}]sql$'


    def replace(self, old, new):
        main_str = None

        if self.block_start_line is None or self.block_end_line is None:
            raise Exception("First call 'find_block' method.")
        
        regex_pattern = Util.get_regex(old)
        for line in range(self.block_start_line, self.block_end_line):
            if re.match(regex_pattern, self.splited_text[line]):
                main_str = re.search(regex_pattern, self.splited_text[line]).groups()[2]
                break  #TODO: Is break necessary or may need to check another match

        if main_str:
            print("Replaced")
            self.splited_text[line] = self.splited_text[line].replace(main_str, new)  # Replace string
            self.file_changed = True
        

    def insert(self, find_str, insert_str, insert_after = True):
        insert_index = None

        if self.block_start_line is None or self.block_end_line is None:
            raise Exception("First call 'find_block' method.")
        
        regex_pattern = Util.get_regex(find_str)
        for line in range(self.block_start_line, self.block_end_line):
            if re.match(regex_pattern, self.splited_text[line]):
                indent = re.search(regex_pattern, self.splited_text[line]).groups()[0]
                insert_index = line + 1 if insert_after else line
                break

        if insert_index:
            print('Inserted')
            self.splited_text.insert(insert_index, indent + insert_str)  # insert string after a string
            self.file_changed = True


    def uncomment(self, str_to_uncomment):
        if self.block_start_line is None or self.block_end_line is None:
            raise Exception("First call 'find_block' method.")
        
        regex_pattern = Util.get_regex(str_to_uncomment)
        for line in range(self.block_start_line, self.block_end_line):
            if re.match(regex_pattern, self.splited_text[line]):
                comment_char = re.search(regex_pattern, self.splited_text[line]).groups()[1]  # Comment character groups as defined in 'get_regex()' function
                self.splited_text[line] = self.splited_text[line].replace(comment_char, '')  # Replace string
                self.file_changed = True
                break  #TODO: Is break necessary or may need to check another match


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('-p, --path', type=str, required=True, dest='path')

    parser.add_argument('--block-start', type=str, required=True)
    parser.add_argument('--block-end', type=str, required=True)

    parser.add_argument('-r', '--replace', action='store_true')
    parser.add_argument('--old-str', type=str, nargs=1, dest='old_str')
    parser.add_argument('--new-str', type=str, nargs=1, dest='new_str')

    parser.add_argument('--uncomment', action='store_true')
    parser.add_argument('--str-to-uncomment', type=str, dest='str_to_uncomment')

    parser.add_argument('-i', '--insert', action='store_true')
    parser.add_argument('--find-str', type=str, nargs=1, dest='find_str')
    parser.add_argument('--insert-str', type=str, nargs=1, dest='insert_str')
    parser.add_argument('--insert-str-stdin', action="store_true")
    parser.add_argument('--insert-position', default='after', const='after', nargs='?', choices=['after', 'before'], dest='insert_position')

    args = parser.parse_args()

    if args.replace and not (args.old_str and args.new_str):
        raise Exception("--old-str or --new-str is empty.")
    
    if args.uncomment and not args.str_to_uncomment:
         raise Exception("--str-to-uncomment is empty.")
    
    if args.insert and not (args.find_str):
        raise Exception("--find-str or --insert-str is empty.")

    if args.insert and (bool(args.insert_str) ^ args.insert_str_stdin == 0):
        raise Exception("One of --insert-str or --inser-str-stdin should be provided.")
    
    
    if args.insert and args.insert_str_stdin:
        input_strings = []
        for line in sys.stdin:
            input_strings.append(line)
            sys.stdout.write(line)
        insert_str_value = "\n".join(input_strings)
    elif args.insert and args.insert_str:
        insert_str_value = str(args.insert_str[0])


    if not os.path.exists(args.path):
        raise Exception("File Does not exist.")
    
    with open(args.path) as f:
        splited = f.read().splitlines()

    # Main class
    o = Util(
        splited, 
        block_start=args.block_start, 
        block_end=args.block_end
        )
    
    o.find_block2()

    if args.replace:
        o.replace(
            old = str(args.old_str[0]), 
            new = str(args.new_str[0])
            )
    
    if args.insert:
        insert_after = True if args.insert_position == "after" else False
        o.insert(
            find_str = str(args.find_str[0]), 
            insert_str = insert_str_value, 
            insert_after = insert_after
            )


    if o.is_changed:
        with open(args.path, 'w') as f:
            f.write("\n".join(o.get_splited_text()))


if __name__ == '__main__':
    main()