import re
import argparse


def check(pattern_path, target_path):
    with open(pattern_path, 'r') as file:
        pattern = re.compile(file.read().strip().replace("\n", "\\\n"))

    with open(target_path, 'r') as file:
        target = file.read().strip()

    # print(pattern.search(target))
    # print(pattern.match(target))
    exit(int(not pattern.fullmatch(target)))

def check2(pattern_path, target_path):
    with open(pattern_path, 'r') as pattern, \
             open(target_path, 'r') as target:
        for pattern, target in zip(pattern, target):

            pattern = re.compile((pattern.strip()).replace("\n", "\\\n"))
            target = target.strip()

            if not pattern.fullmatch(target):
                print(pattern, target)
                exit(1)

        exit(0)

parser = argparse.ArgumentParser(description="Check if one file path matches the regex pattern in another file.")
parser.add_argument('pattern_file', type=str, help="Path to the file containing the regex pattern")
parser.add_argument('target_file', type=str, help="Path to the file to be checked against the regex pattern")

args = parser.parse_args()
check(args.pattern_file, args.target_file)