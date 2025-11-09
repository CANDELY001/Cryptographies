import struct
import math
import argparse
import sys

def caesar_cipher(phrase: str, key: int) -> str:
    encoded_phrase = ''.join(
        chr((ord(char) - 65 + key) % 26 + 65) if char.isupper() else
        chr((ord(char) - 97 + key) % 26 + 97) if char.islower() else
        char
        for char in phrase
    )
    return encoded_phrase

# Example usage
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process some strings.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-s', '--string', help='String to hash')
    parser.add_argument('-k', '--key', help='8-byte key', default='3')
    args = parser.parse_args()

    if args.string is not None:
        digest = caesar_cipher(args.string, int(args.key))
        print(f"Phrase (string): {digest}")   
    elif args.key is not None:
        try:
            key = int(args.key)
            phrase = input("Enter the phrase to encode: ")
            encoded_phrase = ''.join(
                chr((ord(char) - 65 + key) % 26 + 65) if char.isupper() else
                chr((ord(char) - 97 + key) % 26 + 97) if char.islower() else
                char
                for char in phrase
            )
            print(f"Encoded Phrase: {encoded_phrase}")
        except ValueError:
            print("Key must be an integer.", file=sys.stderr)
            digest = caesar_cipher(phrase, 3)
