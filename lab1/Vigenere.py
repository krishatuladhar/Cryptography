def cipher(text, key, mode):
    key = key.upper()
    result = ""
    for i, char in enumerate(text):
        char_input = ord(char.upper()) - 65
        char_key = ord(key[i % len(key)]) - 65
        if mode == "encipher":
            result += chr(65 + ((char_input + char_key) % 26))
        elif mode == "decipher":
            result += chr(65 + ((char_input - char_key) % 26))
    return result


text = input("\nEnter Your Name: ")
key = input("\nEnter Key Value: ")
cipher_text = cipher(text, key, "encipher")
print("\nEnciphered Text:", cipher_text)

decrypted_text = cipher(cipher_text, key, "decipher")
print("\nDeciphered Text:", decrypted_text)