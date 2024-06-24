def rail_fence_cipher(text):
    encrypted_text = []
    for i in range(len(text)):
        if i % 2 == 0:
            encrypted_text.append(text[i])
    for i in range(len(text)):
        if i % 2 == 1:
            encrypted_text.append(text[i])
    return "".join(encrypted_text)


def rail_fence_decipher(text):
    length = len(text)
    if length % 2 == 0:
        k = length // 2
    else:
        k = (length // 2) + 1

    deciphered_text = [' '] * length
    for i in range(k):
        deciphered_text[i * 2] = text[i]
    j = 1
    for i in range(k, length):
        deciphered_text[j] = text[i]
        j += 2

    return "".join(deciphered_text)


text = input("Enter your name: ")
encrypted_text = rail_fence_cipher(text)
print("Cipher text after applying rail fence:", encrypted_text)

decrypted_text = rail_fence_decipher(encrypted_text)
print("Text after decryption:", decrypted_text)
    
    