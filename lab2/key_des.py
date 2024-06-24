def permute_bits(bits, permutation):
  
    return [bits[i] for i in permutation]

def left_shift(bits, shift_count):
   
    return bits[shift_count:] + bits[:shift_count]

def des_key_generation(key):
   
    # Permuted Choice 1 (PC-1)
    pc1_permutation = [
        57, 49, 41, 33, 25, 17, 9, 1,
        58, 50, 42, 34, 26, 18, 10, 2,
        59, 51, 43, 35, 27, 19, 11, 3,
        60, 52, 44, 36, 28, 20, 12, 4,
        61, 53, 45, 37, 29, 21, 13, 5,
        62, 54, 46, 38, 30, 22, 14, 6,
        63, 55, 47, 39, 31, 23, 15, 7,
        56, 48, 40, 32, 24, 16, 8
    ]
    key = permute_bits(key, pc1_permutation)

    # Split the key into two 28-bit halves
    left_half = key[:28]
    right_half = key[28:]

    subkeys = []
    for i in range(16):
        # Perform left shifts on the halves
        left_half = left_shift(left_half, 1)
        right_half = left_shift(right_half, 1)

        # Combine the halves
        key = left_half + right_half

        # Permuted Choice 2 (PC-2)
        pc2_permutation = [
            14, 17, 11, 24, 1, 5, 3, 28,
            15, 6, 21, 10, 23, 19, 12, 4,
            26, 8, 16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55, 30, 40,
            51, 45, 33, 48, 44, 49, 39, 56,
            34, 53, 46, 42, 50, 36, 29, 32
        ]
        subkey = permute_bits(key, pc2_permutation)
        subkeys.append(subkey)

    return subkeys

# Example usage
key = [int(b) for b in '0100110101010101010101010101010101010101010101010101010101010101']
subkeys = des_key_generation(key)
for i, subkey in enumerate(subkeys):
    print(f"Subkey {i+1}: {''.join(str(b) for b in subkey)}")