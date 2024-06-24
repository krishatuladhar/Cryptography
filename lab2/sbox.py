def sbox1(input_bits):
 

    # Extract the row and column indices from the input bits
    row = int(str(input_bits[0]) + str(input_bits[5]), 2)
    col = int(str(input_bits[1]) + str(input_bits[2]) + str(input_bits[3]) + str(input_bits[4]), 2)

    # S-box 1 table
    sbox = [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ]

    # Get the output from the S-box
    output_value = sbox[row][col]

    # Convert the output value to binary representation
    output_bits = bin(output_value)[2:].zfill(4)
    return [int(bit) for bit in output_bits]

# Example usage:
input_bits = [1, 0, 1, 1, 0, 0]  # Example input bits
output_bits = sbox1(input_bits)

print(f"Input bits: {input_bits}")
print(f"Output bits: {output_bits}")