def expansion_pbox(right_half):
 
  p_box = [
      32, 1, 2, 3, 4, 5,
      4, 5, 6, 7, 8, 9,
      8, 9, 10, 11, 12, 13,
      12, 13, 14, 15, 16, 17,
      16, 17, 18, 19, 20, 21,
      20, 21, 22, 23, 24, 25,
      24, 25, 26, 27, 28, 29,
      28, 29, 30, 31, 32, 1
  ]

  # Expand the right half based on the P-box permutation
  expanded_right_half = [right_half[i - 1] for i in p_box]

  return expanded_right_half

# Example usage
right_half = [1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0]
expanded_right_half = expansion_pbox(right_half)

print("Right half (32-bit):", right_half)
print("Expanded right half (48-bit):", expanded_right_half)