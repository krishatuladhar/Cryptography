import struct

def sha1(data):
    # Constants used in the SHA-1 algorithm
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    # Pre-processing
    original_byte_len = len(data)
    original_bit_len = original_byte_len * 8
    data += b'\x80'
    
    while (len(data) % 64) != 56:
        data += b'\x00'
        
    data += struct.pack('>Q', original_bit_len)
    
    # Process the message in successive 512-bit chunks
    for i in range(0, len(data), 64):
        chunk = data[i:i+64]
        w = [0] * 80

        # Break chunk into sixteen 32-bit big-endian words w[i]
        for j in range(16):
            w[j] = struct.unpack('>I', chunk[j*4:j*4+4])[0]
        
        # Extend the sixteen 32-bit words into eighty 32-bit words
        for j in range(16, 80):
            w[j] = (w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16])
            w[j] = ((w[j] << 1) | (w[j] >> 31)) & 0xFFFFFFFF

        # Initialize hash value for this chunk
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        # Main loop
        for j in range(80):
            if 0 <= j <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= j <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= j <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6
            
            temp = ((a << 5) | (a >> 27)) + f + e + k + w[j]
            temp &= 0xFFFFFFFF
            e = d
            d = c
            c = (b << 30) | (b >> 2)
            c &= 0xFFFFFFFF
            b = a
            a = temp

        # Add this chunk's hash to result so far
        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF

    # Produce the final hash value (big-endian)
    return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)

# Example usage
data = b"i love dogs"
hash_value = sha1(data)
print(hash_value)
