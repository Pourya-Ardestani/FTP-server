# Encryption alphabet
alphabet_e = {'a': '01',
              'b': '02',
              'c': '03',
              'd': '04',
              'e': '05',
              'f': '06',
              'g': '07',
              'h': '08',
              'i': '09',
              'j': '10',
              'k': '11',
              'l': '12',
              'm': '13',
              'n': '14',
              'o': '15',
              'p': '16',
              'q': '17',
              'r': '18',
              's': '19',
              't': '20',
              'u': '21',
              'v': '22',
              'w': '23',
              'x': '24',
              'y': '25',
              'z': '26',
              ' ': '32',
              '=': '34',
              ':': '38',
              '\\': '39',
              '/': '40',
              '&': '41',
              '$': '42',
              '-': '43',
              '_': '44',
              '.': '45',
              '0': '46',
              '1': '47',
              '2': '48',
              '3': '49',
              '4': '450',
              '5': '51',
              '6': '52',
              '7': '53',
              '9': '54',
              "'": '55',
              '8': '56',
              '|': '57',
              ',': '58',
              '!': '59',
              '@': '60',
              '<': '61',
              '>': '62',
              '+': '63',
              '"': '64',
              '?': '65',
              '[': '66',
              ']': '67',
              '{': '68',
              '}': '69',
              '(': '70',
              ')': '71',
              '*': '72',
              '`': '73',
              '%': '74',
              '^': '75'
              }

# Decryption alphabet
alphabet_d = {n: c for c, n in alphabet_e.items()}


# Euclidian Algorithm: Find GCD of two numbers
def gcd(a, b):
    if (b == 0):
        return abs(a)
    else:
        return gcd(b, a % b)


# Generate encryption keys, e, and d
def generate_keys(p, q):
    # Part of public key
    n = p * q

    # Part of private key
    N0 = (p - 1) * (q - 1)

    # Part of public key
    # Find e: first integer relatively prime to N0
    for i in range(2, N0):
        if gcd(i, N0) == 1:
            e = i
            break

    # Part of private key
    # Find d: multiplicative inverse of e % N0
    for i in range(0, N0):
        if ((e * i) % N0) == 1:
            d = i
            break

    return n, e, d


# Encrypt character
def encrypt(char, N, e):
    return str((int(char) ** e) % N).zfill(2)


# Decrypt character
def decrypt(char, N, d):
    return str((int(char) ** d) % N).zfill(2)


# Split word into characters
def split(word):
    return [char for char in word]


# Encrypt message
def encrypt_message(msg, N, e):
    # Messages
    plaintext = msg.lower().split()
    encrypted = []

    # Exncrypt message
    for word in plaintext:
        # Split word into characters
        chars = split(word)

        # Create list of encrypted characters
        encrypted_chars = [encrypt(alphabet_e[char], N, e) for char in chars]

        # Add encrypted word to list
        encrypted_word = " ".join(encrypted_chars)
        encrypted.append(encrypted_word)

    # Join encrypted words with space characters
    encrypted = f" {encrypt(alphabet_e[' '], N, e)} ".join(encrypted)

    return encrypted


# Decrypt message
def decrypt_message(msg, N, d):
    # Messages
    encrypted = msg.split()
    decrypted = []
    plaintext = []

    # Decrypt
    for char in encrypted:
        decrypted.append(decrypt(char, N, d))

    # Decipher message
    for char in decrypted:
        plaintext.append(alphabet_d[char])

    plaintext = "".join(plaintext)

    return plaintext


def get_peivate_And_public_key(p, q, owner):
    try:
        # Generate values for encryption / decryption
        N, e, d = generate_keys(p, q)

        # Show keys
        print(f"{owner.title()}_Public key:\nN: {N}\ne: {e}\n")

        print(f"{owner.title()}_Private key:\nN: {N}\nd: {d}\n")
        return N, e, d


    except:
        print("Error: Invalid Primes\n")
# def get_peivate_key(p,q):
#     try:
#         # Generate values for encryption / decryption
#         N, e, d = generate_keys(p, q)
#         return (N, e)
#         # # Show keys
#         # print(f"Public key:\nN: {N}\ne: {e}\n")
#         # print(f"Private key:\nN: {N}\nd: {d}\n")
#         # return (N,e)
#
#     except:
#         print("Error: Invalid Primes\n")
