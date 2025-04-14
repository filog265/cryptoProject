import random
import math


def is_prime(n, k=5):
    """
    Miller-Rabin primality test

    n: number to test
    k: number of test rounds
    """
    if n <= 1 or n == 4:
        return False
    if n <= 3:
        return True

    # Find r and d such that n-1 = 2^r * d, where d is odd
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    # Witness loop
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_large_prime(bits=256):
    """Generate a large prime number with specified bit length"""
    while True:
        # Generate a random odd number with specified bit length
        p = random.getrandbits(bits) | (1 << bits - 1) | 1
        if is_prime(p):
            return p


def find_primitive_root(p):
    """Find a primitive root (generator) for prime p"""
    if p == 2:
        return 1

    # Find prime factors of p-1
    factors = []
    phi = p - 1

    # Find factor 2
    if phi % 2 == 0:
        factors.append(2)
        while phi % 2 == 0:
            phi //= 2

    # Find odd prime factors
    i = 3
    while i * i <= phi:
        if phi % i == 0:
            factors.append(i)
            while phi % i == 0:
                phi //= i
        i += 2

    if phi > 1:
        factors.append(phi)

    # Test random numbers for primitive root property
    while True:
        g = random.randint(2, p - 1)
        is_primitive = True

        for factor in factors:
            if pow(g, (p - 1) // factor, p) == 1:
                is_primitive = False
                break

        if is_primitive:
            return g


def generate_dh_parameters(bits=256):
    """Generate Diffie-Hellman parameters p and g"""
    print("Generating prime p... (this may take a moment)")
    p = generate_large_prime(bits)
    print("Finding generator g...")
    g = find_primitive_root(p)
    return p, g


def mod_exp(base, exponent, mod):
    result = 1
    base = base % mod  # Ensure base is within the modulus
    while exponent > 0:
        if exponent % 2 == 1:  # If exponent is odd, multiply result with base
            result = (result * base) % mod
        exponent = exponent // 2  # Halve the exponent
        base = (base * base) % mod  # Square the base
    return result


def generate_private_key(p):
    # Generate a private key in the range [2, p-2] for security
    return random.randint(2, p - 2)


def generate_public_key(private_key, p, g):
    # Compute public key using modular exponentiation
    return mod_exp(g, private_key, p)


def generate_shared_secret(other_public_key, private_key, p):
    # Compute shared secret using the other party's public key and own private key
    return mod_exp(other_public_key, private_key, p)


# Example usage
if __name__ == "__main__":
    # For demonstration, use smaller bits (32) for faster execution
    # In a real application, use at least 2048 bits
    bits = 32

    # Generate DH parameters
    p, g = generate_dh_parameters(bits)
    print(f"Generated p: {p}")
    print(f"Generated g: {g}")

    # Alice generates her keys
    alice_private = generate_private_key(p)
    alice_public = generate_public_key(alice_private, p, g)

    # Bob generates his keys
    bob_private = generate_private_key(p)
    bob_public = generate_public_key(bob_private, p, g)

    # Both compute the shared secret
    alice_shared = generate_shared_secret(bob_public, alice_private, p)
    bob_shared = generate_shared_secret(alice_public, bob_private, p)

    # Display results
    print("\nAlice's private key:", alice_private)
    print("Alice's public key:", alice_public)
    print("Bob's private key:", bob_private)
    print("Bob's public key:", bob_public)
    print("\nAlice's shared secret:", alice_shared)
    print("Bob's shared secret:", bob_shared)
    print("Shared secrets match?", alice_shared == bob_shared)

    # Generate another set with different parameters
    print("\n\nGenerating a new set of parameters...")
    p2, g2 = generate_dh_parameters(bits)

    # The rest of the process remains the same but with new parameters
    alice_private2 = generate_private_key(p2)
    alice_public2 = generate_public_key(alice_private2, p2, g2)

    bob_private2 = generate_private_key(p2)
    bob_public2 = generate_public_key(bob_private2, p2, g2)

    alice_shared2 = generate_shared_secret(bob_public2, alice_private2, p2)
    bob_shared2 = generate_shared_secret(alice_public2, bob_private2, p2)

    print(f"Generated p: {p2}")
    print(f"Generated g: {g2}")

    print("\nNew Alice's shared secret:", alice_shared2)
    print("New Bob's shared secret:", bob_shared2)
    print("New shared secrets match?", alice_shared2 == bob_shared2)