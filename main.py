import random

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import cryptography.exceptions

# Bob's private key
bob_sk = rsa.generate_private_key(
    backend=default_backend(),
    public_exponent=65537,
    key_size=2048
)

# Alice's private key
alice_sk = rsa.generate_private_key(
    backend=default_backend(),
    public_exponent=65537,
    key_size=2048
)

bob_pk = bob_sk.public_key()

alice_pk = alice_sk.public_key()

alice_dice = random.randint(1, 6)
bob_dice = random.randint(1, 6)


def printt(msg: str) -> None:
    print(msg + " (Press enter)")
    input()


def hash_dice(dice: str, rand: str) -> int:
    return int(dice, 2) ^ int(rand, 2)


alice_dice_to_bits = f'{alice_dice:08b}'
alice_random_bit = f'{random.randint(1, 1000):08b}'
alice_dice_hashed = f'{hash_dice(alice_dice_to_bits, alice_random_bit):08b}'


def encrypt(pk, msg: str) -> str:
    return pk.encrypt(
        msg.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None
        )
    )


def decrypt(sk, msg: str) -> str:
    return sk.decrypt(
        msg,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None
        )
    )


alice_encrypted_msg = encrypt(bob_pk, alice_dice_hashed)
alice_decrypted_msg = decrypt(bob_sk, alice_encrypted_msg)
bob_encrypted_msg = encrypt(alice_pk, str(bob_dice))


def sign(sk, msg):
    return sk.sign(
        msg,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


alice_encrypted_msg_signed = sign(alice_sk, alice_encrypted_msg)
bob_encrypted_msg_signed = sign(bob_sk, bob_encrypted_msg)


def verify(pk, signature, msg):
    try:
        pk.verify(
            signature,
            msg,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return "Verified successfully!"
    except cryptography.exceptions.InvalidSignature:
        return "Verification failed!"


def main():
    printt("Welcome to the dice rolling game!")
    printt(f"Alice and Bob exchanges public keys.")
    printt(f"Alice now proceeds to roll a dice: {alice_dice}")
    printt(f"Bob now proceeds to roll a dice: {bob_dice}")
    printt(f"Alice now proceeds to convert her dice roll into bits and hashes her answer: {alice_dice_hashed}")
    printt(
        f"Alice now proceeds to encrypt her message using Bob's public key.\nEncrypted message: {alice_encrypted_msg}"
    )
    printt(
        f"Alice now signs the encrypted message and sends it to Bob along with the message.\nSignature: {str(sign(alice_sk, alice_encrypted_msg))} "
    )
    printt(
        f"Bob now received the message and signature. He first checks to see if the signature proves to be from "
        f"Alice:\nVerification of signature:\n{verify(alice_pk, alice_encrypted_msg_signed, alice_encrypted_msg)} "
    )
    printt(f"Bob now decrypts the message and thus has Alice's hashed dice roll: {alice_decrypted_msg}")
    printt(
        f"Bob now ecnrypts his result and signs the encrypted message before sending his dice result to "
        f"Alice.\nEncrypted message: {bob_encrypted_msg}"
    )
    printt(f"Signature: {bob_encrypted_msg_signed}")
    printt(
        f"Alice receives Bob's message and signature, Alice then proceeds to verify the signature.\n"
        f"Verification of signature: {verify(bob_pk, bob_encrypted_msg_signed, bob_encrypted_msg)}"
    )
    printt(f"Now Alice decrypts the message: {decrypt(alice_sk, bob_encrypted_msg)}")
    printt(f"Since Alice now has Bob's result, she sends the original random bits used to hash her result along with the "
           f"result to Bob after she has encrypted and signed the message.")
    printt(f"Random bits: {alice_random_bit}")
    printt(f"Original dice result in bits: {alice_dice_to_bits}")
    printt(
        f"Bob receives the messages, verifies the signature and then decrypts the message using his private key and "
        f"receives the following values:\nRandom "
        f"bits: {alice_random_bit},\nDice Roll in bits: {alice_dice_to_bits}.\nBob then verifies, that the hashed "
        f"result he received before is indeed correct by hashing the newly "
        f"received pair from Alice and seeing if they match:\nThe received result hash: {alice_dice_hashed}\nThe "
        f"newly received "
        f"pair from Alice hashed: {f'{hash_dice(alice_dice_to_bits, alice_random_bit):08b}'} "
    )
    printt(f"Now in order to find the final result, we will apply XOR on both their results: {alice_dice ^ bob_dice}")


main()
