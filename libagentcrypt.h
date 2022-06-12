/**
 * @mainpage A library for symmetric encryption with SSH Agent
 *
 * ### Copyright (c) 2019-2022, Nicola Di Lieto <nicola.dilieto@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *
 * # Introduction
 *
 * libagentcrypt allows using the keys in the SSH Agent to perform symmetric,
 * authenticated encryption and decryption securely without typing passwords.
 * It works with both RSA and ED25519 SSH keys including those made available
 * to a remote host by SSH Agent forwarding. The library is based on strong
 * encryption routines from [libsodium](https://www.libsodium.org). The source
 * code is maintained on [github](https://github.com/ndilieto/libagentcrypt).
 *
 * # Algorithms
 *
 * The SSH Agent protocol only allows the use of ssh keys for signing
 * data. Therefore libagentcrypt performs the following process for every
 * symmetric encryption (agc_encrypt() function):
 * - pad the cleartext with random data to a size multiple of the padding
 *   size (to hide true message length) and concatenate the original
 *   length at the end of the cleartext
 * - generate a random hash key
 * - create a nonce by hashing the padded cleartext with the random hash key
 * - create a challenge by concatenating nonce and ssh key fingerprint
 * - submit the challenge to the SSH Agent for signing with the ssh key
 * - compute the symmetric key by hashing the agent signature data
 * - encrypt and authenticate the padded cleartext with the nonce and
 *   the symmetric key (using libsodium's crypto_secretbox algorithm)
 * - output the challenge and ciphertext
 *
 * The decryption process (agc_decrypt() function) is the reverse:
 * - read the challenge and the ciphertext
 * - submit the challenge to the SSH agent for signing
 * - compute the symmetric key by hashing the agent signature data
 * - decrypt and verify the ciphertext
 * - read the original length at the end of the decrypted data and strip
 *   the padding bytes
 * - output the cleartext
 *
 * Both agc_encrypt() and agc_decrypt() are intended to encrypt short
 * blocks of data stored in memory. Two additional functions are also provided
 * to encrypt and decrypt files of arbitrary length: agc_fencrypt() generates a
 * random key, encrypts it with agc_encrypt() and stores it at the beginning of
 * the output; it then uses the random key to encrypt the file with libsodium's
 * crypto_secretstream algorithm. agc_fdecrypt() later reconstructs the key
 * with agc_decrypt() and can then decrypt the file.
 *
 * Two helper functions (agc_from_b64() and agc_to_b64()) are included to encode
 * and decode binary data to/from base64 format. These are very useful when
 * encrypted data must be stored in text/configuration files.
 *
 * ## Installation
 *
@verbatim
export PKG_URL=https://github.com/ndilieto/libagentcrypt/archive/upstream/latest.tar.gz
mkdir -p libagentcrypt
wget -O - $PKG_URL | tar zx -C libagentcrypt --strip-components=1
cd libagentcrypt
./configure --disable-maintainer-mode
make install
@endverbatim
 *
 * ## Usage
 *
 * SSH currently supports four types of keys:
 * - ED25519
 * - RSA
 * - DSA
 * - ECDSA
 *
 * Signatures made by the first two (ED25519 and RSA) are deterministic, i.e.
 * repeatedly signing the same block of input data always produces the same
 * result. This is not true for DSA and ECDSA keys, therefore libagentcrypt
 * cannot possibly function with these - it would still encrypt but of course
 * the symmetric key would never be able to be recovered.
 * The encryption functions in libagentcrypt check the key type and fail if it
 * it is not one of RSA or ED25519. Fortunately DSA is obsolete and ECDSA may
 * even have a NSA backdoor... RSA is still secure as long as the key size
 * is at least 2048. For best security ED25519 keys are recommended.
 *
 * The <a href="agentcrypt.1.html"><b>agentcrypt</b></a> command line utility
 * shows how to use the library.
 *
 * # API Information
 *
 * ## Headers
 *
 * To use libagentcrypt functions in your code you should include the
 * libagentcrypt.h header, i.e. @code #include <libagentcrypt.h> @endcode
 *
 * ## Namespace
 *
 * All identifiers defined by the libagentcrypt.h header use the prefix agc_
 *
 * ## Functions
 *
 * The following functions are provided by the library:
 * - agc_encrypt()
 * - agc_decrypt()
 * - agc_fencrypt()
 * - agc_fdecrypt()
 * - agc_from_b64()
 * - agc_to_b64()
 * - agc_free()
 */
#ifndef __LIBAGENTCRYPT_H__
#define __LIBAGENTCRYPT_H__
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Encrypt and authenticate a block of data, for later decryption by
 * agc_decrypt()
 *
 * @param[in]  agent           The ssh-agent UNIX domain socket bind address.
 *                             If NULL the content of the SSH_AUTH_SOCK
 *                             environment variable is used instead.
 * @param[in]  key_sha256      Pointer to a string containing the SHA256
 *                             fingerprint of the SSH key to be used for
 *                             encryption. This can be obtained by running
 *                             the following command (openssh >= 6.8 required):
 *                             @verbatim ssh-add -E sha256 -l @endverbatim
 *                             The string may or may not begin with "SHA256:"
 *                             The first key whose fingerprint starts with the
 *                             string specified is selected. If NULL the first
 *                             key is chosen automatically. Only RSA and ED25519
 *                             keys are supported.
 *                             When using RSA keys, if the AGENTCRYPT_LEGACY
 *                             environment variable is defined and not zero,
 *                             RSA SHA1 signatures are used for encryption. This
 *                             is not recommended and is only necessary if the
 *                             encrypted data need to be decrypted using legacy
 *                             openssh versions (older than 7.2) whose agent did
 *                             not support RSA SHA256 signatures. Note that data
 *                             encrypted using such legacy versions can always
 *                             be decrypted correctly without needing to define
 *                             this variable.
 * @param[in]  cleartext       Pointer to the data to be encrypted.
 * @param[in]  cleartext_size  Size of data to be encrypted.
 * @param[in]  pad_size        Padding size. A chunk of random data no larger
 *                             than pad_size is added at the end of cleartext,
 *                             such that the combined cleartext and pad size
 *                             is a non-zero integer multiple of pad_size.
 *                             A minimum of 16 is enforced if pad_size < 16.
 * @param[out] ciphertext      This function allocates the output data buffer
 *                             dynamically and it stores a pointer to it into
 *                             *ciphertext upon success. The buffer MUST be
 *                             freed by calling agc_free() after use. Do NOT
 *                             use the standard free() function.
 * @param[out] ciphertext_size The size of the output buffer is stored into
 *                             *ciphertext_size.
 *
 * @return 0 upon success, -1 otherwise. Reasons for failure include
 * \li the ssh key is not available: errno is set to ENOKEY
 * \li invalid data returned by ssh-agent: errno is set to EBADMSG
 * \li failure to allocate memory: errno is set to ENOMEM
 * \li invalid parameters: errno is set to EINVAL
 * \li any other C library error, including socket errors while communicating
 * with ssh-agent: errno is left at the value set by the C library
 */
int agc_encrypt(const char *agent, const char *key_sha256,
        const uint8_t *cleartext, size_t cleartext_size, size_t pad_size,
        uint8_t **ciphertext, size_t *ciphertext_size);

/**
 * Decrypt and verify a block of data encrypted by agc_encrypt()
 *
 * @param[in]  agent           The ssh-agent UNIX domain socket bind address.
 *                             If NULL the content of the SSH_AUTH_SOCK
 *                             environment variable is used instead.
 * @param[in]  ciphertext      Pointer to the data to be decrypted.
 * @param[in]  ciphertext_size Size of the data to be decrypted.
 * @param[out] cleartext       This function allocates the output data buffer
 *                             dynamically and it stores a pointer to it into
 *                             *cleartext upon success. The buffer MUST be
 *                             freed by calling agc_free() after use. Do NOT
 *                             use the standard free() function.
 * @param[out] cleartext_size  The size of the output buffer is stored into
 *                             *ciphertext_size upon success.
 *
 * @return 0 upon success, -1 otherwise. Reasons for failure include
 * \li the ssh key required to decrypt is not available: errno is set to ENOKEY
 * \li invalid data returned by ssh-agent or failure to decrypt: errno is set
 * to EBADMSG
 * \li failure to allocate memory: errno is set to ENOMEM
 * \li invalid parameters: errno is set to EINVAL
 * \li any other C library error, including socket errors while communicating
 * with ssh-agent: errno is left at the value set by the C library
  */
int agc_decrypt(const char *agent,
        const uint8_t *ciphertext, size_t ciphertext_size,
        uint8_t **cleartext, size_t *cleartext_size);

/**
 * Encrypt a file for later decryption by agc_fdecrypt()
 *
 * @param[in]  agent           The ssh-agent UNIX domain socket bind address.
 *                             If NULL the content of the SSH_AUTH_SOCK
 *                             environment variable is used instead.
 * @param[in]  key_sha256      Pointer to a string containing the SHA256
 *                             fingerprint of the SSH key to be used for
 *                             encryption. This can be obtained by running
 *                             the following command (openssh >= 6.8 required):
 *                             @verbatim ssh-add -E sha256 -l @endverbatim
 *                             The string may or may not begin with "SHA256:"
 *                             The first key whose fingerprint starts with the
 *                             string specified is selected. If NULL the first
 *                             key is chosen automatically. Only RSA and ED25519
 *                             keys are supported.
 * @param[in]  f_cleartext     Pointer to the input stream. Cleartext is
 *                             read from this stream.
 * @param[in]  f_ciphertext    Pointer to the output stream. Ciphertext is
 *                             written to this stream. Invalid data may have
 *                             already been written to the output stream when
 *                             an error is detected. Therefore it may be
 *                             advisable to use a temporary file for output
 *                             and delete it upon failure.
 *
 * @return 0 upon success, -1 otherwise. Reasons for failure include
 * \li the ssh key is not available: errno is set to ENOKEY
 * \li invalid data returned by ssh-agent: errno is set to EBADMSG
 * \li failure to allocate memory: errno is set to ENOMEM
 * \li invalid parameters: errno is set to EINVAL
 * \li any other C library error, including socket errors while communicating
 * with ssh-agent or file errors: errno is left at the value set by the C
 * library
 */
int agc_fencrypt(const char *agent, const char *key_sha256,
        FILE *f_cleartext, FILE *f_ciphertext);

/**
 * Decrypt a file encrypted by agc_fencrypt()
 *
 * @param[in]  agent           The ssh-agent UNIX domain socket bind address.
 *                             If NULL the content of the SSH_AUTH_SOCK
 *                             environment variable is used instead.
 * @param[in]  f_ciphertext    Pointer to the input stream. Ciphertext is
 *                             read from this stream.
 * @param[in]  f_cleartext     Pointer to the output stream. Cleartext is
 *                             written to this stream. Invalid data may have
 *                             already been written to the output stream when
 *                             an error is detected. Therefore it may be
 *                             advisable to use a temporary file for output
 *                             and delete it upon failure.
 *
 * @return 0 upon success, -1 otherwise. Reasons for failure include
 * \li the ssh key required to decrypt is not available: errno is set to ENOKEY
 * \li invalid data returned by ssh-agent or failure to decrypt: errno is set
 * to EBADMSG
 * \li failure to allocate memory: errno is set to ENOMEM
 * \li invalid parameters: errno is set to EINVAL
 * \li any other C library error, including socket errors while communicating
 * with ssh-agent or file errors: errno is left at the value set by the C
 * library
 */
int agc_fdecrypt(const char *agent, FILE *f_ciphertext, FILE *f_cleartext);

/**
 * Encode a block of data into a string (base64 format with no padding)
 *
 * @param[in]  in              Pointer to the data to be encoded.
 * @param[in]  in_size         Size of the data to be encoded.
 * @param[out] out             This function allocates the output data
 *                             buffer dynamically and it stores a pointer to it
 *                             into *out upon success. The buffer MUST be freed
 *                             by calling agc_free() after use. Do NOT use the
 *                             standard free() function.
 * @param[out] out_size        The size of the output buffer is stored into
 *                             *out_size upon success.
 *
 * @return 0 upon success, -1 otherwise.
 */
int agc_to_b64(const uint8_t *in, size_t in_size, char **out, size_t *out_size);

/**
 * Decode a string (base64 format with no padding) to a block of data
 *
 * @param[in]  in              Pointer to a NULL terminated input string
 * @param[out] out             This function allocates the output data
 *                             buffer dynamically and it stores a pointer to it
 *                             into *out upon success. The buffer MUST be freed
 *                             by calling agc_free() after use. Do NOT use the
 *                             standard free() function.
 * @param[out] out_size        The size of the output buffer is stored into
 *                             *out_size upon success.
 *
 * @return 0 upon success, -1 otherwise.
 */
int agc_from_b64(const char *in, uint8_t **out, size_t *out_size);

/**
 * Return the library version
 *
 * @return an integer encoding the library version as 0xMMmmuu00 (MM=major,
 * mm=minor, uu=micro)
 */
int agc_version(void);

/**
 * Dynamically allocate and lock a secure buffer
 *
 * @param[in]  size             Size of buffer
 *
 * @return pointer to buffer upon success, NULL otherwise. The buffer MUST be freed
 * by calling agc_free() after use. Do NOT use the standard free() function.
 */
void *agc_malloc(size_t size);

/**
 * Zero fill, unlock and free a dynamically allocated secure buffer
 *
 * @param[in]  buf              Pointer to buffer. If NULL no action is taken.
 * @param[in]  size             Size of buffer. It MUST match the buffer size
 */
void agc_free(void *buf, size_t size);

#ifdef __cplusplus
}
#endif

#endif
