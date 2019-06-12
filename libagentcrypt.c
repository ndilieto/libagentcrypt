/*
 * Copyright (c) 2019, Nicola Di Lieto <nicola.dilieto@gmail.com>
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
 */
#include <errno.h>
#include <fcntl.h>
#include <sodium.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "libagentcrypt.h"

typedef enum
{
    REQUEST_IDENTITIES              = 11,
    SIGN_REQUEST                    = 13,
    ADD_IDENTITY                    = 17,
    REMOVE_IDENTITY                 = 18,
    REMOVE_ALL_IDENTITIES           = 19,
    ADD_ID_CONSTRAINED              = 25,
    ADD_SMARTCARD_KEY               = 20,
    REMOVE_SMARTCARD_KEY            = 21,
    LOCK                            = 22,
    UNLOCK                          = 23,
    ADD_SMARTCARD_KEY_CONSTRAINED   = 26,
    EXTENSION                       = 27
} agent_cmd_t;

typedef enum
{
    FAILURE                         = 5,
    SUCCESS                         = 6,
    EXTENSION_FAILURE               = 28,
    IDENTITIES_ANSWER               = 12,
    SIGN_RESPONSE                   = 14
} agent_reply_t;

typedef enum
{
    RSA_SHA2_256                    = 2,
    RSA_SHA2_512                    = 4
} agent_flags_t;

typedef enum
{
    KT_UNSUPPORTED                  = -1,
    KT_RSA                          = 0,
    KT_ED25519                      = 1
} key_type_t;

typedef enum
{
    ST_UNSUPPORTED                  = -1,
    ST_RSA_SHA1                     = 0,
    ST_RSA_SHA2_256                 = 1,
    ST_RSA_SHA2_512                 = 2,
    ST_ED25519                      = 3,
} sig_type_t;

typedef struct
{
    uint32_t size;
    uint8_t *data;
} string_t;

void *agc_malloc(size_t size)
{
    if (sodium_init() < 0)
    {
        return NULL;
    }
    void *tmp = sodium_malloc(size);
    if (!tmp)
    {
        errno = ENOMEM;
    }
    else if (sodium_mlock(tmp, size) < 0)
    {
        sodium_free(tmp);
        tmp = NULL;
        errno = ENOMEM;
    }
    return tmp;
}

void agc_free(void *buf, size_t size)
{
    if (buf)
    {
        sodium_munlock(buf, size);
        sodium_free(buf);
    }
}

static string_t *string_alloc(const uint8_t *data, size_t size)
{
    string_t *str = agc_malloc(sizeof(string_t));
    if (!str)
    {
        return NULL;
    }

    if (size)
    {
        str->size = size;
        str->data = agc_malloc(size);
        if (!str->data)
        {
            agc_free(str, sizeof(string_t));
            errno = ENOMEM;
            return NULL;
        }
        if (data)
        {
            memcpy(str->data, data, size);
        }
    }
    else
    {
        str->size = 0;
        str->data = NULL;
    }
    return str;
}

static void string_free(string_t *str)
{
    if (str)
    {
        agc_free(str->data, str->size);
        agc_free(str, sizeof(string_t));
    }
}

static int string_get_uint32(const string_t *str, size_t *offset, uint32_t *u)
{
    if (*offset + 4 > str->size)
    {
        errno = EBADMSG;
        return -1;
    }
    *u = str->data[(*offset)++];
    *u <<= 8;
    *u += str->data[(*offset)++];
    *u <<= 8;
    *u += str->data[(*offset)++];
    *u <<= 8;
    *u += str->data[(*offset)++];
    return 4;
}

static int string_put_uint32(string_t *str, uint32_t u)
{
    uint8_t *tmp = agc_malloc(str->size + 4);
    if (!tmp)
    {
        return -1;
    }
    if (str->data)
    {
        memcpy(tmp, str->data, str->size);
        agc_free(str->data, str->size);
    }
    str->data = tmp;
    str->data[str->size++] = u >> 24;
    str->data[str->size++] = u >> 16;
    str->data[str->size++] = u >> 8;
    str->data[str->size++] = u;
    return 4;
}

static int string_put_uint8(string_t *str, uint8_t u)
{
    uint8_t *tmp = agc_malloc(str->size + 1);
    if (!tmp)
    {
        return -1;
    }
    if (str->data)
    {
        memcpy(tmp, str->data, str->size);
        agc_free(str->data, str->size);
    }
    str->data = tmp;
    str->data[str->size++] = u;
    return 1;
}

static int string_get_string(const string_t *str, size_t *offset,
        string_t **out)
{
    string_t *tmp;
    uint32_t size;
    size_t off = *offset;
    if (string_get_uint32(str, &off, &size) < 0)
    {
        return -1;
    }
    if (size > 0x8000000 || size + 4 > str->size)
    {
        errno = EBADMSG;
        return -1;
    }
    tmp = string_alloc(str->data + off, size);
    if (!tmp)
    {
        return -1;
    }
    *out = tmp;
    *offset = off + size;
    return size + 4;
}

static int string_put_string(string_t *str, string_t *add)
{
    uint8_t *tmp = agc_malloc(str->size + add->size + 4);
    if (!tmp)
    {
        return -1;
    }
    if (str->data)
    {
        memcpy(tmp, str->data, str->size);
        agc_free(str->data, str->size);
    }
    str->data = tmp;
    str->data[str->size++] = add->size >> 24;
    str->data[str->size++] = add->size >> 16;
    str->data[str->size++] = add->size >> 8;
    str->data[str->size++] = add->size;
    memcpy(str->data + str->size, add->data, add->size);
    str->size += add->size;
    return add->size + 4;
}

static int string_put_data(string_t *str, const uint8_t *data, size_t data_size)
{
    uint8_t *tmp = agc_malloc(str->size + data_size + 4);
    if (!tmp)
    {
        return -1;
    }
    if (str->data)
    {
        memcpy(tmp, str->data, str->size);
        agc_free(str->data, str->size);
    }
    str->data = tmp;
    str->data[str->size++] = data_size >> 24;
    str->data[str->size++] = data_size >> 16;
    str->data[str->size++] = data_size >> 8;
    str->data[str->size++] = data_size;
    memcpy(str->data + str->size, data, data_size);
    str->size += data_size;
    return data_size + 4;
}

static int sock_open(const char *path)
{
    int fd;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (!path || strlen(path) == 0)
    {
        path = getenv("SSH_AUTH_SOCK");
        if (!path)
        {
            errno = EINVAL;
            return -1;
        }
    }
    strncpy(addr.sun_path, path, sizeof(addr.sun_path)-1);
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
    {
        return -1;
    }
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0 ||
            connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        int errno_save = errno;
        close(fd);
        errno = errno_save;
        return -1;
    }
    return fd;
}

static key_type_t key_type(const string_t *key_blob)
{
    key_type_t ret = KT_UNSUPPORTED;
    size_t offset = 0;
    string_t *type = NULL;
    if (string_get_string(key_blob, &offset, &type) < 0)
    {
        goto done;
    }
    if (strncmp("ssh-rsa", (char *)type->data, type->size) == 0)
    {
        ret = KT_RSA;
    }
    if (strncmp("ssh-ed25519", (char *)type->data, type->size) == 0)
    {
        ret = KT_ED25519;
    }
done:
    string_free(type);
    return ret;
}

static sig_type_t sig_type(const string_t *sig)
{
    sig_type_t ret = ST_UNSUPPORTED;
    size_t offset = 0;
    string_t *type = NULL;
    if (string_get_string(sig, &offset, &type) < 0)
    {
        goto done;
    }
    if (strncmp("ssh-rsa", (char *)type->data, type->size) == 0)
    {
        ret = ST_RSA_SHA1;
    }
    if (strncmp("rsa-sha2-256", (char *)type->data, type->size) == 0)
    {
        ret = ST_RSA_SHA2_256;
    }
    if (strncmp("rsa-sha2-512", (char *)type->data, type->size) == 0)
    {
        ret = ST_RSA_SHA2_512;
    }
    if (strncmp("ssh-ed25519", (char *)type->data, type->size) == 0)
    {
        ret = ST_ED25519;
    }
done:
    string_free(type);
    return ret;
}

static void key_hash(string_t *key,
        const uint8_t nonce[crypto_secretbox_NONCEBYTES],
        uint8_t hash[crypto_generichash_BYTES])
{
    crypto_generichash_state st;
    crypto_generichash_init(&st, NULL, 0, crypto_generichash_BYTES);
    crypto_generichash_update(&st, nonce, crypto_secretbox_NONCEBYTES);
    crypto_generichash_update(&st, key->data, key->size);
    crypto_generichash_final(&st, hash, crypto_generichash_BYTES);
}

static int agent_cmd(int fd, const string_t *cmd, string_t **reply)
{
    ssize_t n = -1;
    fd_set rfds;
    struct timeval tv = {.tv_sec = 10, .tv_usec = 0};
    size_t buf_size = 0;
    size_t sig_size = 0;
    uint8_t *buf = NULL;
    uint8_t cmd_size[4] =
    {
        (cmd->size >> 24),
        (cmd->size >> 16),
        (cmd->size >> 8),
        (cmd->size)
    };

    if (write(fd, cmd_size, sizeof(cmd_size)) != sizeof(cmd_size) ||
            write(fd, cmd->data, cmd->size) != cmd->size)
    {
        return -1;
    }

    while (1)
    {
        uint8_t *tmp;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        if (select(fd+1, &rfds, NULL, NULL, &tv) <= 0)
        {
            break;
        }
        tmp = agc_malloc(buf_size + 0x100);
        if (!tmp)
        {
            agc_free(buf, buf_size);
            errno = ENOMEM;
            return -1;
        }
        if (buf)
        {
            memcpy(tmp, buf, buf_size);
        }
        agc_free(buf, buf_size);
        buf = tmp;
        buf_size += 0x100;
        n = read(fd, buf + sig_size, 0x100);
        if (n < 0)
        {
            agc_free(buf, buf_size);
            return -1;
        }
        sig_size += n;
        if (n < 0x100)
        {
            break;
        }
        tv.tv_sec = 0;
        tv.tv_usec = 1000;
    }
    if (buf)
    {
        string_t *tmp = string_alloc(buf, sig_size);
        agc_free(buf, buf_size);
        if (tmp)
        {
            uint32_t size;
            size_t offset = 0;
            if (string_get_uint32(tmp, &offset, &size) < 0)
            {
                string_free(tmp);
                return -1;
            }
            if (size + 4 != sig_size)
            {
                string_free(tmp);
                errno = EBADMSG;
                return -1;
            }
            *reply = tmp;
            return sig_size;
        }
    }
    else
    {
        string_t *tmp = string_alloc(NULL, 0);
        if (tmp)
        {
            *reply = tmp;
            return 0;
        }
    }
    return -1;
}

static int agent_find_key_sha256(int fd, const char *key_sha256,
        string_t **key_blob)
{
    int ret = -1;
    int errno_save;
    uint32_t nkeys;
    size_t offset = 4;
    string_t *cmd = NULL;
    string_t *reply = NULL;
    uint8_t *hash = NULL;

    if (key_sha256 && strncasecmp(key_sha256, "SHA256:", 7) == 0)
    {
        key_sha256 += 7;
    }

    cmd = string_alloc(NULL, 0);
    if (!cmd)
    {
        goto done;
    }
    if (string_put_uint8(cmd, REQUEST_IDENTITIES) < 0)
    {
        goto done;
    }
    if (agent_cmd(fd, cmd, &reply) < 5)
    {
        errno = EBADMSG;
        goto done;
    }
    if (reply->data[offset++] != IDENTITIES_ANSWER)
    {
        errno = EBADMSG;
        goto done;
    }
    if (string_get_uint32(reply, &offset, &nkeys) < 0)
    {
        goto done;
    }

    while (nkeys--)
    {
        string_t *tmp = NULL;
        if (string_get_string(reply, &offset, &tmp) < 0)
        {
            goto done;
        }
        if (key_type(tmp) != KT_UNSUPPORTED)
        {
            uint8_t h[crypto_hash_sha256_BYTES];
            char h64[sodium_base64_ENCODED_LEN(sizeof(h),
                    sodium_base64_VARIANT_ORIGINAL_NO_PADDING)];
            crypto_hash_sha256(h, tmp->data, tmp->size);
            sodium_bin2base64(h64, sizeof(h64), h, sizeof(h),
                sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
            if (!key_sha256 || !strncmp(h64, key_sha256, strlen(key_sha256)))
            {
                *key_blob = tmp;
                ret = 0;
                goto done;
            }
        }
        string_free(tmp);
        if (string_get_string(reply, &offset, &tmp) < 0)
        {
            goto done;
        }
        string_free(tmp);
    }
done:
    errno_save = errno;
    agc_free(hash, crypto_hash_sha256_BYTES);
    string_free(cmd);
    string_free(reply);
    errno = errno_save;
    return ret;
}

static int agent_find_key(int fd,
        const uint8_t nonce[crypto_secretbox_NONCEBYTES],
        const uint8_t hash[crypto_generichash_BYTES],
        string_t **key_blob)
{
    int ret = -1;
    int errno_save;
    uint32_t nkeys;
    size_t offset = 4;
    string_t *cmd = string_alloc(NULL, 0);
    string_t *reply = NULL;
    if (!cmd)
    {
        goto done;
    }
    if (string_put_uint8(cmd, REQUEST_IDENTITIES) < 0)
    {
        goto done;
    }
    if (agent_cmd(fd, cmd, &reply) < 5)
    {
        errno = EBADMSG;
        goto done;
    }
    if (reply->data[offset++] != IDENTITIES_ANSWER)
    {
        errno = EBADMSG;
        goto done;
    }
    if (string_get_uint32(reply, &offset, &nkeys) < 0)
    {
        goto done;
    }
    while (nkeys--)
    {
        uint8_t h[crypto_generichash_BYTES];
        string_t *tmp = NULL;
        if (string_get_string(reply, &offset, &tmp) < 0)
        {
            goto done;
        }
        if (key_type(tmp) != KT_UNSUPPORTED)
        {
            key_hash(tmp, nonce, h);
            if (!hash || !sodium_memcmp(hash, h, sizeof(h)))
            {
                *key_blob = tmp;
                ret = 0;
                goto done;
            }
        }
        string_free(tmp);
        if (string_get_string(reply, &offset, &tmp) < 0)
        {
            goto done;
        }
        string_free(tmp);
    }
done:
    errno_save = errno;
    string_free(cmd);
    string_free(reply);
    errno = errno_save;
    return ret;
}

static int agent_sign(int fd, string_t *key_blob, const uint8_t *data,
        size_t data_size, bool *legacy,
        uint8_t key[crypto_secretbox_KEYBYTES])
{
    int errno_save;
    int ret = -1;
    size_t offset = 4;
    string_t *reply = NULL;
    string_t *sig = NULL;
    string_t *cmd = NULL;
    uint32_t flags = 0;

    switch (key_type(key_blob))
    {
        case KT_UNSUPPORTED:
            errno = ENOKEY;
            goto done;

        case KT_RSA:
            if (!legacy || !*legacy)
            {
                flags = RSA_SHA2_256;
            }
            break;

        default:
            break;
    }

    cmd = string_alloc(NULL, 0);
    if (!cmd)
    {
        goto done;
    }
    if (string_put_uint8(cmd, SIGN_REQUEST) < 0)
    {
        goto done;
    }
    if (string_put_string(cmd, key_blob) < 0)
    {
        goto done;
    }
    if (string_put_data(cmd, data, data_size) < 0)
    {
        goto done;
    }
    if (string_put_uint32(cmd, flags) < 0)
    {
        goto done;
    }
    if (agent_cmd(fd, cmd, &reply) < 5)
    {
        errno = EBADMSG;
        goto done;
    }
    if (reply->data[offset++] != SIGN_RESPONSE)
    {
        errno = EBADMSG;
        goto done;
    }
    if (string_get_string(reply, &offset, &sig) <= 0)
    {
        goto done;
    }
    if (legacy && flags == RSA_SHA2_256 && sig_type(sig) != ST_RSA_SHA2_256)
    {
        *legacy = true;
    }
    sodium_memzero(reply->data, reply->size);
    crypto_generichash(key, crypto_secretbox_KEYBYTES, sig->data, sig->size,
            NULL, 0);
    sodium_memzero(sig->data, sig->size);
    ret = 0;
done:
    errno_save = errno;
    string_free(cmd);
    string_free(reply);
    string_free(sig);
    errno = errno_save;
    return ret;
}

int agc_encrypt(const char *agent, const char *key_sha256,
        const uint8_t *cleartext, size_t cleartext_size, size_t pad_size,
        uint8_t **ciphertext, size_t *ciphertext_size)
{
    int errno_save;
    int ret = -1;
    int fd = -1;
    string_t *key_blob = NULL;
    uint8_t *key = NULL;
    uint8_t *buf = NULL;
    uint8_t *pad_buf = NULL;
    size_t buf_size = 0;
    size_t pad_buf_size = 0;

    if (!cleartext || cleartext_size > 0x80000000 || pad_size > 0x80000000 ||
            !ciphertext || !ciphertext_size)
    {
        errno = EINVAL;
        return -1;
    }

    if (sodium_init() < 0)
    {
        goto done;
    }

    fd = sock_open(agent);
    if (fd < 0)
    {
        goto done;
    }

    if (agent_find_key_sha256(fd, key_sha256, &key_blob) < 0)
    {
        errno = ENOKEY;
        goto done;
    }

    if (pad_size < 0x10)
    {
        pad_size = 0x10;
    }
    pad_buf_size = pad_size - cleartext_size % pad_size;
    if (cleartext_size < pad_size)
    {
        pad_buf_size = pad_size;
    }
    else if (pad_buf_size == pad_size)
    {
        pad_buf_size = cleartext_size;
    }
    else
    {
        pad_buf_size += cleartext_size;
    }
    pad_buf_size += 4;
    pad_buf = agc_malloc(pad_buf_size);
    if (!pad_buf)
    {
        goto done;
    }
    memcpy(pad_buf, cleartext, cleartext_size);
    randombytes_buf(pad_buf + cleartext_size, pad_buf_size -4 - cleartext_size);
    pad_buf[pad_buf_size - 4] = cleartext_size >> 24;
    pad_buf[pad_buf_size - 3] = cleartext_size >> 16;
    pad_buf[pad_buf_size - 2] = cleartext_size >> 8;
    pad_buf[pad_buf_size - 1] = cleartext_size;

    buf_size = crypto_secretbox_NONCEBYTES + crypto_generichash_BYTES +
        crypto_secretbox_MACBYTES + pad_buf_size;
    buf = agc_malloc(buf_size);
    if (!buf)
    {
        goto done;
    }
    uint8_t *nonce = buf;
    uint8_t *hash = nonce + crypto_secretbox_NONCEBYTES;
    uint8_t *data = hash + crypto_generichash_BYTES;

    uint8_t *rnd = agc_malloc(crypto_generichash_KEYBYTES);
    if (!rnd)
    {
        goto done;
    }
    randombytes_buf(rnd, crypto_generichash_KEYBYTES);
    crypto_generichash(nonce, crypto_secretbox_NONCEBYTES,
            pad_buf, pad_buf_size, rnd, crypto_generichash_KEYBYTES);
    agc_free(rnd, crypto_generichash_KEYBYTES);

    key_hash(key_blob, nonce, hash);

    key = agc_malloc(crypto_secretbox_KEYBYTES);
    if (!key)
    {
        goto done;
    }
    if (agent_sign(fd, key_blob, nonce, data - nonce, NULL, key) < 0)
    {
        goto done;
    }
    crypto_secretbox_easy(data, pad_buf, pad_buf_size, nonce, key);
    sodium_memzero(key, crypto_secretbox_KEYBYTES);
    *ciphertext_size = buf_size;
    *ciphertext = buf;
    buf = NULL;
    ret = 0;
done:
    errno_save = errno;
    string_free(key_blob);
    agc_free(key, crypto_secretbox_KEYBYTES);
    agc_free(buf, buf_size);
    agc_free(pad_buf, pad_buf_size);
    if (fd >= 0)
    {
        close(fd);
    }
    errno = errno_save;
    return ret;
}

int agc_decrypt(const char *agent,
        const uint8_t *ciphertext, size_t ciphertext_size,
        uint8_t **cleartext, size_t *cleartext_size)
{
    int errno_save;
    int ret = -1;
    int fd = -1;
    string_t *key_blob = NULL;
    uint8_t *key = NULL;
    uint8_t *buf = NULL;
    size_t buf_size = ciphertext_size - crypto_secretbox_NONCEBYTES
        - crypto_hash_sha256_BYTES - crypto_secretbox_MACBYTES;

    if (sodium_init() < 0)
    {
        goto done;
    }

    fd = sock_open(agent);
    if (fd < 0)
    {
        goto done;
    }

    if (ciphertext_size < crypto_secretbox_NONCEBYTES
            + crypto_generichash_BYTES + crypto_secretbox_MACBYTES)
    {
        errno = EBADMSG;
        goto done;
    }
    const uint8_t *nonce = ciphertext;
    const uint8_t *hash = nonce + crypto_secretbox_NONCEBYTES;
    const uint8_t *data = hash + crypto_generichash_BYTES;
    key = agc_malloc(crypto_secretbox_KEYBYTES);
    if (!key)
    {
        goto done;
    }
    if (agent_find_key(fd, nonce, hash, &key_blob) < 0)
    {
        errno = ENOKEY;
        goto done;
    }
    buf = agc_malloc(buf_size);
    if (!buf)
    {
        goto done;
    }
    bool legacy = false;
    while (1)
    {
        if (agent_sign(fd, key_blob, nonce, data - nonce, &legacy, key) < 0)
        {
            goto done;
        }
        if (crypto_secretbox_open_easy(buf, data,
                buf_size + crypto_secretbox_MACBYTES, nonce, key) == 0)
        {
            break;
        }
        if (legacy)
        {
            errno = EBADMSG;
            goto done;
        }
        legacy = true;
    }
    size_t decoded_size = buf[buf_size - 4];
    decoded_size <<= 8;
    decoded_size += buf[buf_size - 3];
    decoded_size <<= 8;
    decoded_size += buf[buf_size - 2];
    decoded_size <<= 8;
    decoded_size += buf[buf_size - 1];
    if (decoded_size >= buf_size)
    {
        errno = EBADMSG;
        goto done;
    }
    *cleartext = buf;
    buf = NULL;
    *cleartext_size = decoded_size;
    ret = 0;
done:
    errno_save = errno;
    string_free(key_blob);
    agc_free(key, crypto_secretbox_KEYBYTES);
    agc_free(buf, buf_size);
    if (fd >= 0)
    {
        close(fd);
    }
    errno = errno_save;
    return ret;
}

int agc_to_b64(const uint8_t *in, size_t in_size, char **out, size_t *out_size)
{
    if (sodium_init() < 0)
    {
        return -1;
    }
    size_t size = sodium_base64_ENCODED_LEN(in_size,
            sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
    char *buf = agc_malloc(size);
    if (!buf)
    {
        return -1;
    }
    if (!sodium_bin2base64(buf, size, in, in_size,
                sodium_base64_VARIANT_ORIGINAL_NO_PADDING))
    {
        agc_free(buf, size);
        errno = EBADMSG;
        return -1;
    }
    *out = buf;
    *out_size = size;
    return 0;
}

int agc_from_b64(const char *in, uint8_t **out, size_t *out_size)
{
    if (sodium_init() < 0)
    {
        return -1;
    }
    const char *end;
    size_t size;
    size_t buf_size = strlen(in);
    uint8_t *buf = agc_malloc(buf_size);
    if (!buf)
    {
        return -1;
    }
    if (sodium_base642bin(buf, buf_size, in, buf_size, " \t\r\n",
                &size, &end, sodium_base64_VARIANT_ORIGINAL_NO_PADDING)
            || !end || *end)
    {
        agc_free(buf, buf_size);
        errno = EBADMSG;
        return -1;
    }
    uint8_t *tmp = agc_malloc(size);
    if (!tmp)
    {
        agc_free(buf, buf_size);
        errno = ENOMEM;
        return -1;
    }
    memcpy(tmp, buf, size);
    *out = tmp;
    *out_size = size;
    agc_free(buf, buf_size);
    return 0;
}

static const size_t chunk_size = 4096;

int agc_fencrypt(const char *agent, const char *key_sha256,
        FILE *f_cleartext, FILE *f_ciphertext)
{
    uint8_t *key = NULL;
    const size_t key_size = crypto_secretstream_xchacha20poly1305_KEYBYTES;
    uint8_t buf_in[chunk_size];
    uint8_t buf_out[chunk_size + crypto_secretstream_xchacha20poly1305_ABYTES];
    uint8_t header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state state;
    uint8_t *ekey = NULL;
    size_t ekey_size = 0;
    int rc = -1;

    if (sodium_init() < 0)
    {
        goto done;
    }

    key = agc_malloc(key_size);
    if (!key)
    {
        goto done;
    }
    randombytes_buf(key, key_size);
    if (agc_encrypt(agent, key_sha256, key, key_size, 0, &ekey, &ekey_size) < 0)
    {
        goto done;
    }

    buf_out[0] = 0x41;
    buf_out[1] = 0x43;
    buf_out[2] = 0x42;
    buf_out[3] = 0x00;
    buf_out[4] = ekey_size >> 8;
    buf_out[5] = ekey_size;
    crypto_generichash(buf_out + 6, crypto_generichash_BYTES, buf_out, 6,
            NULL, 0);
    if (fwrite(buf_out, 1, 6 + crypto_generichash_BYTES, f_ciphertext) !=
            6 + crypto_generichash_BYTES)
    {
        goto done;
    }
    if (fwrite(ekey, 1, ekey_size, f_ciphertext) != ekey_size)
    {
        goto done;
    }
    crypto_secretstream_xchacha20poly1305_init_push(&state, header, key);
    sodium_memzero(key, key_size);
    if (fwrite(header, 1, sizeof(header), f_ciphertext) != sizeof(header))
    {
        goto done;
    }
    while (1)
    {
        unsigned long long out_len;
        uint8_t tag = 0;
        size_t nread = fread(buf_in, 1, sizeof(buf_in), f_cleartext);
        if (ferror(f_cleartext))
        {
            goto done;
        }
        if (feof(f_cleartext))
        {
            tag = crypto_secretstream_xchacha20poly1305_TAG_FINAL;
        }
        crypto_secretstream_xchacha20poly1305_push(&state, buf_out, &out_len,
                buf_in, nread, NULL, 0, tag);
        if (fwrite(buf_out, 1, (size_t)out_len, f_ciphertext) != out_len)
        {
            goto done;
        }
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL)
        {
            rc = 0;
            break;
        }
    }
done:
    agc_free(key, key_size);
    agc_free(ekey, ekey_size);
    sodium_memzero(&state, sizeof(state));
    return rc;
}

int agc_fdecrypt(const char *agent, FILE *f_ciphertext, FILE *f_cleartext)
{
    uint8_t buf_in[chunk_size + crypto_secretstream_xchacha20poly1305_ABYTES];
    uint8_t buf_out[chunk_size];
    uint8_t header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state state;
    uint8_t *key = NULL;
    size_t key_size = 0;
    size_t size = 0;
    size_t nread = 0;
    int rc = -1;

    if (sodium_init() < 0)
    {
        goto done;
    }

    nread = fread(buf_in, 1, 6 + crypto_generichash_BYTES, f_ciphertext);
    if (nread != 6 + crypto_generichash_BYTES)
    {
        if (!ferror(f_ciphertext))
        {
            errno = EBADMSG;
        }
        goto done;
    }
    crypto_generichash(buf_out, crypto_generichash_BYTES, buf_in, 6, NULL, 0);
    if (sodium_memcmp(buf_out, buf_in + 6, crypto_generichash_BYTES) != 0)
    {
        errno = EBADMSG;
        goto done;
    }
    if (buf_in[0] != 0x41 || buf_in[1] != 0x43
            || buf_in[2] != 0x42 || buf_in[3] != 0)
    {
        errno = EBADMSG;
        goto done;
    }
    size = buf_in[4];
    size <<= 8;
    size += buf_in[5];
    if (size > sizeof(buf_in))
    {
        errno = EBADMSG;
    }
    nread = fread(buf_in, 1, size, f_ciphertext);
    if (nread < size)
    {
        if (!ferror(f_ciphertext))
        {
            errno = EBADMSG;
        }
        goto done;
    }

    if (agc_decrypt(agent, buf_in, size, &key, &key_size) < 0)
    {
        goto done;
    }

    if (key_size != crypto_secretstream_xchacha20poly1305_KEYBYTES)
    {
        errno = EBADMSG;
        goto done;
    }

    nread = fread(header, 1, sizeof(header), f_ciphertext);
    if (nread != sizeof(header))
    {
        if (!ferror(f_ciphertext))
        {
            errno = EBADMSG;
        }
        goto done;
    }

    if (crypto_secretstream_xchacha20poly1305_init_pull(&state, header,
                key) != 0)
    {
        errno = EBADMSG;
        goto done;
    }
    sodium_memzero(key, key_size);
    while (1)
    {
        unsigned long long out_len;
        uint8_t tag = 0;
        nread = fread(buf_in, 1, sizeof(buf_in), f_ciphertext);
        if (ferror(f_ciphertext))
        {
            goto done;
        }
        if (crypto_secretstream_xchacha20poly1305_pull(&state, buf_out,
                    &out_len, &tag, buf_in, nread, NULL, 0) != 0)
        {
            errno = EBADMSG;
            goto done;
        }
        if (fwrite(buf_out, 1, (size_t)out_len, f_cleartext) != out_len)
        {
            goto done;
        }
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL)
        {
            if (feof(f_ciphertext))
            {
                rc = 0;
                break;
            }
            else
            {
                errno = EMSGSIZE;
                goto done;
            }
        }
    }
done:
    agc_free(key, key_size);
    sodium_memzero(&state, sizeof(state));
    return rc;
}

int agc_version(void)
{
    int version = 0;
    unsigned char major, minor, micro;
    if (sscanf(PACKAGE_VERSION, "%hhu.%hhu.%hhu", &major, &minor, &micro) != 3)
    {
        fprintf(stderr, "Failed to determine libagentcrypt version\n");
        abort();
    }
    version += major;
    version <<= 8;
    version += minor;
    version <<= 8;
    version += micro;
    version <<= 8;
    return version;
}
