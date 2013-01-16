/*-
 * Copyright (C) 2010, Romain Tartiere.
 * 
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 * 
 * $Id$
 */

#include <stdlib.h>
#include <string.h>

#include <freefare.h>
#include "freefare_internal.h"

void crypto_getScheduledKeys(MifareDESFireKey const key, MifareCryptoOperation operation, ScheduledKeyContext* result)
{
    result->operation = operation;
    result->type = key->type;
#ifdef USE_POLARSSL
    if (operation == MCO_ENCYPHER)
    {
        switch (key->type)
        {
        case T_DES:     des_setkey_enc(&result->Key.des, key->data);       break;
        case T_3DES:    des3_set2key_enc(&result->Key.des3, key->data);    break;
        case T_3K3DES:  des3_set3key_enc(&result->Key.des3k3, key->data);  break;
        case T_AES:     aes_setkey_enc(&result->Key.aes, key->data, 128);  break;
        default:
            break;
        }
    }
    else if (operation == MCO_DECYPHER)
    {
        switch (key->type)
        {
        case T_DES:     des_setkey_dec(&result->Key.des, key->data);       break;
        case T_3DES:    des3_set2key_dec(&result->Key.des3, key->data);    break;
        case T_3K3DES:  des3_set3key_dec(&result->Key.des3k3, key->data);  break;
        case T_AES:     aes_setkey_dec(&result->Key.aes, key->data, 128);        break;
        default:
            break;
        }
    }
#else
    if (key->type == T_AES)
    {
        if (operation == MCO_ENCYPHER)
            AES_set_encrypt_key (key->data, 8*16, &result->Key.aes);
        else if (operation == MCO_DECYPHER)
            AES_set_decrypt_key (key->data, 8*16, &result->Key.aes);
    }
    else // DES/3DES/3K3DES
    {
        DES_set_key((DES_cblock *)key->data, &result->Key.Des.ks1);
        DES_set_key ((DES_cblock *)(key->data + 8), &result->Key.Des.ks2);
        if (T_3K3DES == key->type)
        {
            DES_set_key ((DES_cblock *)(key->data + 16), &result->Key.Des.ks3);
        }
    }
#endif
}

MifareDESFireKey
mifare_desfire_des_key_new (uint8_t value[8])
{
    uint8_t data[8];
    memcpy (data, value, 8);
    for (int n=0; n < 8; n++)
	data[n] &= 0xfe;
    return mifare_desfire_des_key_new_with_version (data);
}

MifareDESFireKey
mifare_desfire_des_key_new_with_version (uint8_t value[8])
{
    MifareDESFireKey key;

    if ((key = malloc (sizeof (struct mifare_desfire_key)))) {
	key->type = T_DES;
	memcpy (key->data, value, 8);
    memcpy (key->data+8, value, 8);
    }
    return key;
}

MifareDESFireKey
mifare_desfire_3des_key_new (uint8_t value[16])
{
    uint8_t data[16];
    memcpy (data, value, 16);
    for (int n=0; n < 8; n++)
	data[n] &= 0xfe;
    for (int n=8; n < 16; n++)
	data[n] |= 0x01;
    return mifare_desfire_3des_key_new_with_version (data);
}

MifareDESFireKey
mifare_desfire_3des_key_new_with_version (uint8_t value[16])
{
    MifareDESFireKey key;

    if ((key = malloc (sizeof (struct mifare_desfire_key)))) {
	key->type = T_3DES;
	memcpy (key->data, value, 16);
    }
    return key;
}

MifareDESFireKey
mifare_desfire_3k3des_key_new (uint8_t value[24])
{
    uint8_t data[24];
    memcpy (data, value, 24);
    for (int n=0; n < 8; n++)
	data[n] &= 0xfe;
    return mifare_desfire_3k3des_key_new_with_version (data);
}

MifareDESFireKey
mifare_desfire_3k3des_key_new_with_version (uint8_t value[24])
{
    MifareDESFireKey key;

    if ((key = malloc (sizeof (struct mifare_desfire_key)))) {
	key->type = T_3K3DES;
	memcpy (key->data, value, 24);
    }
    return key;
}

MifareDESFireKey
mifare_desfire_aes_key_new (uint8_t value[16])
{
    return mifare_desfire_aes_key_new_with_version (value, 0);
}

MifareDESFireKey
mifare_desfire_aes_key_new_with_version (uint8_t value[16], uint8_t version)
{
    MifareDESFireKey key;

    if ((key = malloc (sizeof (struct mifare_desfire_key)))) {
	memcpy (key->data, value, 16);
	key->type = T_AES;
	key->aes_version = version;
    }
    return key;
}

uint8_t
mifare_desfire_key_get_version (MifareDESFireKey key)
{
    uint8_t version = 0;

    for (int n = 0; n < 8; n++) {
	version |= ((key->data[n] & 1) << (7 - n));
    }

    return version;
}

void
mifare_desfire_key_set_version (MifareDESFireKey key, uint8_t version)
{
    for (int n = 0; n < 8; n++) {
	uint8_t version_bit = ((version & (1 << (7-n))) >> (7-n));
	key->data[n] &= 0xfe;
	key->data[n] |= version_bit;
	if (key->type == T_DES) {
	    key->data[n+8] = key->data[n];
	} else {
	    // Write ~version to avoid turning a 3DES key into a DES key
	    key->data[n+8] &= 0xfe;
	    key->data[n+8] |= ~version_bit;
	}
    }
}

MifareDESFireKey
mifare_desfire_session_key_new (uint8_t rnda[8], uint8_t rndb[8], MifareDESFireKey authentication_key)
{
    MifareDESFireKey key = NULL;

    uint8_t buffer[24];

    switch (authentication_key->type) {
    case T_DES:
	memcpy (buffer, rnda, 4);
	memcpy (buffer+4, rndb, 4);
	key = mifare_desfire_des_key_new_with_version (buffer);
	break;
    case T_3DES:
	memcpy (buffer, rnda, 4);
	memcpy (buffer+4, rndb, 4);
	memcpy (buffer+8, rnda+4, 4);
	memcpy (buffer+12, rndb+4, 4);
	key = mifare_desfire_3des_key_new_with_version (buffer);
	break;
    case T_3K3DES:
	memcpy (buffer, rnda, 4);
	memcpy (buffer+4, rndb, 4);
	memcpy (buffer+8, rnda+6, 4);
	memcpy (buffer+12, rndb+6, 4);
	memcpy (buffer+16, rnda+12, 4);
	memcpy (buffer+20, rndb+12, 4);
	key = mifare_desfire_3k3des_key_new (buffer);
	break;
    case T_AES:
	memcpy (buffer, rnda, 4);
	memcpy (buffer+4, rndb, 4);
	memcpy (buffer+8, rnda+12, 4);
	memcpy (buffer+12, rndb+12, 4);
	key = mifare_desfire_aes_key_new (buffer);
	break;
    }

    return key;
}

void
mifare_desfire_key_free (MifareDESFireKey key)
{
    free (key);
}
