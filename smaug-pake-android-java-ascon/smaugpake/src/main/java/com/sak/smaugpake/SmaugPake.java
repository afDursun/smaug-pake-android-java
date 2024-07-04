package com.sak.smaugpake;

import static com.sak.smaugpake.SmaugKEM.AUTH_SIZE;
import static com.sak.smaugpake.SmaugKEM.CIPHERTEXT_BYTES;
import static com.sak.smaugpake.SmaugKEM.CRYPTO_BYTES;
import static com.sak.smaugpake.SmaugKEM.ID_BYTES;
import static com.sak.smaugpake.SmaugKEM.KEM_SECRETKEY_BYTES;
import static com.sak.smaugpake.SmaugKEM.PAKE_A0_SEND;
import static com.sak.smaugpake.SmaugKEM.PUBLICKEY_BYTES;
import static com.sak.smaugpake.SmaugKEM.PW_BYTES;
import static com.sak.smaugpake.SmaugKEM.SHA3_256_HashSize;

import android.util.Log;
import android.widget.Toast;

import com.github.aelstad.keccakj.fips202.SHA3_256;
import com.sak.smaugpake.Model.Encapsulation;
import com.sak.smaugpake.Model.PakeA0;
import com.sak.smaugpake.Model.PakeB0;
import com.sak.smaugpake.ascon128v12.Ascon128v12;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class SmaugPake {
    private static byte[] encryptData(byte[] key, byte[] data, int length) {
        try {
            Key aesKey = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey);
            return cipher.doFinal(data, 0, length);
        } catch (Exception e) {
            Log.d("AFD-AFD",e.toString() );
            return null;
        }
    }

    private static byte[] decryptData(byte[] key, byte[] data, int length) {
        try {
            Key aesKey = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, aesKey);
            return cipher.doFinal(data, 0, length);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public PakeA0 a0(byte[] pw, byte[] ssid, SmaugKEM smaugKEM) {

        byte[] pk = new byte[PUBLICKEY_BYTES];
        byte[] sk = new byte[KEM_SECRETKEY_BYTES];

        //final byte[] key = "my_128_bit_key_a".getBytes(StandardCharsets.UTF_8);
        byte[] components = new byte[PAKE_A0_SEND];

        com.sak.smaugpake.Model.Key keypair = smaugKEM.keygen();
        pk = keypair.getPk();
        sk = keypair.getSk();

        byte[] components_part1 = new byte[ID_BYTES];
        byte[] components_part2 = new byte[PW_BYTES];
        byte[] components_part3 = new byte[PUBLICKEY_BYTES];


        System.arraycopy(ssid, 0, components_part1, 0, ID_BYTES);
        System.arraycopy(pw, 0, components_part2, 0, PW_BYTES);
        System.arraycopy(pk, 0, components_part3, 0, PUBLICKEY_BYTES);

        System.arraycopy(components_part1, 0, components, 0, components_part1.length);
        System.arraycopy(components_part2, 0, components, components_part1.length, components_part2.length);
        System.arraycopy(components_part3, 0, components, components_part1.length + components_part2.length, components_part3.length);

        byte[] n = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        byte[] key = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        byte[] a = {0x41, 0x53, 0x43, 0x4f, 0x4e};
        byte[] encrypted_components = new byte[components.length + Ascon128v12.CRYPTO_ABYTES];
        int alen = a.length;

         Ascon128v12.crypto_aead_encrypt(encrypted_components, encrypted_components.length, components, PAKE_A0_SEND, a, alen, null, n, key);


        return new PakeA0(pk,sk,encrypted_components);
    }

    public PakeB0 b0(byte[] pw, byte[] ssid, byte[] aId, byte[] bId, byte[] epk, byte[] send_b0, SmaugKEM smaugKEM) {
        byte[] pk = new byte[PUBLICKEY_BYTES];
        byte[] components = new byte[epk.length];
        byte[] auth_b = new byte[AUTH_SIZE];
        byte[] ct = new byte[CIPHERTEXT_BYTES];
        byte[] k = new byte[CRYPTO_BYTES];
        System.arraycopy(epk, 0, components, 0, PAKE_A0_SEND);

        byte[] n = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        byte[] key = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        byte[] a = {0x41, 0x53, 0x43, 0x4f, 0x4e};
        int alen = a.length;

        Ascon128v12.crypto_aead_decrypt(components, components.length, null, epk, epk.length, a, alen, n, key);

        for (int i = 0; i < PUBLICKEY_BYTES; i++) {
            pk[i] = components[ID_BYTES + PW_BYTES + i];
        }


        Encapsulation enc = smaugKEM.encapsulation(pk);
        ct = enc.getCt();
        k = enc.getSsk();

        for (int i = 0; i < ID_BYTES; i++) {
            auth_b[i] = ssid[i];
        }

        for (int i = 0; i < ID_BYTES; i++) {
            auth_b[i + ID_BYTES] = aId[i];
        }

        for (int i = 0; i < ID_BYTES; i++) {
            auth_b[i + ID_BYTES * 2] = bId[i];
        }

        for (int i = 0; i < PW_BYTES; i++) {
            auth_b[i + ID_BYTES * 3] = pw[i];
        }

        for (int i = 0; i < PAKE_A0_SEND; i++) {
            auth_b[i + ID_BYTES * 3 + PW_BYTES] = epk[i];
        }

        for (int i = 0; i < CIPHERTEXT_BYTES; i++) {
            auth_b[i + ID_BYTES * 3 + PW_BYTES + PAKE_A0_SEND] = ct[i];
        }

        for (int i = 0; i < CRYPTO_BYTES; i++) {
            auth_b[i + ID_BYTES * 3 + PW_BYTES + PAKE_A0_SEND + CIPHERTEXT_BYTES] = k[i];
        }

        MessageDigest md = new SHA3_256();
        send_b0 = md.digest(auth_b);

        return new PakeB0( auth_b, send_b0, ct , k);
    }

    public byte[] a1(byte[] pw, byte[] pk, byte[] sk, byte[] epk, byte[] sendB0, byte[] ssid, byte[] aId, byte[] bId, byte[] ct,SmaugKEM smaugKEM) {
        byte[] key_a = new byte[CRYPTO_BYTES];
        byte[] kPrime = new byte[CRYPTO_BYTES];
        int HASH_SIZE = ID_BYTES * 3 + PAKE_A0_SEND + CIPHERTEXT_BYTES + AUTH_SIZE + CRYPTO_BYTES;
        byte[] auth = new byte[AUTH_SIZE];
        byte[] controlAuth = new byte[SHA3_256_HashSize];
        byte[] hashArray = new byte[HASH_SIZE];

        kPrime = smaugKEM.decapsulation(sk,pk,ct);

        int offset = 0 ;

        System.arraycopy(ssid, 0, auth, offset, ID_BYTES);
        offset += ID_BYTES;

        System.arraycopy(aId, 0, auth, offset, ID_BYTES);
        offset += ID_BYTES;

        System.arraycopy(bId, 0, auth, offset, ID_BYTES);
        offset += ID_BYTES;

        System.arraycopy(pw, 0, auth, offset, PW_BYTES);
        offset += PW_BYTES;

        System.arraycopy(epk, 0, auth, offset, PAKE_A0_SEND);
        offset += PAKE_A0_SEND;

        System.arraycopy(ct, 0, auth, offset, CIPHERTEXT_BYTES);
        offset += CIPHERTEXT_BYTES;

        System.arraycopy(kPrime, 0, auth, offset, CRYPTO_BYTES);

        MessageDigest md = new SHA3_256();
        controlAuth = md.digest(auth);


        if (Arrays.equals(controlAuth, Arrays.copyOf(sendB0, SHA3_256_HashSize))) {
            offset = 0;

            System.arraycopy(ssid, 0, hashArray, offset, ID_BYTES);
            offset += ID_BYTES;

            System.arraycopy(aId, 0, hashArray, offset, ID_BYTES);
            offset += ID_BYTES;

            System.arraycopy(bId, 0, hashArray, offset, ID_BYTES);
            offset += ID_BYTES;

            System.arraycopy(epk, 0, hashArray, offset, PAKE_A0_SEND);
            offset += PAKE_A0_SEND;

            System.arraycopy(ct, 0, hashArray, offset, CIPHERTEXT_BYTES);
            offset += CIPHERTEXT_BYTES;

            System.arraycopy(auth, 0, hashArray, offset, AUTH_SIZE);
            offset += AUTH_SIZE;

            System.arraycopy(kPrime, 0, hashArray, offset, CRYPTO_BYTES);

            md.reset();
            md = new SHA3_256();
            key_a = md.digest(hashArray);

            return key_a;
        } else {

            System.out.println("Auth Failed....");
            return null;
        }
    }
    public byte[] b1(byte[] ssid, byte[] aId, byte[] bId, byte[] epk, byte[] ct, byte[] authB, byte[] k ) {
        byte[] key_b = new byte[CRYPTO_BYTES];
        int HASH_SIZE = ID_BYTES * 3 + PAKE_A0_SEND + CIPHERTEXT_BYTES + AUTH_SIZE + CRYPTO_BYTES;
        byte[] hashArray = new byte[HASH_SIZE];
        int offset = 0;

        System.arraycopy(ssid, 0, hashArray, offset, ID_BYTES);
        offset += ID_BYTES;

        System.arraycopy(aId, 0, hashArray, offset, ID_BYTES);
        offset += ID_BYTES;

        System.arraycopy(bId, 0, hashArray, offset, ID_BYTES);
        offset += ID_BYTES;

        System.arraycopy(epk, 0, hashArray, offset, PAKE_A0_SEND);
        offset += PAKE_A0_SEND;

        System.arraycopy(ct, 0, hashArray, offset, CIPHERTEXT_BYTES);
        offset += CIPHERTEXT_BYTES;

        System.arraycopy(authB, 0, hashArray, offset, AUTH_SIZE);
        offset += AUTH_SIZE;

        System.arraycopy(k, 0, hashArray, offset, CRYPTO_BYTES);


        MessageDigest md = new SHA3_256();
        key_b = md.digest(hashArray);
        return key_b;
    }

}
