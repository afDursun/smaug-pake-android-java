package com.sak.smaugpake;

import static com.sak.smaugpake.SmaugKEM.CIPHERTEXT_BYTES;
import static com.sak.smaugpake.SmaugKEM.CRYPTO_BYTES;
import static com.sak.smaugpake.SmaugKEM.DELTA_BYTES;
import static com.sak.smaugpake.SmaugKEM.IS_RANDOM;
import static com.sak.smaugpake.SmaugKEM.MODULE_RANK;
import static com.sak.smaugpake.SmaugKEM.SHA3_256_HashSize;
import static com.sak.smaugpake.SmaugKEM.SKPOLYVEC_BYTES;
import static com.sak.smaugpake.SmaugKEM.T_BYTES;

import com.github.aelstad.keccakj.core.KeccakSponge;
import com.github.aelstad.keccakj.fips202.SHA3_256;
import com.github.aelstad.keccakj.fips202.Shake256;

import java.security.MessageDigest;
import java.util.Arrays;

import com.sak.smaugpake.Model.Encapsulation;
import com.sak.smaugpake.Model.Key;

public class KEM {

    public static Key crypto_kem_keypair() {

        Key key = Indcpa.indcpa_keypair();
        byte[] random_part = new byte[32];

        if(IS_RANDOM)
            random_part = Utils.random_bytes(32);
        else
            Arrays.fill(random_part, (byte) 1);

        key.setSk(Utils.concatenateArrays(key.getSk(), random_part));

        return  key;
    }

    public static Encapsulation crypto_kem_encap(final byte[] pk){
        byte[] ctxt;
        byte[] ss;


        byte[] mu = new byte[DELTA_BYTES];
        byte[] buf;
        byte[] buf2 = new byte[DELTA_BYTES + CRYPTO_BYTES];


        if(IS_RANDOM)
            mu = Utils.random_bytes(DELTA_BYTES);
        else
            Arrays.fill(mu, (byte) 1);

        MessageDigest md = new SHA3_256();
        buf = md.digest(pk);

        KeccakSponge xof = new Shake256();
        xof.getAbsorbStream().write(mu);
        xof.getAbsorbStream().write(buf);
        xof.getSqueezeStream().read(buf2);

        ctxt = Indcpa.indcpa_enc(pk , mu , buf2);

        ss = Verify.cmov(Arrays.copyOfRange(buf2,DELTA_BYTES,buf2.length) , CRYPTO_BYTES , (byte)1);
        return new Encapsulation(ctxt,ss);
    }

    public static byte[] crypto_kem_decap(byte[] sk, byte[] pk, byte[] ctxt) {

        byte[] ss = new byte[CRYPTO_BYTES];

        byte[] mu = new byte[DELTA_BYTES]; // shared secret and seed
        byte[] buf = new byte[DELTA_BYTES + CRYPTO_BYTES];
        byte[] buf_tmp = new byte[DELTA_BYTES + CRYPTO_BYTES];
        byte[] hash_res = new byte[SHA3_256_HashSize];

        byte[] buf2 = new byte[DELTA_BYTES + CRYPTO_BYTES];
        Indcpa.indcpa_dec(mu , sk , ctxt);



        MessageDigest md = new SHA3_256();
        hash_res = md.digest(pk);

        KeccakSponge xof = new Shake256();
        xof.getAbsorbStream().write(mu);
        xof.getAbsorbStream().write(hash_res);
        xof.getSqueezeStream().read(buf2);


        byte[] ctxt_temp = new byte[CIPHERTEXT_BYTES];
        ctxt_temp  = Indcpa.indcpa_enc(pk,mu,buf2);



        boolean fail = Arrays.equals(ctxt_temp,ctxt);



        md = new SHA3_256();
        hash_res = md.digest(ctxt);

        byte[] sk_r = new byte[T_BYTES];

        for (int i = 0 ; i < T_BYTES ; i++){
            sk_r[i] = sk[i + (2*MODULE_RANK) + SKPOLYVEC_BYTES];
        }

        xof = new Shake256();
        xof.getAbsorbStream().write(sk_r);
        xof.getAbsorbStream().write(hash_res);
        xof.getSqueezeStream().read(buf_tmp);

        byte[] buf_l;
        buf_l = Verify.cmov(Arrays.copyOfRange(buf2,DELTA_BYTES,buf_tmp.length) ,CRYPTO_BYTES , (byte) (fail ? 1 : 0));
        ss = Verify.cmov(buf_l , CRYPTO_BYTES , (byte) 1);
        return ss;
    }
}