package com.sak.smaugpake;

import static com.sak.smaugpake.SmaugKEM.CIPHERTEXT_BYTES;
import static com.sak.smaugpake.SmaugKEM.CRYPTO_BYTES;
import static com.sak.smaugpake.SmaugKEM.DEC_ADD;
import static com.sak.smaugpake.SmaugKEM.DELTA_BYTES;
import static com.sak.smaugpake.SmaugKEM.HR;
import static com.sak.smaugpake.SmaugKEM.IS_RANDOM;
import static com.sak.smaugpake.SmaugKEM.LWE_N;
import static com.sak.smaugpake.SmaugKEM.MODULE_RANK;
import static com.sak.smaugpake.SmaugKEM.PKSEED_BYTES;
import static com.sak.smaugpake.SmaugKEM._16_LOG_P;
import static com.sak.smaugpake.SmaugKEM._16_LOG_P2;
import static com.sak.smaugpake.SmaugKEM._16_LOG_T;

import com.github.aelstad.keccakj.core.KeccakSponge;
import com.github.aelstad.keccakj.fips202.Shake128;

import java.util.Arrays;

import com.sak.smaugpake.Model.Ciphertext;
import com.sak.smaugpake.Model.Key;
import com.sak.smaugpake.Model.PublicKey;
import com.sak.smaugpake.Model.SecretKey;

public class Indcpa {
    private  static void genRx_vec(byte[][] r, byte[] neg_start, byte[] r_cnt_arr, final byte[] input,final int input_size) {

        byte[] res = new byte[LWE_N * MODULE_RANK] ;

        for (int i = 0; i < MODULE_RANK; ++i)
            r_cnt_arr[i] = 0;
        res = Hwt.hwt(r_cnt_arr, input, input_size, HR);

        for (int i = 0; i < MODULE_RANK; ++i) {
            r[i] = new byte[r_cnt_arr[i]];
            neg_start[i] = Poly.convToIdx(r[i], r_cnt_arr[i], Arrays.copyOfRange(res, i*LWE_N , (i+1)*LWE_N), LWE_N);
        }
    }

    public static Key indcpa_keypair(){
        byte[] pk;
        byte[] sk;

        PublicKey pkTmp = new PublicKey();
        SecretKey skTmp = new SecretKey();

        byte[] seed1 = new byte[CRYPTO_BYTES];
        byte[] seed2 = new byte[PKSEED_BYTES + CRYPTO_BYTES];

        if(IS_RANDOM){
            seed1 = Utils.random_bytes(PKSEED_BYTES);
        }
        else{
            for (int i=0 ; i < CRYPTO_BYTES; i++)
                seed1[i] = 1;
        }

        KeccakSponge xof = new Shake128();
        xof.getAbsorbStream().write(seed1);
        xof.getSqueezeStream().read(seed2);

        KeyOperation.genSxVec(skTmp, Arrays.copyOfRange(seed2,0,CRYPTO_BYTES));

        pkTmp.setSeed(Arrays.copyOfRange(seed2,CRYPTO_BYTES, CRYPTO_BYTES+PKSEED_BYTES));
        KeyOperation.genPubKey(pkTmp,skTmp, seed2);

        pk = IO.save_to_string_pk(pkTmp);
        sk = IO.save_to_string_sk(skTmp , true);

        return new Key(pk , sk);
    }

    public static byte[] indcpa_enc(final byte[] pk, final byte[] mu, final byte[] seed){
        byte[] ctxt = new byte[CIPHERTEXT_BYTES];

        byte[] seed_r = new byte[DELTA_BYTES];
        PublicKey pk_tmp = new PublicKey();

        IO.load_from_string_pk(pk_tmp , pk);

        byte[][] r = new byte[MODULE_RANK][];
        byte[] r_neg_start = new byte[MODULE_RANK];
        byte[] r_cnt_arr = new byte[MODULE_RANK];

        if (seed == null)
            seed_r = Utils.random_bytes(DELTA_BYTES);
        else
            seed_r = Verify.cmov(seed, DELTA_BYTES, (byte) 1);

        genRx_vec(r, r_neg_start , r_cnt_arr , seed_r , DELTA_BYTES);


        Ciphertext ctxt_tmp = new Ciphertext();

        ctxt_tmp.setC1( CiphertextOperation.computeC1(pk_tmp.getA(), r, r_cnt_arr, r_neg_start) );
        ctxt_tmp.setC2( CiphertextOperation.computeC2( mu, pk_tmp.getB(), r, r_cnt_arr, r_neg_start ) );


        ctxt = IO.save_to_string(ctxt_tmp);



        return ctxt;
    }

    public static void indcpa_dec(byte[] delta, byte[] sk, byte[] ctxt) {
        short[] delta_temp = new short[LWE_N];
        short[][] c1_temp = new short[MODULE_RANK][LWE_N];
        byte[][] c1_temp_byte = new byte[MODULE_RANK][LWE_N];

        SecretKey sk_temp = new SecretKey();
        IO.load_from_string_sk(sk_temp , sk , true);

        Ciphertext ctxt_tmp = new Ciphertext();

        IO.load_from_string(ctxt_tmp, ctxt);

        c1_temp = Verify.cmov(ctxt_tmp.getC1() , 0 , (byte) 1);

        delta_temp = Verify.cmov(ctxt_tmp.getC2() , 0 , (byte) 1);

        for (int i = 0; i < LWE_N; ++i){
            int result = ((int) delta_temp[i]) << _16_LOG_P2;
            delta_temp[i] = (short) result;
        }

        for (int i = 0; i < MODULE_RANK; ++i)
            for (int j = 0; j < LWE_N; ++j)
                c1_temp[i][j] <<= _16_LOG_P;

        Poly.vec_vec_mult_add(delta_temp, c1_temp, sk_temp.getS(),sk_temp.getCnt_arr(), sk_temp.getNeg_start());



        for (int i = 0; i < LWE_N; ++i) {
            delta_temp[i] = (short) (((delta_temp[i] + DEC_ADD) & 0xFFFF) >>> _16_LOG_T);
        }

        for (int i = 0; i < DELTA_BYTES; ++i) {
            for (int j = 0; j < 8; ++j) {
                delta[i] ^= ((byte) (delta_temp[8 * i + j]) << j);
            }
        }
    }
}
