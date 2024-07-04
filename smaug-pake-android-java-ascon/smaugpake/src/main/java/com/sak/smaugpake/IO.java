package com.sak.smaugpake;

import static com.sak.smaugpake.SmaugKEM.CIPHERTEXT_BYTES;
import static com.sak.smaugpake.SmaugKEM.CTPOLYVEC_BYTES;
import static com.sak.smaugpake.SmaugKEM.LWE_N;
import static com.sak.smaugpake.SmaugKEM.MODULE_RANK;
import static com.sak.smaugpake.SmaugKEM.PKSEED_BYTES;
import static com.sak.smaugpake.SmaugKEM.PUBLICKEY_BYTES;
import static com.sak.smaugpake.SmaugKEM.SKPOLYVEC_BYTES;
import static com.sak.smaugpake.SmaugKEM.T_BYTES;
import static com.sak.smaugpake.SmaugKEM._16_LOG_Q;

import java.util.ArrayList;
import java.util.Arrays;

import com.sak.smaugpake.Model.Ciphertext;
import com.sak.smaugpake.Model.PublicKey;
import com.sak.smaugpake.Model.SecretKey;

public class IO {

    public static byte[] save_to_string_pk(PublicKey pk) {
        byte[] output1 = new byte[PKSEED_BYTES];
        byte[] output2 = new byte[PUBLICKEY_BYTES];

        short[][] vec = new short[MODULE_RANK][LWE_N];
        System.arraycopy(pk.getSeed(), 0, output1, 0, PKSEED_BYTES);

        for (int i = 0; i < MODULE_RANK; i++)
            for (int j = 0; j < LWE_N; j++)
                vec[i][j] = (short) (pk.getB()[i][j] >> _16_LOG_Q);

        output2 = Pack.Rq_vec_to_bytes(vec);

        return Utils.concatenateArrays(output1, output2);
    }

    public static byte[] save_to_string_sk(SecretKey sk, boolean isPKE) {
        ArrayList<byte[]> byteList = new ArrayList<>();

        byte[] output1;
        byte[] output2;
        byte[] output3;
        byte[] output4;

        output1 = Verify.cmov(sk.getCnt_arr(), MODULE_RANK, (byte) 1);
        output2 = Pack.Sx_vec_to_bytes(sk.getS(), sk.getCnt_arr());
        output3 = Verify.cmov(sk.getNeg_start(), MODULE_RANK, (byte) 1);

        byteList.add(output1);
        byteList.add(output2);
        byteList.add(output3);

        if (!isPKE) {
            output4 = Verify.cmov(sk.getT(), T_BYTES, (byte) 1);
            byteList.add(output4);
        }
        return Utils.concatenateArrayList(byteList);
    }

    public static void load_from_string_pk(PublicKey pk, byte[] input) {
        short[][] b = new short[MODULE_RANK][LWE_N];
        short[][] vec;
        pk.setSeed(Arrays.copyOfRange(input, 0, PKSEED_BYTES));
        pk.setA(KeyOperation.genAx(pk.getSeed()));

        vec = Pack.bytes_to_Rq_vec(Arrays.copyOfRange(input, PKSEED_BYTES, input.length));

        for (int i = 0; i < MODULE_RANK; i++)
            for (int j = 0; j < LWE_N; j++)
                b[i][j] = (short) (vec[i][j] << _16_LOG_Q);

        pk.setB(b);
    }

    public static byte[] save_to_string(Ciphertext ctxt) {
        byte[] part1 = new byte[CTPOLYVEC_BYTES];
        byte[] part2 = new byte[CIPHERTEXT_BYTES - CTPOLYVEC_BYTES];
        part1 = Pack.Rp_vec_to_bytes(ctxt.getC1());
        part2 = Pack.Rp2_to_bytes(ctxt.getC2());



        return Utils.concatenateArrays(part1, part2);

    }

    public static void load_from_string_sk(SecretKey sk_temp, byte[] input, boolean isPKE) {
        sk_temp.setCnt_arr(Verify.cmov(input, MODULE_RANK, (byte) 1));

        byte[][] s = new byte[MODULE_RANK][];

        s = Pack.bytes_to_Sx_vec(Arrays.copyOfRange(input, MODULE_RANK , input.length-MODULE_RANK), sk_temp.getCnt_arr());

        sk_temp.setNeg_start(Verify.cmov(Arrays.copyOfRange(input , MODULE_RANK+SKPOLYVEC_BYTES , input.length), MODULE_RANK , (byte)1) );

        if (!isPKE) {
            sk_temp.setT( Verify.cmov(Arrays.copyOfRange(input , 2 * MODULE_RANK + SKPOLYVEC_BYTES , input.length) , T_BYTES , (byte) 1) );
        }

        sk_temp.setS(s);

    }

    public static void load_from_string(Ciphertext ctxt, byte[] input) {
        ctxt.setC1( Pack.bytes_to_Rp_vec(input) );

        ctxt.setC2( Pack.bytes_to_Rp2(Arrays.copyOfRange(input , CTPOLYVEC_BYTES, input.length)) );

    }
}
