package com.sak.smaugpake;

import static com.sak.smaugpake.SmaugKEM.DELTA_BYTES;
import static com.sak.smaugpake.SmaugKEM.LWE_N;
import static com.sak.smaugpake.SmaugKEM.MODULE_RANK;
import static com.sak.smaugpake.SmaugKEM.RD_ADD;
import static com.sak.smaugpake.SmaugKEM.RD_ADD2;
import static com.sak.smaugpake.SmaugKEM.RD_AND;
import static com.sak.smaugpake.SmaugKEM.RD_AND2;
import static com.sak.smaugpake.SmaugKEM._16_LOG_P;
import static com.sak.smaugpake.SmaugKEM._16_LOG_P2;
import static com.sak.smaugpake.SmaugKEM._16_LOG_T;

public class CiphertextOperation {
    public static short[][] computeC1(short[][][] A, byte[][] r, byte[] r_cnt_arr, byte[] r_neg_start) {
        short[][] c1 = new short[MODULE_RANK][LWE_N];

        c1 = Poly.matrix_vec_mult_add(A, r, r_cnt_arr, r_neg_start, 1);
        for (int i = 0; i < MODULE_RANK; ++i) {
            for (int j = 0; j < LWE_N; ++j) {
                c1[i][j] = (short) (((c1[i][j] + RD_ADD) & RD_AND) >> _16_LOG_P);
            }
        }
        return c1;
    }

    public static short[] computeC2(byte[] delta, short[][] b, byte[][] r, byte[] r_cnt_arr, byte[] r_neg_start) {
        short[] c2 = new short[LWE_N];

        for (int i = 0; i < DELTA_BYTES; ++i) {
            for (int j = 0; j < 1* 8; ++j) {
                c2[8 * i + j] = (short) ((delta[i] >> j) << _16_LOG_T);
            }
        }

        Poly.vec_vec_mult_add(c2, b, r, r_cnt_arr, r_neg_start);

        for (int i = 0; i < LWE_N; ++i) {
            c2[i] = (short) (((c2[i] + RD_ADD2) & RD_AND2) >> _16_LOG_P2);
        }

        return c2;
    }
}
