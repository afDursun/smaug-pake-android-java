package com.sak.smaugpake;

import static com.sak.smaugpake.SmaugKEM.LWE_N;
import static com.sak.smaugpake.SmaugKEM.MODULE_RANK;

public class Poly {
    public static void matrix_vec_mult_sub(short[][] res, short[][][] op1, byte[][] op2, byte[] op2_len_arr, byte[] neg_start, int transpose) {
        for (int i = 0; i < MODULE_RANK; i++) {
            for (int j = 0; j < MODULE_RANK; j++) {
                if (transpose == 1) {
                    poly_mult_sub(res[i], op1[j][i], op2[j], op2_len_arr[j],
                            neg_start[j]);
                } else {
                    poly_mult_sub(res[i], op1[i][j], op2[j], op2_len_arr[j],
                            neg_start[j]);
                }
            }
        }
    }
    private static void poly_mult_sub(short[] res,  short[] op1,  byte[] op2, int op2_length,  byte neg_start) {
        short[] temp = new short[LWE_N * 2];
        for (int j = 0; j < neg_start; ++j) {
            if(op2[j] < 0)
                poly_sub(temp, op1, (op2[j]+256));
            else
                poly_sub(temp, op1, op2[j]);
        }

        for (int j = neg_start; j < op2_length; ++j) {
            if(op2[j] < 0)
                poly_add(temp, op1, (op2[j]+256));
            else
                poly_add(temp, op1, op2[j]);
        }
        poly_reduce(res, temp);

    }
    private static void poly_sub(short[] res, short[] op1, int deg) {
        for (int i = 0; i < LWE_N; ++i)
            res[deg + i] -= op1[i];
    }
    private static void poly_add(short[] res, short[] op1, int deg) {
        for (int i = 0; i < LWE_N; ++i)
            res[deg + i] += op1[i];
    }
    private static void poly_reduce(short[] res, short[] temp) {
        for (int j = 0; j < LWE_N; ++j) {
            res[j] += temp[j] - temp[j + LWE_N];
        }
    }
    public static short[] poly_reduce1(short[] temp) {
        short[] res1 = new short[LWE_N];
        for (int j = 0; j < LWE_N; ++j) {
            res1[j] += temp[j] - temp[j + LWE_N];
        }
        return res1;
    }
    public static byte convToIdx(byte[] res, byte res_length, byte[] op, int op_length) {
        byte[] index_arr = {0, (byte) (res_length - 1)}; // 0 for positive, 1 for negative

        byte index;
        for (int i = 0; i < op_length; ++i) {
            index = (byte) (((op[i] & 0x80) >> 7) & 0x01);
            res[index_arr[index]] = (byte) i;
            index_arr[index] += op[i];
        }

        byte finalIndex = index_arr[0];

        return finalIndex;
    }

    public static short[][] matrix_vec_mult_add(short[][][] op1, byte[][] op2, byte[] op2_len_arr, byte[] neg_start, int transpose) {
        short[][] res = new short[MODULE_RANK][LWE_N];
        for (int i = 0; i < MODULE_RANK; i++) {
            for (int j = 0; j< MODULE_RANK; j++) {
                if (transpose == 1 ) {
                    poly_mult_add(res[i] , op1[j][i], op2[j], op2_len_arr[j],
                            neg_start[j]);
                } else {
                    poly_mult_add(res[i] ,op1[i][j], op2[j], op2_len_arr[j],
                            neg_start[j]);
                }
            }
        }

        return res;
    }

    private static void poly_mult_add(short[] res,short[] op1, byte[] op2, int op2_length, byte neg_start) {
        short[] temp = new short[LWE_N * 2];
        for (int j = 0; j < neg_start; ++j) {
            if(op2[j] < 0)
                poly_add(temp, op1, (op2[j]+256));
            else
                poly_add(temp, op1, op2[j]);
        }

        for (int j = neg_start; j < op2_length; ++j) {
            if(op2[j] < 0)
                poly_sub(temp, op1, (op2[j]+256));
            else
                poly_sub(temp, op1, op2[j]);
        }

        poly_reduce(res, temp);

    }

    public static void vec_vec_mult_add(short[] res, short[][] op1, byte[][] op2, byte[] op2_len_arr, byte[] neg_start) {
        for (int j = 0; j < MODULE_RANK; j++) {
            poly_mult_add(res, op1[j], op2[j], op2_len_arr[j], neg_start[j]);
        }
    }
}
