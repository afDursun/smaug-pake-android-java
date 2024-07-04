package com.sak.smaugpake;

import static com.sak.smaugpake.SmaugKEM.LWE_N;
import static com.sak.smaugpake.SmaugKEM.MODULE_RANK;

public class Verify {
    public static byte[] cmov(byte[] x, int len, byte b) {
        byte[] r = new byte[len];
        b = (byte) -b;
        for (int i = 0; i < len; i++) {
            r[i] ^= b & (r[i] ^ x[i]);
        }
        return r;
    }

    public static short[][] cmov(short[][] x, int len, byte b) {
        short[][] r = new short[MODULE_RANK][LWE_N];
        b = (byte) -b;
        for (int i = 0; i < MODULE_RANK; i++) {
            for (int j=0 ; j < LWE_N ; j++){
                r[i][j] ^= b & (r[i][j] ^ x[i][j]);
            }

        }
        return r;
    }

    public static short[] cmov(short[] x, int len, byte b) {
        short[] r = new short[LWE_N];
        b = (byte) -b;
            for (int i=0 ; i < LWE_N ; i++){
                r[i] ^= b & (r[i] ^ x[i]);
            }
        return r;
    }
}
