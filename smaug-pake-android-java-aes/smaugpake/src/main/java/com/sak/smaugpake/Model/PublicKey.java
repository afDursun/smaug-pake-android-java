package com.sak.smaugpake.Model;

import static com.sak.smaugpake.SmaugKEM.LWE_N;
import static com.sak.smaugpake.SmaugKEM.MODULE_RANK;
import static com.sak.smaugpake.SmaugKEM.PKSEED_BYTES;

public class PublicKey {
    private byte[] seed = new byte[PKSEED_BYTES];
    private short[][][] A = new short[MODULE_RANK][MODULE_RANK][LWE_N];
    private short[][] b = new short[MODULE_RANK][LWE_N];

    public PublicKey() {
    }

    public void setSeed(byte[] seed) {
        this.seed = seed;
    }

    public void setA(short[][][] a) {
        A = a;
    }

    public void setB(short[][] b) {
        this.b = b;
    }

    public byte[] getSeed() {
        return seed;
    }

    public short[][][] getA() {
        return A;
    }

    public short[][] getB() {
        return b;
    }
}
