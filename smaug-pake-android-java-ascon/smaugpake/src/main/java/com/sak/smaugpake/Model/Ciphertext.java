package com.sak.smaugpake.Model;

import static com.sak.smaugpake.SmaugKEM.LWE_N;
import static com.sak.smaugpake.SmaugKEM.MODULE_RANK;

public class Ciphertext {
    private short[][] c1 = new short[MODULE_RANK][LWE_N];
    private short[] c2 = new short[LWE_N];

    public short[][] getC1() {
        return c1;
    }
    public void setC1(short[][] c1) {
        this.c1 = c1;
    }

    public void setC2(short[] c2) {
        this.c2 = c2;
    }

    public short[] getC2() {
        return c2;
    }

    public Ciphertext(short[][] c1, short[] c2) {
        this.c1 = c1;
        this.c2 = c2;
    }

    public Ciphertext() {
    }
}
