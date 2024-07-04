package com.sak.smaugpake.Model;

import static com.sak.smaugpake.SmaugKEM.MODULE_RANK;
import static com.sak.smaugpake.SmaugKEM.T_BYTES;

public class SecretKey {

    private byte[][] s = new byte[MODULE_RANK][];
    private byte[] t = new byte[T_BYTES];
    private byte[] neg_start = new byte[MODULE_RANK];
    private byte[] cnt_arr = new byte[MODULE_RANK];


    public SecretKey() {
    }

    public SecretKey(byte[][] s, byte[] t, byte[] neg_start, byte[] cnt_arr) {
        this.s = s;
        this.t = t;
        this.neg_start = neg_start;
        this.cnt_arr = cnt_arr;
    }

    public void setS(byte[][] s) {
        this.s = s;
    }

    public void setT(byte[] t) {
        this.t = t;
    }

    public void setNeg_start(byte[] neg_start) {
        this.neg_start = neg_start;
    }

    public void setCnt_arr(byte[] cnt_arr) {
        this.cnt_arr = cnt_arr;
    }

    public byte[][] getS() {
        return s;
    }

    public byte[] getT() {
        return t;
    }

    public byte[] getNeg_start() {
        return neg_start;
    }

    public byte[] getCnt_arr() {
        return cnt_arr;
    }
}
