package com.sak.smaugpake.Model;

public class PakeA0 {
    byte[] pk,sk,send_a0;

    public byte[] getPk() {
        return pk;
    }

    public byte[] getSk() {
        return sk;
    }

    public byte[] getSend_a0() {
        return send_a0;
    }

    public PakeA0(byte[] pk, byte[] sk, byte[] send_a0) {
        this.pk = pk;
        this.sk = sk;
        this.send_a0 = send_a0;
    }
}
