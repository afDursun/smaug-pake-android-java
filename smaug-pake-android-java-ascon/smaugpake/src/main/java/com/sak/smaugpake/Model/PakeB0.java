package com.sak.smaugpake.Model;

public class PakeB0 {
    byte[] auth;
    byte[] send_b0;
    byte[] ct;

    byte[] k;

    public byte[] getAuth() {
        return auth;
    }

    public byte[] getSend_b0() {
        return send_b0;
    }

    public byte[] getCt() {
        return ct;
    }

    public byte[] getK() {
        return k;
    }

    public PakeB0(byte[] auth, byte[] send_b0, byte[] ct, byte[] k) {
        this.auth = auth;
        this.send_b0 = send_b0;
        this.ct = ct;
        this.k = k;
    }
}
