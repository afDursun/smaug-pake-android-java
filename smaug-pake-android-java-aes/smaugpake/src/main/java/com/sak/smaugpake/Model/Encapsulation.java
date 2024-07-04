package com.sak.smaugpake.Model;

public class Encapsulation {
    private byte[] ct;
    private byte[] ssk;

    public Encapsulation(byte[] ct, byte[] ssk) {
        this.ct = ct;
        this.ssk = ssk;
    }

    public Encapsulation() {
    }

    public void setCt(byte[] ct) {
        this.ct = ct;
    }

    public void setSsk(byte[] ssk) {
        this.ssk = ssk;
    }

    public byte[] getCt() {
        return ct;
    }

    public byte[] getSsk() {
        return ssk;
    }
}
