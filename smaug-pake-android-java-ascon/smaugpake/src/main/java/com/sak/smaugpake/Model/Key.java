package com.sak.smaugpake.Model;

public class Key {
    private byte[] pk,sk;

    public Key(byte[] pk, byte[] sk) {
        this.pk = pk;
        this.sk = sk;
    }

    public byte[] getPk() {
        return pk;
    }

    public void setPk(byte[] pk) {
        this.pk = pk;
    }

    public void setSk(byte[] sk) {
        this.sk = sk;
    }

    public byte[] getSk() {
        return sk;
    }
}
