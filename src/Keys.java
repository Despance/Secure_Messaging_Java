public class Keys {
    public byte[] clientMacKey;
    public byte[] serverMacKey;
    public byte[] clientKey;
    public byte[] serverKey;
    // TODO: add IVs as well if we decide to use cbc with aes

    public Keys(byte[] clientMacKey, byte[] serverMacKey, byte[] clientKey, byte[] serverKey) {
        this.clientMacKey = clientMacKey;
        this.serverMacKey = serverMacKey;
        this.clientKey = clientKey;
        this.serverKey = serverKey;
    }
}
