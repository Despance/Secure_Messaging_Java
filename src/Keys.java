public class Keys {
    public byte[] clientMacKey;
    public byte[] serverMacKey;
    public byte[] clientKey;
    public byte[] serverKey;
    public byte[] clientIv;
    public byte[] serverIv;

    public Keys(byte[] clientMacKey, byte[] serverMacKey, byte[] clientKey, byte[] serverKey, byte[] clientIv, byte[] serverIv) {
        this.clientMacKey = clientMacKey;
        this.serverMacKey = serverMacKey;
        this.clientKey = clientKey;
        this.serverKey = serverKey;
        this.clientIv = clientIv;
        this.serverIv = serverIv;
    }
}
