import java.security.PublicKey;
import java.util.Base64;

public class Certificate {

    private String algorithmName;
    private PublicKey publicKey;
    private String name;

    private String signature;

    public Certificate(String algorithmName, PublicKey publicKey, String name) {
        this.algorithmName = algorithmName;
        this.publicKey = publicKey;
        this.name = name;

    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String getAlgorithmName() {
        return algorithmName;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public String getName() {
        return name;
    }

    public Certificate(String data) {

    }

    public String ToString() {
        StringBuilder sb = new StringBuilder();

        sb.append("Certificate:{ ");

        if (algorithmName != null)
            sb.append("algorithmName: \"").append(algorithmName).append("\" , ");

        if (name != null)
            sb.append("name: \"").append(name).append("\" , ");

        sb.append("publicKey: \"").append(Base64.getEncoder().encodeToString(publicKey.getEncoded())).append("\" , ");

        sb.append("signature: \"").append(signature).append("\"").append("}");

        return sb.toString();
    }
}
