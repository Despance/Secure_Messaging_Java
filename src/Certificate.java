import java.security.PublicKey;
import java.security.Signature;
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

        int startIndexOfCert = data.indexOf("Certificate:{ ");
        int endIndexOfCert = data.indexOf("}");

        data = data.substring(startIndexOfCert, endIndexOfCert + 1);

        String[] strings = data.split(" , ");

        for (String string : strings) {

            int startIndex = string.indexOf("algorithmName: \"", 0);
            if (startIndex != -1) {
                this.algorithmName = string.substring(startIndex + 16, string.length() - 1);
                continue;
            }
            startIndex = string.indexOf("name: \"", 0);
            if (startIndex != -1) {
                this.name = string.substring(startIndex + 7, string.length() - 1);
                continue;
            }
            startIndex = string.indexOf("publicKey: \"", 0);
            if (startIndex != -1) {
                String pubkeyString = string.substring(startIndex + 12, string.length() - 1);
                this.publicKey = RSA.generatePublicKeyFromString(pubkeyString);
                continue;
            }
            startIndex = string.indexOf("signature: \"", 0);
            if (startIndex != -1) {
                this.signature = string.substring(startIndex + 12, string.length() - 3);
                continue;
            }

        }

        Logg.getLogger().info("Certificate parsed from data " + toString());

    }

    public boolean checkSignature(PublicKey caKey) {

        try {
            Signature sig = Signature.getInstance("SHA256withRSA");

            sig.initVerify(caKey);

            sig.update(this.publicKey.getEncoded());
            boolean result = sig.verify(Base64.getDecoder().decode(signature));

            Logg.getLogger().info("certificate validation result : " + result);

            return result;

        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();

        sb.append("Certificate:{ ");

        if (algorithmName != null)
            sb.append("algorithmName: \"").append(algorithmName).append("\" , ");

        if (name != null)
            sb.append("name: \"").append(name).append("\" , ");

        sb.append("publicKey: \"").append(Base64.getEncoder().encodeToString(publicKey.getEncoded())).append("\" , ");

        sb.append("signature: \"").append(signature).append("\"").append(" }");

        return sb.toString();
    }
}
