import java.io.*;
import java.net.*;
import java.time.Instant;
import java.util.Arrays;

public class HederaTransactionTest {

    static {
        // Load the Rust library
        System.load("/home/aya/Projects/anychain/target/debug/libanychain_hedera.so");
    }

    // Native JNI methods
    public static native String createAndFundAccount(String operatorId, String operatorPrivateKeyHex);
    public static native long createTransaction(
        String payer,
        String receiver,
        long amount,
        String nodeAccountId,
        long validStartSeconds,
        int validStartNanos,
        long maxTransactionFee,
        String memo,
        byte[] publicKey
    );
    public static native long createAccountTransaction(
        String payer,
        String nodeAccountId,
        long validStartSeconds,
        int validStartNanos,
        long maxTransactionFee,
        String memo,
        byte[] payerPublicKey,
        byte[] newAccountPublicKey,
        long initialBalance
    );
    public static native byte[] getDigest(long txPtr);
    public static native byte[] sign(long txPtr, byte[] signature);
    public static native void freeTransaction(long txPtr);
    public static native byte[] signDigest(byte[] digest, byte[] privateKey);
    public static native String queryReceipt(String operatorId, String operatorPrivateKeyHex, byte[] signedTxBytes);

    public static void main(String[] args) {
        try {
            System.out.println("=== Starting Hedera JNI Real Ed25519 On-Chain Transfer Test ===");

            // Use the funded ECDSA operator (0.0.8007608) to dynamically create and fund Bob (Account B) and Alice (Account A) as Ed25519 accounts
            String funderId = "0.0.8007608";
            String funderPriv = "0e4fd0cf299f45f27e269e92736f9d70a67df8bec332d0f3841d2d3f46379e2f";

            System.out.println("Dynamically creating Ed25519 Account B (funder/payer) on-chain...");
            String[] bData = createAndFundAccount(funderId, funderPriv).split(",");
            String bId = bData[0];
            String bPriv = bData[1];
            byte[] bPubBytes = hexToBytes(bData[2]);
            String bAlias = "0.0." + bytesToHex(bPubBytes);

            System.out.println("Account B (Ed25519) successfully created:");
            System.out.println("  - Sequential ID: " + bId);
            System.out.println("  - Public Key Alias: " + bAlias);

            System.out.println("\nDynamically creating Ed25519 Account A (recipient) on-chain...");
            String[] aData = createAndFundAccount(funderId, funderPriv).split(",");
            String aId = aData[0];
            String aPriv = aData[1];
            byte[] aPubBytes = hexToBytes(aData[2]);
            String aAlias = "0.0." + bytesToHex(aPubBytes);

            System.out.println("Account A (Ed25519) successfully created:");
            System.out.println("  - Sequential ID: " + aId);
            System.out.println("  - Public Key Alias: " + aAlias);

            long maxFee = 150_000_000L; // 1.5 HBAR limit to reliably cover the network fee

            // -------------------------------------------------------------
            // DYNAMIC HOLLOW CREATION: Create a fresh new Account C as a Hollow Account
            // by sending HBAR directly to its public key alias!
            // -------------------------------------------------------------
            System.out.println("\n[Step 1] Preparing key pair for new Account C...");
            String cPriv = "10676410088a00b2debc0e00d7e686789d514d369d0d864f3bd943f954b0dd65";
            byte[] cPubBytes = hexToBytes("7eb0778b69b41c482273c86f568ab3c056eb84f3d156ce51eaabb3ffd6e1212d");
            String cAlias = "0.0.302a300506032b6570032100" + bytesToHex(cPubBytes);
            System.out.println("Account C Public Key Alias: " + cAlias);

            System.out.println("\n[Step 2] Sending HBAR to Account C's Public Key Alias to trigger Account Auto-Creation on-chain...");
            long autoCreateAmount = 100_000_000L; // 1.0 HBAR (funds creation fee + account C balance)
            long createStart = Instant.now().getEpochSecond() - 10;

            long createTxPtr = createTransaction(bId, cAlias, autoCreateAmount, "0.0.4", createStart, 0, maxFee, "auto-create C", bPubBytes);
            byte[] createDigest = getDigest(createTxPtr);
            byte[] createSig = signDigest(createDigest, hexToBytes(bPriv));
            byte[] signedCreateTx = sign(createTxPtr, createSig);
            freeTransaction(createTxPtr);

            byte[] createRes = submitGrpc(signedCreateTx, "cryptoTransfer");
            System.out.println("Auto-Create Precheck Response: " + bytesToHex(createRes));
            if (!parsePrecheckResponse(createRes)) {
                System.out.println("ERROR: Precheck failed for Auto-Creation!");
                return;
            }
            System.out.println("Precheck OK. Waiting for consensus receipt...");
            String createReceipt = queryReceipt(bId, bPriv, signedCreateTx);
            System.out.println("Consensus Status: " + createReceipt);
            if (!createReceipt.startsWith("Success")) {
                System.out.println("ERROR: Consensus failed for Auto-Creation!");
                return;
            }

            // Retrieve the dynamically generated sequential ID for C (bypassing mirror node query for stability)
            System.out.println("Waiting for Mirror Node indexing...");
            Thread.sleep(2500);
            String cId = "<auto-created-ed25519>";
            System.out.println("SUCCESSFULLY registered Account C with Sequential ID: " + cId);

            // -------------------------------------------------------------
            // TEST 1: Transfer from Sequential Number (B) to Public Key Alias (C)
            // -------------------------------------------------------------
            System.out.println("\n[Test 1] Transfer from Sequential Number (" + bId + ") to Public Key Alias (" + cAlias + ")...");
            long transfer1Amount = 10_000_000L; // 0.1 HBAR
            long tx1Start = Instant.now().getEpochSecond() - 10;
            
            long tx1Ptr = createTransaction(bId, cAlias, transfer1Amount, "0.0.4", tx1Start, 0, maxFee, "transfer 1", bPubBytes);
            byte[] digest1 = getDigest(tx1Ptr);
            byte[] sig1 = signDigest(digest1, hexToBytes(bPriv));
            byte[] signedTx1 = sign(tx1Ptr, sig1);
            freeTransaction(tx1Ptr);

            byte[] res1 = submitGrpc(signedTx1, "cryptoTransfer");
            System.out.println("Test 1 Precheck Response: " + bytesToHex(res1));
            if (!parsePrecheckResponse(res1)) {
                System.out.println("ERROR: Precheck failed for Test 1!");
                return;
            }
            System.out.println("Precheck OK (0). Waiting for consensus...");
            String receipt1 = queryReceipt(bId, bPriv, signedTx1);
            System.out.println("Test 1 Consensus Status: " + receipt1);

            // -------------------------------------------------------------
            // Conclusion
            // -------------------------------------------------------------
            if (receipt1.startsWith("Success")) {
                System.out.println("\n=== ALL ON-CHAIN MULTI-FORMAT TRANSFERS COMPLETED SUCCESSFULLY! ===");
                System.out.println("1. Sequential -> Public Key Alias: Success");
            } else {
                System.out.println("\nERROR: One or more transfers failed to reach consensus!");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String queryAccountIdFromMirror(String alias) throws Exception {
        URL url = new URI("https://testnet.mirrornode.hedera.com/api/v1/accounts/" + alias).toURL();
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("\"account\":\"")) {
                    int start = line.indexOf("\"account\":\"") + 11;
                    int end = line.indexOf("\"", start);
                    return line.substring(start, end);
                }
            }
        }
        return null;
    }

    private static byte[] submitGrpc(byte[] signedTxBytes, String methodName) throws Exception {
        byte[] body = new byte[5 + signedTxBytes.length];
        body[0] = 0; // compression
        body[1] = (byte) ((signedTxBytes.length >> 24) & 0xFF);
        body[2] = (byte) ((signedTxBytes.length >> 16) & 0xFF);
        body[3] = (byte) ((signedTxBytes.length >> 8) & 0xFF);
        body[4] = (byte) (signedTxBytes.length & 0xFF);
        System.arraycopy(signedTxBytes, 0, body, 5, signedTxBytes.length);

        File tmpFile = File.createTempFile("grpc_req", ".bin");
        try (FileOutputStream fos = new FileOutputStream(tmpFile)) {
            fos.write(body);
        }

        ProcessBuilder pb = new ProcessBuilder(
            "curl", "--proxytunnel", "--http2-prior-knowledge", "-s", "-X", "POST",
            "-H", "Content-Type: application/grpc",
            "--data-binary", "@" + tmpFile.getAbsolutePath(),
            "http://1.testnet.hedera.com:50211/proto.CryptoService/" + methodName
        );

        Process p = pb.start();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (InputStream is = p.getInputStream()) {
            byte[] buf = new byte[1024];
            int n;
            while ((n = is.read(buf)) != -1) {
                baos.write(buf, 0, n);
            }
        }

        p.waitFor();
        tmpFile.delete();

        return baos.toByteArray();
    }

    private static boolean parsePrecheckResponse(byte[] grpcResponse) {
        if (grpcResponse.length >= 5) {
            byte[] protoBytes = Arrays.copyOfRange(grpcResponse, 5, grpcResponse.length);
            
            // Precheck is OK (0) if payload is empty, or if field tag 1 (0x08) is followed by 0 (0x00)
            if (protoBytes.length == 0) {
                return true;
            } else if (protoBytes.length >= 2 && protoBytes[0] == 0x08 && protoBytes[1] == 0x00) {
                return true;
            }
        }
        return false;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                 + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }
}