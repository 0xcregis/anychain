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
    public static native String getEvmAddress(byte[] publicKey);

    public static void main(String[] args) {
        try {
            System.out.println("=== Starting Hedera JNI Real public-key-hash EVM On-Chain Transfer Test ===");

            // Define Account B (Sequential format payer, loaded with HBAR)
            String bId = "0.0.9507707";
            String bLongZeroEvm = "0x000000000000000000000000000000000091137b";
            String bPriv = "10676410088a00b2debc0e00d7e686789d514d369d0d864f3bd943f954b0dd65";
            byte[] bPubBytes = hexToBytes("03de71d0528d931b6622f08d30bbb6ebed68ad867348c7ea31fe9e1857fcc5fad6");

            // Derive the real public-key-hash EVM address for Account B
            String bRealEvm = getEvmAddress(bPubBytes);
            System.out.println("Account B IDs:");
            System.out.println("  - Sequential ID: " + bId);
            System.out.println("  - Long-Zero EVM Address: " + bLongZeroEvm);
            System.out.println("  - Real EVM Address (derived): " + bRealEvm);

            // Define Account A (ECDSA public-key-hash EVM recipient)
            String aId = "0.0.9481932";
            String aLongZeroEvm = "0x000000000000000000000000000000000090aecc";
            String aPriv = "a003a4aeeb899bcbcacd87fe1dc7c4a3618e9b7324cb338c6eb69a3b85e7e1d5";
            byte[] aPubBytes = hexToBytes("02c98743af45bd16708b2d2b01498b43ad18209c40838bebf76f9e388177814f4b");

            // Derive the real public-key-hash EVM address for Account A
            String aRealEvm = getEvmAddress(aPubBytes);
            System.out.println("\nAccount A IDs:");
            System.out.println("  - Sequential ID: " + aId);
            System.out.println("  - Long-Zero EVM Address: " + aLongZeroEvm);
            System.out.println("  - Real EVM Address (derived): " + aRealEvm);

            long maxFee = 5_000_000L; // 0.05 HBAR

            // -------------------------------------------------------------
            // DYNAMIC HOLLOW CREATION: Create a fresh new Account C as a Hollow Account
            // by sending HBAR directly to its real public-key-hash EVM Address!
            // -------------------------------------------------------------
            System.out.println("\n[Step 1] Preparing key pair for new Account C...");
            String cPriv = "0e4fd0cf299f45f27e269e92736f9d70a67df8bec332d0f3841d2d3f46379e2f";
            byte[] cPubBytes = hexToBytes("0242d75fdf77dc9517b7f1db96484a4d5fbb0505556ff40d3a757e0d4be8be2768");
            String cRealEvm = getEvmAddress(cPubBytes);
            System.out.println("Account C Real public-key-hash EVM Address: " + cRealEvm);

            System.out.println("\n[Step 2] Sending HBAR to Account C's Real EVM address to trigger Hollow Account Auto-Creation on-chain...");
            long autoCreateAmount = 20_000_000L; // 0.2 HBAR (funds creation fee + account C balance)
            long createStart = Instant.now().getEpochSecond() - 10;

            long createTxPtr = createTransaction(bId, cRealEvm, autoCreateAmount, "0.0.5", createStart, 0, maxFee, "auto-create C", bPubBytes);
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

            // Retrieve the dynamically generated sequential ID for C from mirror node
            System.out.println("Waiting for Mirror Node indexing...");
            Thread.sleep(2500);
            String cId = queryAccountIdFromMirror(cRealEvm);
            if (cId == null) {
                System.out.println("ERROR: Failed to retrieve sequential ID for Account C from Mirror Node!");
                return;
            }
            System.out.println("SUCCESSFULLY registered Account C with Sequential ID: " + cId);

            // -------------------------------------------------------------
            // TEST 1: Transfer from Sequential Number (B) to real EVM Address (C)
            // -------------------------------------------------------------
            System.out.println("\n[Test 1] Transfer from Sequential Number (" + bId + ") to real EVM Address (" + cRealEvm + ")...");
            long transfer1Amount = 10_000_000L; // 0.1 HBAR
            long tx1Start = Instant.now().getEpochSecond() - 10;
            
            long tx1Ptr = createTransaction(bId, cRealEvm, transfer1Amount, "0.0.5", tx1Start, 0, maxFee, "transfer 1", bPubBytes);
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
            // TEST 2: Transfer from real EVM Address (C) to Sequential Number (A)
            // -------------------------------------------------------------
            System.out.println("\n[Test 2] Transfer from real EVM Address (" + cRealEvm + ") to Sequential Number (" + aId + ")...");
            long transfer2Amount = 1_000_000L; // 0.01 HBAR
            long tx2Start = Instant.now().getEpochSecond() - 10;

            long tx2Ptr = createTransaction(cRealEvm, aId, transfer2Amount, "0.0.5", tx2Start, 0, maxFee, "transfer 2", cPubBytes);
            byte[] digest2 = getDigest(tx2Ptr);
            byte[] sig2 = signDigest(digest2, hexToBytes(cPriv));
            byte[] signedTx2 = sign(tx2Ptr, sig2);
            freeTransaction(tx2Ptr);

            byte[] res2 = submitGrpc(signedTx2, "cryptoTransfer");
            System.out.println("Test 2 Precheck Response: " + bytesToHex(res2));
            if (!parsePrecheckResponse(res2)) {
                System.out.println("ERROR: Precheck failed for Test 2!");
                return;
            }
            System.out.println("Precheck OK (0). Waiting for consensus...");
            String receipt2 = queryReceipt(bId, bPriv, signedTx2);
            System.out.println("Test 2 Consensus Status: " + receipt2);

            // -------------------------------------------------------------
            // TEST 3: Transfer from real EVM Address (C) to real EVM Address (A)
            // -------------------------------------------------------------
            System.out.println("\n[Test 3] Transfer from real EVM Address (" + cRealEvm + ") to real EVM Address (" + aRealEvm + ")...");
            long transfer3Amount = 1_000_000L; // 0.01 HBAR
            long tx3Start = Instant.now().getEpochSecond() - 10;

            long tx3Ptr = createTransaction(cRealEvm, aRealEvm, transfer3Amount, "0.0.5", tx3Start, 0, maxFee, "transfer 3", cPubBytes);
            byte[] digest3 = getDigest(tx3Ptr);
            byte[] sig3 = signDigest(digest3, hexToBytes(cPriv));
            byte[] signedTx3 = sign(tx3Ptr, sig3);
            freeTransaction(tx3Ptr);

            byte[] res3 = submitGrpc(signedTx3, "cryptoTransfer");
            System.out.println("Test 3 Precheck Response: " + bytesToHex(res3));
            if (!parsePrecheckResponse(res3)) {
                System.out.println("ERROR: Precheck failed for Test 3!");
                return;
            }
            System.out.println("Precheck OK (0). Waiting for consensus...");
            String receipt3 = queryReceipt(bId, bPriv, signedTx3);
            System.out.println("Test 3 Consensus Status: " + receipt3);

            // -------------------------------------------------------------
            // Conclusion
            // -------------------------------------------------------------
            if (receipt1.startsWith("Success") && receipt2.startsWith("Success") && receipt3.startsWith("Success")) {
                System.out.println("\n=== ALL ON-CHAIN MULTI-FORMAT TRANSFERS COMPLETED SUCCESSFULLY! ===");
                System.out.println("1. Sequential -> Real public-key-hash EVM address: Success");
                System.out.println("2. Real public-key-hash EVM address -> Sequential: Success");
                System.out.println("3. Real public-key-hash EVM address -> Real public-key-hash EVM address: Success");
            } else {
                System.out.println("\nERROR: One or more transfers failed to reach consensus!");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String queryAccountIdFromMirror(String evmAddress) throws Exception {
        URL url = new URI("https://testnet.mirrornode.hedera.com/api/v1/accounts/" + evmAddress).toURL();
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
