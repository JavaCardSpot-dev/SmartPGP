package simpleapdu;

import cardTools.CardManager;
import cardTools.RunConfig;
import cardTools.Util;
import fr.anssi.smartpgp.SmartPGPApplet;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import javacard.security.KeyBuilder;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;
import org.junit.*;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

/**
 * Test class.
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author Petr Svenda (petrs), Dusan Klinec (ph4r05)
 */
public class Tests {
    private static String APPLET_AID = "482871d58ab7465e5e05";
    private static byte APPLET_AID_BYTE[] = Util.hexStringToByteArray(APPLET_AID);

    private static final String STR_APDU_GETRANDOM = "B054100000";
    private CardManager cardMngr = null;


    protected static final short readLength(final byte[] buf, final short off, final short len) {

        if(len < 1) {
            return (short)0;
        }

        if((buf[off] & (byte)0x80) == 0) {
            return javacard.framework.Util.makeShort((byte)0, buf[off]);
        }

        switch(buf[off]) {
            case (byte)0x81:
                if(len < 2) {
                    return (short)0;
                }
                return javacard.framework.Util.makeShort((byte)0, buf[(short)(off + 1)]);

            case (byte)0x82:
                if(len < 3) {
                    return (short)0;
                }
                return javacard.framework.Util.getShort(buf, (short)(off + 1));

            default:
                return (short)0;
        }
    }


    @Before
    public void setUp() throws Exception {
        // CardManager abstracts from real or simulated card, provide with applet AID
        cardMngr = new CardManager(true, APPLET_AID_BYTE);

        // Get default configuration for subsequent connection to card (personalized later)
        final RunConfig runCfg = RunConfig.getDefaultConfig();

        // A) If running on physical card
        // runCfg.setTestCardType(RunConfig.CARD_TYPE.PHYSICAL); // Use real card

        // B) If running in the simulator 
        runCfg.setAppletToSimulate(SmartPGPApplet.class); // main class of applet to simulate
        runCfg.setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL); // Use local simulator

        // Connect to first available card
        // NOTE: selects target applet based on AID specified in CardManager constructor
        System.out.print("Connecting to card...");
        if (!cardMngr.Connect(runCfg)) {
            System.out.println("Connection failed.");
        }
    }

    @Test
    public void verifyAdminPin() throws Exception {

        String pin = "12345678";
        byte[] data = pin.getBytes(StandardCharsets.US_ASCII);

        final ResponseAPDU response = cardMngr.transmit(new CommandAPDU(0x00, 0x20, 0x00, 0x83, data));

        Assert.assertEquals(144, response.getSW1());
        Assert.assertEquals(0, response.getSW2());
    }

    @Test
    public void putDataNotPermittedWihoutAdminPIN() throws Exception {

        byte[] key = Util.hexStringToByteArray("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        final ResponseAPDU response = cardMngr.transmit(new CommandAPDU(0x00, 0xDA, 0x00, 0xD5, key));

        Assert.assertEquals(105, response.getSW1());
        Assert.assertEquals(130, response.getSW2());
    }

    @Test
    public void putAESKey() throws Exception {

        // We have to verify pin first
        String pin = "12345678";
        byte[] data = pin.getBytes(StandardCharsets.US_ASCII);

        cardMngr.transmit(new CommandAPDU(0x00, 0x20, 0x00, 0x83, data));

        byte[] key = Util.hexStringToByteArray("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        final ResponseAPDU response = cardMngr.transmit(new CommandAPDU(0x00, 0xDA, 0x00, 0xD5, key));

        Assert.assertEquals(144, response.getSW1());
        Assert.assertEquals(0, response.getSW2());
    }

    @Test
    public void securityOperationNotPermittedWihoutUserPIN() throws Exception {

        // We have to verify admin pin first
        String pin = "12345678";
        byte[] data = pin.getBytes(StandardCharsets.US_ASCII);
        cardMngr.transmit(new CommandAPDU(0x00, 0x20, 0x00, 0x83, data));

        // Then put AES key on card
        byte[] key = Util.hexStringToByteArray("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        cardMngr.transmit(new CommandAPDU(0x00, 0xDA, 0x00, 0xD5, key));

        // Encrypt
        byte[] plaintext = Util.hexStringToByteArray("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        byte expectedCiphertext[] = Util.hexStringToByteArray("0278498CDE07D82A92B6A07EFA970A854D");

        final ResponseAPDU response = cardMngr.transmit(new CommandAPDU(0x00, 0x2A, 0x86, 0x80, plaintext));

        Assert.assertEquals(105, response.getSW1());
        Assert.assertEquals(130, response.getSW2());
    }

    @Test
    public void encryptAES() throws Exception {

        // We have to verify admin pin first
        String pin = "12345678";
        byte[] data = pin.getBytes(StandardCharsets.US_ASCII);
        cardMngr.transmit(new CommandAPDU(0x00, 0x20, 0x00, 0x83, data));

        // Then put AES key on card
        byte[] key = Util.hexStringToByteArray("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        cardMngr.transmit(new CommandAPDU(0x00, 0xDA, 0x00, 0xD5, key));

        // Verify user pin
        String pin2 = "123456";
        byte[] data2 = pin2.getBytes(StandardCharsets.US_ASCII);
        cardMngr.transmit(new CommandAPDU(0x00, 0x20, 0x00, 0x82, data2));

        // Encrypt
        byte[] plaintext = Util.hexStringToByteArray("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        byte expectedCiphertext[] = Util.hexStringToByteArray("0278498CDE07D82A92B6A07EFA970A854D");

        final ResponseAPDU response = cardMngr.transmit(new CommandAPDU(0x00, 0x2A, 0x86, 0x80, plaintext));

        Assert.assertArrayEquals(expectedCiphertext, response.getData());
        Assert.assertEquals(144, response.getSW1());
        Assert.assertEquals(0, response.getSW2());
    }

    @Test
    public void decryptAES() throws Exception {

        // We have to verify admin pin first
        String pin = "12345678";
        byte[] data = pin.getBytes(StandardCharsets.US_ASCII);
        cardMngr.transmit(new CommandAPDU(0x00, 0x20, 0x00, 0x83, data));

        // Then put AES key on card
        byte[] key = Util.hexStringToByteArray("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        cardMngr.transmit(new CommandAPDU(0x00, 0xDA, 0x00, 0xD5, key));

        // Verify user pin
        String pin2 = "123456";
        byte[] data2 = pin2.getBytes(StandardCharsets.US_ASCII);
        cardMngr.transmit(new CommandAPDU(0x00, 0x20, 0x00, 0x82, data2));

        // Decrypt
        byte[] cipherText = Util.hexStringToByteArray("0278498CDE07D82A92B6A07EFA970A854D");
        byte expectedPlaintext[] = Util.hexStringToByteArray("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

        final ResponseAPDU response = cardMngr.transmit(new CommandAPDU(0x00, 0x2A, 0x80, 0x86, cipherText));

        Assert.assertArrayEquals(expectedPlaintext, response.getData());
        Assert.assertEquals(144, response.getSW1());
        Assert.assertEquals(0, response.getSW2());
    }


    @Test
    public void sign() throws Exception {

        // We have to verify admin pin first
        String pin = "12345678";
        byte[] data = pin.getBytes(StandardCharsets.US_ASCII);
        cardMngr.transmit(new CommandAPDU(0x00, 0x20, 0x00, 0x83, data));

        // Then generate RSA key on card and recieve public part - we first sent key attributes
        byte[] keyAttributes = new byte[] {
                0x01,       // RSA
                0x08, 0x00, // 2048 bits modulus
                0x00, 0x11, // 65537 - 17 bits public exponent
                0x03 } ;    // crt form with modulus
        cardMngr.transmit(new CommandAPDU(0x00, 0xDA, 0x00, 0xC1, keyAttributes));

        byte[] keyToGenerate = new byte[] { (byte) 0xB6, 0x00}; // signature key
        final byte[] response = cardMngr.transmit(new CommandAPDU(0x00, 0x47, 0x80, 0x00, keyToGenerate)).getData();
        final byte[] responseCont = cardMngr.transmit(new CommandAPDU(0x00, 0xC0, 0x00, 0x00)).getData();

        byte[] wholeResponse = new byte[response.length + responseCont.length];
        System.arraycopy(response, 0, wholeResponse, 0, response.length);
        System.arraycopy(responseCont, 0, wholeResponse, response.length, responseCont.length);

        short lenghtOfModulus = readLength(wholeResponse, (short) 6, (short) 3);
        byte[] byteModulus = new byte[lenghtOfModulus];
        System.arraycopy(wholeResponse, 9, byteModulus, 0, lenghtOfModulus);
        BigInteger modulus = new BigInteger(byteModulus);

        short lenghtOfExponent = readLength(wholeResponse, (short) (9 + lenghtOfModulus + 1), (short) 1);
        byte[] byteExponent = new byte[lenghtOfExponent];
        System.arraycopy(wholeResponse, 11 + lenghtOfModulus, byteExponent, 0, lenghtOfExponent);
        BigInteger exponent = new BigInteger(byteExponent);

        final RSAPublicKey pub = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, (short) (lenghtOfModulus * 8), true);

        pub.setModulus(byteModulus, (short) 0, lenghtOfModulus);
        pub.setExponent(byteExponent, (short) 0, lenghtOfExponent);

        // Verify user pin
        String pin2 = "123456";
        byte[] data2 = pin2.getBytes(StandardCharsets.US_ASCII);
        cardMngr.transmit(new CommandAPDU(0x00, 0x20, 0x00, 0x81, data2));

        // Sign
        final byte[] DSI_SHA256_HEADER = {
                (byte)0x30, (byte)0x31,
                (byte)0x30, (byte)0x0D,
                (byte)0x06, (byte)0x09, (byte)0x60, (byte)0x86, (byte)0x48, (byte)0x01, (byte)0x65, (byte)0x03, (byte)0x04, (byte)0x02, (byte)0x01,
                (byte)0x05, (byte)0x00,
                (byte)0x04, (byte)0x20
        };

        byte[] plaintext = Util.hexStringToByteArray("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

        byte[] apduDATA = new byte[DSI_SHA256_HEADER.length + plaintext.length];
        System.arraycopy(DSI_SHA256_HEADER, 0, apduDATA, 0, DSI_SHA256_HEADER.length);
        System.arraycopy(plaintext, 0, apduDATA, DSI_SHA256_HEADER.length, plaintext.length);

        final byte[] signature = cardMngr.transmit(new CommandAPDU(0x00, 0x2A, 0x9E, 0x9A, apduDATA)).getData();

        byte encryptedSignature[] = new byte[256];

        Cipher cipher_rsa_pkcs1 = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);

        cipher_rsa_pkcs1.init(pub, Cipher.MODE_ENCRYPT);

        //cipher_rsa_pkcs1.doFinal(signature, (short)0, (short) signature.length, encryptedSignature, (short)0);

        //Assert.assertArrayEquals(plaintext, encryptedSignature);
    }
}
