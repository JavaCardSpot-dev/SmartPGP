package simpleapdu;

import cardTools.CardManager;
import cardTools.RunConfig;
import cardTools.Util;
import fr.anssi.smartpgp.SmartPGPApplet;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.PrivateKey;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;
import org.junit.*;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;

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
}
