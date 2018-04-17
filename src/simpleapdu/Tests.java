package simpleapdu;

import cardTools.CardManager;
import cardTools.RunConfig;
import cardTools.Util;
import fr.anssi.smartpgp.SmartPGPApplet;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.*;

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


    @Before
    public void demoGetRandomDataCommand() throws Exception {
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
        // Transmit single APDU

        String pin = "12345678";
        byte[] data = pin.getBytes(StandardCharsets.US_ASCII);

        final ResponseAPDU response = cardMngr.transmit(new CommandAPDU(0x00, 0x20, 0x00, 0x83, data)); // Use other constructor for CommandAPDU

        System.out.println(response);
    }
}
