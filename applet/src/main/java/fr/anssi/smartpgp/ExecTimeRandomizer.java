package fr.anssi.smartpgp;

import javacard.framework.JCSystem;
import javacard.security.RandomData;

public class ExecTimeRandomizer {

    /**
     * This method serves as a protection mean against power analysis and fault induction attacks
     *
     * It introduces a random wait time along with random power consumption during its execution
     *
     * Recommended use:
     * call before or during critical security operations to reduce the window for power analysis/fault induction
     */
    public static void randomize(){

        //extremely naive implementation, demonstrative purposes
        //TODO use more sophisticated approach
        RandomData random_data = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        byte[] count = JCSystem.makeTransientByteArray((short) 1,
                JCSystem.CLEAR_ON_DESELECT);
        random_data.generateData(count,(short) 0,(short) 1);
        for (short i = (short) 0; i < (short) count[0]; ++i){}
    }
}
