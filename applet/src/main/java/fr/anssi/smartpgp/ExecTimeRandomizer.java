package fr.anssi.smartpgp;

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
        for (int i = 0; i < 100000; ++i){}
    }
}
