package org.restcomm.protocols.ss7.isup.impl.message.parameter;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.Arrays;

import org.restcomm.protocols.ss7.isup.ParameterException;
import org.restcomm.protocols.ss7.isup.impl.message.parameter.AbstractISUPParameter;
import org.restcomm.protocols.ss7.isup.impl.message.parameter.RangeAndStatusImpl;
import org.testng.annotations.Test;

/**
 * Start time:14:11:03 2009-04-23<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com">Bartosz Baranowski </a>
 */
public class RangeAndStatusTest extends ParameterHarness {

    /**
     * @throws IOException
     */
    public RangeAndStatusTest() throws IOException {
        // super.badBodies.add(new byte[0]);

    }

    @Test(groups = { "functional.encode", "functional.decode", "parameter" })
    public void testBody1EncodedValues() throws SecurityException, NoSuchMethodException, IllegalArgumentException,
            IllegalAccessException, InvocationTargetException, IOException, ParameterException {
        RangeAndStatusImpl bci = new RangeAndStatusImpl(getBody((byte) 12, new byte[] { 0x0F, 0x04 }));
        // not a best here. ech.
        String[] methodNames = { "getRange", "getStatus", };
        Object[] expectedValues = { (byte) 12, new byte[] { 0x0F, 0x04 } };
        super.testValues(bci, methodNames, expectedValues);
    }

    @Test(groups = { "functional.flags", "parameter" })
    public void testAffectedValues() throws SecurityException, NoSuchMethodException, IllegalArgumentException,
            IllegalAccessException, InvocationTargetException, IOException, ParameterException {
        RangeAndStatusImpl bci = new RangeAndStatusImpl(getBody((byte) 12, new byte[] { 0x0F, 0x04 }));
        assertEquals((byte) 12, bci.getRange());

        assertTrue(bci.isAffected((byte) 0));
        assertTrue(bci.isAffected((byte) 1));
        assertTrue(bci.isAffected((byte) 2));
        assertTrue(bci.isAffected((byte) 3));

        assertTrue(!bci.isAffected((byte) 4));
        assertTrue(!bci.isAffected((byte) 5));
        assertTrue(!bci.isAffected((byte) 6));
        assertTrue(!bci.isAffected((byte) 7));

        assertTrue(!bci.isAffected((byte) 8));
        assertTrue(!bci.isAffected((byte) 9));
        assertTrue(bci.isAffected((byte) 10));

        bci.setAffected((byte) 9, true);
        bci.setAffected((byte) 10, false);

        assertTrue(!bci.isAffected((byte) 10));
        assertTrue(bci.isAffected((byte) 9));

        byte[] stat = bci.getStatus();
        assertTrue(Arrays.equals(new byte[] { 0x0F, 0x02 }, stat));
    }

    private byte[] getBody(byte rannge, byte[] enabled) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(rannge);
        bos.write(enabled);
        return bos.toByteArray();
    }

    /*
     * (non-Javadoc)
     *
     * @see org.mobicents.isup.messages.parameters.ParameterHarness#getTestedComponent ()
     */

    public AbstractISUPParameter getTestedComponent() {
        return new RangeAndStatusImpl();
    }

}
