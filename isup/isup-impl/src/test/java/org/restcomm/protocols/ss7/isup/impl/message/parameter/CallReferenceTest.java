package org.restcomm.protocols.ss7.isup.impl.message.parameter;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;

import org.restcomm.protocols.ss7.isup.ParameterException;
import org.restcomm.protocols.ss7.isup.impl.message.parameter.AbstractISUPParameter;
import org.restcomm.protocols.ss7.isup.impl.message.parameter.CallReferenceImpl;
import org.testng.annotations.Test;

/**
 * Start time:14:11:03 2009-04-23<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com">Bartosz Baranowski </a>
 */
public class CallReferenceTest extends ParameterHarness {

    /**
     * @throws IOException
     */
    public CallReferenceTest() throws IOException {
        super.badBodies.add(new byte[1]);
        super.badBodies.add(new byte[2]);
        super.badBodies.add(new byte[3]);
        super.badBodies.add(new byte[4]);
        super.badBodies.add(new byte[6]);

        super.goodBodies.add(getBody2());

    }

    private byte[] getBody1() throws IOException {

        // we will use odd number of digits, so we leave zero as MSB
        byte[] body = new byte[5];
        body[0] = 12;
        body[1] = 73;
        body[2] = 120;
        body[3] = 73;
        body[4] = 120;

        return body;
    }

    private byte[] getBody2() throws IOException {

        // we will use odd number of digits, so we leave zero as MSB
        byte[] body = new byte[5];
        body[0] = 12;
        body[1] = 73;
        body[2] = 120;
        body[3] = 73;
        // one MSB will be ignored.
        body[4] = 120 & 0x3F;

        return body;
    }

    @Test(groups = { "functional.encode", "functional.decode", "parameter" })
    public void testBody1EncodedValues() throws SecurityException, NoSuchMethodException, IllegalArgumentException,
            IllegalAccessException, InvocationTargetException, IOException, ParameterException {
        CallReferenceImpl cr = new CallReferenceImpl();
        cr.decode(getBody1());
        String[] methodNames = { "getCallIdentity", "getSignalingPointCode" };
        Object[] expectedValues = { 805240, 14409 };
        super.testValues(cr, methodNames, expectedValues);
    }

    /*
     * (non-Javadoc)
     *
     * @see org.mobicents.isup.messages.parameters.ParameterHarness#getTestedComponent ()
     */

    public AbstractISUPParameter getTestedComponent() throws ParameterException {
        return new CallReferenceImpl();
    }

}
