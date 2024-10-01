package org.restcomm.protocols.ss7.isup.impl.message.parameter;

import org.restcomm.protocols.ss7.isup.ParameterException;
import org.restcomm.protocols.ss7.isup.impl.message.parameter.AbstractISUPParameter;
import org.restcomm.protocols.ss7.isup.impl.message.parameter.EchoControlInformationImpl;
import org.testng.annotations.Test;

/**
 * Start time:11:34:01 2009-04-24<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com">Bartosz Baranowski </a>
 */
public class EchoControlInformationTest extends ParameterHarness {

    public EchoControlInformationTest() {
        super();
        super.goodBodies.add(new byte[] { 67 });
        super.badBodies.add(new byte[2]);
    }

    private byte[] getBody(int _OUT_E_CDII, int _IN_E_CDII, int _IN_E_CDRI, int _OUT_E_CDRI) {
        byte[] b = new byte[1];
        int v = _OUT_E_CDII;
        v |= _IN_E_CDII << 2;
        v |= _OUT_E_CDRI << 4;
        v |= _IN_E_CDRI << 6;
        b[0] = (byte) v;

        return b;
    }

    @Test(groups = { "functional.encode", "functional.decode", "parameter" })
    public void testBody1EncodedValues() throws ParameterException {
        EchoControlInformationImpl eci = new EchoControlInformationImpl(getBody(
                EchoControlInformationImpl._OUTGOING_ECHO_CDII_NINA, EchoControlInformationImpl._INCOMING_ECHO_CDII_INCLUDED,
                EchoControlInformationImpl._INCOMING_ECHO_CDRI_AR, EchoControlInformationImpl._OUTGOING_ECHO_CDRI_NOINFO));

        String[] methodNames = { "getOutgoingEchoControlDeviceInformationIndicator",
                "getIncomingEchoControlDeviceInformationIndicator", "getIncomingEchoControlDeviceInformationRequestIndicator",
                "getOutgoingEchoControlDeviceInformationRequestIndicator" };
        Object[] expectedValues = { EchoControlInformationImpl._OUTGOING_ECHO_CDII_NINA,
                EchoControlInformationImpl._INCOMING_ECHO_CDII_INCLUDED, EchoControlInformationImpl._INCOMING_ECHO_CDRI_AR,
                EchoControlInformationImpl._OUTGOING_ECHO_CDRI_NOINFO };
        super.testValues(eci, methodNames, expectedValues);
    }

    /*
     * (non-Javadoc)
     *
     * @see org.mobicents.isup.messages.parameters.ParameterHarness#getTestedComponent ()
     */

    public AbstractISUPParameter getTestedComponent() throws ParameterException {
        return new EchoControlInformationImpl(new byte[1]);
    }

}
