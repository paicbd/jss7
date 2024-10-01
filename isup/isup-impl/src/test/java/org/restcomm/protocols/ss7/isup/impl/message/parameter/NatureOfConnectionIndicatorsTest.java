package org.restcomm.protocols.ss7.isup.impl.message.parameter;

import java.io.IOException;

import org.restcomm.protocols.ss7.isup.ParameterException;
import org.restcomm.protocols.ss7.isup.impl.message.parameter.AbstractISUPParameter;
import org.restcomm.protocols.ss7.isup.impl.message.parameter.NatureOfConnectionIndicatorsImpl;
import org.testng.annotations.Test;

/**
 * Start time:13:20:04 2009-04-26<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com">Bartosz Baranowski </a>
 */
public class NatureOfConnectionIndicatorsTest extends ParameterHarness {

    public NatureOfConnectionIndicatorsTest() {
        super();
        super.badBodies.add(new byte[2]);
        super.goodBodies.add(new byte[1]);
        super.goodBodies.add(new byte[] { 0x0E });
    }

    @Test(groups = { "functional.encode", "functional.decode", "parameter" })
    public void testBody1EncodedValues() throws IOException, ParameterException {

        NatureOfConnectionIndicatorsImpl eci = new NatureOfConnectionIndicatorsImpl(
                getBody(NatureOfConnectionIndicatorsImpl._SI_ONE_SATELLITE,
                        NatureOfConnectionIndicatorsImpl._CCI_REQUIRED_ON_THIS_CIRCUIT,
                        NatureOfConnectionIndicatorsImpl._ECDI_INCLUDED));

        String[] methodNames = { "getSatelliteIndicator", "getContinuityCheckIndicator", "isEchoControlDeviceIndicator" };
        Object[] expectedValues = { NatureOfConnectionIndicatorsImpl._SI_ONE_SATELLITE,
                NatureOfConnectionIndicatorsImpl._CCI_REQUIRED_ON_THIS_CIRCUIT, NatureOfConnectionIndicatorsImpl._ECDI_INCLUDED };

        super.testValues(eci, methodNames, expectedValues);
    }

    private byte[] getBody(int siOneSatellite, int cciRequiredOnThisCircuit, boolean ecdiIncluded) {

        byte b = (byte) (siOneSatellite | (cciRequiredOnThisCircuit << 2) | (ecdiIncluded ? (0x01 << 4) : (0x00 << 4)));

        return new byte[] { b };
    }

    /*
     * (non-Javadoc)
     *
     * @see org.mobicents.isup.messages.parameters.ParameterHarness#getTestedComponent ()
     */

    public AbstractISUPParameter getTestedComponent() throws ParameterException {
        return new NatureOfConnectionIndicatorsImpl(new byte[1]);
    }

}
