package org.restcomm.protocols.ss7.isup.impl.message.parameter;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;

import org.restcomm.protocols.ss7.isup.ParameterException;
import org.restcomm.protocols.ss7.isup.impl.message.parameter.AbstractISUPParameter;
import org.restcomm.protocols.ss7.isup.impl.message.parameter.OptionalBackwardCallIndicatorsImpl;
import org.testng.annotations.Test;

/**
 * Start time:16:20:47 2009-04-26<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com">Bartosz Baranowski </a>
 */
public class OptionalBackwardCallIndicatorsTest extends ParameterHarness {

    private static final int _TURN_ON = 1;
    private static final int _TURN_OFF = 0;

    public OptionalBackwardCallIndicatorsTest() {
        super();
        super.goodBodies.add(new byte[] { 8 });
        super.badBodies.add(new byte[] { 8, 8 });
    }

    @Test(groups = { "functional.encode", "functional.decode", "parameter" })
    public void testBody1EncodedValues() throws SecurityException, NoSuchMethodException, IllegalArgumentException,
            IllegalAccessException, InvocationTargetException, IOException, ParameterException {
        OptionalBackwardCallIndicatorsImpl bci = new OptionalBackwardCallIndicatorsImpl();

        bci.decode(getBody(OptionalBackwardCallIndicatorsImpl._IBII_AVAILABLE,
                OptionalBackwardCallIndicatorsImpl._CDI_NO_INDICATION,
                OptionalBackwardCallIndicatorsImpl._SSIR_NO_ADDITIONAL_INFO, OptionalBackwardCallIndicatorsImpl._MLLPUI_USER));
        String[] methodNames = { "isInbandInformationIndicator", "isCallDiversionMayOccurIndicator",
                "isSimpleSegmentationIndicator", "isMllpUserIndicator" };
        Object[] expectedValues = { OptionalBackwardCallIndicatorsImpl._IBII_AVAILABLE,
                OptionalBackwardCallIndicatorsImpl._CDI_NO_INDICATION,
                OptionalBackwardCallIndicatorsImpl._SSIR_NO_ADDITIONAL_INFO, OptionalBackwardCallIndicatorsImpl._MLLPUI_USER };
        super.testValues(bci, methodNames, expectedValues);
    }

    private byte[] getBody(boolean ibiiAvailable, boolean cdiNoIndication, boolean ssirNoAdditionalInfo, boolean mllpuiUser) {
        byte b = (byte) ((ibiiAvailable ? _TURN_ON : _TURN_OFF));
        b |= ((cdiNoIndication ? _TURN_ON : _TURN_OFF) << 1);
        b |= ((ssirNoAdditionalInfo ? _TURN_ON : _TURN_OFF) << 2);
        b |= ((mllpuiUser ? _TURN_ON : _TURN_OFF) << 3);
        return new byte[] { b };
    }

    /*
     * (non-Javadoc)
     *
     * @see org.mobicents.isup.messages.parameters.ParameterHarness#getTestedComponent ()
     */

    public AbstractISUPParameter getTestedComponent() throws ParameterException {
        return new OptionalBackwardCallIndicatorsImpl();
    }

}
