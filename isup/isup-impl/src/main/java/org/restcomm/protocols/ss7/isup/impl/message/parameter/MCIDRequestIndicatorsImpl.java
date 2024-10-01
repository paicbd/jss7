package org.restcomm.protocols.ss7.isup.impl.message.parameter;

import org.restcomm.protocols.ss7.isup.ParameterException;
import org.restcomm.protocols.ss7.isup.message.parameter.MCIDRequestIndicators;

/**
 * Start time:14:44:20 2009-04-01<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com"> Bartosz Baranowski </a>
 *
 */
public class MCIDRequestIndicatorsImpl extends AbstractISUPParameter implements MCIDRequestIndicators {

    private static final int _TURN_ON = 1;
    private static final int _TURN_OFF = 0;

    private boolean mcidRequestIndicator;
    private boolean holdingIndicator;

    public MCIDRequestIndicatorsImpl(byte[] b) throws ParameterException {
        super();
        decode(b);
    }

    public MCIDRequestIndicatorsImpl() {
        super();

    }

    public MCIDRequestIndicatorsImpl(boolean mcidRequest, boolean holdingRequested) {
        super();
        this.mcidRequestIndicator = mcidRequest;
        this.holdingIndicator = holdingRequested;
    }

    public int decode(byte[] b) throws ParameterException {
        if (b == null || b.length != 1) {
            throw new ParameterException("byte[] must  not be null and length must  be 1");
        }

        this.mcidRequestIndicator = (b[0] & 0x01) == _TURN_ON;
        this.holdingIndicator = ((b[0] >> 1) & 0x01) == _TURN_ON;
        return 1;
    }

    public byte[] encode() throws ParameterException {
        int b0 = 0;

        b0 |= (this.mcidRequestIndicator ? _TURN_ON : _TURN_OFF);
        b0 |= ((this.holdingIndicator ? _TURN_ON : _TURN_OFF)) << 1;

        return new byte[] { (byte) b0 };
    }

    public boolean isMcidRequestIndicator() {
        return mcidRequestIndicator;
    }

    public void setMcidRequestIndicator(boolean mcidRequestIndicator) {
        this.mcidRequestIndicator = mcidRequestIndicator;
    }

    public boolean isHoldingIndicator() {
        return holdingIndicator;
    }

    public void setHoldingIndicator(boolean holdingIndicator) {
        this.holdingIndicator = holdingIndicator;
    }

    public int getCode() {

        return _PARAMETER_CODE;
    }
}
