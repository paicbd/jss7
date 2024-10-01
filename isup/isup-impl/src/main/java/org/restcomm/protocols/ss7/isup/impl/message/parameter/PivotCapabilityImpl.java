package org.restcomm.protocols.ss7.isup.impl.message.parameter;

import org.restcomm.protocols.ss7.isup.ParameterException;
import org.restcomm.protocols.ss7.isup.message.parameter.PivotCapability;

/**
 * Start time:15:52:32 2009-04-05<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com"> Bartosz Baranowski </a>
 */
public class PivotCapabilityImpl extends AbstractISUPParameter implements PivotCapability {

    private static final int _TURN_ON = 1;
    private static final int _TURN_OFF = 0;

    private byte[] pivotCapabilities;

    public PivotCapabilityImpl() {
        super();

    }

    public byte[] encode() throws ParameterException {
        for (int index = 0; index < this.pivotCapabilities.length; index++) {
            this.pivotCapabilities[index] = (byte) (this.pivotCapabilities[index] & 0x7F);
        }

        this.pivotCapabilities[this.pivotCapabilities.length - 1] = (byte) ((this.pivotCapabilities[this.pivotCapabilities.length - 1]) | (0x01 << 7));
        return this.pivotCapabilities;
    }

    public int decode(byte[] b) throws ParameterException {

        setPivotCapabilities(b);
        return b.length;
    }

    public byte[] getPivotCapabilities() {
        return pivotCapabilities;
    }

    public void setPivotCapabilities(byte[] pivotCapabilities) {
        if (pivotCapabilities == null || pivotCapabilities.length == 0) {
            throw new IllegalArgumentException("byte[] must not be null and length must be greater than 0");
        }

        this.pivotCapabilities = pivotCapabilities;
    }

    public byte createPivotCapabilityByte(boolean itriNotAllowed, int pivotPossibility) {
        int b = (itriNotAllowed ? _TURN_ON : _TURN_OFF) << 6;
        b |= pivotPossibility & 0x07;

        return (byte) b;

    }

    public boolean getITRINotAllowed(byte b) {
        return ((b >> 6) & 0x01) == _TURN_ON;
    }

    public int getPivotCapability(byte b) {
        return b & 0x07;
    }

    public int getCode() {

        return _PARAMETER_CODE;
    }
}
