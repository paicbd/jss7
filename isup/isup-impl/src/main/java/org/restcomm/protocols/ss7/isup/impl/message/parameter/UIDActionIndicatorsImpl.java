package org.restcomm.protocols.ss7.isup.impl.message.parameter;

import org.restcomm.protocols.ss7.isup.ParameterException;
import org.restcomm.protocols.ss7.isup.message.parameter.UIDActionIndicators;

/**
 * Start time:13:49:42 2009-04-05<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com"> Bartosz Baranowski </a>
 *
 */
public class UIDActionIndicatorsImpl extends AbstractISUPParameter implements UIDActionIndicators {

    private static final int _TURN_ON = 1;
    private static final int _TURN_OFF = 0;

    private byte[] udiActionIndicators = null;

    public UIDActionIndicatorsImpl(byte[] udiActionIndicators) throws ParameterException {
        super();
        decode(udiActionIndicators);
    }

    public UIDActionIndicatorsImpl() {
        super();

    }

    public int decode(byte[] b) throws ParameterException {
        try {
            setUdiActionIndicators(b);
        } catch (Exception e) {
            throw new ParameterException(e);
        }
        return b.length;
    }

    public byte[] encode() throws ParameterException {
        for (int index = 0; index < this.udiActionIndicators.length; index++) {
            this.udiActionIndicators[index] = (byte) (this.udiActionIndicators[index] & 0x7F);
        }

        this.udiActionIndicators[this.udiActionIndicators.length - 1] = (byte) ((this.udiActionIndicators[this.udiActionIndicators.length - 1]) | (0x01 << 7));
        return this.udiActionIndicators;
    }

    public byte[] getUdiActionIndicators() {
        return udiActionIndicators;
    }

    public void setUdiActionIndicators(byte[] udiActionIndicators) {
        if (udiActionIndicators == null || udiActionIndicators.length == 0) {
            throw new IllegalArgumentException("byte[] must not be null and length must be greater than 0");
        }
        this.udiActionIndicators = udiActionIndicators;
    }

    public byte createUIDAction(boolean TCII, boolean T9) {
        byte b = (byte) (TCII ? _TURN_ON : _TURN_OFF);
        b |= (T9 ? _TURN_ON : _TURN_OFF) << 1;
        return b;
    }

    public boolean getT9Indicator(byte b) {
        return ((b >> 1) & 0x01) == _TURN_ON;
    }

    public boolean getTCIIndicator(byte b) {
        return ((b >> 1) & 0x01) == _TURN_ON;
    }

    public int getCode() {

        return _PARAMETER_CODE;
    }
}
