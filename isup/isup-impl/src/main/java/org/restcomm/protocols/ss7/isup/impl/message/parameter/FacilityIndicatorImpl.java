package org.restcomm.protocols.ss7.isup.impl.message.parameter;

import org.restcomm.protocols.ss7.isup.ParameterException;
import org.restcomm.protocols.ss7.isup.message.parameter.FacilityIndicator;

/**
 * Start time:11:50:01 2009-03-31<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com"> Bartosz Baranowski </a>
 */
public class FacilityIndicatorImpl extends AbstractISUPParameter implements FacilityIndicator {

    private byte facilityIndicator = 0;

    public FacilityIndicatorImpl(byte[] b) throws ParameterException {
        super();
        decode(b);
    }

    public FacilityIndicatorImpl() {
        super();

    }

    public FacilityIndicatorImpl(byte facilityIndicator) {
        super();
        this.facilityIndicator = facilityIndicator;
    }

    public int decode(byte[] b) throws ParameterException {
        if (b == null || b.length != 1) {
            throw new ParameterException("byte[] must not be null or have different size than 1");
        }

        this.facilityIndicator = b[0];
        return 1;
    }

    public byte[] encode() throws ParameterException {
        byte[] b = { (byte) this.facilityIndicator };
        return b;
    }

    public byte getFacilityIndicator() {
        return facilityIndicator;
    }

    public void setFacilityIndicator(byte facilityIndicator) {
        this.facilityIndicator = facilityIndicator;
    }

    public int getCode() {

        return _PARAMETER_CODE;
    }
}
