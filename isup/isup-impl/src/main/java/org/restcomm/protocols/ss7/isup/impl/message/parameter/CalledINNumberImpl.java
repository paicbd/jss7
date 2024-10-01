package org.restcomm.protocols.ss7.isup.impl.message.parameter;

import java.io.ByteArrayInputStream;

import org.restcomm.protocols.ss7.isup.ParameterException;
import org.restcomm.protocols.ss7.isup.message.parameter.CalledINNumber;

/**
 * Start time:13:06:26 2009-04-05<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com"> Bartosz Baranowski </a>
 */
public class CalledINNumberImpl extends CalledNumberImpl implements CalledINNumber {

    /**
     * @param representation
     */
    public CalledINNumberImpl(byte[] representation) throws ParameterException {
        super(representation);

    }

    /**
     * @param bis
     */
    public CalledINNumberImpl(ByteArrayInputStream bis) throws ParameterException {
        super(bis);

    }

    public CalledINNumberImpl() {
        super();

    }

    /**
     * @param natureOfAddresIndicator
     * @param address
     * @param numberingPlanIndicator
     * @param addressRepresentationREstrictedIndicator
     */
    public CalledINNumberImpl(int natureOfAddresIndicator, String address, int numberingPlanIndicator,
            int addressRepresentationREstrictedIndicator) {
        super(natureOfAddresIndicator, address, numberingPlanIndicator, addressRepresentationREstrictedIndicator);

    }

    protected String getPrimitiveName() {
        return "CalledINNumber";
    }

    public int getCode() {

        return _PARAMETER_CODE;
    }
}
