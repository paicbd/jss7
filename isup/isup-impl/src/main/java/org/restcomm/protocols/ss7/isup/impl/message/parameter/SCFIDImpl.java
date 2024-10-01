package org.restcomm.protocols.ss7.isup.impl.message.parameter;

import java.io.ByteArrayInputStream;

import org.restcomm.protocols.ss7.isup.ParameterException;
import org.restcomm.protocols.ss7.isup.message.parameter.SCFID;

/**
 * Start time:12:48:19 2009-04-05<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com"> Bartosz Baranowski </a>
 *
 */
public class SCFIDImpl extends NetworkRoutingNumberImpl implements SCFID {

    // FIXME: Q.1218 - oleg is this correct? :
    // http://www.itu.int/ITU-T/asn1/database/itu-t/q/q1238.2/2000/IN-CS3-SSF-SCF-datatypes.html
    public SCFIDImpl() {
        super();

    }

    public SCFIDImpl(byte[] representation) throws ParameterException {
        super(representation);

    }

    public SCFIDImpl(ByteArrayInputStream bis) throws ParameterException {
        super(bis);

    }

    public SCFIDImpl(String address, int numberingPlanIndicator, int natureOfAddressIndicator) {
        super(address, numberingPlanIndicator, natureOfAddressIndicator);

    }

    public int getCode() {

        return SCFID._PARAMETER_CODE;
    }

}
