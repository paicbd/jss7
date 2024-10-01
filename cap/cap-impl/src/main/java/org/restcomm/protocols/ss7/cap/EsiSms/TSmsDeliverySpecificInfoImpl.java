
package org.restcomm.protocols.ss7.cap.EsiSms;

import java.io.IOException;

import org.mobicents.protocols.asn.AsnException;
import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.restcomm.protocols.ss7.cap.api.CAPException;
import org.restcomm.protocols.ss7.cap.api.CAPParsingComponentException;
import org.restcomm.protocols.ss7.cap.api.EsiSms.TSmsDeliverySpecificInfo;
import org.restcomm.protocols.ss7.cap.primitives.SequenceBase;
import org.restcomm.protocols.ss7.inap.api.INAPParsingComponentException;
import org.restcomm.protocols.ss7.map.api.MAPParsingComponentException;

/**
 *
 * @author Lasith Waruna Perera
 *
 */
public class TSmsDeliverySpecificInfoImpl extends SequenceBase implements TSmsDeliverySpecificInfo {

    public TSmsDeliverySpecificInfoImpl() {
        super("TSmsDeliverySpecificInfo");
    }

    @Override
    protected void _decode(AsnInputStream asnInputStream, int length) throws CAPParsingComponentException, IOException,
            AsnException, MAPParsingComponentException, INAPParsingComponentException {

    }

    @Override
    public void encodeData(AsnOutputStream asnOutputStream) throws CAPException {

    }

}
