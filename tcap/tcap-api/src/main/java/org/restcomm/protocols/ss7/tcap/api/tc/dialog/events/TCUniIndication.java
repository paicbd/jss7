package org.restcomm.protocols.ss7.tcap.api.tc.dialog.events;

import org.restcomm.protocols.ss7.sccp.parameter.SccpAddress;
import org.restcomm.protocols.ss7.tcap.asn.ApplicationContextName;
import org.restcomm.protocols.ss7.tcap.asn.UserInformation;

/**
 * @author baranowb
 *
 */
public interface TCUniIndication extends DialogIndication {

    // public Byte getQOS();

    // parts from DialogPortion, if present
    ApplicationContextName getApplicationContextName();

    UserInformation getUserInformation();

    SccpAddress getDestinationAddress();

    SccpAddress getOriginatingAddress();
}
