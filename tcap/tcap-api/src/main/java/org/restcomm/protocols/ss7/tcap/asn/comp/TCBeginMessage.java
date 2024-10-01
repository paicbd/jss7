
package org.restcomm.protocols.ss7.tcap.asn.comp;

import org.mobicents.protocols.asn.Tag;
import org.restcomm.protocols.ss7.tcap.asn.DialogPortion;
import org.restcomm.protocols.ss7.tcap.asn.Encodable;

/**
 * @author baranowb
 *
 */
public interface TCBeginMessage extends Encodable {

    int _TAG = 0x02;
    boolean _TAG_PC_PRIMITIVE = false;
    int _TAG_CLASS = Tag.CLASS_APPLICATION;

    int _TAG_OTX = 0x08;
    boolean _TAG_OTX_PC_PRIMITIVE = true;
    int _TAG_CLASS_OTX = Tag.CLASS_APPLICATION;

    // mandatory
    byte[] getOriginatingTransactionId();

    void setOriginatingTransactionId(byte[] t);

    // opt FIXME: make this External?
    DialogPortion getDialogPortion();

    void setDialogPortion(DialogPortion dialogPortion);

    // opt
    Component[] getComponent();

    void setComponent(Component[] component);

}
