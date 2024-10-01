
package org.restcomm.protocols.ss7.map.service.supplementary;

import javolution.xml.XMLFormat;
import javolution.xml.stream.XMLStreamException;

import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.mobicents.protocols.asn.Tag;
import org.restcomm.protocols.ss7.map.api.MAPException;
import org.restcomm.protocols.ss7.map.api.MAPMessageType;
import org.restcomm.protocols.ss7.map.api.MAPOperationCode;
import org.restcomm.protocols.ss7.map.api.MAPParsingComponentException;
import org.restcomm.protocols.ss7.map.api.MAPParsingComponentExceptionReason;
import org.restcomm.protocols.ss7.map.api.service.supplementary.MAPDialogSupplementary;
import org.restcomm.protocols.ss7.map.api.service.supplementary.UnstructuredSSNotifyResponse;
import org.restcomm.protocols.ss7.map.primitives.MAPAsnPrimitive;

/**
 * @author amit bhayani
 *
 */
public class UnstructuredSSNotifyResponseImpl extends SupplementaryMessageImpl implements UnstructuredSSNotifyResponse, MAPAsnPrimitive {

    public MAPDialogSupplementary getMAPDialog() {
        return (MAPDialogSupplementary) super.getMAPDialog();
    }

    public MAPMessageType getMessageType() {
        return MAPMessageType.unstructuredSSNotify_Response;
    }

    public int getOperationCode() {
        return MAPOperationCode.unstructuredSS_Notify;
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.primitives.MAPAsnPrimitive#getTag()
     */
    public int getTag() throws MAPException {
        return Tag.SEQUENCE;
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.primitives.MAPAsnPrimitive#getTagClass()
     */
    public int getTagClass() {
        return Tag.CLASS_UNIVERSAL;
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.primitives.MAPAsnPrimitive#getIsPrimitive ()
     */
    public boolean getIsPrimitive() {
        return false;
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.primitives.MAPAsnPrimitive#decodeAll(org.mobicents.protocols.asn.AsnInputStream)
     */
    public void decodeAll(AsnInputStream asnInputStream) throws MAPParsingComponentException {
        throw new MAPParsingComponentException("UnstructuredSSNotifyResponseIndication has no MAP message primitive",
                MAPParsingComponentExceptionReason.MistypedParameter);
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.primitives.MAPAsnPrimitive#decodeData(org.mobicents.protocols.asn.AsnInputStream,
     * int)
     */
    public void decodeData(AsnInputStream asnInputStream, int length) throws MAPParsingComponentException {
        throw new MAPParsingComponentException("UnstructuredSSNotifyResponseIndication has no MAP message primitive",
                MAPParsingComponentExceptionReason.MistypedParameter);
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.primitives.MAPAsnPrimitive#encodeAll(org.mobicents.protocols.asn.AsnOutputStream)
     */
    public void encodeAll(AsnOutputStream asnOutputStream) throws MAPException {
        throw new MAPException("UnstructuredSSNotifyResponseIndication has no MAP message primitive");
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.primitives.MAPAsnPrimitive#encodeAll(org.mobicents.protocols.asn.AsnOutputStream,
     * int, int)
     */
    public void encodeAll(AsnOutputStream asnOutputStream, int tagClass, int tag) throws MAPException {
        throw new MAPException("UnstructuredSSNotifyResponseIndication has no MAP message primitive");
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.primitives.MAPAsnPrimitive#encodeData(org.mobicents.protocols.asn.AsnOutputStream)
     */
    public void encodeData(AsnOutputStream asnOutputStream) throws MAPException {
        throw new MAPException("UnstructuredSSNotifyResponseIndication has no MAP message primitive");
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("UnstructuredSSNotifyResponse [");
        if (this.getMAPDialog() != null) {
            sb.append("DialogId=").append(this.getMAPDialog().getLocalDialogId());
        }
        sb.append(super.toString());
        sb.append("]");

        return sb.toString();
    }

    protected static final XMLFormat<UnstructuredSSNotifyResponseImpl> UNSTRUCTURED_SS_NOTIFY_RESPONSE_XML = new XMLFormat<UnstructuredSSNotifyResponseImpl>(
            UnstructuredSSNotifyResponseImpl.class) {

        @Override
        public void read(javolution.xml.XMLFormat.InputElement xml, UnstructuredSSNotifyResponseImpl ussdMessage)
                throws XMLStreamException {
            USSD_MESSAGE_XML.read(xml, ussdMessage);
        }

        @Override
        public void write(UnstructuredSSNotifyResponseImpl ussdMessage, javolution.xml.XMLFormat.OutputElement xml)
                throws XMLStreamException {
            USSD_MESSAGE_XML.write(ussdMessage, xml);
        }
    };
}
