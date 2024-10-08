
package org.restcomm.protocols.ss7.map.service.supplementary;

import java.io.IOException;

import javolution.xml.XMLFormat;
import javolution.xml.stream.XMLStreamException;

import org.mobicents.protocols.asn.AsnException;
import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.mobicents.protocols.asn.Tag;
import org.restcomm.protocols.ss7.map.api.MAPException;
import org.restcomm.protocols.ss7.map.api.MAPMessageType;
import org.restcomm.protocols.ss7.map.api.MAPOperationCode;
import org.restcomm.protocols.ss7.map.api.MAPParsingComponentException;
import org.restcomm.protocols.ss7.map.api.MAPParsingComponentExceptionReason;
import org.restcomm.protocols.ss7.map.api.datacoding.CBSDataCodingScheme;
import org.restcomm.protocols.ss7.map.api.primitives.AlertingPattern;
import org.restcomm.protocols.ss7.map.api.primitives.ISDNAddressString;
import org.restcomm.protocols.ss7.map.api.primitives.USSDString;
import org.restcomm.protocols.ss7.map.api.service.supplementary.ProcessUnstructuredSSRequest;
import org.restcomm.protocols.ss7.map.datacoding.CBSDataCodingSchemeImpl;
import org.restcomm.protocols.ss7.map.primitives.AlertingPatternImpl;
import org.restcomm.protocols.ss7.map.primitives.ISDNAddressStringImpl;
import org.restcomm.protocols.ss7.map.primitives.USSDStringImpl;

/**
 *
 * @author amit bhayani
 * @author sergey vetyutnev
 *
 */
public class ProcessUnstructuredSSRequestImpl extends SupplementaryMessageImpl implements ProcessUnstructuredSSRequest {

    private static final String MSISDN = "msisdn";
    private static final String ALERTING_PATTERN = "alertingPattern";

    private static final int _TAG_MSISDN = 0;

    private ISDNAddressString msisdnAddressString = null;
    private AlertingPattern alertingPattern = null;

    public ProcessUnstructuredSSRequestImpl() {
        super();
    }

    /**
     * @param ussdDataCodingSch
     * @param ussdString
     * @param alertingPattern
     * @param msisdnAddressString
     */
    public ProcessUnstructuredSSRequestImpl(CBSDataCodingScheme ussdDataCodingSch, USSDString ussdString,
            AlertingPattern alertingPattern, ISDNAddressString msisdnAddressString) {
        super(ussdDataCodingSch, ussdString);
        this.alertingPattern = alertingPattern;
        this.msisdnAddressString = msisdnAddressString;
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.api.service.supplementary.
     * ProcessUnstructuredSSRequestIndication#getMSISDNAddressString()
     */
    public ISDNAddressString getMSISDNAddressString() {
        return this.msisdnAddressString;
    }

    public void setMSISDNAddressString(ISDNAddressString msisdnAddressString) {
        this.msisdnAddressString = msisdnAddressString;
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.api.service.supplementary.
     * ProcessUnstructuredSSRequestIndication#getAlertingPattern()
     */
    public AlertingPattern getAlertingPattern() {
        return this.alertingPattern;
    }

    public MAPMessageType getMessageType() {
        return MAPMessageType.processUnstructuredSSRequest_Request;
    }

    public int getOperationCode() {
        return MAPOperationCode.processUnstructuredSS_Request;
    }

    public int getTag() throws MAPException {
        return Tag.SEQUENCE;
    }

    public int getTagClass() {
        return Tag.CLASS_UNIVERSAL;
    }

    public boolean getIsPrimitive() {
        return false;
    }

    public void decodeAll(AsnInputStream asnInputStream) throws MAPParsingComponentException {
        try {
            int length = asnInputStream.readLength();
            this._decode(asnInputStream, length);
        } catch (IOException e) {
            throw new MAPParsingComponentException("IOException when decoding ProcessUnstructuredSSRequestIndication: "
                    + e.getMessage(), e, MAPParsingComponentExceptionReason.MistypedParameter);
        } catch (AsnException e) {
            throw new MAPParsingComponentException("AsnException when decoding ProcessUnstructuredSSRequestIndication: "
                    + e.getMessage(), e, MAPParsingComponentExceptionReason.MistypedParameter);
        }
    }

    public void decodeData(AsnInputStream asnInputStream, int length) throws MAPParsingComponentException {
        try {
            this._decode(asnInputStream, length);
        } catch (IOException e) {
            throw new MAPParsingComponentException("IOException when decoding ProcessUnstructuredSSRequestIndication: "
                    + e.getMessage(), e, MAPParsingComponentExceptionReason.MistypedParameter);
        } catch (AsnException e) {
            throw new MAPParsingComponentException("AsnException when decoding ProcessUnstructuredSSRequestIndication: "
                    + e.getMessage(), e, MAPParsingComponentExceptionReason.MistypedParameter);
        }
    }

    private void _decode(AsnInputStream asnInputStream, int length) throws MAPParsingComponentException, IOException, AsnException {
        AsnInputStream ais = asnInputStream.readSequenceStreamData(length);

        int tag = ais.readTag();

        // ussd-DataCodingScheme USSD-DataCodingScheme
        if (ais.getTagClass() != Tag.CLASS_UNIVERSAL || !ais.isTagPrimitive())
            throw new MAPParsingComponentException(
                    "Error while decoding ProcessUnstructuredSSRequestIndication: Parameter ussd-DataCodingScheme bad tag class or not primitive",
                    MAPParsingComponentExceptionReason.MistypedParameter);

        this.ussdDataCodingSch = new CBSDataCodingSchemeImpl(ais.readOctetString()[0]);

        tag = ais.readTag();

        // ussd-String USSD-String
        if (ais.getTagClass() != Tag.CLASS_UNIVERSAL || !ais.isTagPrimitive())
            throw new MAPParsingComponentException(
                    "Error while decoding ProcessUnstructuredSSRequestIndication: Parameter ussd-String bad tag class or not primitive",
                    MAPParsingComponentExceptionReason.MistypedParameter);

        this.ussdString = new USSDStringImpl(this.ussdDataCodingSch);
        ((USSDStringImpl) this.ussdString).decodeAll(ais);

        while (true) {
            if (ais.available() == 0)
                break;

            tag = ais.readTag();

            switch (tag) {
                case _TAG_MSISDN:
                    // msisdn [0] ISDN-AddressString OPTIONAL
                    if (ais.getTagClass() != Tag.CLASS_CONTEXT_SPECIFIC || !ais.isTagPrimitive())
                        throw new MAPParsingComponentException(
                                "Error while decoding ProcessUnstructuredSSRequestIndication: Parameter msisdn bad tag class or not primitive",
                                MAPParsingComponentExceptionReason.MistypedParameter);

                    this.msisdnAddressString = new ISDNAddressStringImpl();
                    ((ISDNAddressStringImpl) this.msisdnAddressString).decodeAll(ais);
                    break;
                default:
                    // alertingPattern AlertingPattern OPTIONAL
                    if (tag == Tag.STRING_OCTET && ais.getTagClass() == Tag.CLASS_UNIVERSAL && ais.isTagPrimitive()) {
                        this.alertingPattern = new AlertingPatternImpl();
                        ((AlertingPatternImpl) this.alertingPattern).decodeAll(ais);
                    } else {
                        ais.advanceElement();
                    }
                    break;
            }
        }

    }

    public void encodeAll(AsnOutputStream asnOutputStream) throws MAPException {
        this.encodeAll(asnOutputStream, Tag.CLASS_UNIVERSAL, Tag.SEQUENCE);
    }

    public void encodeAll(AsnOutputStream asnOutputStream, int tagClass, int tag) throws MAPException {
        try {
            asnOutputStream.writeTag(tagClass, false, tag);
            int pos = asnOutputStream.StartContentDefiniteLength();
            this.encodeData(asnOutputStream);
            asnOutputStream.FinalizeContent(pos);
        } catch (AsnException e) {
            throw new MAPException("AsnException when encoding ProcessUnstructuredSSRequestIndication", e);
        }
    }

    public void encodeData(AsnOutputStream asnOutputStream) throws MAPException {
        if (this.ussdString == null)
            throw new MAPException("ussdString must not be null");

        try {
            asnOutputStream.writeOctetString(new byte[] { (byte) this.ussdDataCodingSch.getCode() });

            ((USSDStringImpl) this.ussdString).encodeAll(asnOutputStream);

            if (this.alertingPattern != null) {
                ((AlertingPatternImpl) this.alertingPattern).encodeAll(asnOutputStream);
            }

            if (this.msisdnAddressString != null) {
                ((ISDNAddressStringImpl) this.msisdnAddressString).encodeAll(asnOutputStream, Tag.CLASS_CONTEXT_SPECIFIC, _TAG_MSISDN);
            }
        } catch (IOException e) {
            throw new MAPException("IOException when encoding ProcessUnstructuredSSRequestIndication", e);
        } catch (AsnException e) {
            throw new MAPException("AsnException when encoding ProcessUnstructuredSSRequestIndication", e);
        }
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("ProcessUnstructuredSSRequest [");

        if (this.getMAPDialog() != null) {
            sb.append("DialogId=").append(this.getMAPDialog().getLocalDialogId());
        }

        sb.append(super.toString());

        if (alertingPattern != null) {
            sb.append(", alertingPattern=");
            sb.append(alertingPattern.toString());
        }
        if (msisdnAddressString != null) {
            sb.append(", msisdn=");
            sb.append(msisdnAddressString.toString());
        }

        sb.append("]");

        return sb.toString();
    }

    /**
     * XML Serialization/Deserialization
     */
    protected static final XMLFormat<ProcessUnstructuredSSRequestImpl> PROCESS_UNSTRUCTURED_SS_REQUEST_XML = new XMLFormat<ProcessUnstructuredSSRequestImpl>(
            ProcessUnstructuredSSRequestImpl.class) {

        @Override
        public void read(javolution.xml.XMLFormat.InputElement xml, ProcessUnstructuredSSRequestImpl ussdMessage)
                throws XMLStreamException {
            USSD_MESSAGE_XML.read(xml, ussdMessage);
            ussdMessage.msisdnAddressString = xml.get(MSISDN, ISDNAddressStringImpl.class);
            ussdMessage.alertingPattern = xml.get(ALERTING_PATTERN, AlertingPatternImpl.class);

        }

        @Override
        public void write(ProcessUnstructuredSSRequestImpl ussdMessage, javolution.xml.XMLFormat.OutputElement xml)
                throws XMLStreamException {
            USSD_MESSAGE_XML.write(ussdMessage, xml);
            xml.add(((ISDNAddressStringImpl) ussdMessage.msisdnAddressString), MSISDN, ISDNAddressStringImpl.class);
            xml.add(((AlertingPatternImpl) ussdMessage.alertingPattern), ALERTING_PATTERN, AlertingPatternImpl.class);
        }
    };

}
