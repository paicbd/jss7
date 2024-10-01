
package org.restcomm.protocols.ss7.cap.isup;

import java.io.IOException;

import javolution.xml.XMLFormat;
import javolution.xml.stream.XMLStreamException;

import org.mobicents.protocols.asn.AsnException;
import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.mobicents.protocols.asn.Tag;
import org.restcomm.protocols.ss7.cap.api.CAPException;
import org.restcomm.protocols.ss7.cap.api.CAPParsingComponentException;
import org.restcomm.protocols.ss7.cap.api.CAPParsingComponentExceptionReason;
import org.restcomm.protocols.ss7.cap.api.isup.GenericNumberCap;
import org.restcomm.protocols.ss7.cap.primitives.CAPAsnPrimitive;
import org.restcomm.protocols.ss7.isup.ParameterException;
import org.restcomm.protocols.ss7.isup.impl.message.parameter.GenericNumberImpl;
import org.restcomm.protocols.ss7.isup.message.parameter.GenericNumber;

/**
 *
 *
 * @author sergey vetyutnev
 * @author tamas gyorgyey
 */
public class GenericNumberCapImpl implements GenericNumberCap, CAPAsnPrimitive {

    public static final String _PrimitiveName = "GenericNumberCap";

    private static final String ISUP_GENERIC_NUMBER_XML = "genericNumber";

    private byte[] data;

    public GenericNumberCapImpl() {
    }

    public GenericNumberCapImpl(byte[] data) {
        // TODO: should use setData(byte[]), but omitted for now to keep no-throws constructor. Check performed in #encodeData(AsnOutputStream).
        this.data = data;
    }

    public GenericNumberCapImpl(GenericNumber genericNumber) throws CAPException {
        setGenericNumber(genericNumber);
    }

    public void setGenericNumber(GenericNumber genericNumber) throws CAPException {
        if (genericNumber == null)
            throw new CAPException("The genericNumber parameter must not be null");
        try {
            setData(((GenericNumberImpl) genericNumber).encode());
        } catch (ParameterException e) {
            throw new CAPException("ParameterException when encoding genericNumber: " + e.getMessage(), e);
        }
    }

    private void setData(byte[] data) throws CAPException {
        if (data == null)
            throw new CAPException("Generic Number data field must not be null");
        if (data.length < 3 || data.length > 11)
            throw new CAPException("Generic Number data field length must be from 3 to 11 octets. Provided octets: " + data.length);
        this.data = data;
    }

    @Override
    public byte[] getData() {
        return data;
    }

    @Override
    public GenericNumber getGenericNumber() throws CAPException {
        if (this.data == null)
            throw new CAPException("The data has not been filled");

        try {
            GenericNumberImpl ocn = new GenericNumberImpl();
            ocn.decode(this.data);
            return ocn;
        } catch (ParameterException e) {
            throw new CAPException("ParameterException when decoding GenericNumber: " + e.getMessage(), e);
        }
    }

    @Override
    public int getTag() throws CAPException {
        return Tag.STRING_OCTET;
    }

    @Override
    public int getTagClass() {
        return Tag.CLASS_UNIVERSAL;
    }

    @Override
    public boolean getIsPrimitive() {
        return true;
    }

    @Override
    public void decodeAll(AsnInputStream asnInputStream) throws CAPParsingComponentException {

        try {
            int length = asnInputStream.readLength();
            this._decode(asnInputStream, length);
        } catch (IOException e) {
            throw new CAPParsingComponentException("IOException when decoding " + _PrimitiveName + ": " + e.getMessage(), e,
                    CAPParsingComponentExceptionReason.MistypedParameter);
        } catch (AsnException e) {
            throw new CAPParsingComponentException("AsnException when decoding " + _PrimitiveName + ": " + e.getMessage(), e,
                    CAPParsingComponentExceptionReason.MistypedParameter);
        } catch (CAPParsingComponentException e) {
            throw new CAPParsingComponentException("MAPParsingComponentException when decoding " + _PrimitiveName + ": "
                    + e.getMessage(), e, CAPParsingComponentExceptionReason.MistypedParameter);
        }
    }

    @Override
    public void decodeData(AsnInputStream asnInputStream, int length) throws CAPParsingComponentException {

        try {
            this._decode(asnInputStream, length);
        } catch (IOException e) {
            throw new CAPParsingComponentException("IOException when decoding " + _PrimitiveName + ": " + e.getMessage(), e,
                    CAPParsingComponentExceptionReason.MistypedParameter);
        } catch (AsnException e) {
            throw new CAPParsingComponentException("AsnException when decoding " + _PrimitiveName + ": " + e.getMessage(), e,
                    CAPParsingComponentExceptionReason.MistypedParameter);
        } catch (CAPParsingComponentException e) {
            throw new CAPParsingComponentException("MAPParsingComponentException when decoding " + _PrimitiveName + ": "
                    + e.getMessage(), e, CAPParsingComponentExceptionReason.MistypedParameter);
        }
    }

    private void _decode(AsnInputStream asnInputStream, int length) throws CAPParsingComponentException, IOException, AsnException {

        try {
            setData(asnInputStream.readOctetStringData(length));
        } catch (CAPException e) {
            throw new CAPParsingComponentException("Error while decoding " + _PrimitiveName + ": " + e.getMessage(), e,
                    CAPParsingComponentExceptionReason.MistypedParameter);
        }
    }

    @Override
    public void encodeAll(AsnOutputStream asnOutputStream) throws CAPException {
        this.encodeAll(asnOutputStream, this.getTagClass(), this.getTag());
    }

    @Override
    public void encodeAll(AsnOutputStream asnOutputStream, int tagClass, int tag) throws CAPException {

        try {
            asnOutputStream.writeTag(tagClass, true, tag);
            int pos = asnOutputStream.StartContentDefiniteLength();
            this.encodeData(asnOutputStream);
            asnOutputStream.FinalizeContent(pos);
        } catch (AsnException e) {
            throw new CAPException("AsnException when encoding " + _PrimitiveName + ": " + e.getMessage(), e);
        }
    }

    @Override
    public void encodeData(AsnOutputStream asnOutputStream) throws CAPException {

        // note: if GenericNumberCapImpl(byte[]) threw a CAPException for invalid data, we wouldn't have to check here.
        setData(this.data); // reset the same value to perform validity checks

        asnOutputStream.writeOctetStringData(data);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(_PrimitiveName);
        sb.append(" [");

        if (this.data != null) {
            sb.append("data=[");
            sb.append(printDataArr(this.data));
            sb.append("]");
            try {
                GenericNumber gn = this.getGenericNumber();
                sb.append(", ");
                sb.append(gn.toString());
            } catch (CAPException e) {
            }
        }

        sb.append("]");

        return sb.toString();
    }

    private String printDataArr(byte[] arr) {
        StringBuilder sb = new StringBuilder();
        for (int b : arr) {
            sb.append(b);
            sb.append(", ");
        }

        return sb.toString();
    }

    /**
     * XML Serialization/Deserialization
     */
    protected static final XMLFormat<GenericNumberCapImpl> GENERIC_NUMBER_CAP_XML = new XMLFormat<GenericNumberCapImpl>(
            GenericNumberCapImpl.class) {

        @Override
        public void read(javolution.xml.XMLFormat.InputElement xml, GenericNumberCapImpl genericNumber)
                throws XMLStreamException {
            try {
                genericNumber.setGenericNumber(xml.get(ISUP_GENERIC_NUMBER_XML, GenericNumberImpl.class));
            } catch (CAPException e) {
                throw new XMLStreamException(e);
            }
        }

        @Override
        public void write(GenericNumberCapImpl genericNumber, javolution.xml.XMLFormat.OutputElement xml)
                throws XMLStreamException {
            try {
                xml.add(((GenericNumberImpl) genericNumber.getGenericNumber()), ISUP_GENERIC_NUMBER_XML,
                        GenericNumberImpl.class);
            } catch (CAPException e) {
                throw new XMLStreamException(e);
            }
        }
    };
}
