
package org.restcomm.protocols.ss7.cap.gap;

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
import org.restcomm.protocols.ss7.cap.api.gap.BasicGapCriteria;
import org.restcomm.protocols.ss7.cap.api.gap.CompoundCriteria;
import org.restcomm.protocols.ss7.cap.api.gap.GapCriteria;
import org.restcomm.protocols.ss7.cap.primitives.CAPAsnPrimitive;

/**
 *
 * @author <a href="mailto:bartosz.krok@pro-ids.com"> Bartosz Krok (ProIDS sp. z o.o.)</a>
 */
public class GapCriteriaImpl implements GapCriteria, CAPAsnPrimitive {

    private static final String BASIC_GAP_CRITERIA = "basicGapCriteria";
    private static final String COMPOUND_CRITERIA = "compoundCriteria";

    public static final String _PrimitiveName = "GapCriteria";

    private BasicGapCriteria basicGapCriteria;
    private CompoundCriteria compoundCriteria;

    public GapCriteriaImpl() {
    }

    public GapCriteriaImpl(BasicGapCriteria basicGapCriteria) {
        this.basicGapCriteria = basicGapCriteria;
    }

    public GapCriteriaImpl(CompoundCriteria compoundCriteria) {
        this.compoundCriteria = compoundCriteria;
    }

    public BasicGapCriteria getBasicGapCriteria() {
        return basicGapCriteria;
    }

    public CompoundCriteria getCompoundGapCriteria() {
        return compoundCriteria;
    }

    public int getTag() throws CAPException {
        if (basicGapCriteria != null) {
            return ((BasicGapCriteriaImpl) basicGapCriteria).getTag();
        } else if (compoundCriteria != null) {
            return ((CompoundCriteriaImpl) compoundCriteria).getTag();
        }

        throw new CAPException("Error while encoding " + _PrimitiveName + ": no choice is specified");
    }

    public int getTagClass() {
        if (basicGapCriteria != null) {
            return ((BasicGapCriteriaImpl) basicGapCriteria).getTagClass();
        } else if (compoundCriteria != null) {
            return ((CompoundCriteriaImpl) compoundCriteria).getTagClass();
        }
        return Tag.CLASS_CONTEXT_SPECIFIC;
    }

    public boolean getIsPrimitive() {
        if (basicGapCriteria != null) {
            return ((BasicGapCriteriaImpl) basicGapCriteria).getIsPrimitive();
        } else if (compoundCriteria != null) {
            return ((CompoundCriteriaImpl) compoundCriteria).getIsPrimitive();
        }
        return false;
    }

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
        }
    }

    public void decodeData(AsnInputStream asnInputStream, int length) throws CAPParsingComponentException {

        try {
            this._decode(asnInputStream, length);
        } catch (IOException e) {
            throw new CAPParsingComponentException("IOException when decoding " + _PrimitiveName + ": " + e.getMessage(), e,
                    CAPParsingComponentExceptionReason.MistypedParameter);
        } catch (AsnException e) {
            throw new CAPParsingComponentException("AsnException when decoding " + _PrimitiveName + ": " + e.getMessage(), e,
                    CAPParsingComponentExceptionReason.MistypedParameter);
        }
    }

    private void _decode(AsnInputStream asnInputStream, int length) throws CAPParsingComponentException, IOException, AsnException {
        this.basicGapCriteria = null;
        this.compoundCriteria = null;

        if (asnInputStream.getTagClass() == Tag.CLASS_CONTEXT_SPECIFIC) {
            basicGapCriteria = new BasicGapCriteriaImpl();
            ((BasicGapCriteriaImpl) basicGapCriteria).decodeData(asnInputStream, length);
        } else if (asnInputStream.getTagClass() == Tag.CLASS_UNIVERSAL) {
            this.compoundCriteria = new CompoundCriteriaImpl();
            ((CompoundCriteriaImpl) compoundCriteria).decodeData(asnInputStream, length);
        } else {
            throw new CAPParsingComponentException("Error while decoding " + _PrimitiveName + ": bad choice tagClass",
                    CAPParsingComponentExceptionReason.MistypedParameter);
        }

    }

    public void encodeAll(AsnOutputStream asnOutputStream) throws CAPException {

        this.encodeAll(asnOutputStream, this.getTagClass(), this.getTag());
    }

    public void encodeAll(AsnOutputStream asnOutputStream, int tagClass, int tag) throws CAPException {

        try {
            asnOutputStream.writeTag(tagClass, this.getIsPrimitive(), tag);
            int pos = asnOutputStream.StartContentDefiniteLength();
            this.encodeData(asnOutputStream);
            asnOutputStream.FinalizeContent(pos);
        } catch (AsnException e) {
            throw new CAPException("AsnException when encoding " + _PrimitiveName + ": " + e.getMessage(), e);
        }
    }

    public void encodeData(AsnOutputStream asnOutputStream) throws CAPException {

        if ((this.basicGapCriteria == null && this.compoundCriteria == null) || (this.basicGapCriteria != null && this.compoundCriteria != null)) {
            throw new CAPException("Error while decoding " + _PrimitiveName + ": One and only one choice must be selected");
        }

        try {
            if (basicGapCriteria != null) {
                ((BasicGapCriteriaImpl) basicGapCriteria).encodeData(asnOutputStream);

            } else if (compoundCriteria != null) {
                ((CompoundCriteriaImpl) compoundCriteria).encodeData(asnOutputStream);
            }
        } catch (CAPException e) {
            throw new CAPException("CAPException when encoding " + _PrimitiveName + ": " + e.getMessage(), e);
        }
    }

    protected static final XMLFormat<GapCriteriaImpl> GAP_CRITERIA_XML = new XMLFormat<GapCriteriaImpl>(GapCriteriaImpl.class) {

        @Override
        public void read(javolution.xml.XMLFormat.InputElement xml, GapCriteriaImpl gapCriteria) throws XMLStreamException {
            gapCriteria.basicGapCriteria = xml.get(BASIC_GAP_CRITERIA, BasicGapCriteriaImpl.class);
            gapCriteria.compoundCriteria = xml.get(COMPOUND_CRITERIA, CompoundCriteriaImpl.class);
        }

        @Override
        public void write(GapCriteriaImpl gapCriteria, javolution.xml.XMLFormat.OutputElement xml) throws XMLStreamException {
            if (gapCriteria.basicGapCriteria != null) {
                xml.add((BasicGapCriteriaImpl) gapCriteria.basicGapCriteria, BASIC_GAP_CRITERIA, BasicGapCriteriaImpl.class);
            }
            if (gapCriteria.compoundCriteria != null) {
                xml.add((CompoundCriteriaImpl) gapCriteria.compoundCriteria, COMPOUND_CRITERIA, CompoundCriteriaImpl.class);
            }
        }
    };

    @Override
    public String toString() {

        StringBuilder sb = new StringBuilder();
        sb.append(_PrimitiveName);
        sb.append(" [");

        if (basicGapCriteria != null) {
            sb.append("basicGapCriteria=");
            sb.append(basicGapCriteria);
        } else if (compoundCriteria != null) {
            sb.append("compoundCriteria=");
            sb.append(compoundCriteria);
        }

        sb.append("]");

        return sb.toString();
    }

}
