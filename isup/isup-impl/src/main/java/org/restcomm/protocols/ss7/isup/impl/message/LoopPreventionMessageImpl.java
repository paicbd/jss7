package org.restcomm.protocols.ss7.isup.impl.message;

import java.util.Map;
import java.util.Set;

import org.restcomm.protocols.ss7.isup.ISUPParameterFactory;
import org.restcomm.protocols.ss7.isup.ParameterException;
import org.restcomm.protocols.ss7.isup.impl.message.parameter.AbstractISUPParameter;
import org.restcomm.protocols.ss7.isup.impl.message.parameter.MessageTypeImpl;
import org.restcomm.protocols.ss7.isup.message.LoopPreventionMessage;
import org.restcomm.protocols.ss7.isup.message.parameter.CallTransferReference;
import org.restcomm.protocols.ss7.isup.message.parameter.LoopPreventionIndicators;
import org.restcomm.protocols.ss7.isup.message.parameter.MessageCompatibilityInformation;
import org.restcomm.protocols.ss7.isup.message.parameter.MessageName;
import org.restcomm.protocols.ss7.isup.message.parameter.MessageType;
import org.restcomm.protocols.ss7.isup.message.parameter.ParameterCompatibilityInformation;

/**
 * Start time:00:05:02 2009-09-07<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com">Bartosz Baranowski </a>
 */
public class LoopPreventionMessageImpl extends ISUPMessageImpl implements LoopPreventionMessage {

    public static final MessageType _MESSAGE_TYPE = new MessageTypeImpl(MessageName.LoopPrevention);
    private static final int _MANDATORY_VAR_COUNT = 0;
    private static final boolean _HAS_MANDATORY = true;
    private static final boolean _OPTIONAL_POSSIBLE = true;

    static final int _INDEX_F_MessageType = 0;

    static final int _INDEX_O_MessageCompatibilityInformation = 0;
    static final int _INDEX_O_ParameterCompatibilityInformation = 1;
    static final int _INDEX_O_CallTransferReference = 2;
    static final int _INDEX_O_LoopPreventionIndicators = 3;
    static final int _INDEX_O_EndOfOptionalParameters = 4;

    /**
     *
     * @param source
     * @throws ParameterException
     */
    public LoopPreventionMessageImpl(Set<Integer> mandatoryCodes, Set<Integer> mandatoryVariableCodes, Set<Integer> optionalCodes,
            Map<Integer, Integer> mandatoryCode2Index, Map<Integer, Integer> mandatoryVariableCode2Index,
            Map<Integer, Integer> optionalCode2Index) {
        super(mandatoryCodes, mandatoryVariableCodes, optionalCodes, mandatoryCode2Index, mandatoryVariableCode2Index,
                optionalCode2Index);
        super.f_Parameters.put(_INDEX_F_MessageType, this.getMessageType());
        super.o_Parameters.put(_INDEX_O_EndOfOptionalParameters, _END_OF_OPTIONAL_PARAMETERS);
    }


    protected void decodeMandatoryVariableBody(ISUPParameterFactory parameterFactory, byte[] parameterBody, int parameterIndex)
            throws ParameterException {
    }

    protected void decodeOptionalBody(ISUPParameterFactory parameterFactory, byte[] parameterBody, byte parameterCode)
            throws ParameterException {
        switch (parameterCode & 0xFF) {
            case MessageCompatibilityInformation._PARAMETER_CODE:
                MessageCompatibilityInformation mci = parameterFactory.createMessageCompatibilityInformation();
                ((AbstractISUPParameter) mci).decode(parameterBody);
                this.setMessageCompatibilityInformation(mci);
                break;
            case ParameterCompatibilityInformation._PARAMETER_CODE:
                ParameterCompatibilityInformation pci = parameterFactory.createParameterCompatibilityInformation();
                ((AbstractISUPParameter) pci).decode(parameterBody);
                this.setParameterCompatibilityInformation(pci);
                break;
            case CallTransferReference._PARAMETER_CODE:
                CallTransferReference ro = parameterFactory.createCallTransferReference();
                ((AbstractISUPParameter) ro).decode(parameterBody);
                this.setCallTransferReference(ro);
                break;
            case LoopPreventionIndicators._PARAMETER_CODE:
                LoopPreventionIndicators sa = parameterFactory.createLoopPreventionIndicators();
                ((AbstractISUPParameter) sa).decode(parameterBody);
                this.setLoopPreventionIndicators(sa);
                break;
            default:
                throw new ParameterException("Unrecognized parameter code for optional part: " + parameterCode);
        }

    }

    public MessageType getMessageType() {
        return _MESSAGE_TYPE;
    }

    protected int getNumberOfMandatoryVariableLengthParameters() {
        return _MANDATORY_VAR_COUNT;
    }

    public boolean hasAllMandatoryParameters() {
        return _HAS_MANDATORY;
    }

    protected boolean optionalPartIsPossible() {
        return _OPTIONAL_POSSIBLE;
    }

    @Override
    public MessageCompatibilityInformation getMessageCompatibilityInformation() {
        return (MessageCompatibilityInformation) super.o_Parameters.get(_INDEX_O_MessageCompatibilityInformation);
    }

    @Override
    public void setMessageCompatibilityInformation(MessageCompatibilityInformation mci) {
        super.o_Parameters.put(_INDEX_O_MessageCompatibilityInformation,mci);
    }

    @Override
    public ParameterCompatibilityInformation getParameterCompatibilityInformation() {
        return (ParameterCompatibilityInformation) super.o_Parameters.get(_INDEX_O_ParameterCompatibilityInformation);
    }

    @Override
    public void setParameterCompatibilityInformation(ParameterCompatibilityInformation pci) {
        super.o_Parameters.put(_INDEX_O_ParameterCompatibilityInformation,pci);
    }

    @Override
    public CallTransferReference getCallTransferReference() {
        return (CallTransferReference) super.o_Parameters.get(_INDEX_O_CallTransferReference);
    }

    @Override
    public void setCallTransferReference(CallTransferReference ctr) {
        super.o_Parameters.put(_INDEX_O_CallTransferReference,ctr);
    }

    @Override
    public LoopPreventionIndicators getLoopPreventionIndicators() {
        return (LoopPreventionIndicators) super.o_Parameters.get(_INDEX_O_LoopPreventionIndicators);
    }

    @Override
    public void setLoopPreventionIndicators(LoopPreventionIndicators lpi) {
        super.o_Parameters.put(_INDEX_O_LoopPreventionIndicators,lpi);
    }

}
