package org.restcomm.protocols.ss7.isup.message.parameter;

import org.restcomm.protocols.ss7.isup.message.AddressCompleteMessage;
import org.restcomm.protocols.ss7.isup.message.AnswerMessage;
import org.restcomm.protocols.ss7.isup.message.ApplicationTransportMessage;
import org.restcomm.protocols.ss7.isup.message.BlockingAckMessage;
import org.restcomm.protocols.ss7.isup.message.BlockingMessage;
import org.restcomm.protocols.ss7.isup.message.CallProgressMessage;
import org.restcomm.protocols.ss7.isup.message.ChargeInformationMessage;
import org.restcomm.protocols.ss7.isup.message.CircuitGroupBlockingAckMessage;
import org.restcomm.protocols.ss7.isup.message.CircuitGroupBlockingMessage;
import org.restcomm.protocols.ss7.isup.message.CircuitGroupQueryMessage;
import org.restcomm.protocols.ss7.isup.message.CircuitGroupQueryResponseMessage;
import org.restcomm.protocols.ss7.isup.message.CircuitGroupResetAckMessage;
import org.restcomm.protocols.ss7.isup.message.CircuitGroupResetMessage;
import org.restcomm.protocols.ss7.isup.message.CircuitGroupUnblockingAckMessage;
import org.restcomm.protocols.ss7.isup.message.CircuitGroupUnblockingMessage;
import org.restcomm.protocols.ss7.isup.message.ConfusionMessage;
import org.restcomm.protocols.ss7.isup.message.ConnectMessage;
import org.restcomm.protocols.ss7.isup.message.ContinuityCheckRequestMessage;
import org.restcomm.protocols.ss7.isup.message.ContinuityMessage;
import org.restcomm.protocols.ss7.isup.message.FacilityAcceptedMessage;
import org.restcomm.protocols.ss7.isup.message.FacilityMessage;
import org.restcomm.protocols.ss7.isup.message.FacilityRejectedMessage;
import org.restcomm.protocols.ss7.isup.message.FacilityRequestMessage;
import org.restcomm.protocols.ss7.isup.message.ForwardTransferMessage;
import org.restcomm.protocols.ss7.isup.message.IdentificationRequestMessage;
import org.restcomm.protocols.ss7.isup.message.IdentificationResponseMessage;
import org.restcomm.protocols.ss7.isup.message.InformationMessage;
import org.restcomm.protocols.ss7.isup.message.InformationRequestMessage;
import org.restcomm.protocols.ss7.isup.message.InitialAddressMessage;
import org.restcomm.protocols.ss7.isup.message.LoopPreventionMessage;
import org.restcomm.protocols.ss7.isup.message.LoopbackAckMessage;
import org.restcomm.protocols.ss7.isup.message.NetworkResourceManagementMessage;
import org.restcomm.protocols.ss7.isup.message.OverloadMessage;
import org.restcomm.protocols.ss7.isup.message.PassAlongMessage;
import org.restcomm.protocols.ss7.isup.message.PreReleaseInformationMessage;
import org.restcomm.protocols.ss7.isup.message.ReleaseCompleteMessage;
import org.restcomm.protocols.ss7.isup.message.ReleaseMessage;
import org.restcomm.protocols.ss7.isup.message.ResetCircuitMessage;
import org.restcomm.protocols.ss7.isup.message.ResumeMessage;
import org.restcomm.protocols.ss7.isup.message.SegmentationMessage;
import org.restcomm.protocols.ss7.isup.message.SubsequentAddressMessage;
import org.restcomm.protocols.ss7.isup.message.SubsequentDirectoryNumberMessage;
import org.restcomm.protocols.ss7.isup.message.SuspendMessage;
import org.restcomm.protocols.ss7.isup.message.UnblockingAckMessage;
import org.restcomm.protocols.ss7.isup.message.UnblockingMessage;
import org.restcomm.protocols.ss7.isup.message.UnequippedCICMessage;
import org.restcomm.protocols.ss7.isup.message.UserPartAvailableMessage;
import org.restcomm.protocols.ss7.isup.message.UserPartTestMessage;
import org.restcomm.protocols.ss7.isup.message.UserToUserInformationMessage;

/**
 *
 * @author sergey vetyutnev
 */
public enum MessageName {
    InitialAddress(InitialAddressMessage.MESSAGE_CODE),
    SubsequentAddress(SubsequentAddressMessage.MESSAGE_CODE),
    InformationRequest(InformationRequestMessage.MESSAGE_CODE),
    Information(InformationMessage.MESSAGE_CODE),
    Continuity(ContinuityMessage.MESSAGE_CODE),
    AddressComplete(AddressCompleteMessage.MESSAGE_CODE),
    Connect(ConnectMessage.MESSAGE_CODE),
    ForwardTransfer(ForwardTransferMessage.MESSAGE_CODE),
    Answer(AnswerMessage.MESSAGE_CODE),
    Release(ReleaseMessage.MESSAGE_CODE),
    Suspend(SuspendMessage.MESSAGE_CODE),
    Resume(ResumeMessage.MESSAGE_CODE),
    ReleaseComplete(ReleaseCompleteMessage.MESSAGE_CODE),
    ContinuityCheckRequest(ContinuityCheckRequestMessage.MESSAGE_CODE),
    ResetCircuit(ResetCircuitMessage.MESSAGE_CODE),
    Blocking(BlockingMessage.MESSAGE_CODE),
    Unblocking(UnblockingMessage.MESSAGE_CODE),
    BlockingAck(BlockingAckMessage.MESSAGE_CODE),
    UnblockingAck(UnblockingAckMessage.MESSAGE_CODE),
    CircuitGroupReset(CircuitGroupResetMessage.MESSAGE_CODE),
    CircuitGroupBlocking(CircuitGroupBlockingMessage.MESSAGE_CODE),
    CircuitGroupUnblocking(CircuitGroupUnblockingMessage.MESSAGE_CODE),
    CircuitGroupBlockingAck(CircuitGroupBlockingAckMessage.MESSAGE_CODE),
    CircuitGroupUnblockingAck(CircuitGroupUnblockingAckMessage.MESSAGE_CODE),
    FacilityRequest(FacilityRequestMessage.MESSAGE_CODE),
    FacilityAccepted(FacilityAcceptedMessage.MESSAGE_CODE),
    FacilityRejected(FacilityRejectedMessage.MESSAGE_CODE),
    LoopbackAck(LoopbackAckMessage.MESSAGE_CODE),
    PassAlong(PassAlongMessage.MESSAGE_CODE),
    CircuitGroupResetAck(CircuitGroupResetAckMessage.MESSAGE_CODE),
    CircuitGroupQuery(CircuitGroupQueryMessage.MESSAGE_CODE),
    CircuitGroupQueryResponse(CircuitGroupQueryResponseMessage.MESSAGE_CODE),
    CallProgress(CallProgressMessage.MESSAGE_CODE),
    UserToUserInformation(UserToUserInformationMessage.MESSAGE_CODE),
    UnequippedCIC(UnequippedCICMessage.MESSAGE_CODE),
    Confusion(ConfusionMessage.MESSAGE_CODE),
    Overload(OverloadMessage.MESSAGE_CODE),
    ChargeInformation(ChargeInformationMessage.MESSAGE_CODE),
    NetworkResourceManagement(NetworkResourceManagementMessage.MESSAGE_CODE),
    Facility(FacilityMessage.MESSAGE_CODE),
    UserPartTest(UserPartTestMessage.MESSAGE_CODE),
    UserPartAvailable(UserPartAvailableMessage.MESSAGE_CODE),
    IdentificationRequest(IdentificationRequestMessage.MESSAGE_CODE),
    IdentificationResponse(IdentificationResponseMessage.MESSAGE_CODE),
    Segmentation(SegmentationMessage.MESSAGE_CODE),
    LoopPrevention(LoopPreventionMessage.MESSAGE_CODE),
    ApplicationTransport(ApplicationTransportMessage.MESSAGE_CODE),
    PreReleaseInformation(PreReleaseInformationMessage.MESSAGE_CODE),
    SubsequentDirectoryNumber(SubsequentDirectoryNumberMessage.MESSAGE_CODE);

    private int code;

    private MessageName(int code) {
        this.code = code;
    }

    public int getCode() {
        return code;
    }

}
