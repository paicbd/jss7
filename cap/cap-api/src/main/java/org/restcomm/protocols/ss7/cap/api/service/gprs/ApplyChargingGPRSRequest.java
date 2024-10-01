
package org.restcomm.protocols.ss7.cap.api.service.gprs;

import org.restcomm.protocols.ss7.cap.api.service.gprs.primitive.ChargingCharacteristics;
import org.restcomm.protocols.ss7.cap.api.service.gprs.primitive.PDPID;

/**
 *
 applyChargingGPRS OPERATION ::= { ARGUMENT ApplyChargingGPRSArg RETURN RESULT FALSE ERRORS {missingParameter |
 * unexpectedComponentSequence | unexpectedParameter | unexpectedDataValue | parameterOutOfRange | systemFailure | taskRefused |
 * unknownPDPID} CODE opcode-applyChargingGPRS} -- Direction gsmSCF -> gprsSSF, Timer Tacg -- This operation is used for
 * interacting from the gsmSCF with the gprsSSF CSE-controlled -- GPRS session or PDP Context charging mechanism.
 *
 * ApplyChargingGPRSArg ::= SEQUENCE { chargingCharacteristics [0] ChargingCharacteristics, tariffSwitchInterval [1] INTEGER
 * (1..86400) OPTIONAL, pDPID [2] PDPID OPTIONAL, ... } -- tariffSwitchInterval is measured in 1 second units.
 *
 *
 *
 * @author sergey vetyutnev
 *
 */
public interface ApplyChargingGPRSRequest extends GprsMessage {

    ChargingCharacteristics getChargingCharacteristics();

    Integer getTariffSwitchInterval();

    PDPID getPDPID();

}