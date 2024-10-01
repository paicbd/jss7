
package org.restcomm.protocols.ss7.map.api.service.mobility.handover;

import java.io.Serializable;

/**
 *
 PermittedIntegrityProtectionAlgorithms ::= OCTET STRING (SIZE (1..9)) -- Octets contain a complete
 * PermittedIntegrityProtectionAlgorithms data type -- as defined in 3GPP TS 25.413, encoded according to the encoding scheme --
 * mandated by 3GPP TS 25.413. -- Padding bits are included, if needed, in the least significant bits of the -- last octet of
 * the octet string.
 *
 *
 * @author sergey vetyutnev
 *
 */
public interface PermittedIntegrityProtectionAlgorithms extends Serializable {

    byte[] getData();

}
