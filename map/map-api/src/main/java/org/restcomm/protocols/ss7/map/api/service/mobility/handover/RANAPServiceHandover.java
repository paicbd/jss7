
package org.restcomm.protocols.ss7.map.api.service.mobility.handover;

import java.io.Serializable;

/**
 *
 RANAP-ServiceHandover ::= OCTET STRING (SIZE (1)) -- Octet contains a complete Service-Handover data type -- as defined in
 * 3GPP TS 25.413, encoded according to the encoding scheme -- mandated by 3GPP TS 25.413 -- Padding bits are included in the
 * least significant bits.
 *
 *
 * @author sergey vetyutnev
 *
 */
public interface RANAPServiceHandover extends Serializable {

    int getData();

}
