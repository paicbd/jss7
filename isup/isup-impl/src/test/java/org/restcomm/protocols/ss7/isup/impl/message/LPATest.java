package org.restcomm.protocols.ss7.isup.impl.message;

import org.restcomm.protocols.ss7.isup.message.ISUPMessage;
import org.restcomm.protocols.ss7.isup.message.LoopbackAckMessage;

/**
 * Start time:15:07:07 2009-07-17<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com"> Bartosz Baranowski </a>
 */
public class LPATest extends MessageHarness {

    protected byte[] getDefaultBody() {
        // FIXME: for now we strip MTP part
        byte[] message = {

        0x0C, (byte) 0x0B, LoopbackAckMessage.MESSAGE_CODE

        };

        return message;
    }

    protected ISUPMessage getDefaultMessage() {
        return super.messageFactory.createLPA();
    }
}
