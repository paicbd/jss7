package org.restcomm.protocols.ss7.isup.impl.message;

import org.restcomm.protocols.ss7.isup.message.BlockingMessage;
import org.restcomm.protocols.ss7.isup.message.ISUPMessage;

/**
 * Start time:15:07:07 2009-07-17<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com"> Bartosz Baranowski </a>
 */
public class BLOTest extends MessageHarness {

    protected byte[] getDefaultBody() {
        byte[] message = {

        0x0C, (byte) 0x0B, BlockingMessage.MESSAGE_CODE

        };
        return message;
    }

    protected ISUPMessage getDefaultMessage() {
        return super.messageFactory.createBLO(0);
    }
}
