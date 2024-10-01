package org.restcomm.protocols.ss7.isup.impl.message;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

import org.restcomm.protocols.ss7.isup.impl.message.AbstractISUPMessage;
import org.restcomm.protocols.ss7.isup.message.CircuitGroupUnblockingAckMessage;
import org.restcomm.protocols.ss7.isup.message.ISUPMessage;
import org.restcomm.protocols.ss7.isup.message.parameter.CallReference;
import org.restcomm.protocols.ss7.isup.message.parameter.RangeAndStatus;
import org.testng.annotations.Test;

/**
 * Start time:09:26:46 2009-04-22<br>
 * Project: mobicents-isup-stack<br>
 * Test for CGU
 *
 * @author <a href="mailto:baranowb@gmail.com"> Bartosz Baranowski </a>
 */
public class CGUATest extends MessageHarness {

    @Test(groups = { "functional.encode", "functional.decode", "message" })
    public void testTwo_Params() throws Exception {
        byte[] message = getDefaultBody();

        // CircuitGroupUnblockingAckMessage cgb=new CircuitGroupUnblockingAckMessageImpl(this,message);
        CircuitGroupUnblockingAckMessage cgb = super.messageFactory.createCGUA();
        ((AbstractISUPMessage) cgb).decode(message, messageFactory,parameterFactory);

        try {
            RangeAndStatus RS = (RangeAndStatus) cgb.getParameter(RangeAndStatus._PARAMETER_CODE);
            assertNotNull(RS, "Range And Status return is null, it should not be");
            if (RS == null)
                return;
            byte range = RS.getRange();
            assertEquals(range, 0x0A, "Range is wrong");
            byte[] b = RS.getStatus();
            assertNotNull(b, "RangeAndStatus.getRange() is null");
            if (b == null) {
                return;
            }
            assertEquals(b.length, 2, "Length of param is wrong");
            if (b.length != 2)
                return;
            assertTrue(super.makeCompare(b, new byte[] { 0x02, 0x03 }), "RangeAndStatus.getRange() is wrong");

        } catch (Exception e) {
            e.printStackTrace();
            fail("Failed on get parameter[" + CallReference._PARAMETER_CODE + "]:" + e);
        }

    }

    protected byte[] getDefaultBody() {
        // FIXME: for now we strip MTP part
        byte[] message = {

        0x0C, (byte) 0x0B, CircuitGroupUnblockingAckMessage.MESSAGE_CODE
                // Circuit group supervision message type
                , 0x01 // hardware failure oriented
                , 0x01 // ptr to variable part
                // no optional, so no pointer
                // RangeAndStatus._PARAMETER_CODE
                , 0x03, 0x0A, 0x02, 0x03

        };
        return message;
    }

    protected ISUPMessage getDefaultMessage() {
        return super.messageFactory.createCGUA();
    }
}
