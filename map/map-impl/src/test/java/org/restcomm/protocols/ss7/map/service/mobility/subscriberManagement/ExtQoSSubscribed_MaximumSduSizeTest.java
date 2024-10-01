
package org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement;

import static org.testng.Assert.*;

import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.ExtQoSSubscribed_MaximumSduSizeImpl;
import org.testng.annotations.Test;

/**
*
* @author sergey vetyutnev
*
*/
public class ExtQoSSubscribed_MaximumSduSizeTest {

    @Test(groups = { "functional.decode", "mobility.subscriberManagement" })
    public void testDecode() throws Exception {

        ExtQoSSubscribed_MaximumSduSizeImpl prim = new ExtQoSSubscribed_MaximumSduSizeImpl(0, true);
        assertEquals(prim.getMaximumSduSize(), 0);

        prim = new ExtQoSSubscribed_MaximumSduSizeImpl(1, true);
        assertEquals(prim.getMaximumSduSize(), 10);

        prim = new ExtQoSSubscribed_MaximumSduSizeImpl(149, true);
        assertEquals(prim.getMaximumSduSize(), 1490);

        prim = new ExtQoSSubscribed_MaximumSduSizeImpl(150, true);
        assertEquals(prim.getMaximumSduSize(), 1500);

        prim = new ExtQoSSubscribed_MaximumSduSizeImpl(151, true);
        assertEquals(prim.getMaximumSduSize(), 1502);

        prim = new ExtQoSSubscribed_MaximumSduSizeImpl(152, true);
        assertEquals(prim.getMaximumSduSize(), 1510);

        prim = new ExtQoSSubscribed_MaximumSduSizeImpl(153, true);
        assertEquals(prim.getMaximumSduSize(), 1520);

        prim = new ExtQoSSubscribed_MaximumSduSizeImpl(154, true);
        assertEquals(prim.getMaximumSduSize(), 0);
    }

    @Test(groups = { "functional.encode", "mobility.subscriberManagement" })
    public void testEncode() throws Exception {

        ExtQoSSubscribed_MaximumSduSizeImpl prim = new ExtQoSSubscribed_MaximumSduSizeImpl(0, false);
        assertEquals(prim.getSourceData(), 0);

        prim = new ExtQoSSubscribed_MaximumSduSizeImpl(10, false);
        assertEquals(prim.getSourceData(), 1);

        prim = new ExtQoSSubscribed_MaximumSduSizeImpl(1490, false);
        assertEquals(prim.getSourceData(), 149);

        prim = new ExtQoSSubscribed_MaximumSduSizeImpl(1500, false);
        assertEquals(prim.getSourceData(), 150);

        prim = new ExtQoSSubscribed_MaximumSduSizeImpl(1502, false);
        assertEquals(prim.getSourceData(), 151);

        prim = new ExtQoSSubscribed_MaximumSduSizeImpl(1510, false);
        assertEquals(prim.getSourceData(), 152);

        prim = new ExtQoSSubscribed_MaximumSduSizeImpl(1520, false);
        assertEquals(prim.getSourceData(), 153);

        prim = new ExtQoSSubscribed_MaximumSduSizeImpl(2000, false);
        assertEquals(prim.getSourceData(), 0);
    }

}
