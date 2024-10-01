
package org.restcomm.protocols.ss7.tcap;

import static org.testng.Assert.*;

import java.util.Date;

import javolution.util.FastMap;

import org.restcomm.protocols.ss7.statistics.StatDataCollectionImpl;
import org.restcomm.protocols.ss7.statistics.api.LongValue;
import org.restcomm.protocols.ss7.statistics.api.StatCounterCollection;
import org.restcomm.protocols.ss7.statistics.api.StatDataCollection;
import org.restcomm.protocols.ss7.statistics.api.StatDataCollectorType;
import org.restcomm.protocols.ss7.statistics.api.StatResult;
import org.testng.annotations.Test;

/**
 * Statistic
 *
 * @author sergey vetyutnev
 *
 */
public class StatCounterTest {

    @Test(groups = { "statistic" })
    public void countersManagementTest() throws Exception {

        StatDataCollection sdc = new StatDataCollectionImpl();

        StatCounterCollection scc1_old = sdc.registerStatCounterCollector("counter1", StatDataCollectorType.MIN);
        StatCounterCollection scc1 = sdc.registerStatCounterCollector("counter1", StatDataCollectorType.MIN);
        StatCounterCollection scc2 = sdc.registerStatCounterCollector("counter2", StatDataCollectorType.MIN);

        StatCounterCollection scc1_x = sdc.getStatCounterCollector("counter1");
        StatCounterCollection scc1_y = sdc.getStatCounterCollector("counter3");

        assertEquals(scc1, scc1_x);
        assertNull(scc1_y);

        sdc.unregisterStatCounterCollector("counter1");
        scc1_x = sdc.getStatCounterCollector("counter1");
        assertNull(scc1_x);


        scc1 = sdc.registerStatCounterCollector("counter1", StatDataCollectorType.MIN);
        StatResult res1 = scc1.restartAndGet("a1");
        Thread.sleep(100);

        Date d2 = new Date();
        Thread.sleep(100);

        StatResult res2 = scc1.restartAndGet("a2");
        Thread.sleep(100);

        assertNull(res1);
        assertNull(res2);

        sdc.clearDeadCampaigns(d2);
        
        res1 = sdc.restartAndGet("counter1", "a1");
        res2 = sdc.restartAndGet("counter1", "a2");

        assertNull(res1);
        assertNotNull(res2);

    }

    @Test(groups = { "statistic" })
    public void countersMinTest() throws Exception {

        StatDataCollection sdc = new StatDataCollectionImpl();

        StatCounterCollection scc1 = sdc.registerStatCounterCollector("counter1", StatDataCollectorType.MIN);
        StatCounterCollection scc2 = sdc.registerStatCounterCollector("counter2", StatDataCollectorType.MIN);

        StatResult res1 = sdc.restartAndGet("counter1", "a1");
        StatResult res2 = sdc.restartAndGet("counter1", "a2");
        StatResult res3 = sdc.restartAndGet("counter1", "a3");
        StatResult res4 = sdc.restartAndGet("counter1", "a4");

        assertNull(res1);
        assertNull(res2);
        assertNull(res3);
        assertNull(res4);

        res1 = sdc.restartAndGet("counter1", "a1");
        assertEquals(res1.getLongValue(), Long.MAX_VALUE);

        sdc.updateData("counter1", 100);
        res2 = sdc.restartAndGet("counter2", "a2");
        assertNull(res2);

        res2 = sdc.restartAndGet("counter1", "a2");
        assertEquals(res2.getLongValue(), 100);

        res2 = sdc.restartAndGet("counter1", "a2");
        assertEquals(res2.getLongValue(), Long.MAX_VALUE);

        sdc.updateData("counter1", 10);
        res3 = sdc.restartAndGet("counter1", "a3");
        assertEquals(res3.getLongValue(), 10);

        sdc.updateData("counter1", 100);
        res3 = sdc.restartAndGet("counter1", "a3");
        res4 = sdc.restartAndGet("counter1", "a4");
        assertEquals(res3.getLongValue(), 100);
        assertEquals(res4.getLongValue(), 10);

    }

    @Test(groups = { "statistic" })
    public void countersMaxTest() throws Exception {

        StatDataCollection sdc = new StatDataCollectionImpl();

        StatCounterCollection scc1 = sdc.registerStatCounterCollector("counter1", StatDataCollectorType.MAX);
        StatCounterCollection scc2 = sdc.registerStatCounterCollector("counter2", StatDataCollectorType.MAX);

        StatResult res1 = sdc.restartAndGet("counter1", "a1");
        StatResult res2 = sdc.restartAndGet("counter1", "a2");
        StatResult res3 = sdc.restartAndGet("counter1", "a3");
        StatResult res4 = sdc.restartAndGet("counter1", "a4");

        assertNull(res1);
        assertNull(res2);
        assertNull(res3);
        assertNull(res4);

        res1 = sdc.restartAndGet("counter1", "a1");
        assertEquals(res1.getLongValue(), Long.MIN_VALUE);

        sdc.updateData("counter1", 10);
        res2 = sdc.restartAndGet("counter2", "a2");
        assertNull(res2);

        res2 = sdc.restartAndGet("counter1", "a2");
        assertEquals(res2.getLongValue(), 10);

        res2 = sdc.restartAndGet("counter1", "a2");
        assertEquals(res2.getLongValue(), Long.MIN_VALUE);

        sdc.updateData("counter1", 100);
        res3 = sdc.restartAndGet("counter1", "a3");
        assertEquals(res3.getLongValue(), 100);

        sdc.updateData("counter1", 10);
        res3 = sdc.restartAndGet("counter1", "a3");
        res4 = sdc.restartAndGet("counter1", "a4");
        assertEquals(res3.getLongValue(), 10);
        assertEquals(res4.getLongValue(), 100);

    }

    @Test(groups = { "statistic" })
    public void countersStringTextTest() throws Exception {

        StatDataCollection sdc = new StatDataCollectionImpl();

        StatCounterCollection scc1 = sdc.registerStatCounterCollector("counter1", StatDataCollectorType.StringLongMap);
        StatCounterCollection scc2 = sdc.registerStatCounterCollector("counter2", StatDataCollectorType.StringLongMap);

        StatResult res1 = sdc.restartAndGet("counter1", "a1");
        StatResult res2 = sdc.restartAndGet("counter1", "a2");
        StatResult res3 = sdc.restartAndGet("counter1", "a3");
        StatResult res4 = sdc.restartAndGet("counter1", "a4");

        assertNull(res1);
        assertNull(res2);
        assertNull(res3);
        assertNull(res4);

        res1 = sdc.restartAndGet("counter1", "a1");
        FastMap<String, LongValue> resa1 = res1.getStringLongValue();
        assertEquals(resa1.size(), 0);

        sdc.updateData("counter1", "x1");
        res2 = sdc.restartAndGet("counter2", "a2");
        assertNull(res2);

        res2 = sdc.restartAndGet("counter1", "a2");
        FastMap<String, LongValue> resa2 = res2.getStringLongValue();
        assertEquals(resa2.size(), 1);
        assertEquals(resa2.get("x1").getValue(), 1);

        res2 = sdc.restartAndGet("counter1", "a2");
        resa2 = res2.getStringLongValue();
        assertEquals(resa2.size(), 0);

        sdc.updateData("counter1", "x2");
        res3 = sdc.restartAndGet("counter1", "a3");
        FastMap<String, LongValue> resa3 = res3.getStringLongValue();
        assertEquals(resa3.size(), 2);
        assertEquals(resa3.get("x1").getValue(), 1);
        assertEquals(resa3.get("x2").getValue(), 1);

        sdc.updateData("counter1", "x1");
        res3 = sdc.restartAndGet("counter1", "a3");
        res4 = sdc.restartAndGet("counter1", "a4");

        resa3 = res3.getStringLongValue();
        assertEquals(resa3.size(), 1);
        assertEquals(resa3.get("x1").getValue(), 1);

        FastMap<String, LongValue> resa4 = res4.getStringLongValue();
        assertEquals(resa4.size(), 2);
        assertEquals(resa4.get("x1").getValue(), 2);
        assertEquals(resa4.get("x2").getValue(), 1);

    }

}

