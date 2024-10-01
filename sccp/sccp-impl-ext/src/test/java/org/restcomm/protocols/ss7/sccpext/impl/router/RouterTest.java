
package org.restcomm.protocols.ss7.sccpext.impl.router;

import javolution.util.FastMap;

import org.restcomm.protocols.ss7.Util;
import org.restcomm.protocols.ss7.indicator.GlobalTitleIndicator;
import org.restcomm.protocols.ss7.indicator.RoutingIndicator;
import org.restcomm.protocols.ss7.mtp.Mtp3TransferPrimitive;
import org.restcomm.protocols.ss7.mtp.Mtp3TransferPrimitiveFactory;
import org.restcomm.protocols.ss7.mtp.Mtp3UserPart;
import org.restcomm.protocols.ss7.mtp.Mtp3UserPartListener;
import org.restcomm.protocols.ss7.mtp.RoutingLabelFormat;
import org.restcomm.protocols.ss7.sccp.LoadSharingAlgorithm;
import org.restcomm.protocols.ss7.sccp.LongMessageRule;
import org.restcomm.protocols.ss7.sccp.LongMessageRuleType;
import org.restcomm.protocols.ss7.sccp.Mtp3Destination;
import org.restcomm.protocols.ss7.sccp.Mtp3ServiceAccessPoint;
import org.restcomm.protocols.ss7.sccp.OriginationType;
import org.restcomm.protocols.ss7.sccp.Router;
import org.restcomm.protocols.ss7.sccp.Rule;
import org.restcomm.protocols.ss7.sccp.RuleType;
import org.restcomm.protocols.ss7.sccp.SccpCongestionControlAlgo;
import org.restcomm.protocols.ss7.sccp.SccpProtocolVersion;
import org.restcomm.protocols.ss7.sccp.SccpProvider;
import org.restcomm.protocols.ss7.sccp.SccpResource;
import org.restcomm.protocols.ss7.sccp.SccpStack;
import org.restcomm.protocols.ss7.sccp.impl.parameter.ParameterFactoryImpl;
import org.restcomm.protocols.ss7.sccp.impl.router.RouterImpl;
import org.restcomm.protocols.ss7.sccp.parameter.GlobalTitle;
import org.restcomm.protocols.ss7.sccp.parameter.ParameterFactory;
import org.restcomm.protocols.ss7.sccp.parameter.SccpAddress;
import org.restcomm.protocols.ss7.sccpext.impl.router.RouterExtImpl;
import org.restcomm.protocols.ss7.sccpext.impl.router.RuleImpl;
import org.restcomm.protocols.ss7.ss7ext.Ss7ExtSccpInterface;
import org.restcomm.ss7.congestion.ExecutorCongestionMonitor;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.IOException;
import java.util.Map;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

/**
 * @author amit bhayani
 * @author kulikov
 */
public class RouterTest {

    private SccpAddress primaryAddr1, primaryAddr2;

    private RouterImpl router = null;
    private RouterExtImpl routerExt = null;

    private TestSccpStackImpl testSccpStackImpl = null;
    private ParameterFactory factory = null;
    public RouterTest() {
    }

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @BeforeMethod
    public void setUp() throws IOException {
        testSccpStackImpl = new TestSccpStackImpl();
        factory = new ParameterFactoryImpl();
        GlobalTitle gt = factory.createGlobalTitle("333",1);
        primaryAddr1 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt, 123, 0);
        primaryAddr2 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt, 321, 0);

        // cleans config file
        router = new RouterImpl("RouterTest", testSccpStackImpl);
        router.setPersistDir(Util.getTmpTestDir());
        router.start();
        router.removeAllResources();

        routerExt = new RouterExtImpl("RouterTest", testSccpStackImpl, router);
        routerExt.setPersistDir(Util.getTmpTestDir());
        routerExt.start();
        routerExt.removeAllResources();

    }

    @AfterMethod
    public void tearDown() {
        router.removeAllResources();
        router.stop();
    }

    /**
     * Test of add method, of class RouterImpl.
     */
    @Test(groups = { "router", "functional" })
    public void testRouter() throws Exception {
        routerExt.addRoutingAddress(1, primaryAddr1);
        assertEquals(routerExt.getRoutingAddresses().size(), 1);

        routerExt.addRoutingAddress(2, primaryAddr2);
        assertEquals(routerExt.getRoutingAddresses().size(), 2);

        routerExt.removeRoutingAddress(1);
        SccpAddress pa = routerExt.getRoutingAddresses().values().iterator().next();
        assertNotNull(pa);
        assertEquals(pa.getSignalingPointCode(), 321);
        assertEquals(routerExt.getRoutingAddresses().size(), 1);

        SccpAddress pattern = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, factory.createGlobalTitle("123456789",1),0, 0);
        SccpAddress patternDefaultCalling = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, factory.createGlobalTitle("*",1),0, 0);

        routerExt.addRule(1, RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.ALL, pattern, "R", 2,
                2, null, 0, patternDefaultCalling);
        assertEquals(routerExt.getRules().size(), 1);

        routerExt.addRule(2, RuleType.LOADSHARED, LoadSharingAlgorithm.Bit4, OriginationType.ALL, pattern, "K", 2,
                2, null, 0, patternDefaultCalling);
        assertEquals(routerExt.getRules().size(), 2);

        routerExt.removeRule(2);
        Rule rule = routerExt.getRules().values().iterator().next();
        assertNotNull(rule);
        assertEquals(rule.getRuleType(), RuleType.SOLITARY);
        assertEquals(routerExt.getRules().size(), 1);

        router.addLongMessageRule(1, 1, 2, LongMessageRuleType.XUDT_ENABLED);
        assertEquals(router.getLongMessageRules().size(), 1);
        router.addLongMessageRule(2, 3, 4, LongMessageRuleType.LUDT_ENABLED);
        assertEquals(router.getLongMessageRules().size(), 2);
        router.removeLongMessageRule(2);
        LongMessageRule lmr = router.getLongMessageRules().values().iterator().next();
        assertNotNull(lmr);
        assertEquals(lmr.getLongMessageRuleType(), LongMessageRuleType.XUDT_ENABLED);
        assertEquals(router.getLongMessageRules().size(), 1);

        router.addMtp3ServiceAccessPoint(1, 1, 11, 2, 0, null);
        assertEquals(router.getMtp3ServiceAccessPoints().size(), 1);
        router.addMtp3ServiceAccessPoint(2, 2, 12, 2, 0, null);
        assertEquals(router.getMtp3ServiceAccessPoints().size(), 2);
        router.removeMtp3ServiceAccessPoint(2);
        Mtp3ServiceAccessPoint sap = router.getMtp3ServiceAccessPoints().values().iterator().next();
        assertNotNull(sap);
        assertEquals(sap.getOpc(), 11);
        assertEquals(router.getLongMessageRules().size(), 1);

        router.addMtp3Destination(1, 1, 101, 110, 0, 255, 255);
        assertEquals(sap.getMtp3Destinations().size(), 1);
        router.addMtp3Destination(1, 2, 111, 120, 0, 255, 255);
        assertEquals(sap.getMtp3Destinations().size(), 2);
        router.removeMtp3Destination(1, 2);
        Mtp3Destination dest = sap.getMtp3Destinations().values().iterator().next();
        assertNotNull(dest);
        assertEquals(dest.getFirstDpc(), 101);
        assertEquals(sap.getMtp3Destinations().size(), 1);
    }

    @Test(groups = { "router", "functional.translate" })
    public void testTranslate11() throws Exception {
        // Match any digits and pattern SSN=0 (management message) keep the digits in the and add a PC(123) & SSN (8).

        SccpAddress pattern = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE,
                factory.createGlobalTitle("*", 1), 0, 0);
        SccpAddress patternDefaultCalling = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, factory.createGlobalTitle("*",1),0, 0);

        SccpAddress primaryAddress = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_DPC_AND_SSN,
                factory.createGlobalTitle("-"), 123, 146);

        RuleImpl rule = new RuleImpl(RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.ALL, pattern, "K", 0, patternDefaultCalling);
        rule.setPrimaryAddressId(1);

        SccpAddress address = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE,
                factory.createGlobalTitle("4414257897897", 1), 0, 146);

        assertTrue(rule.matches(address, address, false, 0));

        SccpAddress translatedAddress = rule.translate(address, primaryAddress);

        assertEquals(translatedAddress.getAddressIndicator().getRoutingIndicator(),
                RoutingIndicator.ROUTING_BASED_ON_DPC_AND_SSN);
        assertEquals(translatedAddress.getAddressIndicator().getGlobalTitleIndicator(),
                GlobalTitleIndicator.GLOBAL_TITLE_INCLUDES_TRANSLATION_TYPE_ONLY);
        assertEquals(translatedAddress.getSignalingPointCode(), 123);
        assertEquals(translatedAddress.getSubsystemNumber(), 146);
        assertEquals(translatedAddress.getGlobalTitle().getDigits(), "4414257897897");
    }

    @Test(groups = { "router", "functional.translate" })
    public void testTranslate12() throws Exception {
        // Match any digits and pattern SSN>0 - pattern SSN present flag must be set.

        SccpAddress pattern = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE,
                factory.createGlobalTitle("*", 1), 0, 146);

        SccpAddress patternDefaultCalling = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE,
                factory.createGlobalTitle("*", 1), 0, 0);

        SccpAddress primaryAddress = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_DPC_AND_SSN,
                factory.createGlobalTitle("-"), 123, 146);

        RuleImpl rule = new RuleImpl(RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.ALL, pattern, "K", 0, patternDefaultCalling);
        rule.setPrimaryAddressId(1);

        SccpAddress address = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE,
                factory.createGlobalTitle("4414257897897", 1), 0, 146);

        assertTrue(rule.matches(address, address, false, 0));

        SccpAddress translatedAddress = rule.translate(address, primaryAddress);

        assertEquals(translatedAddress.getAddressIndicator().getRoutingIndicator(),
                RoutingIndicator.ROUTING_BASED_ON_DPC_AND_SSN);
        assertEquals(translatedAddress.getAddressIndicator().getGlobalTitleIndicator(),
                GlobalTitleIndicator.GLOBAL_TITLE_INCLUDES_TRANSLATION_TYPE_ONLY);
        assertEquals(translatedAddress.getSignalingPointCode(), 123);
        assertEquals(translatedAddress.getSubsystemNumber(), 146);
        assertEquals(translatedAddress.getGlobalTitle().getDigits(), "4414257897897");
    }

   @Test(groups = { "router", "functional.encode" })
    public void testSerialization() throws Exception {
        routerExt.addRoutingAddress(1, primaryAddr1);
        routerExt.addRoutingAddress(2, primaryAddr2);

        SccpAddress pattern = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, factory.createGlobalTitle("123456789",1),0, 0);

        String callingAddressDigits = "987654321";
        SccpAddress patternCallingAddress = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE,
               factory.createGlobalTitle(callingAddressDigits,1), 0, 0);

        routerExt.addRule(1, RuleType.LOADSHARED, LoadSharingAlgorithm.Bit4, OriginationType.REMOTE, pattern, "K", 1, 2,
                null, 6, patternCallingAddress );

        router.addLongMessageRule(1, 1, 2, LongMessageRuleType.XUDT_ENABLED);
        router.addMtp3ServiceAccessPoint(3, 1, 11, 2, 5, null);
        router.addMtp3ServiceAccessPoint(4, 1, 11, 2, 5, "87654321");
        router.addMtp3Destination(3, 1, 101, 110, 0, 255, 255);
        router.stop();
        routerExt.stop();

        RouterImpl router1 = new RouterImpl(router.getName(), null);
        router1.setPersistDir(Util.getTmpTestDir());
        router1.start();

        LongMessageRule lmr = router1.getLongMessageRule(1);
        Mtp3ServiceAccessPoint sap = router1.getMtp3ServiceAccessPoint(3);
        Mtp3Destination dst = sap.getMtp3Destination(1);

        assertEquals(lmr.getFirstSpc(), 1);
        assertEquals(sap.getMtp3Destinations().size(), 1);
        assertEquals(sap.getNetworkId(), 5);
        assertNull(sap.getLocalGtDigits());
        assertEquals(dst.getLastDpc(), 110);

        sap = router1.getMtp3ServiceAccessPoint(4);
        assertEquals(sap.getNetworkId(), 5);
        assertEquals(sap.getLocalGtDigits(), "87654321");

        router1.stop();


        RouterExtImpl routerExt1 = new RouterExtImpl(router.getName(), null, router);
        routerExt1.setPersistDir(Util.getTmpTestDir());
        routerExt1.start();

        Rule rl = routerExt1.getRule(1);
        SccpAddress adp = routerExt1.getRoutingAddress(2);
        assertEquals(rl.getPrimaryAddressId(), 1);
        assertEquals(rl.getSecondaryAddressId(), 2);
        assertNull(rl.getNewCallingPartyAddressId());
        assertEquals(rl.getLoadSharingAlgorithm(), LoadSharingAlgorithm.Bit4);
        assertEquals(rl.getOriginationType(), OriginationType.REMOTE);
        assertNull(rl.getNewCallingPartyAddressId());
        assertEquals(rl.getNetworkId(), 6);
        assertEquals(adp.getSignalingPointCode(), primaryAddr2.getSignalingPointCode());
        assertTrue(rl.getPatternCallingAddress().getGlobalTitle().getDigits().equals( callingAddressDigits ));
    }

    /**
     * Test of Ordering.
     */
    @Test(groups = { "router", "functional.order" })
    public void testOrdering() throws Exception {

        SccpAddress patternDefaultCalling = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE,
                factory.createGlobalTitle("*", 1), 0, 0);

        primaryAddr1 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE,
                factory.createGlobalTitle("333/---/4", 1), 123, 0);
        routerExt.addRoutingAddress(1, primaryAddr1);

        SccpAddress pattern1 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE,
                factory.createGlobalTitle("800/????/9", 1), 0, 0);
        routerExt.addRule(1, RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.ALL, pattern1, "R/K/R", 1, -1,
                null, 0, patternDefaultCalling);

        // Rule 2
        SccpAddress pattern2 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE,
                factory.createGlobalTitle("*", 1), 0, 0);
        SccpAddress primaryAddr2 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE,
                factory.createGlobalTitle("-", 1), 123, 0);
        routerExt.addRoutingAddress(2, primaryAddr2);

        routerExt.addRule(2, RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.ALL, pattern2, "K", 2, -1,
                null, 0, patternDefaultCalling);

        // Rule 3
        SccpAddress pattern3 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE,
                factory.createGlobalTitle("9/?/9/*", 1), 0, 0);
        SccpAddress primaryAddr3 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE,
                factory.createGlobalTitle("-/-/-/-", 1), 123, 0);
        routerExt.addRoutingAddress(3, primaryAddr3);
        routerExt.addRule(3, RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.ALL, pattern3, "K/K/K/K", 3, -1,
                null, 0, patternDefaultCalling);

        // Rule 4
        SccpAddress pattern4 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, factory.createGlobalTitle("80/??/0/???/9", 1),0, 0);
        SccpAddress primaryAddr4 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, factory.createGlobalTitle( "90/-/1/-/7", 1),123,
                 0);
        routerExt.addRoutingAddress(4, primaryAddr4);
        routerExt.addRule(4, RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.ALL, pattern4, "R/K/R/K/R", 4, -1,
                null, 0, patternDefaultCalling);

        // Rule 5
        SccpAddress pattern5 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE,factory.createGlobalTitle("800/?????/9", 1), 0,  0);
        SccpAddress primaryAddr5 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, factory.createGlobalTitle( "90/-/7",1), 123,
                0);
        routerExt.addRoutingAddress(5, primaryAddr5);
        routerExt.addRule(5, RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.ALL, pattern5, "R/K/R", 5, -1,
                null, 0, patternDefaultCalling);

        // Rule 6
        SccpAddress pattern6 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, factory.createGlobalTitle("123456",1), 0, 0);
        SccpAddress primaryAddr6 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, factory.createGlobalTitle("-", 1),123, 0);
        routerExt.addRoutingAddress(6, primaryAddr6);
        routerExt.addRule(6, RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.ALL, pattern6, "K", 6,
                -1, null, 0, patternDefaultCalling);

        // Rule 7
        SccpAddress pattern7 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, factory.createGlobalTitle("1234567890", 1), 0, 0);
        SccpAddress primaryAddr7 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, factory.createGlobalTitle("-", 1), 123, 0);
        routerExt.addRoutingAddress(7, primaryAddr7);
        routerExt.addRule(7, RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.ALL, pattern7, "K", 7,
                -1, null, 0, patternDefaultCalling);

        // Rule 8

        SccpAddress pattern8 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, factory.createGlobalTitle("999/*", 1), 0, 0);
        SccpAddress primaryAddr8 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, factory.createGlobalTitle("111/-", 1), 123, 0);
        routerExt.addRoutingAddress(8, primaryAddr8);
        routerExt.addRule(8, RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.ALL, pattern8, "R/K", 8,
                -1, null, 0, patternDefaultCalling);

        // Rule 9 // with missing callingAddress

        SccpAddress pattern9 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, factory.createGlobalTitle("999/2/*", 1), 0, 0);
        SccpAddress primaryAddr9 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, factory.createGlobalTitle("111/-/-", 1), 123, 0);
        routerExt.addRoutingAddress(9, primaryAddr9);
        routerExt.addRule(9, RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.ALL, pattern9, "R/K/K",9,
                -1, null, 0, null);

        // TEST find rule

        // Rule 6
        SccpAddress calledParty = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, factory.createGlobalTitle("123456", 1), 0, 0);
        SccpAddress callingParty = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, factory.createGlobalTitle("654321", 1), 0, 0); // does not matter as we have * as rule for calling
        Rule rule = routerExt.findRule(calledParty, callingParty, false, 0);

        assertEquals(LoadSharingAlgorithm.Undefined, rule.getLoadSharingAlgorithm());
        assertEquals(pattern6, rule.getPattern());
        assertEquals(RuleType.SOLITARY, rule.getRuleType());
        assertEquals(-1, rule.getSecondaryAddressId());
        assertEquals("K", rule.getMask());


        // Rule 9
        calledParty = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, factory.createGlobalTitle("999234", 1), 0, 0);
        rule = routerExt.findRule(calledParty, callingParty, false, 0);
        assertEquals(LoadSharingAlgorithm.Undefined, rule.getLoadSharingAlgorithm());
        assertEquals(pattern9, rule.getPattern());
        assertEquals(RuleType.SOLITARY, rule.getRuleType());
        assertEquals(-1, rule.getSecondaryAddressId());
        assertEquals("R/K/K", rule.getMask());

        // Rule 7
        calledParty = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, factory.createGlobalTitle("1234567890", 1), 0, 0);
        rule = routerExt.findRule(calledParty, callingParty, false, 0);
        assertEquals(LoadSharingAlgorithm.Undefined, rule.getLoadSharingAlgorithm());
        assertEquals(pattern7, rule.getPattern());
        assertEquals(RuleType.SOLITARY, rule.getRuleType());
        assertEquals(-1, rule.getSecondaryAddressId());
        assertEquals("K", rule.getMask());

        // Rule 1
        calledParty = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, factory.createGlobalTitle("80012039", 1), 0, 0);
        rule = routerExt.findRule(calledParty, callingParty, false, 0);
        assertEquals(LoadSharingAlgorithm.Undefined, rule.getLoadSharingAlgorithm());
        assertEquals(pattern1, rule.getPattern());
        assertEquals(RuleType.SOLITARY, rule.getRuleType());
        assertEquals(-1, rule.getSecondaryAddressId());
        assertEquals("R/K/R", rule.getMask());

        // Rule 5
        calledParty = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, factory.createGlobalTitle("800120349", 1), 0, 0);
        rule = routerExt.findRule(calledParty, callingParty, false, 0);
        assertEquals(LoadSharingAlgorithm.Undefined, rule.getLoadSharingAlgorithm());
        assertEquals(pattern5, rule.getPattern());
        assertEquals(RuleType.SOLITARY, rule.getRuleType());
        assertEquals(-1, rule.getSecondaryAddressId());
        assertEquals("R/K/R", rule.getMask());

        // Rule 4
        calledParty = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, factory.createGlobalTitle("801203459", 1), 0, 0);
        rule = routerExt.findRule(calledParty, callingParty, false, 0);
        assertEquals(LoadSharingAlgorithm.Undefined, rule.getLoadSharingAlgorithm());
        assertEquals(pattern4, rule.getPattern());
        assertEquals(RuleType.SOLITARY, rule.getRuleType());
        assertEquals(-1, rule.getSecondaryAddressId());
        assertEquals("R/K/R/K/R", rule.getMask());

        // Rule 8
        calledParty = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, factory.createGlobalTitle("999123456", 1), 0, 0);
        rule = routerExt.findRule(calledParty, callingParty, false, 0);
        assertEquals(LoadSharingAlgorithm.Undefined, rule.getLoadSharingAlgorithm());
        assertEquals(pattern8, rule.getPattern());
        assertEquals(RuleType.SOLITARY, rule.getRuleType());
        assertEquals(-1, rule.getSecondaryAddressId());
        assertEquals("R/K", rule.getMask());

        // Rule 3
        calledParty = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, factory.createGlobalTitle( "919123456", 1), 0, 0);
        rule = routerExt.findRule(calledParty, callingParty, false, 0);
        assertEquals(LoadSharingAlgorithm.Undefined, rule.getLoadSharingAlgorithm());
        assertEquals(pattern3, rule.getPattern());
        assertEquals(RuleType.SOLITARY, rule.getRuleType());
        assertEquals(-1, rule.getSecondaryAddressId());
        assertEquals("K/K/K/K", rule.getMask());

    }

    /**
     * Test of Ordering by calling address pattern.
     */
    @Test(groups = { "router", "functional.order" })
    public void testOrderingByCallingAddress() throws Exception {

        // Rule 1
        primaryAddr1 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE,
                factory.createGlobalTitle("333/---/4", 1), 123, 0);
        routerExt.addRoutingAddress(1, primaryAddr1);

        SccpAddress patternCalling1 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE,
                factory.createGlobalTitle("900/????", 1), 0, 0);

        SccpAddress pattern1 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE,
                factory.createGlobalTitle("800/????/9", 1), 0, 0);
        routerExt.addRule(1, RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.ALL, pattern1, "R/K/R", 1, -1,
                null, 0, patternCalling1);


        // Rule 2
        SccpAddress pattern2 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE,
                factory.createGlobalTitle("800/????/9", 1), 0, 0);
        routerExt.addRoutingAddress(2, primaryAddr1);
        SccpAddress patternCalling2 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE,
                factory.createGlobalTitle("*", 1), 0, 0);

        routerExt.addRule(2, RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.ALL, pattern2, "K/K/K", 2, -1,
                null, 0, patternCalling2);

        // Rule 3
        SccpAddress pattern3 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE,
                factory.createGlobalTitle("800/????/9", 1), 0, 0);
        routerExt.addRoutingAddress(3, primaryAddr1);
        SccpAddress patternCalling3 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE,
                factory.createGlobalTitle("900/????/2", 1), 0, 0);

        routerExt.addRule(3, RuleType.SOLITARY, LoadSharingAlgorithm.Bit0, OriginationType.ALL, pattern3, "K/R/K", 3, -1,
                null, 0, patternCalling3);

        // Rule 4
        SccpAddress pattern4 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE,
                factory.createGlobalTitle("800/????/9", 1),0, 0);
        routerExt.addRoutingAddress(4, primaryAddr1);
        SccpAddress patternCalling4 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE,
                factory.createGlobalTitle("900/????/1", 1), 0, 0);

        routerExt.addRule(4, RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.ALL, pattern4, "K/K/R", 4, -1,
                null, 0, patternCalling4);


        // Rule 5
        SccpAddress pattern5 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE,
                factory.createGlobalTitle("*", 1),0, 0);
        SccpAddress primaryAddr5 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE,
                factory.createGlobalTitle("333", 1), 123, 0);
        routerExt.addRoutingAddress(5, primaryAddr5);
        SccpAddress patternCalling5 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE,
                factory.createGlobalTitle("900/????/1", 1), 0, 0);

        routerExt.addRule(5, RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.ALL, pattern5, "R", 5, -1,
                null, 0, patternCalling5);


        // Rule 6
        SccpAddress pattern6 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE,
                factory.createGlobalTitle("800/????/9", 1),0, 0);
        routerExt.addRoutingAddress(6, primaryAddr1);

        routerExt.addRule(6, RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.ALL, pattern6, "K/K/R", 6, -1,
                null, 0, null);


        // Rule Tests

        // Rule 3
        SccpAddress calledParty = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, factory.createGlobalTitle( "80012039", 1), 0, 0);
        SccpAddress callingParty = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, factory.createGlobalTitle( "90012032", 1), 0, 0);
        Rule rule = routerExt.findRule(calledParty, callingParty, false, 0);
        assertEquals(LoadSharingAlgorithm.Bit0, rule.getLoadSharingAlgorithm());
        assertEquals(pattern3, rule.getPattern());
        assertEquals(RuleType.SOLITARY, rule.getRuleType());
        assertEquals(-1, rule.getSecondaryAddressId());
        assertEquals("K/R/K", rule.getMask());

        // Rule 6
        callingParty = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, factory.createGlobalTitle( "90012031", 1), 0, 0);
        rule = routerExt.findRule(calledParty, callingParty, false, 0);
        assertEquals(LoadSharingAlgorithm.Undefined, rule.getLoadSharingAlgorithm());
        assertEquals(pattern6, rule.getPattern());
        assertEquals(RuleType.SOLITARY, rule.getRuleType());
        assertEquals(-1, rule.getSecondaryAddressId());
        assertEquals("K/K/R", rule.getMask());


        // Rule 1
        callingParty = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, factory.createGlobalTitle( "9001203", 1), 0, 0);
        rule = routerExt.findRule(calledParty, callingParty, false, 0);
        assertEquals(LoadSharingAlgorithm.Undefined, rule.getLoadSharingAlgorithm());
        assertEquals(pattern4, rule.getPattern());
        assertEquals(RuleType.SOLITARY, rule.getRuleType());
        assertEquals(-1, rule.getSecondaryAddressId());
        assertEquals("R/K/R", rule.getMask());

        // Rule 5
        SccpAddress calledParty9 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, factory.createGlobalTitle( "712345", 1), 0, 0);
        callingParty = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, factory.createGlobalTitle( "90012031", 1), 0, 0);
        rule = routerExt.findRule(calledParty9, callingParty, false, 0);
        assertEquals(LoadSharingAlgorithm.Undefined, rule.getLoadSharingAlgorithm());
        assertEquals(pattern5, rule.getPattern());
        assertEquals(patternCalling5, rule.getPatternCallingAddress());
        assertEquals(RuleType.SOLITARY, rule.getRuleType());
        assertEquals(-1, rule.getSecondaryAddressId());
        assertEquals("R", rule.getMask());

        // Rule 4
        callingParty = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, factory.createGlobalTitle( "90012031", 1), 0, 0);
        rule = routerExt.findRule(calledParty, callingParty, false, 0);
        assertEquals(LoadSharingAlgorithm.Undefined, rule.getLoadSharingAlgorithm());
        assertEquals(pattern4, rule.getPattern());
        assertEquals(RuleType.SOLITARY, rule.getRuleType());
        assertEquals(-1, rule.getSecondaryAddressId());
        assertEquals("K/K/R", rule.getMask());

        // Rule 2
        callingParty = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, factory.createGlobalTitle( "90012037", 1), 0, 0);
        rule = routerExt.findRule(calledParty, callingParty, false, 0);
        assertEquals(LoadSharingAlgorithm.Undefined, rule.getLoadSharingAlgorithm());
        assertEquals(pattern2, rule.getPattern());
        assertEquals(RuleType.SOLITARY, rule.getRuleType());
        assertEquals(-1, rule.getSecondaryAddressId());
        assertEquals("K/K/K", rule.getMask());

    }
    /**
     * Test of Ordering.
     */
    @Test(groups = { "router", "functional.order" })
    public void testRuleConfigReadWithoutCalling() throws Exception {
    }
    /**
     * Test of Ordering with OriginationType.
     */
    @Test(groups = { "router", "functional.order" })
    public void testOrderingWithOriginationType() throws Exception {
        SccpAddress patternDefaultCalling = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE,
                factory.createGlobalTitle("*", 1), 0, 0);
        // Rule 1
        primaryAddr1 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, factory.createGlobalTitle("999", 1),123, 
                0);
        routerExt.addRoutingAddress(1, primaryAddr1);

        SccpAddress pattern1 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, factory.createGlobalTitle("*", 1), 0, 0);
        routerExt.addRule(1, RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.ALL, pattern1, "K", 1,
                -1, null, 0, patternDefaultCalling);

        // Rule 2
        routerExt.addRule(2, RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.LOCAL, pattern1, "K", 1,
                -1, null, 0, patternDefaultCalling);

        // Rule 3
        SccpAddress pattern2 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, factory.createGlobalTitle("999", 1), 0, 0);
        routerExt.addRule(3, RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.ALL, pattern2, "K", 1,
                -1, null, 0, patternDefaultCalling);

        // Rule 4
        routerExt.addRule(4, RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.REMOTE, pattern2, "K",
                1, -1, null, 0, patternDefaultCalling);

        // TEST find rule
        boolean localOriginatedSign = false;
        boolean remoteOriginatedSign = true;

        SccpAddress calledParty1 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE,
                factory.createGlobalTitle("123456", 1), 0, 0);
        SccpAddress calledParty2 = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE,
                factory.createGlobalTitle("999", 1), 0, 0);

        Rule rule1 = routerExt.findRule(calledParty1, null, localOriginatedSign, 0);
        Rule rule2 = routerExt.findRule(calledParty1, null, remoteOriginatedSign, 0);
        Rule rule3 = routerExt.findRule(calledParty2, null, localOriginatedSign, 0);
        Rule rule4 = routerExt.findRule(calledParty2, null, remoteOriginatedSign, 0);

        assertTrue(rule1.getPattern().getGlobalTitle().getDigits().equals("*"));
        assertEquals(rule1.getOriginationType(), OriginationType.LOCAL);

        assertTrue(rule2.getPattern().getGlobalTitle().getDigits().equals("*"));
        assertEquals(rule2.getOriginationType(), OriginationType.ALL);

        assertTrue(rule3.getPattern().getGlobalTitle().getDigits().equals("*"));
        assertEquals(rule3.getOriginationType(), OriginationType.LOCAL);

        assertTrue(rule4.getPattern().getGlobalTitle().getDigits().equals("999"));
        assertEquals(rule4.getOriginationType(), OriginationType.REMOTE);

    }

    private class TestSccpStackImpl implements SccpStack {

        protected FastMap<Integer, Mtp3UserPart> mtp3UserParts = new FastMap<Integer, Mtp3UserPart>();

        TestSccpStackImpl() {
            Mtp3UserPartImpl mtp3UserPartImpl1 = new Mtp3UserPartImpl();
            Mtp3UserPartImpl mtp3UserPartImpl2 = new Mtp3UserPartImpl();

            mtp3UserParts.put(1, mtp3UserPartImpl1);
            mtp3UserParts.put(2, mtp3UserPartImpl2);
        }

        @Override
        public void start() throws IllegalStateException {
            // TODO Auto-generated method stub

        }

        @Override
        public void stop() {
            // TODO Auto-generated method stub

        }

        @Override
        public SccpProvider getSccpProvider() {
            return null;
        }

        @Override
        public String getPersistDir() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public void setPersistDir(String persistDir) {
            // TODO Auto-generated method stub

        }

        @Override
        public void setRemoveSpc(boolean removeSpc) {
            // TODO Auto-generated method stub

        }

        @Override
        public boolean isRemoveSpc() {
            // TODO Auto-generated method stub
            return false;
        }

        @Override
        public SccpResource getSccpResource() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public Map<Integer, Mtp3UserPart> getMtp3UserParts() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public Mtp3UserPart getMtp3UserPart(int id) {
            return this.mtp3UserParts.get(id);
        }

        @Override
        public String getName() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public int getSstTimerDuration_Min() {
            // TODO Auto-generated method stub
            return 0;
        }

        @Override
        public int getSstTimerDuration_Max() {
            // TODO Auto-generated method stub
            return 0;
        }

        @Override
        public double getSstTimerDuration_IncreaseFactor() {
            // TODO Auto-generated method stub
            return 0;
        }

        @Override
        public int getZMarginXudtMessage() {
            // TODO Auto-generated method stub
            return 0;
        }

        @Override
        public int getMaxDataMessage() {
            // TODO Auto-generated method stub
            return 0;
        }

        @Override
        public int getReassemblyTimerDelay() {
            // TODO Auto-generated method stub
            return 0;
        }

        @Override
        public Router getRouter() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public void setPreviewMode(boolean previewMode) {
            // TODO Auto-generated method stub
            
        }

        @Override
        public boolean isPreviewMode() {
            // TODO Auto-generated method stub
            return false;
        }

        @Override
        public void setSstTimerDuration_Min(int sstTimerDuration_Min) {
            // TODO Auto-generated method stub
            
        }

        @Override
        public void setSstTimerDuration_Max(int sstTimerDuration_Max) {
            // TODO Auto-generated method stub
            
        }

        @Override
        public void setSstTimerDuration_IncreaseFactor(double sstTimerDuration_IncreaseFactor) {
            // TODO Auto-generated method stub
            
        }

        @Override
        public void setZMarginXudtMessage(int zMarginXudtMessage) {
            // TODO Auto-generated method stub
            
        }

        @Override
        public void setMaxDataMessage(int maxDataMessage) {
            // TODO Auto-generated method stub
            
        }

        @Override
        public void setReassemblyTimerDelay(int reassemblyTimerDelay) {
            // TODO Auto-generated method stub
            
        }

        @Override
        public boolean isCanRelay() {
            // TODO Auto-generated method stub
            return false;
        }

        @Override
        public void setCanRelay(boolean canRelay) throws Exception {
            // TODO Auto-generated method stub
        }

        @Override
        public int getConnEstTimerDelay() {
            // TODO Auto-generated method stub
            return 0;
        }

        @Override
        public void setConnEstTimerDelay(int connEstTimerDelay) throws Exception {
            // TODO Auto-generated method stub
        }

        @Override
        public int getIasTimerDelay() {
            // TODO Auto-generated method stub
            return 0;
        }

        @Override
        public void setIasTimerDelay(int iasTimerDelay) throws Exception {
            // TODO Auto-generated method stub
        }

        @Override
        public int getIarTimerDelay() {
            // TODO Auto-generated method stub
            return 0;
        }

        @Override
        public void setIarTimerDelay(int iarTimerDelay) throws Exception {
            // TODO Auto-generated method stub
        }

        @Override
        public int getRelTimerDelay() {
            // TODO Auto-generated method stub
            return 0;
        }

        @Override
        public void setRelTimerDelay(int relTimerDelay) throws Exception {
            // TODO Auto-generated method stub
        }

        @Override
        public int getRepeatRelTimerDelay() {
            // TODO Auto-generated method stub
            return 0;
        }

        @Override
        public void setRepeatRelTimerDelay(int repeatRelTimerDelay) throws Exception {
            // TODO Auto-generated method stub
        }

        @Override
        public int getIntTimerDelay() {
            // TODO Auto-generated method stub
            return 0;
        }

        @Override
        public void setIntTimerDelay(int intTimerDelay) throws Exception {
            // TODO Auto-generated method stub
        }

        @Override
        public int getGuardTimerDelay() {
            // TODO Auto-generated method stub
            return 0;
        }

        @Override
        public void setGuardTimerDelay(int guardTimerDelay) throws Exception {
            // TODO Auto-generated method stub
        }

        @Override
        public int getResetTimerDelay() {
            // TODO Auto-generated method stub
            return 0;
        }

        @Override
        public void setResetTimerDelay(int resetTimerDelay) throws Exception {
            // TODO Auto-generated method stub
        }

        @Override
        public void setMtp3UserParts(Map<Integer, Mtp3UserPart> mtp3UserPartsTemp) {
            // TODO Auto-generated method stub
            
        }

        @Override
        public void setSccpProtocolVersion(SccpProtocolVersion sccpProtocolVersion) {
            // TODO Auto-generated method stub
            
        }

        @Override
        public SccpProtocolVersion getSccpProtocolVersion() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public int getCongControlTIMER_A() {
            // TODO Auto-generated method stub
            return 0;
        }

        @Override
        public void setCongControlTIMER_A(int value) {
            // TODO Auto-generated method stub
            
        }

        @Override
        public int getCongControlTIMER_D() {
            // TODO Auto-generated method stub
            return 0;
        }

        @Override
        public void setCongControlTIMER_D(int value) {
            // TODO Auto-generated method stub
            
        }

        @Override
        public String getCongControl_Algo() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public boolean isCongControl_blockingOutgoingSccpMessages() {
            // TODO Auto-generated method stub
            return false;
        }

        @Override
        public void setCongControl_blockingOutgoingSccpMessages(boolean value) {
            // TODO Auto-generated method stub
            
        }

        @Override
        public int getFirstSls() {
            return 0;
        }

        @Override
        public int getLastSls() {
            return 255;
        }

        @Override
        public int getSlsMask() {
            return 255;
        }

        @Override
        public void setCongControl_Algo(String value) {
            // TODO Auto-generated method stub
            
        }

        @Override
        public boolean isStarted() {
            // TODO Auto-generated method stub
            return false;
        }

		@Override
		public int getPeriodOfLogging() {
			// TODO Auto-generated method stub
			return 0;
		}

		@Override
		public void setPeriodOfLogging(int periodOfLogging) throws Exception {
			// TODO Auto-generated method stub
			
		}

        @Override
        public void setRespectPc(boolean respectPc) throws Exception {
            // TODO Auto-generated method stub
            
        }

        @Override
        public boolean isRespectPc() {
            // TODO Auto-generated method stub
            return false;
        }

        @Override
        public Ss7ExtSccpInterface getSs7ExtSccpInterface() {
            // TODO Auto-generated method stub
            return null;
        }

    }

    private class Mtp3UserPartImpl implements Mtp3UserPart {

        @Override
        public void addMtp3UserPartListener(Mtp3UserPartListener arg0) {
            // TODO Auto-generated method stub

        }

        @Override
        public int getMaxUserDataLength(int arg0) {
            // TODO Auto-generated method stub
            return 0;
        }

        @Override
        public Mtp3TransferPrimitiveFactory getMtp3TransferPrimitiveFactory() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public RoutingLabelFormat getRoutingLabelFormat() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public boolean isUseLsbForLinksetSelection() {
            // TODO Auto-generated method stub
            return false;
        }

        @Override
        public void removeMtp3UserPartListener(Mtp3UserPartListener arg0) {
            // TODO Auto-generated method stub

        }

        @Override
        public void sendMessage(Mtp3TransferPrimitive arg0) throws IOException {
            // TODO Auto-generated method stub

        }

        @Override
        public void setRoutingLabelFormat(RoutingLabelFormat arg0) {
            // TODO Auto-generated method stub

        }

        @Override
        public void setUseLsbForLinksetSelection(boolean arg0) {
            // TODO Auto-generated method stub

        }

        @Override
        public int getDeliveryMessageThreadCount() {
            // TODO Auto-generated method stub
            return 0;
        }

        @Override
        public void setDeliveryMessageThreadCount(int deliveryMessageThreadCount) {
            // TODO Auto-generated method stub
            
        }

        @Override
        public ExecutorCongestionMonitor getExecutorCongestionMonitor() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public void start() throws Exception {
            // TODO Auto-generated method stub
            
        }

        @Override
        public void stop() throws Exception {
            // TODO Auto-generated method stub
            
        }

    }
}
