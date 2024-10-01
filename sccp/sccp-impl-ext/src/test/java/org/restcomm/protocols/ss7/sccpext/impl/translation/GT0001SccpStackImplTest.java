
package org.restcomm.protocols.ss7.sccpext.impl.translation;

import org.restcomm.protocols.ss7.indicator.NatureOfAddress;
import org.restcomm.protocols.ss7.indicator.RoutingIndicator;
import org.restcomm.protocols.ss7.sccp.LoadSharingAlgorithm;
import org.restcomm.protocols.ss7.sccp.OriginationType;
import org.restcomm.protocols.ss7.sccp.RuleType;
import org.restcomm.protocols.ss7.sccp.impl.SccpHarnessExt;
import org.restcomm.protocols.ss7.sccp.impl.User;
import org.restcomm.protocols.ss7.sccp.message.SccpDataMessage;
import org.restcomm.protocols.ss7.sccp.message.SccpMessage;
import org.restcomm.protocols.ss7.sccp.parameter.GlobalTitle0001;
import org.restcomm.protocols.ss7.sccp.parameter.SccpAddress;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.testng.Assert.assertTrue;

/**
 * @author amit bhayani
 * @author kulikov
 * @author baranowb
 */
public class GT0001SccpStackImplTest extends SccpHarnessExt {

    private SccpAddress a1, a2;

    public GT0001SccpStackImplTest() {
    }

    @BeforeClass
    public void setUpClass() throws Exception {
        this.sccpStack1Name = "GT0001TestSccpStack1";
        this.sccpStack2Name = "GT0001TestSccpStack2";
    }

    @AfterClass
    public void tearDownClass() throws Exception {
    }

    @BeforeMethod
    public void setUp() throws Exception {
        super.setUp();

    }

    @AfterMethod
    public void tearDown() {
        super.tearDown();
    }

    protected static final String GT1_digits = "1234567890";
    protected static final String GT2_digits = "0987654321";

    protected static final String GT1_pattern_digits = "1/???????/90";
    protected static final String GT2_pattern_digits = "0/???????/21";

    @Test(groups = { "gtt", "functional.route" })
    public void testRemoteRoutingBasedOnGT_DPC_SSN() throws Exception {

        GlobalTitle0001 gt1 = super.sccpProvider1.getParameterFactory().createGlobalTitle(GT1_digits, NatureOfAddress.NATIONAL);
        GlobalTitle0001 gt2 = super.sccpProvider1.getParameterFactory().createGlobalTitle(GT2_digits, NatureOfAddress.NATIONAL);

        a1 = super.sccpProvider1.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt1, 0, getSSN());
        a2 = super.sccpProvider1.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt2, 0, getSSN());

        // add addresses to translate
        SccpAddress primary1SccpAddress = super.sccpProvider1.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_DPC_AND_SSN, super.sccpProvider1.getParameterFactory().createGlobalTitle("-/-/-"), getStack2PC(), getSSN());
        SccpAddress primary2SccpAddress = super.sccpProvider1.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_DPC_AND_SSN, super.sccpProvider1.getParameterFactory().createGlobalTitle("-/-/-"), getStack1PC(), getSSN());
        super.routerExt1.addRoutingAddress(22, primary1SccpAddress);
        super.routerExt2.addRoutingAddress(33, primary2SccpAddress);

        SccpAddress rule1SccpAddress = super.sccpProvider1.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, super.sccpProvider1.getParameterFactory().createGlobalTitle(
                GT2_pattern_digits, NatureOfAddress.NATIONAL), 0, getSSN());
        SccpAddress rule2SccpAddress = super.sccpProvider1.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, super.sccpProvider1.getParameterFactory().createGlobalTitle(
                GT1_pattern_digits, NatureOfAddress.NATIONAL), 0, getSSN());
        super.routerExt1.addRule(1, RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.ALL, rule1SccpAddress,
                "K/R/K", 22, -1, null, 0, null);
        super.routerExt2.addRule(1, RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.ALL, rule2SccpAddress,
                "R/R/R", 33, -1, null, 0, null);

        // now create users, we need to override matchX methods, since our rules do kinky stuff with digits, plus
        User u1 = new User(sccpStack1.getSccpProvider(), a1, a2, getSSN()) {

            protected boolean matchCalledPartyAddress() {
                SccpMessage msg = messages.get(0);
                SccpDataMessage udt = (SccpDataMessage) msg;
                SccpAddress addressToMatch = sccpProvider1.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_DPC_AND_SSN, null, getStack1PC(), getSSN());
                if (!addressToMatch.equals(udt.getCalledPartyAddress())) {
                    return false;
                }
                return true;
            }

        };
        User u2 = new User(sccpStack2.getSccpProvider(), a2, a1, getSSN()) {

            protected boolean matchCalledPartyAddress() {
                SccpMessage msg = messages.get(0);
                SccpDataMessage udt = (SccpDataMessage) msg;
                SccpAddress addressToMatch = sccpProvider1.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_DPC_AND_SSN, sccpProvider1.getParameterFactory().createGlobalTitle("021", NatureOfAddress.NATIONAL), getStack2PC(), getSSN());
                if (!addressToMatch.equals(udt.getCalledPartyAddress())) {
                    return false;
                }
                return true;
            }

        };

        u1.register();
        u2.register();

        u1.send();
        u2.send();

        Thread.currentThread().sleep(3000);

        assertTrue(u1.check(), "Message not received");
        assertTrue(u2.check(), "Message not received");
    }

    @Test(groups = { "gtt", "functional.route" })
    public void testRemoteRoutingBasedOnGT() throws Exception {

        // here we do as above, however receiving stack needs also rule, to match it localy.
        GlobalTitle0001 gt1 = super.sccpProvider1.getParameterFactory().createGlobalTitle(GT1_digits, NatureOfAddress.NATIONAL);
        GlobalTitle0001 gt2 = super.sccpProvider1.getParameterFactory().createGlobalTitle(GT2_digits, NatureOfAddress.NATIONAL);

        a1 = super.sccpProvider1.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt1, 0, getSSN());
        a2 = super.sccpProvider1.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt2, 0, getSSN());

        // add addresses to translate
        SccpAddress primary1SccpAddress = super.sccpProvider1.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, super.sccpProvider1.getParameterFactory().createGlobalTitle("-/-/-"), getStack2PC(), getSSN());
        SccpAddress primary2SccpAddress = super.sccpProvider1.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, super.sccpProvider1.getParameterFactory().createGlobalTitle("-/-/-"), getStack1PC(), getSSN());
        super.routerExt1.addRoutingAddress(22, primary1SccpAddress);
        super.routerExt2.addRoutingAddress(33, primary2SccpAddress);

        SccpAddress rule1SccpAddress = super.sccpProvider1.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, super.sccpProvider1.getParameterFactory().createGlobalTitle(
                GT2_pattern_digits, NatureOfAddress.NATIONAL), 0, getSSN());
        SccpAddress rule2SccpAddress = super.sccpProvider1.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, super.sccpProvider1.getParameterFactory().createGlobalTitle(
                GT1_pattern_digits, NatureOfAddress.NATIONAL), 0, getSSN());
        super.routerExt1.addRule(1, RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.ALL, rule1SccpAddress,
                "K/R/K", 22, -1, null, 0, null);
        super.routerExt2.addRule(1, RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.ALL, rule2SccpAddress,
                "R/K/R", 33, -1, null, 0, null);

        // add rules for incoming messages,

        // 1. add primary addresses
        // NOTE PC passed in address match local PC for stack
        primary1SccpAddress = super.sccpProvider1.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_DPC_AND_SSN, super.sccpProvider1.getParameterFactory().createGlobalTitle("-/-/-"), getStack1PC(), getSSN());
        primary2SccpAddress = super.sccpProvider1.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_DPC_AND_SSN, super.sccpProvider1.getParameterFactory().createGlobalTitle("-/-"), getStack2PC(), getSSN());
        super.routerExt1.addRoutingAddress(44, primary1SccpAddress);
        super.routerExt2.addRoutingAddress(66, primary2SccpAddress);
        // 2. add rules to make translation to above
        rule1SccpAddress = super.sccpProvider1.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, super.sccpProvider1.getParameterFactory().createGlobalTitle(
                "23456/?/8", NatureOfAddress.NATIONAL), 0, getSSN());
        rule2SccpAddress = super.sccpProvider1.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, super.sccpProvider1.getParameterFactory().createGlobalTitle(
                "02/?", NatureOfAddress.NATIONAL), 0, getSSN());
        super.routerExt1.addRule(2, RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.ALL, rule1SccpAddress,
                "K/K/K", 44, -1, null, 0, null);
        super.routerExt2.addRule(2, RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.ALL, rule2SccpAddress,
                "K/K", 66, -1, null, 0, null);

        // now create users, we need to override matchX methods, since our rules do kinky stuff with digits, plus
        User u1 = new User(sccpStack1.getSccpProvider(), a1, a2, getSSN()) {

            protected boolean matchCalledPartyAddress() {
                SccpMessage msg = messages.get(0);
                SccpDataMessage udt = (SccpDataMessage) msg;
                // pc=1,ssn=8,gt=GLOBAL_TITLE_INCLUDES_NATURE_OF_ADDRESS_INDICATOR_ONLY 2345678
                SccpAddress addressToMatch = sccpProvider1.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_DPC_AND_SSN, sccpProvider1.getParameterFactory().createGlobalTitle("2345678", NatureOfAddress.NATIONAL), getStack1PC(), getSSN());
                if (!addressToMatch.equals(udt.getCalledPartyAddress())) {
                    return false;
                }
                return true;
            }

        };

        User u2 = new User(sccpStack2.getSccpProvider(), a2, a1, getSSN()) {

            protected boolean matchCalledPartyAddress() {
                SccpMessage msg = messages.get(0);
                SccpDataMessage udt = (SccpDataMessage) msg;
                SccpAddress addressToMatch = sccpProvider1.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_DPC_AND_SSN, sccpProvider1.getParameterFactory().createGlobalTitle("021", NatureOfAddress.NATIONAL), getStack2PC(), getSSN());
                if (!addressToMatch.equals(udt.getCalledPartyAddress())) {
                    return false;
                }
                return true;
            }

        };

        u1.register();
        u2.register();

        u1.send();
        u2.send();

        Thread.currentThread().sleep(3000);

        assertTrue(u1.check(), "Message not received");
        assertTrue(u2.check(), "Message not received");
    }

}
