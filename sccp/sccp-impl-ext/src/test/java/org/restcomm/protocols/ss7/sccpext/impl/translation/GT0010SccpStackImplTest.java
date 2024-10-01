
package org.restcomm.protocols.ss7.sccpext.impl.translation;

import org.restcomm.protocols.ss7.indicator.RoutingIndicator;
import org.restcomm.protocols.ss7.sccp.LoadSharingAlgorithm;
import org.restcomm.protocols.ss7.sccp.OriginationType;
import org.restcomm.protocols.ss7.sccp.RuleType;
import org.restcomm.protocols.ss7.sccp.impl.SccpHarnessExt;
import org.restcomm.protocols.ss7.sccp.impl.User;
import org.restcomm.protocols.ss7.sccp.message.SccpDataMessage;
import org.restcomm.protocols.ss7.sccp.message.SccpMessage;
import org.restcomm.protocols.ss7.sccp.parameter.GlobalTitle;
import org.restcomm.protocols.ss7.sccp.parameter.SccpAddress;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.testng.Assert.assertTrue;

/**
 * @author amit bhayani
 * @author baranowb
 */
public class GT0010SccpStackImplTest extends SccpHarnessExt {

    private SccpAddress a1, a2;

    public GT0010SccpStackImplTest() {
    }

    @BeforeClass
    public void setUpClass() throws Exception {
        this.sccpStack1Name = "GT0010TestSccpStack1";
        this.sccpStack2Name = "GT0010TestSccpStack2";
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
    protected static final String GT2_digits = "09876432";

    protected static final String GT1_pattern_digits = "1/???????/90";
    protected static final String GT2_pattern_digits = "0/??????/2";

    @Test(groups = { "gtt", "functional.route" })
    public void testRemoteRoutingBasedOnGT_DPC_SSN() throws Exception {

        GlobalTitle gt1 = super.sccpProvider1.getParameterFactory().createGlobalTitle(GT1_digits, 0);
        GlobalTitle gt2 = super.sccpProvider1.getParameterFactory().createGlobalTitle(GT2_digits, 0);

        a1 = super.sccpProvider1.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt1, 0, getSSN());
        a2 = super.sccpProvider1.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt2, 0, getSSN());

        // add addresses to translate
        SccpAddress primary1SccpAddress = super.sccpProvider1.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_DPC_AND_SSN, super.sccpProvider1.getParameterFactory().createGlobalTitle("-/-/-"), getStack2PC(), getSSN());
        SccpAddress primary2SccpAddress = super.sccpProvider1.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_DPC_AND_SSN, super.sccpProvider1.getParameterFactory().createGlobalTitle("-/-/-"), getStack1PC(), getSSN());
        super.routerExt1.addRoutingAddress(22, primary1SccpAddress);
        super.routerExt2.addRoutingAddress(33, primary2SccpAddress);

        SccpAddress rule1SccpAddress = super.sccpProvider1.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, super.sccpProvider1.getParameterFactory().createGlobalTitle(GT2_pattern_digits, 0), 0, getSSN());
        SccpAddress rule2SccpAddress = super.sccpProvider1.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, super.sccpProvider1.getParameterFactory().createGlobalTitle(
                GT1_pattern_digits, 0), 0, getSSN());
        SccpAddress patternDefaultCalling = super.sccpProvider1.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, super.sccpProvider1.getParameterFactory().createGlobalTitle("*", 0), 0, 0);

        super.routerExt1.addRule(1, RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.ALL, rule1SccpAddress,
                "K/R/K", 22, -1, null, 0, patternDefaultCalling);
        super.routerExt2.addRule(1, RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.ALL, rule2SccpAddress,
                "R/R/R", 33, -1, null, 0, patternDefaultCalling);

        // now create users, we need to override matchX methods, since our rules do kinky stuff with digits, plus
        User u1 = new User(sccpStack1.getSccpProvider(), a1, a2, getSSN()) {

            protected boolean matchCalledPartyAddress() {
                SccpMessage msg = messages.get(0);
                SccpDataMessage udt = (SccpDataMessage) msg;
                SccpAddress addressToMatch = sccpProvider1.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_DPC_AND_SSN, null, getStack1PC(),
                        getSSN());
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
                SccpAddress addressToMatch = sccpProvider1.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, sccpProvider1.getParameterFactory().createGlobalTitle("02",0), getStack2PC(), getSSN());
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

    // TODO: add more ?
}
