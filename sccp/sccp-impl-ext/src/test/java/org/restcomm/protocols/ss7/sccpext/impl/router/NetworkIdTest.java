
package org.restcomm.protocols.ss7.sccpext.impl.router;

import org.apache.log4j.Logger;
import org.restcomm.protocols.ss7.indicator.NatureOfAddress;
import org.restcomm.protocols.ss7.indicator.NumberingPlan;
import org.restcomm.protocols.ss7.indicator.RoutingIndicator;
import org.restcomm.protocols.ss7.mtp.Mtp3TransferPrimitive;
import org.restcomm.protocols.ss7.mtp.Mtp3TransferPrimitiveFactory;
import org.restcomm.protocols.ss7.mtp.Mtp3UserPart;
import org.restcomm.protocols.ss7.mtp.Mtp3UserPartListener;
import org.restcomm.protocols.ss7.mtp.RoutingLabelFormat;
import org.restcomm.protocols.ss7.sccp.LoadSharingAlgorithm;
import org.restcomm.protocols.ss7.sccp.LongMessageRuleType;
import org.restcomm.protocols.ss7.sccp.NetworkIdState;
import org.restcomm.protocols.ss7.sccp.OriginationType;
import org.restcomm.protocols.ss7.sccp.RemoteSccpStatus;
import org.restcomm.protocols.ss7.sccp.RuleType;
import org.restcomm.protocols.ss7.sccp.SccpListener;
import org.restcomm.protocols.ss7.sccp.SccpProtocolVersion;
import org.restcomm.protocols.ss7.sccp.SignallingPointStatus;
import org.restcomm.protocols.ss7.sccp.impl.BaseSccpListener;
import org.restcomm.protocols.ss7.sccp.impl.SccpRoutingControl;
import org.restcomm.protocols.ss7.sccp.impl.SccpStackImpl;
import org.restcomm.protocols.ss7.sccp.impl.message.EncodingResultData;
import org.restcomm.protocols.ss7.sccp.impl.message.MessageFactoryImpl;
import org.restcomm.protocols.ss7.sccp.impl.message.SccpDataMessageImpl;
import org.restcomm.protocols.ss7.sccp.impl.parameter.BCDEvenEncodingScheme;
import org.restcomm.protocols.ss7.sccp.impl.parameter.HopCounterImpl;
import org.restcomm.protocols.ss7.sccp.impl.parameter.ImportanceImpl;
import org.restcomm.protocols.ss7.sccp.impl.parameter.ParameterFactoryImpl;
import org.restcomm.protocols.ss7.sccp.impl.router.RouterImpl;
import org.restcomm.protocols.ss7.sccp.message.SccpDataMessage;
import org.restcomm.protocols.ss7.sccp.message.SccpNoticeMessage;
import org.restcomm.protocols.ss7.sccp.parameter.GlobalTitle;
import org.restcomm.protocols.ss7.sccp.parameter.HopCounter;
import org.restcomm.protocols.ss7.sccp.parameter.Importance;
import org.restcomm.protocols.ss7.sccp.parameter.ParameterFactory;
import org.restcomm.protocols.ss7.sccp.parameter.SccpAddress;
import org.restcomm.protocols.ss7.sccpext.impl.SccpExtModuleImpl;
import org.restcomm.protocols.ss7.sccpext.impl.router.RouterExtImpl;
import org.restcomm.protocols.ss7.ss7ext.Ss7ExtInterface;
import org.restcomm.protocols.ss7.ss7ext.Ss7ExtInterfaceImpl;
import org.restcomm.ss7.congestion.ExecutorCongestionMonitor;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.IOException;

import static org.testng.Assert.assertEquals;

/**
 * 
 * @author sergey vetyutnev
 * 
 */
public class NetworkIdTest extends BaseSccpListener implements SccpListener {

    private SccpAddress primaryAddr1_L, primaryAddr1_R;
    private SccpAddress primaryAddr2_L, primaryAddr2_R;
    private SccpAddress primaryAddr3_L, primaryAddr3_R;

    private int dpc1_L, dpc1_R;
    private int dpc2_L, dpc2_R;

    private RouterImpl router = null;
    private RouterExtImpl routerExt = null;

    private SccpStackImpl testSccpStackImpl = null;
    private SccpExtModuleImpl sccpExtModule1;
    private ParameterFactory factory = null;
    private MessageFactoryImpl messageFactory = null;

    private int localTerm_1;
    private int localTerm_2;
    private int localTerm_3;
    private int remTerm_1;
    private int remTerm_2;

    public NetworkIdTest() {
    }

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @BeforeMethod
    public void setUp() throws Exception {
        Ss7ExtInterface ss7ExtInterface = new Ss7ExtInterfaceImpl();
        sccpExtModule1 = new SccpExtModuleImpl();
        ss7ExtInterface.setSs7ExtSccpInterface(sccpExtModule1);
        testSccpStackImpl = new SccpStackImpl("Test", ss7ExtInterface);
        testSccpStackImpl.start();
        factory = new ParameterFactoryImpl();
        messageFactory = new MessageFactoryImpl(testSccpStackImpl);

        dpc1_L = 11;
        dpc1_R = 111;
        dpc2_L = 22;
        dpc2_R = 222;
        GlobalTitle gt_1L = factory.createGlobalTitle("1111", 0, NumberingPlan.ISDN_TELEPHONY, BCDEvenEncodingScheme.INSTANCE, NatureOfAddress.INTERNATIONAL);
        GlobalTitle gt_1R = factory.createGlobalTitle("1119", 0, NumberingPlan.ISDN_TELEPHONY, BCDEvenEncodingScheme.INSTANCE, NatureOfAddress.INTERNATIONAL);
        GlobalTitle gt_2L = factory.createGlobalTitle("2229", 0, NumberingPlan.ISDN_TELEPHONY, BCDEvenEncodingScheme.INSTANCE, NatureOfAddress.INTERNATIONAL);
        GlobalTitle gt_2R = factory.createGlobalTitle("2229", 0, NumberingPlan.ISDN_TELEPHONY, BCDEvenEncodingScheme.INSTANCE, NatureOfAddress.INTERNATIONAL);
        GlobalTitle gt_3L = factory.createGlobalTitle("3229", 0, NumberingPlan.ISDN_TELEPHONY, BCDEvenEncodingScheme.INSTANCE, NatureOfAddress.INTERNATIONAL);
        GlobalTitle gt_3R = factory.createGlobalTitle("3229", 0, NumberingPlan.ISDN_TELEPHONY, BCDEvenEncodingScheme.INSTANCE, NatureOfAddress.INTERNATIONAL);
        primaryAddr1_L = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt_1L, 11, 0);
        primaryAddr1_R = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt_1R, 111, 0);
        primaryAddr2_L = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt_2L, 22, 0);
        primaryAddr2_R = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt_2R, 222, 0);
        primaryAddr3_L = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt_3L, 22, 0);
        primaryAddr3_R = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt_3R, 222, 0);

        Mtp3UserPartProxy mtp3UserPart = new Mtp3UserPartProxy();
        testSccpStackImpl.setMtp3UserPart(1, mtp3UserPart);

        // cleans config file
        this.router = (RouterImpl) this.testSccpStackImpl.getRouter();
        this.routerExt = (RouterExtImpl) sccpExtModule1.getRouterExt();
        this.testSccpStackImpl.removeAllResources();
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
    public void testNetworkId() throws Exception {

        this.testSccpStackImpl.getSccpProvider().registerSccpListener(8, this);
        
        router.addMtp3ServiceAccessPoint(1, 1, dpc1_L, 2, 1, null);
        router.addMtp3ServiceAccessPoint(2, 1, dpc2_L, 2, 2, "null");
        router.addMtp3ServiceAccessPoint(3, 1, dpc2_L, 2, 3, "876543");
        // int id, int mtp3Id, int opc, int ni, int networkId
        router.addMtp3Destination(1, 1, dpc1_R, dpc1_R, 0, 255, 255);
        router.addMtp3Destination(2, 1, dpc2_R, dpc2_R, 0, 255, 255);
        router.addMtp3Destination(3, 1, dpc2_R, dpc2_R, 0, 255, 255);
        // sapId, destId, firstDpc, lastDpc, firstSls, lastSls, slsMask

        routerExt.addRoutingAddress(1, primaryAddr1_R);
        routerExt.addRoutingAddress(2, primaryAddr2_R);
        routerExt.addRoutingAddress(3, primaryAddr1_L);
        routerExt.addRoutingAddress(4, primaryAddr2_L);
        routerExt.addRoutingAddress(5, primaryAddr3_R);
        routerExt.addRoutingAddress(6, primaryAddr3_L);

        SccpAddress pattern = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, factory.createGlobalTitle("*", 1), 0, 0);
        SccpAddress patternDefaultCalling = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, factory.createGlobalTitle("*", 1), 0, 0);
        routerExt.addRule(1, RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.LOCAL, pattern, "K", 1, 1, null, 1, patternDefaultCalling);
        routerExt.addRule(2, RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.LOCAL, pattern, "K", 2, 2, null, 2, patternDefaultCalling);
        routerExt.addRule(3, RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.REMOTE, pattern, "K", 3, 3, null, 1, patternDefaultCalling);
        routerExt.addRule(4, RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.REMOTE, pattern, "K", 4, 4, null, 2, patternDefaultCalling);
        routerExt.addRule(5, RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.LOCAL, pattern, "K", 3, 3, null, 1, patternDefaultCalling);
        routerExt.addRule(6, RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.REMOTE, pattern, "K", 4, 4, null, 3, patternDefaultCalling);


        // int id, RuleType ruleType, LoadSharingAlgorithm algo, OriginationType
        // originationType, SccpAddress pattern, String mask, int pAddressId,
        // int sAddressId, Integer newCallingPartyAddressAddressId, int networkId

        this.testSccpStackImpl.getSccpResource().addRemoteSpc(1, dpc1_R, 0, 0);
        this.testSccpStackImpl.getSccpResource().addRemoteSpc(2, dpc2_R, 0, 0);
        // remoteSpcId, remoteSpc, remoteSpcFlag, mask

        // ***** remote orig - network=1
        Mtp3TransferPrimitiveFactory mtp3TransferPrimitiveFactory = new Mtp3TransferPrimitiveFactory(RoutingLabelFormat.ITU);
        byte[] data = new byte[] { 1, 2, 3 };
        GlobalTitle gt1 = factory.createGlobalTitle("3333", 1);
        GlobalTitle gt2 = factory.createGlobalTitle("0000", 1);
        SccpAddress calledParty = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt1, 0, 8);
        SccpAddress callingParty = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt2, 0, 8);
        HopCounter hc = new HopCounterImpl(3);
        Importance imp = new ImportanceImpl((byte) 0);
        SccpDataMessageImpl msg1 = (SccpDataMessageImpl) messageFactory.createDataMessageClass1(calledParty, callingParty, data, 0, 0, false, hc, imp);
        // calledParty, callingParty, data, sls, localSsn, returnMessageOnError,
        // hopCounter, importance
        Logger logger = Logger.getLogger(SccpRoutingControl.class);
        EncodingResultData erd = msg1.encode(this.testSccpStackImpl, LongMessageRuleType.LONG_MESSAGE_FORBBIDEN, 1000, logger, true, SccpProtocolVersion.ITU);
        // longMessageRuleType, maxMtp3UserDataLength, logger, removeSPC,
        // sccpProtocolVersion

        Mtp3TransferPrimitive mtp3Msg = mtp3TransferPrimitiveFactory.createMtp3TransferPrimitive(3, 2, 0, dpc1_R, dpc1_L, 0, erd.getSolidData());
        // int si, int ni, int mp, int opc, int dpc, int sls, byte[] data,
        // RoutingLabelFormat pointCodeFormat
        this.testSccpStackImpl.onMtp3TransferMessage(mtp3Msg);

        assertEquals(this.localTerm_1, 1);
        assertEquals(this.localTerm_2, 0);
        assertEquals(this.localTerm_3, 0);
        assertEquals(this.remTerm_1, 0);
        assertEquals(this.remTerm_2, 0);


        // ***** remote orig - network=2
        mtp3Msg = mtp3TransferPrimitiveFactory.createMtp3TransferPrimitive(3, 2, 0, dpc2_R, dpc2_L, 0, erd.getSolidData());
        // int si, int ni, int mp, int opc, int dpc, int sls, byte[] data,
        // RoutingLabelFormat pointCodeFormat
        this.testSccpStackImpl.onMtp3TransferMessage(mtp3Msg);

        assertEquals(this.localTerm_1, 1);
        assertEquals(this.localTerm_2, 1);
        assertEquals(this.localTerm_3, 0);
        assertEquals(this.remTerm_1, 0);
        assertEquals(this.remTerm_2, 0);


        // ***** remote orig - network=3
        GlobalTitle gt11 = factory.createGlobalTitle("876543", 1);
        SccpAddress calledPartySt = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt11, 0, 8);
        SccpDataMessageImpl msg2 = (SccpDataMessageImpl) messageFactory.createDataMessageClass1(calledPartySt, callingParty, data, 0, 0, false, hc, imp);
        EncodingResultData erd2 = msg2.encode(this.testSccpStackImpl, LongMessageRuleType.LONG_MESSAGE_FORBBIDEN, 1000, logger, true, SccpProtocolVersion.ITU);
        mtp3Msg = mtp3TransferPrimitiveFactory.createMtp3TransferPrimitive(3, 2, 0, dpc2_R, dpc2_L, 0, erd2.getSolidData());
        // int si, int ni, int mp, int opc, int dpc, int sls, byte[] data,
        // RoutingLabelFormat pointCodeFormat
        this.testSccpStackImpl.onMtp3TransferMessage(mtp3Msg);

        assertEquals(this.localTerm_1, 1);
        assertEquals(this.localTerm_2, 1);
        assertEquals(this.localTerm_3, 1);
        assertEquals(this.remTerm_1, 0);
        assertEquals(this.remTerm_2, 0);


        // ***** local orig - network=1
        gt1 = factory.createGlobalTitle("0000", 1);
        gt2 = factory.createGlobalTitle("3333", 1);
        calledParty = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt1, 0, 8);
        callingParty = factory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt2, 0, 8);
        SccpDataMessageImpl msg = (SccpDataMessageImpl) messageFactory.createDataMessageClass1(calledParty, callingParty, data, 0, 8, false, hc, imp);
        msg.setNetworkId(1);
        this.testSccpStackImpl.getSccpProvider().send(msg);

        assertEquals(this.localTerm_1, 1);
        assertEquals(this.localTerm_2, 1);
        assertEquals(this.localTerm_3, 1);
        assertEquals(this.remTerm_1, 1);
        assertEquals(this.remTerm_2, 0);


        // ***** local orig - network=2
        msg = (SccpDataMessageImpl) messageFactory.createDataMessageClass1(calledParty, callingParty, data, 0, 8, false, hc, imp);
        msg.setNetworkId(2);
        this.testSccpStackImpl.getSccpProvider().send(msg);

        assertEquals(this.localTerm_1, 1);
        assertEquals(this.localTerm_2, 1);
        assertEquals(this.localTerm_3, 1);
        assertEquals(this.remTerm_1, 1);
        assertEquals(this.remTerm_2, 1);
    }

    private class Mtp3UserPartProxy implements Mtp3UserPart {

        @Override
        public void addMtp3UserPartListener(Mtp3UserPartListener listener) {
            // TODO Auto-generated method stub

        }

        @Override
        public void removeMtp3UserPartListener(Mtp3UserPartListener listener) {
            // TODO Auto-generated method stub

        }

        @Override
        public RoutingLabelFormat getRoutingLabelFormat() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public void setRoutingLabelFormat(RoutingLabelFormat routingLabelFormat) {
            // TODO Auto-generated method stub

        }

        @Override
        public Mtp3TransferPrimitiveFactory getMtp3TransferPrimitiveFactory() {
            return new Mtp3TransferPrimitiveFactory(RoutingLabelFormat.ITU);
        }

        @Override
        public int getMaxUserDataLength(int dpc) {
            return 1000;
        }

        @Override
        public void sendMessage(Mtp3TransferPrimitive msg) throws IOException {
            int dpc = msg.getDpc();

            if (dpc == dpc1_R)
                remTerm_1++;
            if (dpc == dpc2_R)
                remTerm_2++;
        }

        @Override
        public void setUseLsbForLinksetSelection(boolean useLsbForLinksetSelection) {
            // TODO Auto-generated method stub

        }

        @Override
        public boolean isUseLsbForLinksetSelection() {
            // TODO Auto-generated method stub
            return false;
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

    @Override
    public void onMessage(SccpDataMessage message) {
        int dpc = message.getCalledPartyAddress().getSignalingPointCode();

        if (dpc == dpc1_L && message.getNetworkId() == 1)
            localTerm_1++;
        if (dpc == dpc2_L && message.getNetworkId() == 2)
            localTerm_2++;
        if (dpc == dpc2_L && message.getNetworkId() == 3)
            localTerm_3++;
    }

    @Override
    public void onNotice(SccpNoticeMessage message) {
        // TODO Auto-generated method stub
        
    }

    @Override
    public void onCoordResponse(int ssn, int multiplicityIndicator) {
        // TODO Auto-generated method stub
        
    }

    @Override
    public void onState(int dpc, int ssn, boolean inService, int multiplicityIndicator) {
        // TODO Auto-generated method stub
        
    }

    @Override
    public void onPcState(int dpc, SignallingPointStatus status, Integer restrictedImportanceLevel,
            RemoteSccpStatus remoteSccpStatus) {
        // TODO Auto-generated method stub
        
    }

    @Override
    public void onNetworkIdState(int networkId, NetworkIdState networkIdState) {
        // TODO Auto-generated method stub
        
    }
}
