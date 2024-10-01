
package org.restcomm.protocols.ss7.map.load.sms.mt;

import com.google.common.util.concurrent.RateLimiter;
import org.apache.log4j.Logger;
import org.mobicents.protocols.api.IpChannelType;
import org.mobicents.protocols.sctp.netty.NettySctpManagementImpl;
import org.restcomm.protocols.ss7.indicator.NatureOfAddress;
import org.restcomm.protocols.ss7.indicator.RoutingIndicator;
import org.restcomm.protocols.ss7.m3ua.Asp;
import org.restcomm.protocols.ss7.m3ua.ExchangeType;
import org.restcomm.protocols.ss7.m3ua.Functionality;
import org.restcomm.protocols.ss7.m3ua.IPSPType;
import org.restcomm.protocols.ss7.m3ua.impl.M3UAManagementImpl;
import org.restcomm.protocols.ss7.m3ua.parameter.NetworkAppearance;
import org.restcomm.protocols.ss7.m3ua.parameter.RoutingContext;
import org.restcomm.protocols.ss7.m3ua.parameter.TrafficModeType;
import org.restcomm.protocols.ss7.map.MAPStackImpl;
import org.restcomm.protocols.ss7.map.api.MAPApplicationContext;
import org.restcomm.protocols.ss7.map.api.MAPApplicationContextName;
import org.restcomm.protocols.ss7.map.api.MAPApplicationContextVersion;
import org.restcomm.protocols.ss7.map.api.MAPDialog;
import org.restcomm.protocols.ss7.map.api.MAPException;
import org.restcomm.protocols.ss7.map.api.MAPMessage;
import org.restcomm.protocols.ss7.map.api.MAPProvider;
import org.restcomm.protocols.ss7.map.api.dialog.MAPAbortProviderReason;
import org.restcomm.protocols.ss7.map.api.dialog.MAPAbortSource;
import org.restcomm.protocols.ss7.map.api.dialog.MAPNoticeProblemDiagnostic;
import org.restcomm.protocols.ss7.map.api.dialog.MAPRefuseReason;
import org.restcomm.protocols.ss7.map.api.dialog.MAPUserAbortChoice;
import org.restcomm.protocols.ss7.map.api.dialog.ServingCheckData;
import org.restcomm.protocols.ss7.map.api.errors.AbsentSubscriberDiagnosticSM;
import org.restcomm.protocols.ss7.map.api.errors.MAPErrorMessage;
import org.restcomm.protocols.ss7.map.api.primitives.AddressNature;
import org.restcomm.protocols.ss7.map.api.primitives.AddressString;
import org.restcomm.protocols.ss7.map.api.primitives.IMSI;
import org.restcomm.protocols.ss7.map.api.primitives.ISDNAddressString;
import org.restcomm.protocols.ss7.map.api.primitives.MAPExtensionContainer;
import org.restcomm.protocols.ss7.map.api.primitives.NumberingPlan;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.TeleserviceCode;
import org.restcomm.protocols.ss7.map.api.service.sms.AlertServiceCentreRequest;
import org.restcomm.protocols.ss7.map.api.service.sms.AlertServiceCentreResponse;
import org.restcomm.protocols.ss7.map.api.service.sms.CorrelationID;
import org.restcomm.protocols.ss7.map.api.service.sms.ForwardShortMessageRequest;
import org.restcomm.protocols.ss7.map.api.service.sms.ForwardShortMessageResponse;
import org.restcomm.protocols.ss7.map.api.service.sms.InformServiceCentreRequest;
import org.restcomm.protocols.ss7.map.api.service.sms.LocationInfoWithLMSI;
import org.restcomm.protocols.ss7.map.api.service.sms.MAPDialogSms;
import org.restcomm.protocols.ss7.map.api.service.sms.MAPServiceSmsListener;
import org.restcomm.protocols.ss7.map.api.service.sms.MoForwardShortMessageRequest;
import org.restcomm.protocols.ss7.map.api.service.sms.MoForwardShortMessageResponse;
import org.restcomm.protocols.ss7.map.api.service.sms.MtForwardShortMessageRequest;
import org.restcomm.protocols.ss7.map.api.service.sms.MtForwardShortMessageResponse;
import org.restcomm.protocols.ss7.map.api.service.sms.NoteSubscriberPresentRequest;
import org.restcomm.protocols.ss7.map.api.service.sms.ReadyForSMRequest;
import org.restcomm.protocols.ss7.map.api.service.sms.ReadyForSMResponse;
import org.restcomm.protocols.ss7.map.api.service.sms.ReportSMDeliveryStatusRequest;
import org.restcomm.protocols.ss7.map.api.service.sms.ReportSMDeliveryStatusResponse;
import org.restcomm.protocols.ss7.map.api.service.sms.SMDeliveryNotIntended;
import org.restcomm.protocols.ss7.map.api.service.sms.SMDeliveryOutcome;
import org.restcomm.protocols.ss7.map.api.service.sms.SM_RP_DA;
import org.restcomm.protocols.ss7.map.api.service.sms.SM_RP_MTI;
import org.restcomm.protocols.ss7.map.api.service.sms.SM_RP_OA;
import org.restcomm.protocols.ss7.map.api.service.sms.SM_RP_SMEA;
import org.restcomm.protocols.ss7.map.api.service.sms.SendRoutingInfoForSMRequest;
import org.restcomm.protocols.ss7.map.api.service.sms.SendRoutingInfoForSMResponse;
import org.restcomm.protocols.ss7.map.api.service.sms.SmsSignalInfo;
import org.restcomm.protocols.ss7.map.api.smstpdu.AbsoluteTimeStamp;
import org.restcomm.protocols.ss7.map.api.smstpdu.AddressField;
import org.restcomm.protocols.ss7.map.api.smstpdu.CharacterSet;
import org.restcomm.protocols.ss7.map.api.smstpdu.DataCodingScheme;
import org.restcomm.protocols.ss7.map.api.smstpdu.NumberingPlanIdentification;
import org.restcomm.protocols.ss7.map.api.smstpdu.ProtocolIdentifier;
import org.restcomm.protocols.ss7.map.api.smstpdu.SmsDeliverTpdu;
import org.restcomm.protocols.ss7.map.api.smstpdu.TypeOfNumber;
import org.restcomm.protocols.ss7.map.api.smstpdu.UserData;
import org.restcomm.protocols.ss7.map.api.smstpdu.UserDataHeader;
import org.restcomm.protocols.ss7.map.load.CsvWriter;
import org.restcomm.protocols.ss7.map.primitives.AddressStringImpl;
import org.restcomm.protocols.ss7.map.primitives.ISDNAddressStringImpl;
import org.restcomm.protocols.ss7.map.smstpdu.AbsoluteTimeStampImpl;
import org.restcomm.protocols.ss7.map.smstpdu.AddressFieldImpl;
import org.restcomm.protocols.ss7.map.smstpdu.ApplicationPortAddressing16BitAddressImpl;
import org.restcomm.protocols.ss7.map.smstpdu.DataCodingSchemeImpl;
import org.restcomm.protocols.ss7.map.smstpdu.ProtocolIdentifierImpl;
import org.restcomm.protocols.ss7.map.smstpdu.SmsDeliverTpduImpl;
import org.restcomm.protocols.ss7.map.smstpdu.UserDataHeaderImpl;
import org.restcomm.protocols.ss7.map.smstpdu.UserDataImpl;
import org.restcomm.protocols.ss7.sccp.LoadSharingAlgorithm;
import org.restcomm.protocols.ss7.sccp.NetworkIdState;
import org.restcomm.protocols.ss7.sccp.OriginationType;
import org.restcomm.protocols.ss7.sccp.Router;
import org.restcomm.protocols.ss7.sccp.RuleType;
import org.restcomm.protocols.ss7.sccp.SccpResource;
import org.restcomm.protocols.ss7.sccp.impl.SccpStackImpl;
import org.restcomm.protocols.ss7.sccp.impl.parameter.BCDEvenEncodingScheme;
import org.restcomm.protocols.ss7.sccp.impl.parameter.ParameterFactoryImpl;
import org.restcomm.protocols.ss7.sccp.impl.parameter.SccpAddressImpl;
import org.restcomm.protocols.ss7.sccp.parameter.EncodingScheme;
import org.restcomm.protocols.ss7.sccp.parameter.GlobalTitle;
import org.restcomm.protocols.ss7.sccp.parameter.SccpAddress;
import org.restcomm.protocols.ss7.sccpext.impl.SccpExtModuleImpl;
import org.restcomm.protocols.ss7.sccpext.router.RouterExt;
import org.restcomm.protocols.ss7.ss7ext.Ss7ExtInterface;
import org.restcomm.protocols.ss7.ss7ext.Ss7ExtInterfaceImpl;
import org.restcomm.protocols.ss7.tcap.TCAPStackImpl;
import org.restcomm.protocols.ss7.tcap.api.TCAPStack;
import org.restcomm.protocols.ss7.tcap.asn.ApplicationContextName;
import org.restcomm.protocols.ss7.tcap.asn.ReturnResultLastImpl;
import org.restcomm.protocols.ss7.tcap.asn.comp.Problem;
import org.restcomm.protocols.ss7.tcap.asn.comp.ReturnResultLast;

import java.nio.charset.Charset;
import java.util.Calendar;
import java.util.GregorianCalendar;

/**
 * @modified <a href="mailto:fernando.mendioroz@gmail.com"> Fernando Mendioroz </a>
 */
public class Client extends TestHarnessSmsMt {

    private static Logger logger = Logger.getLogger(Client.class);

    // TCAP
    private TCAPStack tcapStack;

    // MAP
    private MAPStackImpl mapStack;
    private MAPProvider mapProvider;

    // SCCP
    SccpExtModuleImpl sccpExtModule;
    private SccpStackImpl sccpStack;
    private Router router;
    private RouterExt routerExt;
    private SccpResource sccpResource;

    // M3UA
    private M3UAManagementImpl clientM3UAMgmt;

    // SCTP
    private NettySctpManagementImpl sctpManagement;

    // a ramp-up period is required for performance testing.
    int endCount;
    transient boolean endReportPrinted;

    // AtomicInteger nbConcurrentDialogs = new AtomicInteger(0);

    volatile long start = 0L;
    volatile long prev = 0L;

    private RateLimiter rateLimiterObj = null;

    private CsvWriter csvWriter;

    protected void initializeStack(IpChannelType ipChannelType) throws Exception {

        this.rateLimiterObj = RateLimiter.create(MAXCONCURRENTDIALOGS); // rate

        this.initSCTP(ipChannelType);

        // Initialize M3UA first
        this.initM3UA();

        // Initialize SCCP
        this.initSCCP();

        // Initialize TCAP
        this.initTCAP();

        // Initialize MAP
        this.initMAP();

        // Finally, start the ASP
        this.clientM3UAMgmt.startAsp("ASP1");

        this.csvWriter = new CsvWriter("map");
        this.csvWriter.addCounter(CREATED_DIALOGS);
        this.csvWriter.addCounter(SUCCESSFUL_DIALOGS);
        this.csvWriter.addCounter(ERROR_DIALOGS);
        this.csvWriter.start(TEST_START_DELAY, PRINT_WRITER_PERIOD);
    }

    private void initSCTP(IpChannelType ipChannelType) throws Exception {
        this.sctpManagement = new NettySctpManagementImpl("Client");
        // this.sctpManagement.setSingleThread(false);
        this.sctpManagement.start();
        this.sctpManagement.setConnectDelay(10000);
        this.sctpManagement.removeAllResources();

        // 1. Create SCTP Association
        if (EXTRA_HOST_ADDRESS.equals("-1"))
            sctpManagement.addAssociation(HOST_IP, HOST_PORT, PEER_IP, PEER_PORT, CLIENT_ASSOCIATION_NAME, ipChannelType, null);
        else
            sctpManagement.addAssociation(HOST_IP, HOST_PORT, PEER_IP, PEER_PORT, CLIENT_ASSOCIATION_NAME, ipChannelType, new String[] { EXTRA_HOST_ADDRESS });
    }

    private void initM3UA() throws Exception {
        this.clientM3UAMgmt = new M3UAManagementImpl("Client", null, new Ss7ExtInterfaceImpl());
        this.clientM3UAMgmt.setTransportManagement(this.sctpManagement);
        this.clientM3UAMgmt.setDeliveryMessageThreadCount(DELIVERY_TRANSFER_MESSAGE_THREAD_COUNT);
        this.clientM3UAMgmt.start();
        this.clientM3UAMgmt.removeAllResources();

        // m3ua as create rc <rc> <ras-name>
        RoutingContext rc = factory.createRoutingContext(new long[] { ROUTING_CONTEXT });
        TrafficModeType trafficModeType = factory.createTrafficModeType(TrafficModeType.Loadshare);
        NetworkAppearance na = factory.createNetworkAppearance(NETWORK_APPEARANCE);

        IPSPType ipspType = null;
        if (AS_FUNCTIONALITY == Functionality.IPSP)
            ipspType = IPSPType.CLIENT;

        // Step 1 : Create AS
        this.clientM3UAMgmt.createAs("AS1", AS_FUNCTIONALITY, ExchangeType.SE, ipspType, rc, trafficModeType, 1, na);
        // Step 2 : Create ASP
        this.clientM3UAMgmt.createAspFactory("ASP1", CLIENT_ASSOCIATION_NAME);
        // Step 3 : Assign ASP to AS
        Asp asp = this.clientM3UAMgmt.assignAspToAs("AS1", "ASP1");
        // Step 4 : Add Route. Remote point code is 2
        this.clientM3UAMgmt.addRoute(DESTINATION_PC, ORIGINATING_PC, SERVICE_INDICATOR, "AS1");
    }

    private void initSCCP() throws Exception {
        Ss7ExtInterface ss7ExtInterface = new Ss7ExtInterfaceImpl();
        sccpExtModule = new SccpExtModuleImpl();
        ss7ExtInterface.setSs7ExtSccpInterface(sccpExtModule);
        this.sccpStack = new SccpStackImpl("MapLoadClientSccpStack", ss7ExtInterface);
        this.sccpStack.setMtp3UserPart(1, this.clientM3UAMgmt);

        // this.sccpStack.setCongControl_Algo(SccpCongestionControlAlgo.levelDepended);

        this.sccpStack.start();
        this.sccpStack.removeAllResources();

        this.router = this.sccpStack.getRouter();
        this.routerExt = sccpExtModule.getRouterExt();
        this.sccpResource = this.sccpStack.getSccpResource();

        this.sccpResource.addRemoteSpc(1, DESTINATION_PC, 0, 0);
        this.sccpResource.addRemoteSsn(1, DESTINATION_PC, HLR_SSN, 0, false);
        this.sccpResource.addRemoteSsn(2, DESTINATION_PC, MSC_SSN, 0, false);

        this.router.addMtp3ServiceAccessPoint(1, 1, ORIGINATING_PC, NETWORK_INDICATOR, 0, null);
        this.router.addMtp3Destination(1, 1, DESTINATION_PC, DESTINATION_PC, 0, 255, 255);

        ParameterFactoryImpl fact = new ParameterFactoryImpl();
        EncodingScheme ec = new BCDEvenEncodingScheme();
        GlobalTitle gt1 = fact.createGlobalTitle("-", 0, org.restcomm.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, ec,
                NatureOfAddress.INTERNATIONAL);
        GlobalTitle gt2 = fact.createGlobalTitle("-", 0, org.restcomm.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, ec,
                NatureOfAddress.INTERNATIONAL);
        SccpAddress localAddress = new SccpAddressImpl(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt1, ORIGINATING_PC, 0);
        this.routerExt.addRoutingAddress(1, localAddress);
        SccpAddress remoteAddress = new SccpAddressImpl(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt2, DESTINATION_PC, 0);
        this.routerExt.addRoutingAddress(2, remoteAddress);

        GlobalTitle gt = fact.createGlobalTitle("*", 0, org.restcomm.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, ec,
                NatureOfAddress.INTERNATIONAL);
        SccpAddress pattern = new SccpAddressImpl(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt, 0, 0);
        this.routerExt.addRule(1, RuleType.SOLITARY, LoadSharingAlgorithm.Bit0, OriginationType.REMOTE, pattern,
                "K", 1, -1, null, 0, null);
        this.routerExt.addRule(2, RuleType.SOLITARY, LoadSharingAlgorithm.Bit0, OriginationType.LOCAL, pattern, "K",
                2, -1, null, 0, null);
    }

    private void initTCAP() throws Exception {
        this.tcapStack = new TCAPStackImpl("Test", this.sccpStack.getSccpProvider(), SMSC_SSN);
        this.tcapStack.start();
        this.tcapStack.setDialogIdleTimeout(60000);
        this.tcapStack.setInvokeTimeout(30000);
        this.tcapStack.setMaxDialogs(MAX_DIALOGS);
    }

    private void initMAP() throws Exception {
        this.mapStack = new MAPStackImpl("TestClient", this.tcapStack.getProvider());
        this.mapProvider = this.mapStack.getMAPProvider();

        this.mapProvider.addMAPDialogListener(this);
        this.mapProvider.getMAPServiceSms().addMAPServiceListener(this);

        this.mapProvider.getMAPServiceSms().activate();

        this.mapStack.start();
    }

    private void initiateMTSM() throws MAPException {
        NetworkIdState networkIdState = this.mapStack.getMAPProvider().getNetworkIdState(0);
        int executorCongestionLevel = this.mapStack.getMAPProvider().getExecutorCongestionLevel();
        if (!(networkIdState == null
                || networkIdState.isAvailable() && networkIdState.getCongLevel() <= 0 && executorCongestionLevel <= 0)) {
            // congestion or unavailable
            logger.warn("**** Outgoing congestion control: MAP load test client: networkIdState=" + networkIdState
                    + ", executorCongestionLevel=" + executorCongestionLevel);
            try {
                Thread.sleep(3000);
            } catch (InterruptedException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }

        this.rateLimiterObj.acquire();

        // First create Dialog
        AddressString originAddressString = this.mapProvider.getMAPParameterFactory()
            .createAddressString(AddressNature.international_number, NumberingPlan.ISDN, "598990012345");
        AddressString destinationAddressString = this.mapProvider.getMAPParameterFactory()
            .createAddressString(AddressNature.international_number, NumberingPlan.ISDN, "598990067890");

        SccpAddress clientSccpAddress = createSccpAddress(ROUTING_INDICATOR, ORIGINATING_PC, SMSC_SSN, SCCP_CLIENT_ADDRESS);
        SccpAddress serverSccpAddress = createSccpAddress(ROUTING_INDICATOR, DESTINATION_PC, HLR_SSN, SCCP_SERVER_ADDRESS);
        MAPDialogSms mapDialogSms = this.mapProvider.getMAPServiceSms().createNewDialog(MAPApplicationContext
                .getInstance(MAPApplicationContextName.shortMsgGatewayContext, MAPApplicationContextVersion.version3),
            clientSccpAddress, originAddressString, serverSccpAddress, destinationAddressString);

        ISDNAddressString msisdn = new ISDNAddressStringImpl(AddressNature.international_number,
            org.restcomm.protocols.ss7.map.api.primitives.NumberingPlan.ISDN, "59899077937");
        boolean sm_RP_PRI = true;
        AddressString serviceCentreAddress = new AddressStringImpl(AddressNature.international_number, NumberingPlan.ISDN, "5989900123");
        MAPExtensionContainer mapExtensionContainer = null;
        boolean gprsSupportIndicator = false;
        // SM_RP_MTI sM_RP_MTI = SM_RP_MTI.getInstance(0); // SMS_DELIVER
        SM_RP_MTI sM_RP_MTI = null;
        SM_RP_SMEA sM_RP_SMEA = null;
        // SMDeliveryNotIntended smDeliveryNotIntended = SMDeliveryNotIntended.getInstance(0); // onlyIMSIRequested
        SMDeliveryNotIntended smDeliveryNotIntended = null;
        boolean ipSmGwGuidanceIndicator = false;
        IMSI imsi = null;
        boolean t4TriggerIndicator = false;
        boolean singleAttemptDelivery = false;
        //TeleserviceCodeValue teleserviceCodeValue = TeleserviceCodeValue.allShortMessageServices;
        // TeleserviceCode teleserviceCode = new TeleserviceCodeImpl(teleserviceCodeValue);
        TeleserviceCode teleserviceCode = null;
        CorrelationID correlationID = null;

        mapDialogSms.addSendRoutingInfoForSMRequest(msisdn, sm_RP_PRI, serviceCentreAddress, mapExtensionContainer,
            gprsSupportIndicator, sM_RP_MTI, sM_RP_SMEA, smDeliveryNotIntended, ipSmGwGuidanceIndicator,
            imsi, t4TriggerIndicator, singleAttemptDelivery, teleserviceCode, correlationID);

        // nbConcurrentDialogs.incrementAndGet();

        // This will initiate the TC-BEGIN with INVOKE component
        mapDialogSms.send();

        this.csvWriter.incrementCounter(CREATED_DIALOGS);
    }

    private SccpAddress createSccpAddress(RoutingIndicator ri, int dpc, int ssn, String address) {
        ParameterFactoryImpl fact = new ParameterFactoryImpl();
        GlobalTitle gt = fact.createGlobalTitle(address, 0, org.restcomm.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY,
        BCDEvenEncodingScheme.INSTANCE, NatureOfAddress.INTERNATIONAL);
        return fact.createSccpAddress(ri, gt, dpc, ssn);
    }

    public void terminate() {
        try {
            this.csvWriter.stop(TEST_END_DELAY);
        } catch (InterruptedException e) {
            logger.error("an error occurred while stopping csvWriter", e);
        }
    }

    public static void main(String[] args) {
        int i = 0;
        IpChannelType ipChannelType = IpChannelType.SCTP;

        if (args.length == 23) {
            NDIALOGS = Integer.parseInt(args[i++]);
            MAXCONCURRENTDIALOGS = Integer.parseInt(args[i++]);
            if (args[i++].toLowerCase().equals("tcp"))
                ipChannelType = IpChannelType.TCP;
            HOST_IP = args[i++];
            HOST_PORT = Integer.parseInt(args[i++]);
            EXTRA_HOST_ADDRESS = args[i++];
            PEER_IP = args[i++];
            PEER_PORT = Integer.parseInt(args[i++]);
            AS_FUNCTIONALITY = Functionality.valueOf(args[i++]);
            ROUTING_CONTEXT = Integer.parseInt(args[i++]);
            NETWORK_APPEARANCE = Integer.parseInt(args[i++]);
            ORIGINATING_PC = Integer.parseInt(args[i++]);
            DESTINATION_PC = Integer.parseInt(args[i++]);
            SERVICE_INDICATOR = Integer.parseInt(args[i++]);
            NETWORK_INDICATOR = Integer.parseInt(args[i++]);
            SMSC_SSN = Integer.parseInt(args[i++]);
            HLR_SSN = Integer.parseInt(args[i++]);
            MSC_SSN = Integer.parseInt(args[i++]);
            SCCP_CLIENT_ADDRESS = args[i++];
            SCCP_SERVER_ADDRESS = args[i++];
            ROUTING_INDICATOR = RoutingIndicator.valueOf(Integer.parseInt(args[i++]));
            DELIVERY_TRANSFER_MESSAGE_THREAD_COUNT = Integer.parseInt(args[i++]);
            RAMP_UP_PERIOD = Integer.parseInt(args[i++]);

            System.out.println("IpChannelType = " + ipChannelType);
            System.out.println("HOST_IP = " + HOST_IP);
            System.out.println("HOST_PORT = " + HOST_PORT);
            System.out.println("EXTRA_HOST_ADDRESS = " + EXTRA_HOST_ADDRESS);
            System.out.println("PEER_IP = " + PEER_IP);
            System.out.println("PEER_PORT = " + PEER_PORT);
            System.out.println("AS_FUNCTIONALITY = " + AS_FUNCTIONALITY);
            System.out.println("ROUTING_CONTEXT = " + ROUTING_CONTEXT);
            System.out.println("NETWORK_APPEARANCE = " + NETWORK_APPEARANCE);
            System.out.println("ORIGINATING_PC = " + ORIGINATING_PC);
            System.out.println("DESTINATION_PC = " + DESTINATION_PC);
            System.out.println("SERVICE_INDICATOR = " + SERVICE_INDICATOR);
            System.out.println("NETWORK_INDICATOR = " + NETWORK_INDICATOR);
            System.out.println("SMSC_SSN = " + SMSC_SSN);
            System.out.println("HLR_SSN = " + HLR_SSN);
            System.out.println("MSC_SSN = " + MSC_SSN);
            System.out.println("SCCP_CLIENT_ADDRESS = " + SCCP_CLIENT_ADDRESS);
            System.out.println("SCCP_SERVER_ADDRESS = " + SCCP_SERVER_ADDRESS);
            System.out.println("ROUTING_INDICATOR = " + ROUTING_INDICATOR);
            System.out.println("DELIVERY_TRANSFER_MESSAGE_THREAD_COUNT = " + DELIVERY_TRANSFER_MESSAGE_THREAD_COUNT);
            System.out.println("RAMP_UP_PERIOD = " + RAMP_UP_PERIOD);
            System.out.println("SENDING_MESSAGE_THREAD_COUNT = " + SENDING_MESSAGE_THREAD_COUNT);
            System.out.println("NDIALOGS = " + NDIALOGS);
            System.out.println("MAXCONCURRENTDIALOGS = " + MAXCONCURRENTDIALOGS);
        }

        final Client client = new Client();
        client.endCount = RAMP_UP_PERIOD;

        try {
            client.initializeStack(ipChannelType);

            Thread.sleep(TEST_START_DELAY);

           // threads creating
            Thread[] threads = new Thread[SENDING_MESSAGE_THREAD_COUNT];
            for (int j = 0; j < SENDING_MESSAGE_THREAD_COUNT; j++) {
                threads[j] = new Thread(client.new DialogInitiator());
            }
            for (int j = 0; j < SENDING_MESSAGE_THREAD_COUNT; j++) {
                threads[j].start();
            }

            while (client.endCount < NDIALOGS) {
                Thread.sleep(100);
                // while (client.nbConcurrentDialogs.intValue() >= MAXCONCURRENTDIALOGS) {

                // logger.warn("Number of concurrent MAP dialog's = " +
                // client.nbConcurrentDialogs.intValue()
                // + " Waiting for max dialog count to go down!");

                // synchronized (client) {
                // try {
                // client.wait();
                // } catch (Exception ex) {
                // }
                // }
                // }// end of while (client.nbConcurrentDialogs.intValue() >= MAXCONCURRENTDIALOGS)

                //if (client.endCount < 0) {
                //    client.start = System.currentTimeMillis();
                //    client.prev = client.start;
                    // logger.warn("StartTime = " + client.start);
                //}

            }

            client.terminate();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.api.MAPServiceListener#onErrorComponent
     * (org.restcomm.protocols.ss7.map.api.MAPDialog, java.lang.Long,
     * org.restcomm.protocols.ss7.map.api.errors.MAPErrorMessage)
     */
    @Override
    public void onErrorComponent(MAPDialog mapDialog, Long invokeId, MAPErrorMessage mapErrorMessage) {
        if (logger.isDebugEnabled()) {
            logger.warn(String.format("onErrorComponent for Dialog=%d and invokeId=%d MAPErrorMessage=%s",
                mapDialog.getLocalDialogId(), invokeId, mapErrorMessage));
        }
        try {
            MAPApplicationContextName mapApplicationContextName = mapDialog.getApplicationContext().getApplicationContextName();
            MAPApplicationContextVersion mapApplicationContextVersion = mapDialog.getApplicationContext().getApplicationContextVersion();
            if (mapApplicationContextName == MAPApplicationContextName.shortMsgMTRelayContext) {
                AddressString originAddressString = this.mapProvider.getMAPParameterFactory()
                    .createAddressString(AddressNature.international_number, NumberingPlan.ISDN, "598990012345");
                AddressString destinationAddressString = this.mapProvider.getMAPParameterFactory()
                    .createAddressString(AddressNature.international_number, NumberingPlan.ISDN, "598990067890");

                SccpAddress clientSccpAddress = createSccpAddress(ROUTING_INDICATOR, ORIGINATING_PC, SMSC_SSN, SCCP_CLIENT_ADDRESS);
                SccpAddress serverSccpAddress = createSccpAddress(ROUTING_INDICATOR, DESTINATION_PC, MSC_SSN, SCCP_SERVER_ADDRESS);
                MAPDialogSms mapDialogSms = this.mapProvider.getMAPServiceSms().createNewDialog(MAPApplicationContext
                        .getInstance(MAPApplicationContextName.shortMsgGatewayContext, MAPApplicationContextVersion.version3),
                    clientSccpAddress, originAddressString, serverSccpAddress, destinationAddressString);

                ISDNAddressString msisdn = new ISDNAddressStringImpl(AddressNature.international_number,
                    org.restcomm.protocols.ss7.map.api.primitives.NumberingPlan.ISDN, "59899077937");
                AddressString serviceCentreAddress = new AddressStringImpl(AddressNature.international_number, NumberingPlan.ISDN, "5989900123");
                SMDeliveryOutcome sMDeliveryOutcome = SMDeliveryOutcome.absentSubscriber;
                Integer absentSubscriberDiagnosticSM = AbsentSubscriberDiagnosticSM.NoPagingResponseViaTheMSC.getCode();
                MAPExtensionContainer extensionContainer = null;
                Boolean gprsSupportIndicator = false;
                Boolean deliveryOutcomeIndicator = false;
                SMDeliveryOutcome additionalSMDeliveryOutcome = SMDeliveryOutcome.absentSubscriber;
                Integer additionalAbsentSubscriberDiagnosticSM = AbsentSubscriberDiagnosticSM.NoPagingResponseViaTheSGSN.getCode();

                mapDialogSms.addReportSMDeliveryStatusRequest(msisdn, serviceCentreAddress, sMDeliveryOutcome, absentSubscriberDiagnosticSM,
                    extensionContainer, gprsSupportIndicator, deliveryOutcomeIndicator, additionalSMDeliveryOutcome, additionalAbsentSubscriberDiagnosticSM);
                mapDialogSms.send();
            }
        } catch (MAPException e) {
            logger.error("Error while processing onErrorResponse and/or sending ReportSMDeliveryStatusRequest ", e);
        }
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.api.MAPServiceListener#onRejectComponent
     * (org.restcomm.protocols.ss7.map.api.MAPDialog, java.lang.Long, org.restcomm.protocols.ss7.tcap.asn.comp.Problem)
     */
    @Override
    public void onRejectComponent(MAPDialog mapDialog, Long invokeId, Problem problem, boolean isLocalOriginated) {
        logger.error(String.format("onRejectComponent for Dialog=%d and invokeId=%d Problem=%s isLocalOriginated=%s",
                mapDialog.getLocalDialogId(), invokeId, problem, isLocalOriginated));
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.api.MAPServiceListener#onInvokeTimeout
     * (org.restcomm.protocols.ss7.map.api.MAPDialog, java.lang.Long)
     */
    @Override
    public void onInvokeTimeout(MAPDialog mapDialog, Long invokeId) {
        logger.error(String.format("onInvokeTimeout for Dialog=%d and invokeId=%d", mapDialog.getLocalDialogId(), invokeId));
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.api.MAPDialogListener#onDialogDelimiter
     * (org.restcomm.protocols.ss7.map.api.MAPDialog)
     */
    @Override
    public void onDialogDelimiter(MAPDialog mapDialog) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onDialogDelimiter for DialogId=%d", mapDialog.getLocalDialogId()));
        }
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.api.MAPDialogListener#onDialogRequest
     * (org.restcomm.protocols.ss7.map.api.MAPDialog, org.restcomm.protocols.ss7.map.api.primitives.AddressString,
     * org.restcomm.protocols.ss7.map.api.primitives.AddressString,
     * org.restcomm.protocols.ss7.map.api.primitives.MAPExtensionContainer)
     */
    @Override
    public void onDialogRequest(MAPDialog mapDialog, AddressString destReference, AddressString origReference, MAPExtensionContainer extensionContainer) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format(
                    "onDialogRequest for DialogId=%d DestinationReference=%s OriginReference=%s MAPExtensionContainer=%s",
                    mapDialog.getLocalDialogId(), destReference, origReference, extensionContainer));
        }
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.api.MAPDialogListener#onDialogRequestEricsson
     * (org.restcomm.protocols.ss7.map.api.MAPDialog, org.restcomm.protocols.ss7.map.api.primitives.AddressString,
     * org.restcomm.protocols.ss7.map.api.primitives.AddressString, org.restcomm.protocols.ss7.map.api.primitives.IMSI,
     * org.restcomm.protocols.ss7.map.api.primitives.AddressString)
     */
    @Override
    public void onDialogRequestEricsson(MAPDialog mapDialog, AddressString destReference, AddressString origReference, AddressString arg3,
                                        AddressString arg4) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onDialogRequest for DialogId=%d DestinationReference=%s OriginReference=%s ",
                    mapDialog.getLocalDialogId(), destReference, origReference));
        }
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.api.MAPDialogListener#onDialogAccept( org.restcomm.protocols.ss7.map.api.MAPDialog,
     * org.restcomm.protocols.ss7.map.api.primitives.MAPExtensionContainer)
     */
    @Override
    public void onDialogAccept(MAPDialog mapDialog, MAPExtensionContainer extensionContainer) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onDialogAccept for DialogId=%d MAPExtensionContainer=%s", mapDialog.getLocalDialogId(), extensionContainer));
        }
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.api.MAPDialogListener#onDialogReject( org.restcomm.protocols.ss7.map.api.MAPDialog,
     * org.restcomm.protocols.ss7.map.api.dialog.MAPRefuseReason, org.restcomm.protocols.ss7.map.api.dialog.MAPProviderError,
     * org.restcomm.protocols.ss7.tcap.asn.ApplicationContextName,
     * org.restcomm.protocols.ss7.map.api.primitives.MAPExtensionContainer)
     */
    @Override
    public void onDialogReject(MAPDialog mapDialog, MAPRefuseReason refuseReason, ApplicationContextName alternativeApplicationContext,
                               MAPExtensionContainer extensionContainer) {
        logger.error(String.format(
                "onDialogReject for DialogId=%d MAPRefuseReason=%s ApplicationContextName=%s MAPExtensionContainer=%s",
                mapDialog.getLocalDialogId(), refuseReason, alternativeApplicationContext, extensionContainer));
        this.csvWriter.incrementCounter(ERROR_DIALOGS);
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.api.MAPDialogListener#onDialogUserAbort
     * (org.restcomm.protocols.ss7.map.api.MAPDialog, org.restcomm.protocols.ss7.map.api.dialog.MAPUserAbortChoice,
     * org.restcomm.protocols.ss7.map.api.primitives.MAPExtensionContainer)
     */
    @Override
    public void onDialogUserAbort(MAPDialog mapDialog, MAPUserAbortChoice userReason, MAPExtensionContainer extensionContainer) {
        logger.error(String.format("onDialogUserAbort for DialogId=%d MAPUserAbortChoice=%s MAPExtensionContainer=%s",
                mapDialog.getLocalDialogId(), userReason, extensionContainer));
        this.csvWriter.incrementCounter(ERROR_DIALOGS);
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.api.MAPDialogListener#onDialogProviderAbort
     * (org.restcomm.protocols.ss7.map.api.MAPDialog, org.restcomm.protocols.ss7.map.api.dialog.MAPAbortProviderReason,
     * org.restcomm.protocols.ss7.map.api.dialog.MAPAbortSource,
     * org.restcomm.protocols.ss7.map.api.primitives.MAPExtensionContainer)
     */
    @Override
    public void onDialogProviderAbort(MAPDialog mapDialog, MAPAbortProviderReason abortProviderReason, MAPAbortSource abortSource,
            MAPExtensionContainer extensionContainer) {
        logger.error(String.format(
                "onDialogProviderAbort for DialogId=%d MAPAbortProviderReason=%s MAPAbortSource=%s MAPExtensionContainer=%s",
                mapDialog.getLocalDialogId(), abortProviderReason, abortSource, extensionContainer));
        this.csvWriter.incrementCounter(ERROR_DIALOGS);
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.api.MAPDialogListener#onDialogClose(org .mobicents.protocols.ss7.map.api.MAPDialog)
     */
    @Override
    public void onDialogClose(MAPDialog mapDialog) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("DialogClose for Dialog=%d", mapDialog.getLocalDialogId()));
        }
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.api.MAPDialogListener#onDialogNotice( org.restcomm.protocols.ss7.map.api.MAPDialog,
     * org.restcomm.protocols.ss7.map.api.dialog.MAPNoticeProblemDiagnostic)
     */
    @Override
    public void onDialogNotice(MAPDialog mapDialog, MAPNoticeProblemDiagnostic noticeProblemDiagnostic) {
        logger.error(String.format("onDialogNotice for DialogId=%d MAPNoticeProblemDiagnostic=%s ",
                mapDialog.getLocalDialogId(), noticeProblemDiagnostic));
        this.csvWriter.incrementCounter(ERROR_DIALOGS);
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.api.MAPDialogListener#onDialogResease
     * (org.restcomm.protocols.ss7.map.api.MAPDialog)
     */
    @Override
    public void onDialogRelease(MAPDialog mapDialog) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onDialogRelease for DialogId=%d", mapDialog.getLocalDialogId()));
        }
        this.csvWriter.incrementCounter(SUCCESSFUL_DIALOGS);
        this.endCount++;

        if (this.endCount < NDIALOGS) {
            if ((this.endCount % 10000) == 0) {
                long current = System.currentTimeMillis();
                float sec = (float) (current - prev) / 1000f;
                prev = current;
                logger.warn("Completed 10000 Dialogs, dialogs per second: " + (float) (10000 / sec));
            }
        } else {
            if (this.endCount >= NDIALOGS && !endReportPrinted) {
                endReportPrinted = true;
                long current = System.currentTimeMillis();
                logger.warn("Start Time = " + start);
                logger.warn("Current Time = " + current);
                float sec = (float) (current - start) / 1000f;

                logger.warn("Total time in sec = " + sec);
                logger.warn("Throughput = " + (float) (NDIALOGS / sec));
            }
        }
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.api.MAPDialogListener#onDialogTimeout
     * (org.restcomm.protocols.ss7.map.api.MAPDialog)
     */
    @Override
    public void onDialogTimeout(MAPDialog mapDialog) {
        logger.error(String.format("onDialogTimeout for DialogId=%d", mapDialog.getLocalDialogId()));
        this.csvWriter.incrementCounter(ERROR_DIALOGS);
    }

    @Override
    public void onMAPMessage(MAPMessage mapMessage) {
        // TODO Auto-generated method stub

    }

    @Override
    public MAPProvider getMAPProvider() {
        return null;
    }

    @Override
    public ServingCheckData isServingService(MAPApplicationContext dialogApplicationContext) {
        return null;
    }

    @Override
    public boolean isActivated() {
        return false;
    }

    @Override
    public void activate() {

    }

    @Override
    public void deactivate() {

    }

    @Override
    public MAPDialogSms createNewDialog(MAPApplicationContext mapApplicationContext, SccpAddress sccpCallingPartyAddress, AddressString origReference, SccpAddress sccpCalledPartyAddress, AddressString destReference, Long localTransactionId) throws MAPException {
        return null;
    }

    @Override
    public MAPDialogSms createNewDialog(MAPApplicationContext mapApplicationContext, SccpAddress sccpCallingPartyAddress, AddressString origReference, SccpAddress sccpCalledPartyAddress, AddressString destReference) throws MAPException {
        return null;
    }

    @Override
    public void addMAPServiceListener(MAPServiceSmsListener mapServiceSmsListener) {

    }

    @Override
    public void removeMAPServiceListener(MAPServiceSmsListener mapServiceSmsListener) {

    }

    @Override
    public void onForwardShortMessageRequest(ForwardShortMessageRequest forwardShortMessageRequestIndication) {

    }

    @Override
    public void onForwardShortMessageResponse(ForwardShortMessageResponse forwardShortMessageResponseIndication) {

    }

    @Override
    public void onMoForwardShortMessageRequest(MoForwardShortMessageRequest moForwardShortMessageRequestIndication) {

    }

    @Override
    public void onMoForwardShortMessageResponse(MoForwardShortMessageResponse moForwardShortMessageResponseIndication) {

    }

    @Override
    public void onMtForwardShortMessageRequest(MtForwardShortMessageRequest mtForwardShortMessageRequestIndication) {

    }

    @Override
    public void onMtForwardShortMessageResponse(MtForwardShortMessageResponse mtForwardShortMessageResponseIndication) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onMtForwardShortMessageResponse for DialogId=%d", mtForwardShortMessageResponseIndication
                .getMAPDialog().getLocalDialogId()));
        }
    }

    @Override
    public void onSendRoutingInfoForSMRequest(SendRoutingInfoForSMRequest sendRoutingInfoForSMRequestIndication) {

    }

    @Override
    public void onSendRoutingInfoForSMResponse(SendRoutingInfoForSMResponse sendRoutingInfoForSMResponseIndication) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onSendRoutingInfoForSMResponse for DialogId=%d", sendRoutingInfoForSMResponseIndication
                .getMAPDialog().getLocalDialogId()));
        }
        try {
            // Get IMSI and Network Node Number from sendRoutingInfoForSMResponseIndication
            IMSI imsi = sendRoutingInfoForSMResponseIndication.getIMSI();
            LocationInfoWithLMSI locationInfoWithLMSI = sendRoutingInfoForSMResponseIndication.getLocationInfoWithLMSI();
            AddressString networkNodeNumber = locationInfoWithLMSI.getNetworkNodeNumber();
            // Create Dialog
            AddressString originAddressString = this.mapProvider.getMAPParameterFactory()
                .createAddressString(AddressNature.international_number, NumberingPlan.ISDN, "598990012345");

            SccpAddress clientSccpAddress = createSccpAddress(ROUTING_INDICATOR, ORIGINATING_PC, SMSC_SSN, SCCP_CLIENT_ADDRESS);
            SccpAddress serverSccpAddress = createSccpAddress(ROUTING_INDICATOR, DESTINATION_PC, MSC_SSN, networkNodeNumber.getAddress());

            MAPApplicationContextVersion mapAcnVersion = MAPApplicationContextVersion.version3;
            MAPApplicationContextName mapAcn = MAPApplicationContextName.shortMsgMTRelayContext;
            MAPApplicationContext mapAppContext = MAPApplicationContext.getInstance(mapAcn, mapAcnVersion);

            MAPDialogSms mapDialogSms = this.mapProvider.getMAPServiceSms().createNewDialog(mapAppContext, clientSccpAddress,
                originAddressString, serverSccpAddress, networkNodeNumber);

            SM_RP_DA da = mapProvider.getMAPParameterFactory().createSM_RP_DA(imsi);
            AddressString serviceCentreAddressOA = new AddressStringImpl(AddressNature.international_number, NumberingPlan.ISDN, "5989900123");

            SM_RP_OA oa = mapProvider.getMAPParameterFactory().createSM_RP_OA_ServiceCentreAddressOA(serviceCentreAddressOA);
            AddressField originatingAddress = new AddressFieldImpl(TypeOfNumber.Alphanumeric, NumberingPlanIdentification.Unknown, "447");
            Calendar cld = new GregorianCalendar();
            int year = cld.get(Calendar.YEAR);
            int mon = cld.get(Calendar.MONTH);
            int day = cld.get(Calendar.DAY_OF_MONTH);
            int h = cld.get(Calendar.HOUR);
            int m = cld.get(Calendar.MINUTE);
            int s = cld.get(Calendar.SECOND);
            int tz = cld.get(Calendar.ZONE_OFFSET);
            AbsoluteTimeStamp serviceCentreTimeStamp = new AbsoluteTimeStampImpl(year - 2000, mon, day, h, m, s, tz / 1000 / 60 / 15);
            int dcsVal = 4; // 0 = GSM7, 4 = GSM8, 8 = UCS2
            DataCodingScheme dcs = new DataCodingSchemeImpl(dcsVal);
            UserDataHeader udh = null;
            if (dcs.getCharacterSet() == CharacterSet.GSM8) {
                ApplicationPortAddressing16BitAddressImpl apa16 = new ApplicationPortAddressing16BitAddressImpl(16020, 0);
                udh = new UserDataHeaderImpl();
                udh.addInformationElement(apa16);
            }
            Boolean moreMessagesToSend = false;
            Boolean forwardedOrSpawned = false;
            Boolean replyPathExists = false;
            Boolean statusReportIndication = true;
            Charset gsm8Charset = Charset.defaultCharset();
            UserData userData = new UserDataImpl("Load test MT-SMS text", dcs, udh, gsm8Charset);
            ProtocolIdentifier pi = new ProtocolIdentifierImpl(0);
            SmsDeliverTpdu tpdu = new SmsDeliverTpduImpl(moreMessagesToSend, forwardedOrSpawned, replyPathExists, statusReportIndication, originatingAddress, pi, serviceCentreTimeStamp, userData);
            SmsSignalInfo si = mapProvider.getMAPParameterFactory().createSmsSignalInfo(tpdu, gsm8Charset);

            MAPExtensionContainer mapExtensionContainer = null;

            mapDialogSms.addMtForwardShortMessageRequest(da, oa, si, moreMessagesToSend, mapExtensionContainer);

            mapDialogSms.send();

            this.csvWriter.incrementCounter(CREATED_DIALOGS);

        } catch (MAPException e) {
            logger.error("Error while sending SendRoutingInfoForSMRequest ", e);
        }
    }

    @Override
    public void onReportSMDeliveryStatusRequest(ReportSMDeliveryStatusRequest reportSMDeliveryStatusRequestIndication) {

    }

    @Override
    public void onReportSMDeliveryStatusResponse(ReportSMDeliveryStatusResponse reportSMDeliveryStatusResponseIndication) {

    }

    @Override
    public void onInformServiceCentreRequest(InformServiceCentreRequest informServiceCentreRequestIndication) {

    }

    @Override
    public void onAlertServiceCentreRequest(AlertServiceCentreRequest alertServiceCentreRequestIndication) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onAlertServiceCentreRequest for DialogId=%d", alertServiceCentreRequestIndication
                .getMAPDialog().getLocalDialogId()));
        }
        try {
            MAPDialogSms mapDialogSms = alertServiceCentreRequestIndication.getMAPDialog();
            ReturnResultLast returnResultLast = new ReturnResultLastImpl();
            returnResultLast.setInvokeId(alertServiceCentreRequestIndication.getInvokeId());
            mapDialogSms.sendReturnResultLastComponent(returnResultLast);
            mapDialogSms.close(false);
            // start the MT-SM process again now that's reported available
            initiateMTSM();
        } catch (MAPException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void onAlertServiceCentreResponse(AlertServiceCentreResponse alertServiceCentreResponseIndication) {

    }

    @Override
    public void onReadyForSMRequest(ReadyForSMRequest readyForSMRequest) {

    }

    @Override
    public void onReadyForSMResponse(ReadyForSMResponse readyForSMResponse) {

    }

    @Override
    public void onNoteSubscriberPresentRequest(NoteSubscriberPresentRequest noteSubscriberPresentRequest) {

    }

    public class DialogInitiator implements Runnable {

        @Override
        public void run() {
            try {
                while (endCount < NDIALOGS) {
                    // while (client.nbConcurrentDialogs.intValue() >= MAXCONCURRENTDIALOGS) {

                    // logger.warn("Number of concurrent MAP dialog's = " +
                    // client.nbConcurrentDialogs.intValue()
                    // + " Waiting for max dialog count to go down!");

                    // synchronized (client) {
                    // try {
                    // client.wait();
                    // } catch (Exception ex) {
                    // }
                    // }
                    // }// end of while (client.nbConcurrentDialogs.intValue() >=
                    // MAXCONCURRENTDIALOGS)

                    if (endCount < 0) {
                        start = System.currentTimeMillis();
                        prev = start;
                        // logger.warn("StartTime = " + client.start);
                    }

                    initiateMTSM();
                }
            } catch (MAPException ex) {
                logger.error("Exception when sending a new MAP dialog", ex);
            }
        }

    }
}
