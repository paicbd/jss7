
package org.restcomm.protocols.ss7.map.load.sms.mo;

import com.google.common.util.concurrent.RateLimiter;
import javolution.util.FastList;
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
import org.restcomm.protocols.ss7.map.api.errors.MAPErrorMessage;
import org.restcomm.protocols.ss7.map.api.primitives.AddressNature;
import org.restcomm.protocols.ss7.map.api.primitives.AddressString;
import org.restcomm.protocols.ss7.map.api.primitives.IMSI;
import org.restcomm.protocols.ss7.map.api.primitives.ISDNAddressString;
import org.restcomm.protocols.ss7.map.api.primitives.LMSI;
import org.restcomm.protocols.ss7.map.api.primitives.MAPExtensionContainer;
import org.restcomm.protocols.ss7.map.api.primitives.NumberingPlan;
import org.restcomm.protocols.ss7.map.api.service.lsm.AdditionalNumber;
import org.restcomm.protocols.ss7.map.api.service.sms.AlertServiceCentreRequest;
import org.restcomm.protocols.ss7.map.api.service.sms.AlertServiceCentreResponse;
import org.restcomm.protocols.ss7.map.api.service.sms.ForwardShortMessageRequest;
import org.restcomm.protocols.ss7.map.api.service.sms.ForwardShortMessageResponse;
import org.restcomm.protocols.ss7.map.api.service.sms.InformServiceCentreRequest;
import org.restcomm.protocols.ss7.map.api.service.sms.IpSmGwGuidance;
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
import org.restcomm.protocols.ss7.map.api.service.sms.SM_RP_DA;
import org.restcomm.protocols.ss7.map.api.service.sms.SendRoutingInfoForSMRequest;
import org.restcomm.protocols.ss7.map.api.service.sms.SendRoutingInfoForSMResponse;
import org.restcomm.protocols.ss7.map.api.service.sms.SmsSignalInfo;
import org.restcomm.protocols.ss7.map.api.smstpdu.AddressField;
import org.restcomm.protocols.ss7.map.api.smstpdu.DataCodingScheme;
import org.restcomm.protocols.ss7.map.api.smstpdu.NumberingPlanIdentification;
import org.restcomm.protocols.ss7.map.api.smstpdu.ProtocolIdentifier;
import org.restcomm.protocols.ss7.map.api.smstpdu.SmsTpduType;
import org.restcomm.protocols.ss7.map.api.smstpdu.TypeOfNumber;
import org.restcomm.protocols.ss7.map.api.smstpdu.UserData;
import org.restcomm.protocols.ss7.map.api.smstpdu.UserDataHeader;
import org.restcomm.protocols.ss7.map.api.smstpdu.ValidityPeriod;
import org.restcomm.protocols.ss7.map.load.CsvWriter;
import org.restcomm.protocols.ss7.map.primitives.AddressStringImpl;
import org.restcomm.protocols.ss7.map.primitives.IMSIImpl;
import org.restcomm.protocols.ss7.map.primitives.ISDNAddressStringImpl;
import org.restcomm.protocols.ss7.map.primitives.LMSIImpl;
import org.restcomm.protocols.ss7.map.service.sms.LocationInfoWithLMSIImpl;
import org.restcomm.protocols.ss7.map.service.sms.SM_RP_DAImpl;
import org.restcomm.protocols.ss7.map.service.sms.SM_RP_OAImpl;
import org.restcomm.protocols.ss7.map.service.sms.SmsSignalInfoImpl;
import org.restcomm.protocols.ss7.map.smstpdu.AddressFieldImpl;
import org.restcomm.protocols.ss7.map.smstpdu.DataCodingSchemeImpl;
import org.restcomm.protocols.ss7.map.smstpdu.ProtocolIdentifierImpl;
import org.restcomm.protocols.ss7.map.smstpdu.SmsSubmitTpduImpl;
import org.restcomm.protocols.ss7.map.smstpdu.SmsTpduImpl;
import org.restcomm.protocols.ss7.map.smstpdu.UserDataHeaderImpl;
import org.restcomm.protocols.ss7.map.smstpdu.UserDataImpl;
import org.restcomm.protocols.ss7.map.smstpdu.ValidityPeriodImpl;
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
import java.util.List;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * @modified <a href="mailto:fernando.mendioroz@gmail.com"> Fernando Mendioroz </a>
 */
public class Client extends TestHarnessSmsMo {

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

    private AtomicInteger messageReferenceForMo = new AtomicInteger(0);
    private AtomicInteger counterIncrement = new AtomicInteger(0);

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
        this.sccpResource.addRemoteSsn(1, DESTINATION_PC, REMOTE_SSN, 0, false);
        this.sccpResource.addRemoteSsn(2, DESTINATION_PC, 6, 0, false);

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
        List<Integer> extraSsns = new FastList<Integer>();
        extraSsns.add(6);

        this.tcapStack = new TCAPStackImpl("Test", this.sccpStack.getSccpProvider(), SSN);
        this.tcapStack.setExtraSsns(extraSsns);
        this.tcapStack.start();
        this.tcapStack.setDialogIdleTimeout(60000);
        this.tcapStack.setInvokeTimeout(30000);
        this.tcapStack.setMaxDialogs(MAX_DIALOGS);
    }

    private void initMAP() throws Exception {

        // this.mapStack = new MAPStackImpl(this.sccpStack.getSccpProvider(), SSN);
        this.mapStack = new MAPStackImpl("TestClient", this.tcapStack.getProvider());
        this.mapProvider = this.mapStack.getMAPProvider();

        this.mapProvider.addMAPDialogListener(this);
        this.mapProvider.getMAPServiceSms().addMAPServiceListener(this);

        this.mapProvider.getMAPServiceSms().activate();

        this.mapStack.start();
    }

    private void initiateSMS() throws MAPException {
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
        // System.out.println("initiateSMS");

        // First create Dialog
        AddressString origRef = this.mapProvider.getMAPParameterFactory()
                .createAddressString(AddressNature.international_number, NumberingPlan.ISDN, "12345");
        AddressString destRef = this.mapProvider.getMAPParameterFactory()
                .createAddressString(AddressNature.international_number, NumberingPlan.ISDN, "67890");

        SccpAddress clientSccpAddress = createSccpAddress(ROUTING_INDICATOR, ORIGINATING_PC, SSN, SCCP_CLIENT_ADDRESS);
        SccpAddress serverSccpAddress = createSccpAddress(ROUTING_INDICATOR, DESTINATION_PC, SSN, SCCP_SERVER_ADDRESS);
        MAPDialogSms mapDialogSms = this.mapProvider.getMAPServiceSms().createNewDialog(MAPApplicationContext
                .getInstance(MAPApplicationContextName.shortMsgMORelayContext, MAPApplicationContextVersion.version3),
                clientSccpAddress, origRef, serverSccpAddress, destRef);

        AddressString serviceCentreAddressDA = new AddressStringImpl(AddressNature.international_number, NumberingPlan.ISDN, "5989900123");
        SM_RP_DA sm_rp_da = new SM_RP_DAImpl(serviceCentreAddressDA);

        String uniqueMsisdn = "31" + String.format("%0" + 9 + "d", this.getCounterIncrement());
        ISDNAddressString msisdn = this.mapProvider.getMAPParameterFactory()
            .createISDNAddressString(AddressNature.international_number, NumberingPlan.ISDN, uniqueMsisdn);
        SM_RP_OAImpl sm_rp_oa = new SM_RP_OAImpl();
        sm_rp_oa.setMsisdn(msisdn);

        boolean rejectDuplicates = true;
        boolean replyPathExists = false;
        boolean statusReportRequest = STATUS_REPORT_REQUEST;
        int messageReference = messageReferenceForMo.incrementAndGet();
        AddressField destinationAddress = new AddressFieldImpl(TypeOfNumber.InternationalNumber,
            NumberingPlanIdentification.ISDNTelephoneNumberingPlan, "59899077937");
        ProtocolIdentifier protocolIdentifier = new ProtocolIdentifierImpl(0);
        ValidityPeriod validityPeriod = new ValidityPeriodImpl(3);
        SmsTpduType smsTpduType = SmsTpduType.SMS_SUBMIT;
        DataCodingScheme dataCodingScheme = new DataCodingSchemeImpl(0);
        UserDataHeader userDataHeader = new UserDataHeaderImpl();
        Charset gsm8Charset = Charset.defaultCharset();
        UserData userData = new UserDataImpl("SMS load test", dataCodingScheme, userDataHeader, gsm8Charset);
        SmsTpduImpl smsTpdu = new SmsSubmitTpduImpl(rejectDuplicates, replyPathExists, statusReportRequest, messageReference, destinationAddress,
            protocolIdentifier, validityPeriod, userData);
        SmsSignalInfo smsSignalInfo = new SmsSignalInfoImpl(smsTpdu, gsm8Charset);
        MAPExtensionContainer mapExtensionContainer = null;

        String uniqueImsi = "712345" + String.format("%0" + 9 + "d", this.getCounterIncrement());
        IMSI imsi = new IMSIImpl(uniqueImsi);

        mapDialogSms.addMoForwardShortMessageRequest(sm_rp_da, sm_rp_oa, smsSignalInfo, mapExtensionContainer, imsi);

        // nbConcurrentDialogs.incrementAndGet();

        // This will initiate the TC-BEGIN with INVOKE component
        mapDialogSms.send();

        this.csvWriter.incrementCounter(CREATED_DIALOGS);
    }

    private SccpAddress createSccpAddress(RoutingIndicator ri, int dpc, int ssn, String address) {
        ParameterFactoryImpl fact = new ParameterFactoryImpl();
        GlobalTitle gt = fact.createGlobalTitle(address, 0, org.restcomm.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY,
        BCDEvenEncodingScheme.INSTANCE, NatureOfAddress.INTERNATIONAL);
        if (ssn < 0) {
            ssn = SSN;
        }
        return fact.createSccpAddress(ri, gt, dpc, ssn);
    }

    public void terminate() {
        try {
            this.csvWriter.stop(TEST_END_DELAY);
        } catch (InterruptedException e) {
            logger.error("an error occurred while stopping csvWriter", e);
        }
    }

    public static void main(String[] args) throws InterruptedException {
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
            SSN = Integer.parseInt(args[i++]);
            REMOTE_SSN = Integer.parseInt(args[i++]);
            SCCP_CLIENT_ADDRESS = args[i++];
            SCCP_SERVER_ADDRESS = args[i++];
            ROUTING_INDICATOR = RoutingIndicator.valueOf(Integer.parseInt(args[i++]));
            DELIVERY_TRANSFER_MESSAGE_THREAD_COUNT = Integer.parseInt(args[i++]);
            RAMP_UP_PERIOD = Integer.parseInt(args[i++]);

            STATUS_REPORT_REQUEST = Boolean.parseBoolean(args[i++]);

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
            System.out.println("SSN = " + SSN);
            System.out.println("REMOTE_SSN = " + REMOTE_SSN);
            System.out.println("SCCP_CLIENT_ADDRESS = " + SCCP_CLIENT_ADDRESS);
            System.out.println("SCCP_SERVER_ADDRESS = " + SCCP_SERVER_ADDRESS);
            System.out.println("ROUTING_INDICATOR = " + ROUTING_INDICATOR);
            System.out.println("DELIVERY_TRANSFER_MESSAGE_THREAD_COUNT = " + DELIVERY_TRANSFER_MESSAGE_THREAD_COUNT);
            System.out.println("RAMP_UP_PERIOD = " + RAMP_UP_PERIOD);
            System.out.println("SENDING_MESSAGE_THREAD_COUNT = " + SENDING_MESSAGE_THREAD_COUNT);
            System.out.println("NDIALOGS = " + NDIALOGS);
            System.out.println("MAXCONCURRENTDIALOGS = " + MAXCONCURRENTDIALOGS);
            System.out.println("STATUS_REPORT_REQUEST = " + STATUS_REPORT_REQUEST);
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

               // client.initiateUSSD();
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
        logger.error(String.format("onErrorComponent for Dialog=%d and invokeId=%d MAPErrorMessage=%s",
                mapDialog.getLocalDialogId(), invokeId, mapErrorMessage));
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
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onMtForwardShortMessageRequest for DialogId=%d", mtForwardShortMessageRequestIndication
                    .getMAPDialog().getLocalDialogId()));
        }
        try {
            long invokeId = mtForwardShortMessageRequestIndication.getInvokeId();
            MAPDialogSms mapDialogSms = mtForwardShortMessageRequestIndication.getMAPDialog();
            mapDialogSms.setUserObject(invokeId);

            ReturnResultLast returnResultLast = new ReturnResultLastImpl();
            returnResultLast.setInvokeId(invokeId);
            mapDialogSms.sendReturnResultLastComponent(returnResultLast);
            mapDialogSms.close(false);

        } catch (MAPException e) {
            logger.error("Error while sending MtForwardShortMessageRequest result ", e);
        }
    }

    @Override
    public void onMtForwardShortMessageResponse(MtForwardShortMessageResponse mtForwardShortMessageResponseIndication) {

    }

    @Override
    public void onSendRoutingInfoForSMRequest(SendRoutingInfoForSMRequest sendRoutingInfoForSMRequestIndication) {
        /**
         * It is only used when the simulator is being used in client mode.
         */
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onSendRoutingInfoForSMRequest for DialogId=%d", sendRoutingInfoForSMRequestIndication
                    .getMAPDialog().getLocalDialogId()));
        }
        try {
            long invokeId = sendRoutingInfoForSMRequestIndication.getInvokeId();
            MAPDialogSms mapDialogSms = sendRoutingInfoForSMRequestIndication.getMAPDialog();
            mapDialogSms.setUserObject(invokeId);
            IMSI imsi = new IMSIImpl("748031234567890");
            ISDNAddressString networkNodeNumber = new ISDNAddressStringImpl(AddressNature.international_number, NumberingPlan.ISDN, "598991900032");
            byte[] lmsiByte = null;
            Random rand = new Random();
            int lmsiRandom = rand.nextInt(4) + 1;
            switch (lmsiRandom) {
                case 1:
                    // char packet_bytes[] = {0x72, 0x02, 0xe9, 0x8c};
                    lmsiByte = new byte[]{114, 2, (byte) 233, (byte) 140};
                    break;
                case 2:
                    // char packet_bytes[] = {0x71, 0xff, 0xac, 0xce};
                    lmsiByte = new byte[]{113, (byte) 255, (byte) 172, (byte) 206};
                    break;
                case 3:
                    // char packet_bytes[] = {0x72, 0x02, 0xeb, 0x37};
                    lmsiByte = new byte[]{114, 2, (byte) 235, 55};
                    break;
                case 4:
                    // char packet_bytes[] = {0x72, 0x02, 0xe7, 0xd5};
                    lmsiByte = new byte[]{114, 2, (byte) 231, (byte) 213};
                    break;
            }
            LMSI lmsi = new LMSIImpl(lmsiByte);
            MAPExtensionContainer mapExtensionContainer = null;
            boolean gprsNodeIndicator = false;
            AdditionalNumber additionalNumber = null;
            LocationInfoWithLMSI locationInfoWithLMSI = new LocationInfoWithLMSIImpl(networkNodeNumber, lmsi, mapExtensionContainer,
                    gprsNodeIndicator, additionalNumber);
            Boolean mwdSet = null;
            IpSmGwGuidance ipSmGwGuidance = null;
            mapDialogSms.addSendRoutingInfoForSMResponse(invokeId, imsi, locationInfoWithLMSI, mapExtensionContainer, mwdSet, ipSmGwGuidance);

            mapDialogSms.close(false);

        } catch (MAPException e) {
            logger.error("Error while sending SendRoutingInfoForSMRequest ", e);
        }
    }

    @Override
    public void onSendRoutingInfoForSMResponse(SendRoutingInfoForSMResponse sendRoutingInfoForSMResponseIndication) {

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

                    initiateSMS();
                }
            } catch (MAPException ex) {
                logger.error("Exception when sending a new MAP dialog", ex);
            }
        }

    }

    private int getCounterIncrement() {
        int x = counterIncrement.incrementAndGet();
        if (x > 147483647) {
            x = 1;
            counterIncrement.set(x);
        }

        return x;
    }
}
