
package org.restcomm.protocols.ss7.map.load.ussd;

import java.util.Random;
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
import org.restcomm.protocols.ss7.map.api.datacoding.CBSDataCodingScheme;
import org.restcomm.protocols.ss7.map.api.dialog.MAPAbortProviderReason;
import org.restcomm.protocols.ss7.map.api.dialog.MAPAbortSource;
import org.restcomm.protocols.ss7.map.api.dialog.MAPNoticeProblemDiagnostic;
import org.restcomm.protocols.ss7.map.api.dialog.MAPRefuseReason;
import org.restcomm.protocols.ss7.map.api.dialog.MAPUserAbortChoice;
import org.restcomm.protocols.ss7.map.api.errors.MAPErrorMessage;
import org.restcomm.protocols.ss7.map.api.primitives.AddressNature;
import org.restcomm.protocols.ss7.map.api.primitives.AddressString;
import org.restcomm.protocols.ss7.map.api.primitives.ISDNAddressString;
import org.restcomm.protocols.ss7.map.api.primitives.MAPExtensionContainer;
import org.restcomm.protocols.ss7.map.api.primitives.NumberingPlan;
import org.restcomm.protocols.ss7.map.api.primitives.USSDString;
import org.restcomm.protocols.ss7.map.api.service.sms.AlertServiceCentreRequest;
import org.restcomm.protocols.ss7.map.api.service.sms.AlertServiceCentreResponse;
import org.restcomm.protocols.ss7.map.api.service.sms.ForwardShortMessageRequest;
import org.restcomm.protocols.ss7.map.api.service.sms.ForwardShortMessageResponse;
import org.restcomm.protocols.ss7.map.api.service.sms.InformServiceCentreRequest;
import org.restcomm.protocols.ss7.map.api.service.sms.MoForwardShortMessageRequest;
import org.restcomm.protocols.ss7.map.api.service.sms.MoForwardShortMessageResponse;
import org.restcomm.protocols.ss7.map.api.service.sms.MtForwardShortMessageRequest;
import org.restcomm.protocols.ss7.map.api.service.sms.MtForwardShortMessageResponse;
import org.restcomm.protocols.ss7.map.api.service.sms.NoteSubscriberPresentRequest;
import org.restcomm.protocols.ss7.map.api.service.sms.ReadyForSMRequest;
import org.restcomm.protocols.ss7.map.api.service.sms.ReadyForSMResponse;
import org.restcomm.protocols.ss7.map.api.service.sms.ReportSMDeliveryStatusRequest;
import org.restcomm.protocols.ss7.map.api.service.sms.ReportSMDeliveryStatusResponse;
import org.restcomm.protocols.ss7.map.api.service.sms.SendRoutingInfoForSMRequest;
import org.restcomm.protocols.ss7.map.api.service.sms.SendRoutingInfoForSMResponse;
import org.restcomm.protocols.ss7.map.api.service.supplementary.ActivateSSRequest;
import org.restcomm.protocols.ss7.map.api.service.supplementary.ActivateSSResponse;
import org.restcomm.protocols.ss7.map.api.service.supplementary.DeactivateSSRequest;
import org.restcomm.protocols.ss7.map.api.service.supplementary.DeactivateSSResponse;
import org.restcomm.protocols.ss7.map.api.service.supplementary.EraseSSRequest;
import org.restcomm.protocols.ss7.map.api.service.supplementary.EraseSSResponse;
import org.restcomm.protocols.ss7.map.api.service.supplementary.GetPasswordRequest;
import org.restcomm.protocols.ss7.map.api.service.supplementary.GetPasswordResponse;
import org.restcomm.protocols.ss7.map.api.service.supplementary.InterrogateSSRequest;
import org.restcomm.protocols.ss7.map.api.service.supplementary.InterrogateSSResponse;
import org.restcomm.protocols.ss7.map.api.service.supplementary.MAPDialogSupplementary;
import org.restcomm.protocols.ss7.map.api.service.supplementary.ProcessUnstructuredSSRequest;
import org.restcomm.protocols.ss7.map.api.service.supplementary.ProcessUnstructuredSSResponse;
import org.restcomm.protocols.ss7.map.api.service.supplementary.RegisterPasswordRequest;
import org.restcomm.protocols.ss7.map.api.service.supplementary.RegisterPasswordResponse;
import org.restcomm.protocols.ss7.map.api.service.supplementary.RegisterSSRequest;
import org.restcomm.protocols.ss7.map.api.service.supplementary.RegisterSSResponse;
import org.restcomm.protocols.ss7.map.api.service.supplementary.UnstructuredSSNotifyRequest;
import org.restcomm.protocols.ss7.map.api.service.supplementary.UnstructuredSSNotifyResponse;
import org.restcomm.protocols.ss7.map.api.service.supplementary.UnstructuredSSRequest;
import org.restcomm.protocols.ss7.map.api.service.supplementary.UnstructuredSSResponse;
import org.restcomm.protocols.ss7.map.datacoding.CBSDataCodingSchemeImpl;
import org.restcomm.protocols.ss7.map.load.CsvWriter;
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
import org.restcomm.protocols.ss7.tcap.asn.comp.Problem;

import com.google.common.util.concurrent.RateLimiter;

/**
 * @author amit bhayani
 * @modified <a href="mailto:fernando.mendioroz@gmail.com"> Fernando Mendioroz </a>
 */
public class Client extends TestHarnessUssd {

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
        this.sccpResource.addRemoteSsn(1, DESTINATION_PC, USSD_SSN, 0, false);

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
        this.tcapStack = new TCAPStackImpl("Test", this.sccpStack.getSccpProvider(), MSC_SSN);
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
        this.mapProvider.getMAPServiceSupplementary().addMAPServiceListener(this);

        this.mapProvider.getMAPServiceSupplementary().activate();

        this.mapStack.start();
    }

    private void initiateUSSD() throws MAPException {
        Random r = new Random();
        NetworkIdState networkIdState = this.mapStack.getMAPProvider().getNetworkIdState(0);
        int executorCongestionLevel = this.mapStack.getMAPProvider().getExecutorCongestionLevel();
        int random = 0;
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
        // System.out.println("initiateUSSD");

        // First create Dialog
        AddressString origRef = this.mapProvider.getMAPParameterFactory()
                .createAddressString(AddressNature.international_number, NumberingPlan.ISDN, "12345");
        AddressString destRef = this.mapProvider.getMAPParameterFactory()
                .createAddressString(AddressNature.international_number, NumberingPlan.ISDN, "67890");

        SccpAddress clientSccpAddress = createSccpAddress(ROUTING_INDICATOR, ORIGINATING_PC, MSC_SSN, SCCP_CLIENT_ADDRESS);
        SccpAddress serverSccpAddress = createSccpAddress(ROUTING_INDICATOR, DESTINATION_PC, USSD_SSN, SCCP_SERVER_ADDRESS);
        MAPDialogSupplementary mapDialog = this.mapProvider.getMAPServiceSupplementary().createNewDialog(MAPApplicationContext
                .getInstance(MAPApplicationContextName.networkUnstructuredSsContext, MAPApplicationContextVersion.version2),
                clientSccpAddress, origRef, serverSccpAddress, destRef);

        CBSDataCodingScheme ussdDataCodingScheme = new CBSDataCodingSchemeImpl(0x0f);

        // USSD String: *125*+31628839999#
        // The Charset is null, here we let system use default Charset (UTF-7 as
        // explained in GSM 03.38. However if MAP User wants, it can set its own
        // impl of Charset
        random = 8000000 + r.nextInt(1000000);

        USSDString ussdString = this.mapProvider.getMAPParameterFactory().createUSSDString("*125*+3162" + random + "#", null, null);

        ISDNAddressString msisdn = this.mapProvider.getMAPParameterFactory()
                .createISDNAddressString(AddressNature.international_number, NumberingPlan.ISDN, "3162" + random);

        mapDialog.addProcessUnstructuredSSRequest(ussdDataCodingScheme, ussdString, null, msisdn);

        // nbConcurrentDialogs.incrementAndGet();

        // This will initiate the TC-BEGIN with INVOKE component
        mapDialog.send();

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
            USSD_SSN = Integer.parseInt(args[i++]);
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
            System.out.println("USSD_SSN = " + USSD_SSN);
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
                // }// end of while (client.nbConcurrentDialogs.intValue() >=
                // MAXCONCURRENTDIALOGS)

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
     * @see org.restcomm.protocols.ss7.map.api.service.supplementary. MAPServiceSupplementaryListener
     * #onProcessUnstructuredSSRequestIndication(org .mobicents.protocols.ss7.map.
     * api.service.supplementary.ProcessUnstructuredSSRequestIndication)
     */
    @Override
    public void onProcessUnstructuredSSRequest(ProcessUnstructuredSSRequest processUnstructuredSSRequest) {
        // This error condition. Client should never receive the
        // ProcessUnstructuredSSRequestIndication
        logger.error(String.format("onProcessUnstructuredSSRequestIndication for Dialog=%d and invokeId=%d",
            processUnstructuredSSRequest.getMAPDialog().getLocalDialogId(), processUnstructuredSSRequest.getInvokeId()));
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.api.service.supplementary. MAPServiceSupplementaryListener
     * #onProcessUnstructuredSSResponseIndication( org.restcomm.protocols.ss7.map
     * .api.service.supplementary.ProcessUnstructuredSSResponseIndication)
     */
    @Override
    public void onProcessUnstructuredSSResponse(ProcessUnstructuredSSResponse processUnstructuredSSResponse) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("Rx ProcessUnstructuredSSResponseIndication. USSD String=%s",
                processUnstructuredSSResponse.getUSSDString()));
        }
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.api.service.supplementary. MAPServiceSupplementaryListener
     * #onUnstructuredSSRequestIndication(org.mobicents .protocols.ss7.map.api.service
     * .supplementary.UnstructuredSSRequestIndication)
     */
    @Override
    public void onUnstructuredSSRequest(UnstructuredSSRequest unstructuredSSRequest) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("Rx UnstructuredSSRequestIndication. USSD String=%s ", unstructuredSSRequest.getUSSDString()));
        }
        MAPDialogSupplementary mapDialog = unstructuredSSRequest.getMAPDialog();

        try {
            CBSDataCodingScheme ussdDataCodingScheme = new CBSDataCodingSchemeImpl(0x0f);

            USSDString ussdString = this.mapProvider.getMAPParameterFactory().createUSSDString("1", null, null);

            AddressString msisdn = this.mapProvider.getMAPParameterFactory()
                    .createAddressString(AddressNature.international_number, NumberingPlan.ISDN, "31628838002");

            mapDialog.addUnstructuredSSResponse(unstructuredSSRequest.getInvokeId(), ussdDataCodingScheme, ussdString);
            mapDialog.send();

        } catch (MAPException e) {
            logger.error(
                    String.format("Error while sending UnstructuredSSResponse for Dialog=%d", mapDialog.getLocalDialogId()));
        }
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.api.service.supplementary. MAPServiceSupplementaryListener
     * #onUnstructuredSSResponseIndication(org.mobicents .protocols.ss7.map.api.service
     * .supplementary.UnstructuredSSResponseIndication)
     */
    @Override
    public void onUnstructuredSSResponse(UnstructuredSSResponse unstructuredSSResponse) {
        // This is an error condition.
        // Client should never receive UnstructuredSSResponseIndication
        logger.error(String.format("onUnstructuredSSResponseIndication for Dialog=%d and invokeId=%d",
            unstructuredSSResponse.getMAPDialog().getLocalDialogId(), unstructuredSSResponse.getInvokeId()));
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.api.service.supplementary. MAPServiceSupplementaryListener
     * #onUnstructuredSSNotifyRequestIndication(org .mobicents.protocols.ss7.map.api
     * .service.supplementary.UnstructuredSSNotifyRequestIndication)
     */
    @Override
    public void onUnstructuredSSNotifyRequest(UnstructuredSSNotifyRequest unstructuredSSNotifyRequest) {
        // This error condition. Client should never receive the
        // UnstructuredSSNotifyRequestIndication
        logger.error(String.format("onUnstructuredSSNotifyRequestIndication for Dialog=%d and invokeId=%d",
            unstructuredSSNotifyRequest.getMAPDialog().getLocalDialogId(), unstructuredSSNotifyRequest.getInvokeId()));
    }

    public void onUnstructuredSSNotifyResponseIndication(UnstructuredSSNotifyResponse unstructuredSSNotifyResponse) {
        // This error condition. Client should never receive the
        // UnstructuredSSNotifyRequestIndication
        logger.error(String.format("onUnstructuredSSNotifyResponseIndication for Dialog=%d and invokeId=%d",
            unstructuredSSNotifyResponse.getMAPDialog().getLocalDialogId(), unstructuredSSNotifyResponse.getInvokeId()));
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
    public void onUnstructuredSSNotifyResponse(UnstructuredSSNotifyResponse unstructuredSSNotifyResponse) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onMAPMessage(MAPMessage mapMessage) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onRegisterSSRequest(RegisterSSRequest request) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onRegisterSSResponse(RegisterSSResponse response) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onEraseSSRequest(EraseSSRequest request) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onEraseSSResponse(EraseSSResponse response) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onActivateSSRequest(ActivateSSRequest request) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onActivateSSResponse(ActivateSSResponse response) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onDeactivateSSRequest(DeactivateSSRequest request) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onDeactivateSSResponse(DeactivateSSResponse response) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onInterrogateSSRequest(InterrogateSSRequest request) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onInterrogateSSResponse(InterrogateSSResponse response) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onGetPasswordRequest(GetPasswordRequest request) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onGetPasswordResponse(GetPasswordResponse response) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onRegisterPasswordRequest(RegisterPasswordRequest request) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onRegisterPasswordResponse(RegisterPasswordResponse response) {
        // TODO Auto-generated method stub

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

                    initiateUSSD();
                }
            } catch (MAPException ex) {
                logger.error("Exception when sending a new MAP dialog", ex);
            }
        }

    }

    @Override
    public void onSendRoutingInfoForSMRequest(SendRoutingInfoForSMRequest sendRoutingInfoForSMRequestIndication) {
    }

    @Override
    public void onForwardShortMessageRequest(ForwardShortMessageRequest forwardShortMessageRequestIndication) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onForwardShortMessageResponse(ForwardShortMessageResponse forwardShortMessageResponseIndication) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onMoForwardShortMessageRequest(MoForwardShortMessageRequest moForwardShortMessageRequestIndication) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onMoForwardShortMessageResponse(MoForwardShortMessageResponse moForwardShortMessageResponseIndication) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onMtForwardShortMessageRequest(MtForwardShortMessageRequest mtForwardShortMessageRequestIndication) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onMtForwardShortMessageResponse(MtForwardShortMessageResponse mtForwardShortMessageResponseIndication) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onSendRoutingInfoForSMResponse(SendRoutingInfoForSMResponse sendRoutingInfoForSMResponseIndication) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onReportSMDeliveryStatusRequest(ReportSMDeliveryStatusRequest reportSMDeliveryStatusRequestIndication) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onReportSMDeliveryStatusResponse(ReportSMDeliveryStatusResponse reportSMDeliveryStatusResponseIndication) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onInformServiceCentreRequest(InformServiceCentreRequest informServiceCentreRequestIndication) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onAlertServiceCentreRequest(AlertServiceCentreRequest alertServiceCentreRequestIndication) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onAlertServiceCentreResponse(AlertServiceCentreResponse alertServiceCentreResponseIndication) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onReadyForSMRequest(ReadyForSMRequest readyForSMRequest) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onReadyForSMResponse(ReadyForSMResponse readyForSMResponse) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onNoteSubscriberPresentRequest(NoteSubscriberPresentRequest noteSubscriberPresentRequest) {
        // TODO Auto-generated method stub

    }
}
