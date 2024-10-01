
package org.restcomm.protocols.ss7.map.load.sms.mo;

import org.apache.log4j.Logger;
import org.mobicents.protocols.api.IpChannelType;
import org.mobicents.protocols.sctp.netty.NettySctpManagementImpl;
import org.restcomm.protocols.ss7.indicator.NatureOfAddress;
import org.restcomm.protocols.ss7.indicator.RoutingIndicator;
import org.restcomm.protocols.ss7.m3ua.As;
import org.restcomm.protocols.ss7.m3ua.Asp;
import org.restcomm.protocols.ss7.m3ua.AspFactory;
import org.restcomm.protocols.ss7.m3ua.ExchangeType;
import org.restcomm.protocols.ss7.m3ua.Functionality;
import org.restcomm.protocols.ss7.m3ua.IPSPType;
import org.restcomm.protocols.ss7.m3ua.impl.M3UAManagementImpl;
import org.restcomm.protocols.ss7.m3ua.parameter.NetworkAppearance;
import org.restcomm.protocols.ss7.m3ua.parameter.RoutingContext;
import org.restcomm.protocols.ss7.m3ua.parameter.TrafficModeType;
import org.restcomm.protocols.ss7.map.MAPStackImpl;
import org.restcomm.protocols.ss7.map.api.MAPApplicationContext;
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
import org.restcomm.protocols.ss7.map.api.primitives.AddressString;
import org.restcomm.protocols.ss7.map.api.primitives.MAPExtensionContainer;
import org.restcomm.protocols.ss7.map.api.service.sms.AlertServiceCentreRequest;
import org.restcomm.protocols.ss7.map.api.service.sms.AlertServiceCentreResponse;
import org.restcomm.protocols.ss7.map.api.service.sms.ForwardShortMessageRequest;
import org.restcomm.protocols.ss7.map.api.service.sms.ForwardShortMessageResponse;
import org.restcomm.protocols.ss7.map.api.service.sms.InformServiceCentreRequest;
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
import org.restcomm.protocols.ss7.map.api.service.sms.SendRoutingInfoForSMRequest;
import org.restcomm.protocols.ss7.map.api.service.sms.SendRoutingInfoForSMResponse;
import org.restcomm.protocols.ss7.sccp.LoadSharingAlgorithm;
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

/**
 * @modified <a href="mailto:fernando.mendioroz@gmail.com"> Fernando Mendioroz </a>
 */
public class Server extends TestHarnessSmsMo {

    private static Logger logger = Logger.getLogger(Server.class);

    // MAP
    private MAPStackImpl mapStack;
    private MAPProvider mapProvider;

    // TCAP
    private TCAPStack tcapStack;

    // SCCP
    SccpExtModuleImpl sccpExtModule;
    private SccpStackImpl sccpStack;
    private SccpResource sccpResource;
    private Router router;
    private RouterExt routerExt;

    // M3UA
    private M3UAManagementImpl serverM3UAMgmt;

    // SCTP
    private NettySctpManagementImpl sctpManagement;

    int endCount = 0;
    volatile long start = System.currentTimeMillis();

    protected void initializeStack(IpChannelType ipChannelType) throws Exception {

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
        serverM3UAMgmt.startAsp("ASP1");
    }

    private void initSCTP(IpChannelType ipChannelType) throws Exception {
        this.sctpManagement = new NettySctpManagementImpl("Server");
        // this.sctpManagement.setSingleThread(false);
        this.sctpManagement.start();
        this.sctpManagement.setConnectDelay(10000);
        this.sctpManagement.removeAllResources();

        // 1. Create SCTP Server
        if (EXTRA_HOST_ADDRESS.equals("-1"))
            sctpManagement.addServer(SERVER_NAME, HOST_IP, HOST_PORT, ipChannelType, null);
        else
            sctpManagement.addServer(SERVER_NAME, HOST_IP, HOST_PORT, ipChannelType, new String[] { EXTRA_HOST_ADDRESS });

        // 2. Create SCTP Server Association
        sctpManagement.addServerAssociation(PEER_IP, PEER_PORT, SERVER_NAME, SERVER_ASSOCIATION_NAME, ipChannelType);

        // 3. Start Server
        sctpManagement.startServer(SERVER_NAME);
    }

    private void initM3UA() throws Exception {
        this.serverM3UAMgmt = new M3UAManagementImpl("Server", null, new Ss7ExtInterfaceImpl());
        this.serverM3UAMgmt.setTransportManagement(this.sctpManagement);
        this.serverM3UAMgmt.setDeliveryMessageThreadCount(DELIVERY_TRANSFER_MESSAGE_THREAD_COUNT);
        this.serverM3UAMgmt.start();
        this.serverM3UAMgmt.removeAllResources();

        RoutingContext rc = factory.createRoutingContext(new long[] { ROUTING_CONTEXT });
        TrafficModeType trafficModeType = factory.createTrafficModeType(TrafficModeType.Loadshare);
        NetworkAppearance na = factory.createNetworkAppearance(NETWORK_APPEARANCE);

        IPSPType ipspType = null;
        if (AS_FUNCTIONALITY == Functionality.IPSP)
            ipspType = IPSPType.SERVER;

        // Step 1 : Create AS
        As as = this.serverM3UAMgmt.createAs("AS1", AS_FUNCTIONALITY, ExchangeType.SE, ipspType, rc, trafficModeType,1, na);
        // Step 2 : Create ASP
        AspFactory aspFactor = this.serverM3UAMgmt.createAspFactory("ASP1", SERVER_ASSOCIATION_NAME);
        // Step 3 : Assign ASP to AS
        Asp asp = this.serverM3UAMgmt.assignAspToAs("AS1", "ASP1");
        // Step 4: Add Route. Remote point code is 2
        this.serverM3UAMgmt.addRoute(DESTINATION_PC, ORIGINATING_PC, SERVICE_INDICATOR, "AS1");
    }

    private void initSCCP() throws Exception {
        Ss7ExtInterface ss7ExtInterface = new Ss7ExtInterfaceImpl();
        sccpExtModule = new SccpExtModuleImpl();
        ss7ExtInterface.setSs7ExtSccpInterface(sccpExtModule);
        this.sccpStack = new SccpStackImpl("MapLoadServerSccpStack", ss7ExtInterface);
        this.sccpStack.setMtp3UserPart(1, this.serverM3UAMgmt);

        this.sccpStack.start();
        this.sccpStack.removeAllResources();

        this.router = this.sccpStack.getRouter();
        this.routerExt = sccpExtModule.getRouterExt();
        this.sccpResource = this.sccpStack.getSccpResource();

        this.sccpResource.addRemoteSpc(1, DESTINATION_PC, 0, 0);
        this.sccpResource.addRemoteSsn(1, DESTINATION_PC, REMOTE_SSN, 0, false);

        this.router.addMtp3ServiceAccessPoint(1, 1, ORIGINATING_PC, NETWORK_INDICATOR, 0, null);
        this.router.addMtp3Destination(1, 1, DESTINATION_PC, DESTINATION_PC, 0, 255, 255);

        ParameterFactoryImpl fact = new ParameterFactoryImpl();
        EncodingScheme ec = new BCDEvenEncodingScheme();
        GlobalTitle gt1 = fact.createGlobalTitle("-", 0, org.restcomm.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY,
                ec, NatureOfAddress.INTERNATIONAL);
        GlobalTitle gt2 = fact.createGlobalTitle("-", 0, org.restcomm.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY,
                ec, NatureOfAddress.INTERNATIONAL);
        SccpAddress localAddress = new SccpAddressImpl(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt1, ORIGINATING_PC, 0);
        this.routerExt.addRoutingAddress(1, localAddress);
        SccpAddress remoteAddress = new SccpAddressImpl(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt2, DESTINATION_PC, 0);
        this.routerExt.addRoutingAddress(2, remoteAddress);

        GlobalTitle gt = fact.createGlobalTitle("*", 0, org.restcomm.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, ec,
                NatureOfAddress.INTERNATIONAL);
        SccpAddress pattern = new SccpAddressImpl(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt, 0, 0);
        this.routerExt.addRule(1, RuleType.SOLITARY, LoadSharingAlgorithm.Bit0, OriginationType.REMOTE, pattern,
                "K", 1, -1, null, 0, null);
        this.routerExt.addRule(2, RuleType.SOLITARY, LoadSharingAlgorithm.Bit0, OriginationType.LOCAL, pattern,
                "K", 2, -1, null, 0, null);
    }

    private void initTCAP() throws Exception {
        this.tcapStack = new TCAPStackImpl("TestServer", this.sccpStack.getSccpProvider(), SSN);
        this.tcapStack.start();
        this.tcapStack.setDialogIdleTimeout(60000);
        this.tcapStack.setInvokeTimeout(30000);
        this.tcapStack.setMaxDialogs(MAX_DIALOGS);
    }

    private void initMAP() throws Exception {
        this.mapStack = new MAPStackImpl("TestServer", this.tcapStack.getProvider());
        this.mapProvider = this.mapStack.getMAPProvider();

        this.mapProvider.addMAPDialogListener(this);
        this.mapProvider.getMAPServiceSms().addMAPServiceListener(this);

        this.mapProvider.getMAPServiceSms().activate();

        this.mapStack.start();
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
    public void onDialogRequest(MAPDialog mapDialog, AddressString destReference, AddressString origReference,
            MAPExtensionContainer extensionContainer) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format(
                    "onDialogRequest for DialogId=%d DestinationReference=%s OriginReference=%s MAPExtensionContainer=%s",
                    mapDialog.getLocalDialogId(), destReference, origReference, extensionContainer));
        }
    }

    @Override
    public void onDialogRequestEricsson(MAPDialog mapDialog, AddressString destReference, AddressString origReference,
            AddressString imsi, AddressString vlr) {
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
            logger.debug(String.format("onDialogAccept for DialogId=%d MAPExtensionContainer=%s", mapDialog.getLocalDialogId(),
                    extensionContainer));
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

        this.endCount++;

        if ((this.endCount % 10000) == 0) {
            long currentTime = System.currentTimeMillis();
            long processingTime = currentTime - start;
            start = currentTime;
            logger.warn("Completed 10000 Dialogs in " + processingTime + " milliseconds");
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

    public static void main(String[] args) {
        int i = 0;
        IpChannelType ipChannelType = IpChannelType.SCTP;

        if (args.length >= 17) {
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
            DELIVERY_TRANSFER_MESSAGE_THREAD_COUNT = Integer.parseInt(args[i++]);

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
            System.out.println("DELIVERY_TRANSFER_MESSAGE_THREAD_COUNT = " + DELIVERY_TRANSFER_MESSAGE_THREAD_COUNT);
        }

        final Server server = new Server();
        try {
            server.initializeStack(ipChannelType);
        } catch (Exception e) {
            e.printStackTrace();
        }
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
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onMoForwardShortMessageRequest for DialogId=%d", moForwardShortMessageRequestIndication
                .getMAPDialog().getLocalDialogId()));
        }
        try {
            long invokeId = moForwardShortMessageRequestIndication.getInvokeId();
            MAPDialogSms mapDialogSms = moForwardShortMessageRequestIndication.getMAPDialog();
            ReturnResultLast returnResultLast = new ReturnResultLastImpl();
            returnResultLast.setInvokeId(invokeId);
            mapDialogSms.sendReturnResultLastComponent(returnResultLast);
            mapDialogSms.close(false);

        } catch (MAPException e) {
            logger.error("Error while sending MoForwardShortMessageRequest ", e);
        }
    }

    @Override
    public void onMoForwardShortMessageResponse(MoForwardShortMessageResponse moForwardShortMessageResponseIndication) {

    }

    @Override
    public void onMtForwardShortMessageRequest(MtForwardShortMessageRequest mtForwardShortMessageRequestIndication) {

    }

    @Override
    public void onMtForwardShortMessageResponse(MtForwardShortMessageResponse mtForwardShortMessageResponseIndication) {

    }

    @Override
    public void onSendRoutingInfoForSMRequest(SendRoutingInfoForSMRequest sendRoutingInfoForSMRequestIndication) {

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
}
