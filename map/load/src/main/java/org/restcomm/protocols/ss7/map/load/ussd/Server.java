
package org.restcomm.protocols.ss7.map.load.ussd;

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
import org.restcomm.protocols.ss7.map.api.primitives.IMSI;
import org.restcomm.protocols.ss7.map.api.primitives.ISDNAddressString;
import org.restcomm.protocols.ss7.map.api.primitives.LMSI;
import org.restcomm.protocols.ss7.map.api.primitives.MAPExtensionContainer;
import org.restcomm.protocols.ss7.map.api.primitives.NumberingPlan;
import org.restcomm.protocols.ss7.map.api.primitives.USSDString;
import org.restcomm.protocols.ss7.map.api.service.lsm.AdditionalNumber;
import org.restcomm.protocols.ss7.map.api.service.sms.AlertServiceCentreRequest;
import org.restcomm.protocols.ss7.map.api.service.sms.AlertServiceCentreResponse;
import org.restcomm.protocols.ss7.map.api.service.sms.ForwardShortMessageRequest;
import org.restcomm.protocols.ss7.map.api.service.sms.ForwardShortMessageResponse;
import org.restcomm.protocols.ss7.map.api.service.sms.InformServiceCentreRequest;
import org.restcomm.protocols.ss7.map.api.service.sms.IpSmGwGuidance;
import org.restcomm.protocols.ss7.map.api.service.sms.LocationInfoWithLMSI;
import org.restcomm.protocols.ss7.map.api.service.sms.MAPDialogSms;
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
import org.restcomm.protocols.ss7.map.primitives.IMSIImpl;
import org.restcomm.protocols.ss7.map.primitives.ISDNAddressStringImpl;
import org.restcomm.protocols.ss7.map.primitives.LMSIImpl;
import org.restcomm.protocols.ss7.map.service.sms.LocationInfoWithLMSIImpl;
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
import org.restcomm.protocols.ss7.tcap.asn.comp.Problem;

import java.util.List;
import java.util.Random;
import javolution.util.FastList;

/**
 * @author amit bhayani
 * @modified <a href="mailto:fernando.mendioroz@gmail.com"> Fernando Mendioroz </a>
 */
public class Server extends TestHarnessUssd {

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
        this.sccpResource.addRemoteSsn(1, DESTINATION_PC, USSD_SSN, 0, false);

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
        List<Integer> extraSsns = new FastList<Integer>();
        extraSsns.add(HLR_SSN);
        this.tcapStack = new TCAPStackImpl("TestServer", this.sccpStack.getSccpProvider(), MSC_SSN);
        this.tcapStack.setExtraSsns(extraSsns);
        this.tcapStack.start();
        this.tcapStack.setDialogIdleTimeout(60000);
        this.tcapStack.setInvokeTimeout(30000);
        this.tcapStack.setMaxDialogs(MAX_DIALOGS);
    }

    private void initMAP() throws Exception {
        this.mapStack = new MAPStackImpl("TestServer", this.tcapStack.getProvider());
        this.mapProvider = this.mapStack.getMAPProvider();

        this.mapProvider.addMAPDialogListener(this);
        this.mapProvider.getMAPServiceSupplementary().addMAPServiceListener(this);

        this.mapProvider.getMAPServiceSupplementary().activate();

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
     * @see org.restcomm.protocols.ss7.map.api.service.supplementary. MAPServiceSupplementaryListener
     * #onProcessUnstructuredSSRequestIndication(org .mobicents.protocols.ss7.map.
     * api.service.supplementary.ProcessUnstructuredSSRequestIndication)
     */
    @Override
    public void onProcessUnstructuredSSRequest(ProcessUnstructuredSSRequest processUnstructuredSSRequest) {
//        NetworkIdState networkIdState = this.mapStack.getMAPProvider().getNetworkIdState(0);
//        if (!(networkIdState == null || networkIdState.isAvailable() && networkIdState.getCongLevel() == 0)) {
//            // congestion or unavailable
//            logger.warn("onProcessUnstructuredSSRequest Congestion - onUnstructuredSSRequest: networkIdState=" + networkIdState);
//            try {
//                Thread.sleep(1000);
//            } catch (InterruptedException e) {
//                // TODO Auto-generated catch block
//                e.printStackTrace();
//            }
//        }

        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onProcessUnstructuredSSRequestIndication for DialogId=%d", processUnstructuredSSRequest
                    .getMAPDialog().getLocalDialogId()));
        }
        try {
            long invokeId = processUnstructuredSSRequest.getInvokeId();

            USSDString ussdStrObj = this.mapProvider.getMAPParameterFactory().createUSSDString(
                    "USSD String : Hello World <CR> 1. Balance <CR> 2. Texts Remaining");
            CBSDataCodingScheme ussdDataCodingScheme = new CBSDataCodingSchemeImpl(0x0F);
            MAPDialogSupplementary dialog = processUnstructuredSSRequest.getMAPDialog();

            dialog.setUserObject(invokeId);

            ISDNAddressString msisdn = this.mapProvider.getMAPParameterFactory().createISDNAddressString(
                    AddressNature.international_number, NumberingPlan.ISDN, "31628838002");

            dialog.addUnstructuredSSRequest(ussdDataCodingScheme, ussdStrObj, null, msisdn);
            dialog.send();
        } catch (MAPException e) {
            logger.error("Error while sending UnstructuredSSRequest ", e);
        }
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
        // This is an error condition
        // Server shouldn't be getting ProcessUnstructuredSSResponseIndication
        logger.error(String.format("onProcessUnstructuredSSResponseIndication for Dialog=%d and invokeId=%d",
            processUnstructuredSSResponse.getMAPDialog().getLocalDialogId(), processUnstructuredSSResponse.getInvokeId()));
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
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onUnstructuredSSResponseIndication for DialogId=%d", unstructuredSSResponse.getMAPDialog().getLocalDialogId()));
        }
        try {
            USSDString ussdStrObj = this.mapProvider.getMAPParameterFactory().createUSSDString("Your balance is 500");
            CBSDataCodingScheme ussdDataCodingScheme = new CBSDataCodingSchemeImpl(0x0F);
            MAPDialogSupplementary dialog = unstructuredSSResponse.getMAPDialog();

            AddressString msisdn = this.mapProvider.getMAPParameterFactory().createAddressString(
                    AddressNature.international_number, NumberingPlan.ISDN, "31628838002");

            dialog.addProcessUnstructuredSSResponse(((Long) dialog.getUserObject()).longValue(), ussdDataCodingScheme,
                    ussdStrObj);
            dialog.close(false);
        } catch (MAPException e) {
            logger.error("Error while sending UnstructuredSSRequest ", e);
        }
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
        MAPDialogSupplementary mapDialog = unstructuredSSNotifyRequest.getMAPDialog();

        try {
            mapDialog.addUnstructuredSSNotifyResponse(unstructuredSSNotifyRequest.getInvokeId());
            mapDialog.send();
        } catch (MAPException e) {
            logger.error(
                    String.format("Error while sending UnstructuredSSNotifyResponse for Dialog=%d", mapDialog.getLocalDialogId()));
        }
    }

    public void onUnstructuredSSNotifyResponseIndication(UnstructuredSSNotifyResponse unstructuredSSNotifyResponse) {
        // This is an error condition.
        // Server should never receive an UnstructuredSSNotifyRequestIndication
        logger.error(String.format("onUnstructuredSSNotifyResponseIndication for Dialog=%d and invokeId=%d",
            unstructuredSSNotifyResponse.getMAPDialog().getLocalDialogId(), unstructuredSSNotifyResponse.getInvokeId()));
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
            USSD_SSN = Integer.parseInt(args[i++]);
            HLR_SSN = Integer.parseInt(args[i++]);
            MSC_SSN = Integer.parseInt(args[i++]);
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
            System.out.println("USSD_SSN = " + USSD_SSN);
            System.out.println("HLR_SSN = " + HLR_SSN);
            System.out.println("MSC_SSN = " + MSC_SSN);
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
    public void onUnstructuredSSNotifyResponse(UnstructuredSSNotifyResponse unstrNotifyInd) {
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

    @Override
    public void onSendRoutingInfoForSMRequest(SendRoutingInfoForSMRequest sendRoutingInfoForSMRequestIndication) {
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
