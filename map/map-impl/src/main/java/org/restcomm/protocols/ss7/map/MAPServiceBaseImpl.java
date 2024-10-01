
package org.restcomm.protocols.ss7.map;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.restcomm.protocols.ss7.map.api.MAPApplicationContext;
import org.restcomm.protocols.ss7.map.api.MAPDialog;
import org.restcomm.protocols.ss7.map.api.MAPException;
import org.restcomm.protocols.ss7.map.api.MAPParsingComponentException;
import org.restcomm.protocols.ss7.map.api.MAPProvider;
import org.restcomm.protocols.ss7.map.api.MAPServiceBase;
import org.restcomm.protocols.ss7.map.api.MAPServiceListener;
import org.restcomm.protocols.ss7.map.api.errors.MAPErrorMessage;
import org.restcomm.protocols.ss7.sccp.parameter.SccpAddress;
import org.restcomm.protocols.ss7.tcap.api.TCAPException;
import org.restcomm.protocols.ss7.tcap.api.tc.dialog.Dialog;
import org.restcomm.protocols.ss7.tcap.asn.comp.ComponentType;
import org.restcomm.protocols.ss7.tcap.asn.comp.Invoke;
import org.restcomm.protocols.ss7.tcap.asn.comp.OperationCode;
import org.restcomm.protocols.ss7.tcap.asn.comp.Parameter;
import org.restcomm.protocols.ss7.tcap.asn.comp.Problem;

/**
 * This class must be the super class of all MAP services
 *
 * @author sergey vetyutnev
 *
 */
public abstract class MAPServiceBaseImpl implements MAPServiceBase {

    protected Boolean _isActivated = false;
    // protected Set<MAPServiceListener> serviceListeners = new HashSet<MAPServiceListener>();
    protected List<MAPServiceListener> serviceListeners = new CopyOnWriteArrayList<MAPServiceListener>();
    protected MAPProviderImpl mapProviderImpl;

    protected MAPServiceBaseImpl(MAPProviderImpl mapProviderImpl) {
        this.mapProviderImpl = mapProviderImpl;
    }

    public MAPProvider getMAPProvider() {
        return this.mapProviderImpl;
    }

    /**
     * Creation a MAP Dialog implementation for the specific service
     *
     * @param mapApplicationContext
     * @param tcapDialog
     * @return
     */
    protected abstract MAPDialogImpl createNewDialogIncoming(MAPApplicationContext mapApplicationContext, Dialog tcapDialog);

    /**
     * Creating new outgoing TCAP Dialog. Used when creating a new outgoing MAP Dialog
     *
     * @param sccpCallingPartyAddress
     * @param sccpCalledPartyAddress
     * @param localTransactionId
     * @return
     * @throws MAPException
     */
    protected Dialog createNewTCAPDialog(SccpAddress sccpCallingPartyAddress, SccpAddress sccpCalledPartyAddress, Long localTransactionId) throws MAPException {
        try {
            return this.mapProviderImpl.getTCAPProvider().getNewDialog(sccpCallingPartyAddress, sccpCalledPartyAddress, localTransactionId);
        } catch (TCAPException e) {
            throw new MAPException(e.getMessage(), e);
        }
    }

    public abstract void processComponent(ComponentType comp, OperationCode operationCode, Parameter parameter, MAPDialog mapDialog,
            Long invokeId, Long linkedId, Invoke linkedInvoke) throws MAPParsingComponentException;

    /**
     * Adding MAP Dialog into MAPProviderImpl.dialogs Used when creating a new outgoing MAP Dialog
     *
     * @param mapDialog
     */
    protected void putMAPDialogIntoCollection(MAPDialogImpl mapDialog) {
        this.mapProviderImpl.addDialog((MAPDialogImpl) mapDialog);
    }

    protected void addMAPServiceListener(MAPServiceListener mapServiceListener) {
        this.serviceListeners.add(mapServiceListener);
    }

    protected void removeMAPServiceListener(MAPServiceListener mapServiceListener) {
        this.serviceListeners.remove(mapServiceListener);
    }

    /**
     * {@inheritDoc}
     */
    public MAPApplicationContext getMAPv1ApplicationContext(int operationCode, Invoke invoke) {
        return null;
    }

    /**
     *
     * Returns a list of linked operations for operationCode operation
     *
     * @param operationCode
     * @return
     */
    public long[] getLinkedOperationList(long operationCode) {
        return null;
    }

    /**
     * This method is invoked when MAPProviderImpl.onInvokeTimeOut() is invoked. An InvokeTimeOut may be a normal situation for
     * the component class 2, 3, or 4. In this case checkInvokeTimeOut() should return true and deliver to the MAP-user correct
     * indication
     *
     * @param mapDialog
     * @param invoke
     * @return
     */
    public boolean checkInvokeTimeOut(MAPDialog mapDialog, Invoke invoke) {
        return false;
    }

    /**
     * {@inheritDoc}
     */
    public boolean isActivated() {
        return this._isActivated;
    }

    /**
     * {@inheritDoc}
     */
    public void activate() {
        this._isActivated = true;
    }

    /**
     * {@inheritDoc}
     */
    public void deactivate() {
        this._isActivated = false;

        // TODO: abort all active dialogs ?
    }

    protected void deliverErrorComponent(MAPDialog mapDialog, Long invokeId, MAPErrorMessage mapErrorMessage) {
        for (MAPServiceListener mapServiceListener : this.serviceListeners) {
            mapServiceListener.onErrorComponent(mapDialog, invokeId, mapErrorMessage);
        }
    }

    protected void deliverRejectComponent(MAPDialog mapDialog, Long invokeId, Problem problem, boolean isLocalOriginated) {
        for (MAPServiceListener mapServiceListener : this.serviceListeners) {
            mapServiceListener.onRejectComponent(mapDialog, invokeId, problem, isLocalOriginated);
        }
    }

    // protected void deliverProviderErrorComponent(MAPDialog mapDialog, Long invokeId, MAPProviderError providerError) {
    // for (MAPServiceListener serLis : this.serviceListeners) {
    // serLis.onProviderErrorComponent(mapDialog, invokeId, providerError);
    // }
    // }

    protected void deliverInvokeTimeout(MAPDialog mapDialog, Invoke invoke) {
        for (MAPServiceListener mapServiceListener : this.serviceListeners) {
            mapServiceListener.onInvokeTimeout(mapDialog, invoke.getInvokeId());
        }
    }

}
