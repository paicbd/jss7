
package org.restcomm.protocols.ss7.m3ua.impl.oam;

/**
 *
 * @author amit bhayani
 *
 */
public interface M3UAOAMMessages {

    /**
     * Pre defined messages
     */
    String INVALID_COMMAND = "Invalid Command";

    String ADD_ASP_TO_AS_SUCCESSFUL = "Successfully added ASP name=%s to AS name=%s on stack=%s";

    String REMOVE_ASP_FROM_AS_SUCCESSFUL = "Successfully removed ASP name=%s from AS name=%s on stack=%s";

    String NO_AS_FOUND = "No AS found for given name %s";

    String ADD_ASP_TO_AS_FAIL_ALREADY_ASSIGNED_TO_THIS_AS = "Cannot assign ASP=%s to AS=%s. This ASP is already assigned to this AS";

    String ADD_ASP_TO_AS_FAIL_ALREADY_ASSIGNED_TO_OTHER_AS = "Cannot assign ASP=%s to AS=%s. This ASP is already assigned to another AS";

    String ADD_ASP_TO_AS_FAIL_ALREADY_ASSIGNED_TO_OTHER_AS_WITH_NULL_RC = "Cannot assign ASP=%s to AS=%s. This ASP is already assigned to another AS which has null RoutingContext";

    String ADD_ASP_TO_AS_FAIL_ALREADY_ASSIGNED_TO_OTHER_AS_TYPE = "Cannot assign ASP=%s to AS=%s. This ASP is already assigned to another AS of type=%s";

    String ADD_ASP_TO_AS_FAIL_ALREADY_ASSIGNED_TO_OTHER_IPSP_TYPE = "Cannot assign ASP=%s to AS=%s. This ASP is already assigned to another AS of which has IPSP type=%s";

    String ADD_ASP_TO_AS_FAIL_ALREADY_ASSIGNED_TO_OTHER_AS_EXCHANGETYPE = "Cannot assign ASP=%s to AS=%s. This ASP is already assigned to another AS of ExchangeType=%s";

    String ASP_NOT_ASSIGNED_TO_AS = "ASP name=%s not assigned to any AS yet";

    String NO_ASP_FOUND = "No ASP found for given name %s";

    String ASP_ALREADY_STOPPED = "ASP name=%s already stopped";

    String ASP_ALREADY_STARTED = "ASP name=%s already started";

    String ASP_START_SUCCESSFUL = "Successfully started ASP name=%s on stack=%s";

    String ASP_STOP_SUCCESSFUL = "Successfully stopped ASP name=%s on stack=%s";

    String CREATE_AS_SUCCESSFUL = "Successfully created AS name=%s on stack=%s";

    String DESTROY_AS_SUCCESSFUL = "Successfully destroyed AS name=%s from stack=%s";

    String DESTROY_AS_FAILED_ASP_ASSIGNED = "As=%s still has ASPs assigned. Unassign ASPs before destroying this As";

    String CREATE_AS_FAIL_NAME_EXIST = "Creation of AS failed. Other AS with name=%s already exist";

    String CREATE_ASP_SUCCESSFUL = "Successfully created ASP name=%s on stack=%s";

    String DESTROY_ASP_SUCCESSFUL = "Successfully destroyed ASP name=%s from stack=%s";

    String CREATE_ASP_FAIL_NAME_EXIST = "Creation of ASP failed. Other ASP with name=%s already exist";

    String CREATE_ASP_FAIL_IPPORT_EXIST = "Creation of ASP failed. Other ASP with ip=%s port=%d already exist";

    String ROUTE_AS_FOR_DPC_EXIST = "AS=%s already routes for DPC=%d";

    String ADD_ROUTE_AS_FOR_DPC_SUCCESSFUL = "AS=%s successfully added as route for DPC=%d on stack=%s";

    String NO_ROUTE_DEFINED_FOR_DPC = "No route defined for DPC=%d";

    String NO_AS_ROUTE_FOR_DPC = "AS=%s doesn't have routes defined for DPC=%d";

    String REMOVE_AS_ROUTE_FOR_DPC_SUCCESSFUL = "Successfully removed AS=%s as route for DPC=%d on stack=%s";

    String CMD_NOTSUPPORTED_M3UAMANAGEMENT_IS_SERVER = "The M3UAManagement is Server side and does not support command %s";

    String NOT_SUPPORTED_YET = "Not supported yet";

    String NO_ASP_DEFINED_YET = "No ASP defined yet for stack=%s";

    String NO_AS_DEFINED_YET = "No AS defined yet for stack=%s";

    String NO_ROUTE_DEFINED_YET = "No Route defined yet for stack=%s";

    String AS_USED_IN_ROUTE_ERROR = "As=%s used in route=%s. Remove from route";

    String NO_ASSOCIATION_FOUND = "No Association found for name=%s";

    String ASSOCIATION_IS_STARTED = "Association=%s is started";

    String ASSOCIATION_IS_ASSOCIATED = "Association=%s is already associated";

    String ASP_ID_TAKEN = "ASP Identifier=%d is already taken";

    String PARAMETER_SUCCESSFULLY_SET = "Parameter has been successfully set on stack=%s";

    String NO_SCTP_MANAGEMENT_BEAN = "No SCTP management bean defined";

    String NO_SCTP_MANAGEMENT_BEAN_FOR_NAME = "No SCTP management bean found for passed name=%s";

    String NO_M3UA_MANAGEMENT_BEAN_FOR_NAME = "No M3UA management bean found for passed name=%s";

    String M3UA_ERROR_MANAGEMENT_ADD_SUCCESS = "The error definition for code %d has been added successfully";
    /**
     * Generic constants
     */
    String TAB = "        ";

    String NEW_LINE = "\n";

    String COMMA = ",";

    /**
     * Show command specific constants
     */
    String SHOW_ASSIGNED_TO = "Assigned to :\n";

    String SHOW_ASP_NAME = "ASP name=";

    String SHOW_AS_NAME = "AS name=";

    String SHOW_SCTP_ASSOC = " sctpAssoc=";

    String SHOW_ASPID = " aspid=";

    String SHOW_HEARTBEAT_ENABLED = " heartbeat=";

    String SHOW_STARTED = " started=";

    String SHOW_FUNCTIONALITY = " functionality=";

    String SHOW_MODE = " mode=";

    String SHOW_IPSP_TYPE = " ipspType=";

    String SHOW_LOCAL_FSM_STATE = " localFSMState=";

    String SHOW_PEER_FSM_STATE = " peerFSMState=";

    String INVALID_ERROR_CODE = "The error code provided is not valid";

    String ERROR_CODE_NOT_DEFINED = "The error code is not defined" ;

    String ERROR_CODE_REMOVED_SUCCESS = "The error code has been removed successfully";

    String GENERIC_ERROR_CODE = "Could not complete the operation";
}
