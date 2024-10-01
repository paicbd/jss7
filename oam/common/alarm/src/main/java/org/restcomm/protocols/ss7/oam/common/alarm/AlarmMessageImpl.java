
package org.restcomm.protocols.ss7.oam.common.alarm;

import java.io.Serializable;
import java.util.Calendar;

/**
 *
 * @author sergey vetyutnev
 *
 */
public class AlarmMessageImpl implements AlarmMessage, Serializable {

    private boolean isCleared;
    private String alarmSource;
    private AlarmSeverity alarmSeverity;
    private String objectName;
    private String objectPath;
    private String problemName;
    private String cause;
    private Calendar timeAlarm;
    private Calendar timeClear;

    public AlarmMessageImpl() {
    }

    public boolean getIsCleared() {
        return this.isCleared;
    }

    public String getAlarmSource() {
        return this.alarmSource;
    }

    public AlarmSeverity getAlarmSeverity() {
        return this.alarmSeverity;
    }

    public String getObjectName() {
        return this.objectName;
    }

    public String getObjectPath() {
        return this.objectPath;
    }

    public String getProblemName() {
        return this.problemName;
    }

    public String getCause() {
        return this.cause;
    }

    public Calendar getTimeAlarm() {
        return timeAlarm;
    }

    public Calendar getTimeClear() {
        return timeClear;
    }

    public void setIsCleared(boolean value) {
        this.isCleared = value;
    }

    public void setAlarmSource(String value) {
        this.alarmSource = value;
    }

    public void setAlarmSeverity(AlarmSeverity value) {
        this.alarmSeverity = value;
    }

    public void setObjectName(String value) {
        this.objectName = value;
    }

    public void setObjectPath(String value) {
        this.objectPath = value;
    }

    public void setProblemName(String value) {
        this.problemName = value;
    }

    public void setCause(String value) {
        this.cause = value;
    }

    public void setTimeAlarm(Calendar value) {
        timeAlarm = value;
    }

    public void setTimeClear(Calendar value) {
        timeClear = value;
    }

    public void setCurentTimeAlarm() {
        timeAlarm = getCurrentTime();
    }

    public void setCurentTimeClear() {
        timeClear = getCurrentTime();
    }

    private Calendar getCurrentTime() {
        return Calendar.getInstance();
    }

    @Override
    public void addPrefixToAlarmSource(String prefix) {
        if (this.alarmSource == null) {
            this.alarmSource = prefix;
        } else {
            this.alarmSource = prefix + "_" + this.alarmSource;
        }
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (!(obj instanceof AlarmMessageImpl))
            return false;

        AlarmMessageImpl other = (AlarmMessageImpl) obj;

        if (this.isCleared != other.isCleared)
            return false;
        if (alarmSource == null) {
            if (other.alarmSource != null)
                return false;
        } else if (!alarmSource.equals(other.alarmSource))
            return false;
        if (alarmSeverity == null) {
            if (other.alarmSeverity != null)
                return false;
        } else if (alarmSeverity != other.alarmSeverity)
            return false;
        if (objectName == null) {
            if (other.objectName != null)
                return false;
        } else if (!objectName.equals(other.objectName))
            return false;
        if (objectPath == null) {
            if (other.objectPath != null)
                return false;
        } else if (!objectPath.equals(other.objectPath))
            return false;

        if (problemName == null) {
            if (other.problemName != null)
                return false;
        } else if (!problemName.equals(other.problemName))
            return false;
        if (cause == null) {
            if (other.cause != null)
                return false;
        } else if (!cause.equals(other.cause))
            return false;
        if (timeAlarm == null) {
            if (other.timeAlarm != null)
                return false;
        } else if (!timeAlarm.equals(other.timeAlarm))
            return false;
        if (timeClear == null) {
            if (other.timeClear != null)
                return false;
        } else if (!timeClear.equals(other.timeClear))
            return false;

        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime * result + ((isCleared) ? 1 : 0);
        result = prime * result + ((alarmSource == null) ? 0 : alarmSource.hashCode());
        result = prime * result + ((alarmSeverity == null) ? 0 : alarmSeverity.hashCode());
        result = prime * result + ((objectName == null) ? 0 : objectName.hashCode());
        result = prime * result + ((objectPath == null) ? 0 : objectPath.hashCode());
        result = prime * result + ((problemName == null) ? 0 : problemName.hashCode());
        result = prime * result + ((cause == null) ? 0 : cause.hashCode());
        result = prime * result + ((timeAlarm == null) ? 0 : timeAlarm.hashCode());
        result = prime * result + ((timeClear == null) ? 0 : timeClear.hashCode());

        return result;
    }

    @Override
    public int compareTo(AlarmMessage obj) {

        if (obj == null)
            return -1;
        if (!(obj instanceof AlarmMessageImpl))
            return -1;

        AlarmMessageImpl other = (AlarmMessageImpl) obj;

        if (this.timeAlarm == null && other.timeAlarm == null)
            return 0;
        if (this.timeAlarm == null)
            return 1;
        if (other.timeAlarm == null)
            return -1;

        return this.timeAlarm.compareTo(other.timeAlarm);
    }

    @Override
    public String toString() {

        StringBuilder sb = new StringBuilder();

        sb.append("AlarmMessage [");

        if (this.timeAlarm != null) {
            sb.append("timeAlarm=");
            sb.append(this.timeAlarm.getTime().toString());
            sb.append(", ");
        }
        if (this.timeClear != null) {
            sb.append("timeClear=");
            sb.append(this.timeClear.getTime().toString());
            sb.append(", ");
        }
        if (this.isCleared)
            sb.append("isCleared, ");
        if (this.alarmSource != null) {
            sb.append("alarmSource=");
            sb.append(this.alarmSource);
            sb.append(", ");
        }
        if (this.alarmSeverity != null) {
            sb.append("alarmSeverity=");
            sb.append(this.alarmSeverity.toString());
            sb.append(", ");
        }
        if (this.objectName != null) {
            sb.append("objectName=");
            sb.append(this.objectName);
            sb.append(", ");
        }
        if (this.objectPath != null) {
            sb.append("objectPath=");
            sb.append(this.objectPath);
            sb.append(", ");
        }
        if (this.problemName != null) {
            sb.append("problemName=");
            sb.append(this.problemName);
            sb.append(", ");
        }
        if (this.cause != null) {
            sb.append("cause=");
            sb.append(this.cause);
            sb.append(", ");
        }

        sb.append("]");

        return sb.toString();
    }

}
