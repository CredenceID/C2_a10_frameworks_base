/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.bluetooth.le;

import android.os.Parcel;
import android.os.Parcelable;

/**
 * Represents Transport Block related to Transport Discovery Data AD Type.
 * Consists of following fields:
 * Organization ID (1 byte), TDS Flags (1 byte),
 * Transport Data Length (1 byte) and
 * Transport Data (Transport Data Length bytes)
 */
public final class TransportBlock implements Parcelable {
    private final int mOrgId;
    private final int mTdsFlags;
    private final int mTransportDataLength;
    private final byte[] mTransportData;
    /**
     * Transport Data located at an offset of 3 bytes
     * from the start of a TransportBlock
     * after Organization ID (1 byte), TDS Flags (1 byte) and
     * Transport Data Length (1 byte)
     */
    public static final int TRANSPORT_DATA_OFFSET = 3;

    public TransportBlock(int orgId, int tdsFlags,
            int transportDataLength, byte[] transportData) {
        mOrgId = orgId;
        mTdsFlags = tdsFlags;
        mTransportDataLength = transportDataLength;
        mTransportData = transportData;
    }

    /**
     * Returns Organization ID in the Transport Block
     */
    public int getOrgId() {
        return mOrgId;
    }

    /**
     * Returns TDS Flags in the Transport Block
     */
    public int getTdsFlags() {
        return mTdsFlags;
    }

    /**
     * Returns Transport Data Length in the Transport Block
     */
    public int getTransportDataLength() {
        return mTransportDataLength;
    }

    /**
     * Returns Transport Data in the Transport Block
     */
    public byte[] getTransportData() {
        return mTransportData;
    }

    /**
     * Returns Bytes of the Transport Block
     */
    public byte[] getBytes() {
        int transportDataLength = (mTransportData == null) ? 0 : mTransportData.length;
        byte[] transportBlockBytes =
            new byte[transportDataLength + TRANSPORT_DATA_OFFSET];
        transportBlockBytes[0] = (byte) (mOrgId);
        transportBlockBytes[1] = (byte) (mTdsFlags);
        transportBlockBytes[2] = (byte) (mTransportDataLength);
        if (transportDataLength > 0) {
            System.arraycopy(mTransportData, 0,
                    transportBlockBytes, TRANSPORT_DATA_OFFSET, transportDataLength);
        }
        return transportBlockBytes;
    }

    /**
     * Returns Bytes length of the Transport Block
     */
    public int getLength() {
        int transportDataLength = (mTransportData == null) ? 0 : mTransportData.length;
        return transportDataLength + TRANSPORT_DATA_OFFSET;
    }

    @Override
    public String toString() {
        return "TransportBlock [orgId=" + mOrgId
                + ", tdsFlags=" + mTdsFlags
                + ", transportDataLength=" + mTransportDataLength
                + ", transportData=" + mTransportData + "]";
    }

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel out, int flags) {
        out.writeInt(mOrgId);
        out.writeInt(mTdsFlags);
        out.writeInt(mTransportDataLength);
        out.writeInt(mTransportData == null ? 0 : 1);
        if (mTransportData != null) {
            out.writeInt(mTransportData.length);
            out.writeByteArray(mTransportData);
        }
    }

    public static final Parcelable.Creator<TransportBlock> CREATOR =
            new Creator<TransportBlock>() {
                @Override
                public TransportBlock createFromParcel(Parcel in) {
                    int orgId = in.readInt();
                    int tdsFlags = in.readInt();
                    int transportDataLength = in.readInt();
                    byte[] transportData = null;
                    if (in.readInt() == 1) {
                        transportData = new byte[in.readInt()];
                        in.readByteArray(transportData);
                    } else {
                        transportData = new byte[0];
                    }
                    return new TransportBlock(orgId, tdsFlags,
                        transportDataLength, transportData);
                }

                @Override
                public TransportBlock[] newArray(int size) {
                    return new TransportBlock[size];
                }
    };
}
