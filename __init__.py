# pyPCAP
# Copyright (C) 2024  Hallabalooza
#
# This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this program. If not, see
# <https://www.gnu.org/licenses/>.


####################################################################################################


import enum
import itertools
import io
import os.path
import socket
import struct
import sys
import typing
import warnings


####################################################################################################


class IPv4(object):
    """
    @brief  Class representing an IPv4 Ethernet frame
    """

    PROTOCOL_TCP =  6
    PROTOCOL_UDP = 17

    def __init__(self, pProtocol:int=PROTOCOL_UDP, pMacSrc:str="B4-45-06-2D-4A-99", pMacDst:str="CC-15-31-0A-C0-C2", pAddrSrc:str="192.168.0.1", pAddrDst:str="192.168.0.2", pPortSrc:int=0, pPortDst:int=0, pData:bytes=bytes([])):
        """
        @brief  Creates an IPv4 instance
        @param  pProtocol  tbd
        @param  pMacSrc    tbd
        @param  pMacDst    tbd
        @param  pAddrSrc   tbd
        @param  pAddrDst   tbd
        @param  pPortSrc   tbd
        @param  pPortDst   tbd
        @param  pData      tbd
        """
        self._frmEthr = None
        self._frmIPv4 = None
        self._frmProt = None

        vIPv4HdrDscp   = 0  # Differentiated Services Code Point
        vIPv4HdrEcn    = 0  # Explicit Congestion Notification
        vIPv4HdrFlgRsv = 0  # Flag; Reserved
        vIPv4HdrFlgDf  = 0  # Flag; Don't Fragment
        vIPv4HdrFlgMf  = 0  # Flag; More Fragments
        vIPv4HdrFo     = 0  # Fragment Offset

        if pProtocol == self.PROTOCOL_UDP:
            self._frmProt = (  struct.pack('!HHHH', pPortSrc, pPortDst, (len(pData) + 8), 0)  # Header
                             + pData                                                          # Data
                            )

        self._frmIPv4 = (  struct.pack('!BBHHHBBH4s4s', ((4 << 4) + 5),                        # Version (4) + Internet Header Length (5)
                                                        ((vIPv4HdrDscp << 2) + vIPv4HdrEcn),
                                                        (len(self._frmProt) + 20),             # Total Length
                                                        0xAFFE,                                # Identification
                                                        ((vIPv4HdrFlgRsv << 7) + (vIPv4HdrFlgDf << 6) + (vIPv4HdrFlgMf << 5) + vIPv4HdrFo),
                                                        255,                                   # Time to live
                                                        pProtocol,                             # Protocol
                                                        0,                                     # Header Checksum
                                                        socket.inet_aton(pAddrSrc),            # Source address
                                                        socket.inet_aton(pAddrDst)             # Destination address
                                      )
                         + self._frmProt
                        )

        self._frmEthr = (  int(pMacDst.replace("-", ""), 16).to_bytes(6, 'big') + int(pMacSrc.replace("-", ""), 16).to_bytes(6, 'big') + 0x0800.to_bytes(2, 'big')  # Header
                         + self._frmIPv4                                                                                                                            # Data
                         + bytes([0, 0, 0, 0])                                                                                                                      # Checksum
                        )

    @property
    def eth(self):
        """
        @brief  Returns the Ethernet frames binary representation
        """
        return self._frmEthr

    @property
    def ipv4(self):
        """
        @brief  Returns the IPv4 packets binary representation
        """
        return self._frmIPv4

    @property
    def prot(self):
        """
        @brief  Returns the IPv4 data portions binary representation
        """
        return self._frmProt


####################################################################################################


class __EnumStr(enum.Enum):
    """
    @brief  pyPCAPNG enumeration class
    """

    @classmethod
    def has_value(cls, value):
        return value in cls._value2member_map_

    @classmethod
    def range(self):
        return ",".join(["{}.{}".format(self.__name__, x) for x in self.__members__.keys()])


class __EnumInt(enum.IntEnum):
    """
    @brief  pyPCAPNG enumeration class
    """

    @classmethod
    def has_value(cls, value):
        return value in cls._value2member_map_

    @classmethod
    def range(self):
        return ",".join(["{}.{}".format(self.__name__, x) for x in self.__members__.keys()])


class PCAPNGException(Exception):
    """
    @brief  pyPCAPNG exception class
    """

    def __init__(self, pMssg=None):
        """
        @brief  Creates a pyPCAPNG exception instance
        @param  pMssg  The Exception message
        """
        self._mssg = pMssg

    def __str__(self):
        """
        @brief  Prints a nicely string representation
        """
        if   (self._mssg is None): return
        else                     : return repr(self._mssg)


class PCAPNGWarning(Warning):
    """
    @brief  pyPCAPNG warning class
    """

    def __init__(self, pMssg=None, pFile=None, pLiNo=None, pTrgt=None):
        """
        @brief  Creates a pyPCAPNG warning instance and prints the message
        @param  pMssg  The Warning message
        @param  pFile  The File the Warning relates to
        @param  pLiNo  The number of the line in pFile the Warning relates to
        @param  pTrgt  The stream or file the Warning shall be printed to. Default is sys.stderr.
        """
        self.__name__ = "PCAPNGWarning"
        self._mssg = {True:"UnknownMessage", False:pMssg}[pMssg is None]
        self._file = {True:"UnknownFile",    False:pFile}[pFile is None]
        self._lino = {True:0,                False:pLiNo}[pLiNo is None]
        warnings.showwarning(self._mssg, self, self._file, self._lino, pTrgt)

    def __str__(self):
        """
        @brief  Prints a nicely string representation
        """
        return repr("{fFile}:{fLiNo}: PCAPNGWarning: {fMssg}".format(fFile=self._file, fLiNo=self._lino, fMssg=self._mssg))


class BLKType(__EnumInt):
    SHB     = 0x0A0D0D0A
    IDB     = 0x00000001
    EPB     = 0x00000006
    SPB     = 0x00000003
    NRB     = 0x00000004
    ISB     = 0x00000005
    DSB     = 0x0000000A
    CB0     = 0x00000BAD
    CB1     = 0x40000BAD
    UNKNOWN = 0xFFFFFFFF


class BLKByteOrderType(__EnumStr):
    BIG    = ">"
    LITTLE = "<"
    NATIVE = {"little":"<", "big":">"}[sys.byteorder]
    EVITAN = {"little":">", "big":"<"}[sys.byteorder]


class BLKOptionType(__EnumInt):
    ENDOFOPT = 0x0000
    COMMENT  = 0x0001
    CUSTOM0  = 0x0BAC
    CUSTOM1  = 0x0BAD
    CUSTOM2  = 0x4BAC
    CUSTOM3  = 0x4BAD


class SHBOptionType(__EnumInt):
    HARDWARE = 0x0002
    OS       = 0x0003
    USERAPPL = 0x0004


class IDBOptionType(__EnumInt):
    NAME        = 0x0002
    DESCRIPTION = 0x0003
    IPV4ADDR    = 0x0004
    IPV6ADDR    = 0x0005
    MACADDR     = 0x0006
    EUIADDR     = 0x0007
    SPEED       = 0x0008
    TSRESOL     = 0x0009
    TZONE       = 0x000A
    FILTER      = 0x000B
    OS          = 0x000C
    FCSLEN      = 0x000D
    TSOFFSET    = 0x000E
    HARDWARE    = 0x000F
    TXSPEED     = 0x0010
    RXSPEED     = 0x0011


class EPBOptionType(__EnumInt):
    FLAGS     = 0x0002
    HASH      = 0x0003
    DROPCOUNT = 0x0004
    PACKETID  = 0x0005
    QUEUE     = 0x0006
    VERDICT   = 0x0007


class SPBOptionType(__EnumInt):
    pass


class NRBOptionType(__EnumInt):
    DNSNAME    = 0x0002
    DNSIP4ADDR = 0x0003
    DNSIP6ADDR = 0x0004


class ISBOptionType(__EnumInt):
    STARTTIME    = 0x0002
    ENDTIME      = 0x0003
    IFRECV       = 0x0004
    IFDROP       = 0x0005
    FILTERACCEPT = 0x0006
    OSDROP       = 0x0007
    USRDELIV     = 0x0008


class DSBOptionType(__EnumInt):
    pass


class CB0BOptionType(__EnumInt):
    pass


class CB1OptionType(__EnumInt):
    pass


SHBOptionType = __EnumInt('SHBOptionType', [(i.name, i.value) for i in itertools.chain(BLKOptionType, SHBOptionType)])
IDBOptionType = __EnumInt('IDBOptionType', [(i.name, i.value) for i in itertools.chain(BLKOptionType, IDBOptionType)])
EPBOptionType = __EnumInt('EPBOptionType', [(i.name, i.value) for i in itertools.chain(BLKOptionType, EPBOptionType)])
SPBOptionType = SPBOptionType
NRBOptionType = __EnumInt('NRBOptionType', [(i.name, i.value) for i in itertools.chain(BLKOptionType, NRBOptionType)])
ISBOptionType = __EnumInt('ISBOptionType', [(i.name, i.value) for i in itertools.chain(BLKOptionType, ISBOptionType)])
DSBOptionType = BLKOptionType
CB0OptionType = BLKOptionType
CB1OptionType = BLKOptionType


class NRBRecordType(__EnumInt):
    END  = 0x0000
    IPV4 = 0x0001
    IPV6 = 0x0002


BLKOptionSpec = {BLKOptionType.ENDOFOPT : dict(lenMin = 0, lenMax =     0, type = None,       unique = True ),
                 BLKOptionType.COMMENT  : dict(lenMin = 0, lenMax = 65535, type = "{f_len}s", unique = False),
                 BLKOptionType.CUSTOM0  : dict(lenMin = 4, lenMax = 65535, type = None,       unique = False),
                 BLKOptionType.CUSTOM1  : dict(lenMin = 4, lenMax = 65535, type = None,       unique = False),
                 BLKOptionType.CUSTOM2  : dict(lenMin = 4, lenMax = 65535, type = None,       unique = False),
                 BLKOptionType.CUSTOM3  : dict(lenMin = 4, lenMax = 65535, type = None,       unique = False)
                }

SHBOptionSpec = {SHBOptionType.HARDWARE : dict(lenMin = 0, lenMax = 65535, type = None, unique = True ),
                 SHBOptionType.OS       : dict(lenMin = 0, lenMax = 65535, type = None, unique = True ),
                 SHBOptionType.USERAPPL : dict(lenMin = 0, lenMax = 65535, type = None, unique = True )
                }

IDBOptionSpec = {IDBOptionType.NAME        : dict(lenMin =  0, lenMax = 65535, type = None, unique = True ),
                 IDBOptionType.DESCRIPTION : dict(lenMin =  0, lenMax = 65535, type = None, unique = True ),
                 IDBOptionType.IPV4ADDR    : dict(lenMin =  8, lenMax =     8, type = None, unique = False),
                 IDBOptionType.IPV6ADDR    : dict(lenMin = 17, lenMax =    17, type = None, unique = False),
                 IDBOptionType.MACADDR     : dict(lenMin =  6, lenMax =     6, type = None, unique = True ),
                 IDBOptionType.EUIADDR     : dict(lenMin =  8, lenMax =     8, type = None, unique = True ),
                 IDBOptionType.SPEED       : dict(lenMin =  8, lenMax =     8, type = "Q",  unique = True ),
                 IDBOptionType.TSRESOL     : dict(lenMin =  1, lenMax =     1, type = None, unique = True ),
                 IDBOptionType.TZONE       : dict(lenMin =  4, lenMax =     4, type = None, unique = True ),
                 IDBOptionType.FILTER      : dict(lenMin =  1, lenMax = 65535, type = None, unique = True ),
                 IDBOptionType.OS          : dict(lenMin =  0, lenMax = 65535, type = None, unique = True ),
                 IDBOptionType.FCSLEN      : dict(lenMin =  1, lenMax =     1, type = None, unique = True ),
                 IDBOptionType.TSOFFSET    : dict(lenMin =  8, lenMax =     8, type = "Q",  unique = True ),
                 IDBOptionType.HARDWARE    : dict(lenMin =  0, lenMax = 65535, type = None, unique = True ),
                 IDBOptionType.TXSPEED     : dict(lenMin =  8, lenMax =     8, type = "Q",  unique = True ),
                 IDBOptionType.RXSPEED     : dict(lenMin =  8, lenMax =     8, type = "Q",  unique = True ),
                }

EPBOptionSpec = {EPBOptionType.FLAGS     : dict(lenMin =  4, lenMax =     4, type = None, unique = True ),
                 EPBOptionType.HASH      : dict(lenMin =  0, lenMax = 65535, type = None, unique = False),
                 EPBOptionType.DROPCOUNT : dict(lenMin =  8, lenMax =     8, type = None, unique = True ),
                 EPBOptionType.PACKETID  : dict(lenMin =  8, lenMax =     8, type = None, unique = True ),
                 EPBOptionType.QUEUE     : dict(lenMin =  4, lenMax =     4, type = None, unique = True ),
                 EPBOptionType.VERDICT   : dict(lenMin =  0, lenMax = 65535, type = None, unique = False),
                }

SPBOptionSpec = {}

NRBOptionSpec = {NRBOptionType.DNSNAME    : dict(lenMin =  0, lenMax = 65535, type = None, unique = True),
                 NRBOptionType.DNSIP4ADDR : dict(lenMin =  4, lenMax =     4, type = None, unique = True),
                 NRBOptionType.DNSIP6ADDR : dict(lenMin = 16, lenMax =    16, type = None, unique = True),
                }

ISBOptionSpec = {ISBOptionType.STARTTIME    : dict(lenMin = 8, lenMax = 8, type = None, unique = True),
                 ISBOptionType.ENDTIME      : dict(lenMin = 8, lenMax = 8, type = None, unique = True),
                 ISBOptionType.IFRECV       : dict(lenMin = 8, lenMax = 8, type = None, unique = True),
                 ISBOptionType.IFDROP       : dict(lenMin = 8, lenMax = 8, type = None, unique = True),
                 ISBOptionType.FILTERACCEPT : dict(lenMin = 8, lenMax = 8, type = None, unique = True),
                 ISBOptionType.OSDROP       : dict(lenMin = 8, lenMax = 8, type = None, unique = True),
                 ISBOptionType.USRDELIV     : dict(lenMin = 8, lenMax = 8, type = None, unique = True),
                }

DSBOptionSpec = {}

CB0OptionSpec = {}

CB1OptionSpec = {}


SHBOptionSpec.update(BLKOptionSpec)
IDBOptionSpec.update(BLKOptionSpec)
EPBOptionSpec.update(BLKOptionSpec)
SPBOptionSpec.update()
NRBOptionSpec.update(BLKOptionSpec)
ISBOptionSpec.update(BLKOptionSpec)
DSBOptionSpec.update(BLKOptionSpec)
CB0OptionSpec.update(BLKOptionSpec)
CB1OptionSpec.update(BLKOptionSpec)


NRBRecordSpec = {NRBRecordType.END  : dict(lenMin =  0, lenMax =     0, type = None, unique = True),
                 NRBRecordType.IPV4 : dict(lenMin =  0, lenMax = 65535, type = None, unique = False),
                 NRBRecordType.IPV6 : dict(lenMin =  0, lenMax = 65535, type = None, unique = False),
                }


class LINKType(__EnumInt):
    # https://datatracker.ietf.org/doc/html/draft-richardson-opsawg-pcaplinktype-01
    NULL                       = 0
    ETHERNET                   = 1
    EXP_ETHERNET               = 2
    AX25                       = 3
    PRONET                     = 4
    CHAOS                      = 5
    IEEE802_5                  = 6
    ARCNET_BSD                 = 7
    SLIP                       = 8
    PPP                        = 9
    FDDI                       = 10
    PPP_HDLC                   = 50
    PPP_ETHER                  = 51
    SYMANTEC_FIREWALL          = 99
    ATM_RFC1483                = 100
    RAW                        = 101
    SLIP_BSDOS                 = 102
    PPP_BSDOS                  = 103
    C_HDLC                     = 104
    IEEE802_11                 = 105
    ATM_CLIP                   = 106
    FRELAY                     = 107
    LOOP                       = 108
    ENC                        = 109
    LANE8023                   = 110
    HIPPI                      = 111
    HDLC                       = 112
    LINUX_SLL                  = 113
    LTALK                      = 114
    ECONET                     = 115
    IPFILTER                   = 116
    PFLOG                      = 117
    CISCO_IOS                  = 118
    IEEE802_11_PRISM           = 119
    IEEE802_11_AIRONET         = 120
    HHDLC                      = 121
    IP_OVER_FC                 = 122
    SUNATM                     = 123
    RIO                        = 124
    PCI_EXP                    = 125
    AURORA                     = 126
    IEEE802_11_RADIOTAP        = 127
    TZSP                       = 128
    ARCNET_LINUX               = 129
    JUNIPER_MLPPP              = 130
    JUNIPER_MLFR               = 131
    JUNIPER_ES                 = 132
    JUNIPER_GGSN               = 133
    JUNIPER_MFR                = 134
    JUNIPER_ATM2               = 135
    JUNIPER_SERVICES           = 136
    JUNIPER_ATM1               = 137
    APPLE_IP_OVER_IEEE1394     = 138
    MTP2_WITH_PHDR             = 139
    MTP2                       = 140
    MTP3                       = 141
    SCCP                       = 142
    DOCSIS                     = 143
    LINUX_IRDA                 = 144
    IBM_SP                     = 145
    IBM_SN                     = 146
    RESERVED_01                = 147
    RESERVED_02                = 148
    RESERVED_03                = 149
    RESERVED_04                = 150
    RESERVED_05                = 151
    RESERVED_06                = 152
    RESERVED_07                = 153
    RESERVED_08                = 154
    RESERVED_09                = 155
    RESERVED_10                = 156
    RESERVED_11                = 157
    RESERVED_12                = 158
    RESERVED_13                = 159
    RESERVED_14                = 160
    RESERVED_15                = 161
    RESERVED_16                = 162
    IEEE802_11_AVS             = 163
    JUNIPER_MONITOR            = 164
    BACNET_MS_TP               = 165
    PPP_PPPD                   = 166
    JUNIPER_PPPOE              = 167
    JUNIPER_PPPOE_ATM          = 168
    GPRS_LLC                   = 169
    GPF_T                      = 170
    GPF_F                      = 171
    GCOM_T1E1                  = 172
    GCOM_SERIAL                = 173
    JUNIPER_PIC_PEER           = 174
    ERF_ETH                    = 175
    ERF_POS                    = 176
    LINUX_LAPD                 = 177
    JUNIPER_ETHER              = 178
    JUNIPER_PPP                = 179
    JUNIPER_FRELAY             = 180
    JUNIPER_CHDLC              = 181
    MFR                        = 182
    JUNIPER_VP                 = 182
    A653_ICM                   = 185
    USB_FREEBSD                = 186
    BLUETOOTH_HCI_H4           = 187
    IEEE802_16_MAC_CPS         = 188
    USB_LINUX                  = 189
    CAN20B                     = 190
    IEEE802_15_4_LINUX         = 191
    PPI                        = 192
    IEEE802_16_MAC_CPS_RADIO   = 193
    JUNIPER_ISM                = 194
    IEEE802_15_4_WITHFCS       = 195
    SITA                       = 196
    ERF                        = 197
    RAIF1                      = 198
    IPMB_KONTRON               = 199
    JUNIPER_ST                 = 200
    BLUETOOTH_HCI_H4_WITH_PHDR = 201
    AX25_KISS                  = 202
    LAPD                       = 203
    PPP_WITH_DIR               = 204
    C_HDLC_WITH_DIR            = 205
    FRELAY_WITH_DIR            = 206
    LAPB_WITH_DIR              = 207
    Reserved_17                = 208
    IPMB_LINUX                 = 209
    FLEXRAY                    = 210
    MOST                       = 211
    LIN                        = 212
    X2E_SERIAL                 = 213
    X2E_XORAYA                 = 214
    IEEE802_15_4_NONASK_PHY    = 215
    LINUX_EVDEV                = 216
    GSMTAP_UM                  = 217
    GSMTAP_ABIS                = 218
    MPLS                       = 219
    USB_LINUX_MMAPPED          = 220
    DECT                       = 221
    AOS                        = 222
    WIHART                     = 223
    FC_2                       = 224
    FC_2_WITH_FRAME_DELIMS     = 225
    IPNET                      = 226
    CAN_SOCKETCAN              = 227
    IPV4                       = 228
    IPV6                       = 229
    IEEE802_15_4_NOFCS         = 230
    DBUS                       = 231
    JUNIPER_VS                 = 232
    JUNIPER_SRX_E2E            = 233
    JUNIPER_FIBRECHANNEL       = 234
    DVB_CI                     = 235
    MUX27010                   = 236
    STANAG_5066_D_PDU          = 237
    JUNIPER_ATM_CEMIC          = 238
    NFLOG                      = 239
    NETANALYZER                = 240
    NETANALYZER_TRANSPARENT    = 241
    IPOIB                      = 242
    MPEG_2_TS                  = 243
    NG40                       = 244
    NFC_LLCP                   = 245
    PFSYNC                     = 246
    INFINIBAND                 = 247
    SCTP                       = 248
    USBPCAP                    = 249
    RTAC_SERIAL                = 250
    BLUETOOTH_LE_LL            = 251
    WIRESHARK_UPPER_PDU        = 252
    NETLINK                    = 253
    BLUETOOTH_LINUX_MONITOR    = 254
    BLUETOOTH_BREDR_BB         = 255
    BLUETOOTH_LE_LL_WITH_PHDR  = 256
    PROFIBUS_DL                = 257
    PKTAP                      = 258
    EPON                       = 259
    IPMI_HPM_2                 = 260
    ZWAVE_R1_R2                = 261
    ZWAVE_R3                   = 262
    WATTSTOPPER_DLM            = 263
    ISO_14443                  = 264
    RDS                        = 265
    USB_DARWIN                 = 266
    OPENFLOW                   = 267
    SDLC                       = 268
    TI_LLN_SNIFFER             = 269
    LORATAP                    = 270
    VSOCK                      = 271
    NORDIC_BLE                 = 272
    DOCSIS31_XRA31             = 273
    ETHERNET_MPACKET           = 274
    DISPLAYPORT_AUX            = 275
    LINUX_SLL2                 = 276
    SERCOS_MONITOR             = 277
    OPENVIZSLA                 = 278
    EBHSCR                     = 279
    VPP_DISPATCH               = 280
    DSA_TAG_BRCM               = 281
    DSA_TAG_BRCM_PREPEND       = 282
    IEEE802_15_4_TAP           = 283
    DSA_TAG_DSA                = 284
    DSA_TAG_EDSA               = 285
    ELEE                       = 286
    Z_WAVE_SERIAL              = 287
    USB_2_0                    = 288
    ATSC_ALP                   = 289


class _GB(object):
    """
    @brief  Class representing a PCAPNG general block structure
    """

    def __init__(self, pFile=None, **kwargs) -> None:
        """
        @brief  Creates a general PCAPNG block
        @param  pFile  Name of the file this block is located in. This is only used for informational outputs.
        """
        if   (set(kwargs.keys()) == set(["pBlockType", "pBlockByteOrder"                 ])): self.__init_gb_spc__(pFile, **kwargs)
        elif (set(kwargs.keys()) == set(["pBlockType", "pBlockByteOrder", "pBlockBinData"])): self.__init_gb_bin__(pFile, **kwargs)
        else                                                                                : raise PCAPNGException("Failed to instaniate an object of class '_GB'.")

    def __init_gb_spc__(self, pFile=None, pBlockType=BLKType.UNKNOWN, pBlockByteOrder:BLKByteOrderType=BLKByteOrderType.NATIVE) -> None:
        """
        @brief  Creates a general PCAPNG block from specific data
        @param  pFile            Name of the file this block is located in. This is only used for informational outputs.
        @param  pBlockType       Value of type 'BLKType' that specifies the desired PCAPNG format block type.
        @param  pBlockByteOrder  Value of type 'BLKByteOrderType' that specifies the desired PCAPNG block byte order.
        """
        if (not BLKType.has_value(pBlockType)                    ): raise PCAPNGException("Failed to create a {f_bt} object. Parameter 'pBlockType' (== {f_val}) is not in range '[{f_rng}]'."     .format(f_bt=str(pBlockType), f_val=pBlockType,      f_rng=BLKType.range())         )
        if (not BLKByteOrderType.has_value(pBlockByteOrder.value)): raise PCAPNGException("Failed to create a {f_bt} object. Parameter 'pBlockByteOrder' (== {f_val}) is not in range '[{f_rng}]'.".format(f_bt=str(pBlockType), f_val=pBlockByteOrder, f_rng=BLKByteOrderType.range()))

        self._file            = pFile
        self._blockType       = pBlockType
        self._blockLength     = None
        self._blockByteOrder  = None
        self._blockRecords    = dict(raw=None, lst=None)
        self._blockRecordType = {BLKType.SHB: None, BLKType.IDB: None, BLKType.EPB: None, BLKType.SPB: None, BLKType.NRB: NRBRecordType, BLKType.ISB: None, BLKType.DSB: None, BLKType.CB0: None, BLKType.CB1: None, BLKType.UNKNOWN: None}[pBlockType]
        self._blockRecordSpec = {BLKType.SHB: None, BLKType.IDB: None, BLKType.EPB: None, BLKType.SPB: None, BLKType.NRB: NRBRecordSpec, BLKType.ISB: None, BLKType.DSB: None, BLKType.CB0: None, BLKType.CB1: None, BLKType.UNKNOWN: None}[pBlockType]
        self._blockOptions    = dict(raw=None, lst=None)
        self._blockOptionType = {BLKType.SHB: SHBOptionType, BLKType.IDB: IDBOptionType, BLKType.EPB: EPBOptionType, BLKType.SPB: SPBOptionType, BLKType.NRB: NRBOptionType, BLKType.ISB: ISBOptionType, BLKType.DSB: DSBOptionType, BLKType.CB0: CB0OptionType, BLKType.CB1: CB1OptionType, BLKType.UNKNOWN: None}[pBlockType]
        self._blockOptionSpec = {BLKType.SHB: SHBOptionSpec, BLKType.IDB: IDBOptionSpec, BLKType.EPB: EPBOptionSpec, BLKType.SPB: SPBOptionSpec, BLKType.NRB: NRBOptionSpec, BLKType.ISB: ISBOptionSpec, BLKType.DSB: DSBOptionSpec, BLKType.CB0: CB0OptionSpec, BLKType.CB1: CB1OptionSpec, BLKType.UNKNOWN: None}[pBlockType]

        self.blockByteOrder   = pBlockByteOrder

    def __init_gb_bin__(self, pFile=None, pBlockType:BLKType=BLKType.UNKNOWN, pBlockByteOrder:BLKByteOrderType=BLKByteOrderType.NATIVE, pBlockBinData:typing.Union[bytes, bytearray]=None) -> None:
        """
        @brief  Creates a general PCAPNG block from binary data
        @param  pFile            Name of the file this block is located in. This is only used for informational outputs.
        @param  pBlockType       Value of type 'BLKType' that specifies the desired PCAPNG format block type.
        @param  pBlockByteOrder  Value of type 'BLKByteOrderType' that specifies the desired PCAPNG block byte order.
        @param  pBlockBinData    Value of type 'bytes' or 'bytearray' that specifies the exact binary data of the block.
        """
        if (not BLKType.has_value(pBlockType)                    ): raise PCAPNGException("Failed to create a {f_bt} object. Parameter 'pBlockType' (== {f_val}) is not in range '[{f_rng}]'."             .format(f_bt=str(pBlockType), f_val=pBlockType,      f_rng=BLKType.range())         )
        if (not BLKByteOrderType.has_value(pBlockByteOrder.value)): raise PCAPNGException("Failed to create a {f_bt} object. Parameter 'pBlockByteOrder' (== {f_val}) is not in range '[{f_rng}]'."        .format(f_bt=str(pBlockType), f_val=pBlockByteOrder, f_rng=BLKByteOrderType.range()))
        if (not isinstance(pBlockBinData, (bytes, bytearray))    ): raise PCAPNGException("Failed to create a {f_bt} object. Parameter 'pBlockBinData' (== {f_val}) is not of type 'bytes' or 'bytearray'.".format(f_bt=str(pBlockType), f_val=type(pBlockBinData))                            )
        if ((len(pBlockBinData) % 4) != 0                        ): raise PCAPNGException("Failed to create a {f_bt} object. Length of parameter 'pBlockBinData' (== {f_val}) is not a multiple of 4."     .format(f_bt=str(pBlockType), f_val=len(pBlockBinData))                             )

        self._file            = pFile
        self._blockType       = BLKType(struct.unpack("{f_bo}I".format(f_bo=pBlockByteOrder.value), pBlockBinData[0:4])[0])
        self._blockLength     = struct.unpack("{f_bo}I".format(f_bo=pBlockByteOrder.value), pBlockBinData[4:8])[0]
        self._blockByteOrder  = None
        self._blockRecords    = dict(raw=None, lst=None)
        self._blockRecordType = {BLKType.SHB: None, BLKType.IDB: IDBOptionType, BLKType.EPB: EPBOptionType, BLKType.SPB: SPBOptionType, BLKType.NRB: NRBRecordType, BLKType.ISB: None, BLKType.DSB: None, BLKType.CB0: None, BLKType.CB1: None, BLKType.UNKNOWN: None}[pBlockType]
        self._blockRecordSpec = {BLKType.SHB: None, BLKType.IDB: IDBOptionSpec, BLKType.EPB: EPBOptionSpec, BLKType.SPB: SPBOptionSpec, BLKType.NRB: NRBRecordSpec, BLKType.ISB: None, BLKType.DSB: None, BLKType.CB0: None, BLKType.CB1: None, BLKType.UNKNOWN: None}[pBlockType]
        self._blockOptions    = dict(raw=None, lst=None)
        self._blockOptionType = {BLKType.SHB: SHBOptionType, BLKType.IDB: IDBOptionType, BLKType.EPB: EPBOptionType, BLKType.SPB: SPBOptionType, BLKType.NRB: NRBOptionType, BLKType.ISB: ISBOptionType, BLKType.DSB: DSBOptionType, BLKType.CB0: CB0OptionType, BLKType.CB1: CB1OptionType, BLKType.UNKNOWN: None}[pBlockType]
        self._blockOptionSpec = {BLKType.SHB: SHBOptionSpec, BLKType.IDB: IDBOptionSpec, BLKType.EPB: EPBOptionSpec, BLKType.SPB: SPBOptionSpec, BLKType.NRB: NRBOptionSpec, BLKType.ISB: ISBOptionSpec, BLKType.DSB: DSBOptionSpec, BLKType.CB0: CB0OptionSpec, BLKType.CB1: CB1OptionSpec, BLKType.UNKNOWN: None}[pBlockType]

        if (not BLKType.has_value(self._blockType)               ): raise PCAPNGException("Failed to create a {f_bt} object. Block type (== {f_val}) extracted from parameter 'pBlockBinData' is not in range '[{f_rng}]'.".format(f_bt=str(pBlockType), f_val=self._blockType, f_rng=BLKType.range()))

        self.blockByteOrder   = pBlockByteOrder

        if ((pBlockType != BLKType.UNKNOWN) and (pBlockType != self._blockType)                                   ): raise PCAPNGException("Failed to create a {f_bt} object. Block type (== {f_val0}) extracted from parameter 'pBlockBinData' does not match the the expected block type (== {f_val1}) specified via parameter 'pBlockType'.".format(f_bt=str(pBlockType), f_val0=self._blockType, f_val1=pBlockType))
        if (self.blockLength != struct.unpack("{f_bo}I".format(f_bo=pBlockByteOrder.value), pBlockBinData[-4:])[0]): raise PCAPNGException("Failed to create a {f_bt} object. Block length elements extracted from parameter 'pBlockBinData' are not equal.".format(f_bt=str(pBlockType)))

    def __tlvListCheck(self, pTlvSpec:dict=None, pValue:list=None) -> dict:
        """
        tlv list = [ (tag1.1, valX), (tag1.2, valY), (tag2.1, valZ), ... ]
        """
        lRslt = list()
        if (pValue is not None):
            lTlvCntr = dict([(k,0) for k in pTlvSpec.keys()])
            for i,(lTag, lVal) in enumerate(pValue):
                if (lTag not in pTlvSpec                                                                   ): lRslt.append(("Failed to check {f_bt} object {{f_typ}}s, because of illegal tag '{{f_tag}}'.".format(f_bt=str(self.blockType)), lTag))
                if ((pTlvSpec[lTag]["unique"] is True) and (lTlvCntr[lTag] != 0)                           ): lRslt.append(("Failed to check {f_bt} object {{f_typ}}s, because unique tag '{{f_tag}}' exists multiple times.".format(f_bt=str(self.blockType)), lTag))
                if (isinstance(lVal, bytes) and (len(lVal) < pTlvSpec[lTag]["lenMin"])                     ): lRslt.append(("Failed to check {f_bt} object {{f_typ}}s, because the actual length '{f_actLen}' of the value for tag '{{f_tag}}' is smaller then minimum specified length '{f_nomLen}'.".format(f_bt=str(self.blockType), f_actLen=len(lVal),                    f_nomLen=pTlvSpec[lTag]["lenMin"]), lTag))
                if (isinstance(lVal, bytes) and (len(lVal) > pTlvSpec[lTag]["lenMax"])                     ): lRslt.append(("Failed to check {f_bt} object {{f_typ}}s, because tag actual length '{f_actLen}' of the value for tag '{{f_tag}}' is greater then maximum specified length '{f_nomLen}'.".format(f_bt=str(self.blockType), f_actLen=len(lVal),                    f_nomLen=pTlvSpec[lTag]["lenMax"]), lTag))
                if (isinstance(lVal, int)   and (((lVal.bit_length() + 7) // 8) > pTlvSpec[lTag]["lenMax"])): lRslt.append(("Failed to check {f_bt} object {{f_typ}}s, because tag actual length '{f_actLen}' of the value for tag '{{f_tag}}' is greater then maximum specified length '{f_nomLen}'.".format(f_bt=str(self.blockType), f_actLen=(lVal.bit_length() + 7) // 8, f_nomLen=pTlvSpec[lTag]["lenMax"]), lTag))
                lTlvCntr[lTag] += 1
        return lRslt

    def __tlvListToRaw(self, pTlvSpecs:dict=None, pValue:list=None) -> bytearray:
        lRslt = bytearray()
        for lTag, lVal in pValue:
            if   ((pTlvSpecs[lTag]["type"] is not None) and (not pTlvSpecs[lTag]["type"].startswith("{f_len}"))): lVal = bytearray(struct.pack(pTlvSpecs["type"].format(f_len=len(lVal)), lVal))
            else                                                                                                : lVal = bytearray(                                                       lVal )
            lLen = len(lVal)
            lPad = ((4 - (lLen % 4)) & 0x3)
            lRslt += bytearray(struct.pack("{f_bo}HH".format(f_bo=self.blockByteOrder.value), lTag, lLen)) + lVal + bytearray([0 for i in range(lPad)])
        return lRslt

    def __tlvRawToList(self, pTlvSpecs:dict=None, pValue:typing.Union[bytes, bytearray]=None, pType="unknown") -> list:
        lRslt = list()
        lPos  = 0
        while (lPos < len(pValue)):
            lTag, lLen = struct.unpack("{f_bo}HH".format(f_bo=self.blockByteOrder.value), pValue[lPos : (lPos + 4)])
            if (lTag in pTlvSpecs):
                if (pTlvSpecs[lTag]["type"] is not None): lVal = struct.unpack(pTlvSpecs[lTag]["type"].format(f_len=lLen), pValue[(lPos + 4) : (lPos + 4 + lLen)])[0]
                else                                    : lVal =                                                           pValue[(lPos + 4) : (lPos + 4 + lLen)]
                lRslt.append(tuple([lTag, lVal]))
            else:
                # ignore not specified option
                PCAPNGWarning(pMssg="[{f_blk}] unspecified {f_typ} tag code '{f_tag:>6d}/0x{f_tag:>04X}' ignored ('{f_val}')".format(f_blk=str(self.blockType), f_typ=pType, f_tag=lTag, f_val=pValue[(lPos + 4) : (lPos + 4 + lLen)]), pFile=self.file)
            lPad  = pValue[(lPos + 4 + lLen) : (lPos + 4 + lLen + ((4 - (lLen % 4)) & 0x3))]
            lPos += ((4 + lLen) + len(lPad))
        return lRslt

    def _rawData(self, pBlockBody) -> bytes:
        """
        @brief  Returns the blocks binary representation
        """
        self._blockLength = 12 + len(pBlockBody)
        return struct.pack("{f_bo}II".format(f_bo=self._blockByteOrder.value), self._blockType, self._blockLength) + pBlockBody + struct.pack("{f_bo}I".format(f_bo=self._blockByteOrder.value), self._blockLength)

    def _recordListCheck(self, pRecordSpec:dict=None, pRecordList:list=None) -> dict:
        lRslt = list()
        if (pRecordSpec is None):
            lRslt.append("Failed to check {f_bt} object records, because no record definiton is available.".format(f_bt=str(self.blockType)))
        else:
            lRslt.extend(self.__tlvListCheck(pRecordSpec, pRecordList))
            if ((pRecordList is not None) and (len(pRecordList) >= 1) and (pRecordList[-1][0] != NRBRecordType.END)): lRslt.append("Failed to check {f_bt} object records, because tag '{f_tag}' is not located at the end.".format(f_bt=str(self.blockType), f_tag=NRBRecordType.END))
            lRslt = [m[0].format(f_typ="record", f_tag=self._blockRecordType(m[1]).name) for m in lRslt]
        return lRslt

    def _recordListToRaw(self, pRecordSpecs:dict=None, pValue:typing.Union[bytes, bytearray]=None) -> list:
        return self.__tlvListToRaw(pRecordSpecs, pValue)

    def _recordRawToList(self, pRecordSpecs:dict=None, pValue:typing.Union[bytes, bytearray]=None) -> list:
        lRslt = self.__tlvRawToList(pRecordSpecs, pValue, "record")
        if (lRslt): lRslt = [(self.blockRecordType(lTag), lVal) for lTag, lVal in lRslt]
        return lRslt

    def _optionListCheck(self, pOptionSpec:dict=None, pOptionList:list=None) -> dict:
        lRslt = list()
        if (pOptionSpec is None):
            lRslt.append("Failed to check {f_bt} object options, because no option definiton is available.".format(f_bt=str(self.blockType)))
        else:
            lRslt.extend(self.__tlvListCheck(pOptionSpec, pOptionList))
            if ((pOptionList is not None) and (len(pOptionList) >= 1) and (pOptionList[-1][0] != BLKOptionType.ENDOFOPT)): lRslt.append("Failed to check {f_bt} object options, because tag '{f_tag}' is not located at the end.".format(f_bt=str(self.blockType), f_tag=BLKOptionType.ENDOFOPT))
            lRslt = [m[0].format(f_typ="option", f_tag=self._blockOptionType(m[1]).name) for m in lRslt]
        return lRslt

    def _optionListToRaw(self, pOptionSpecs:dict=None, pValue:typing.Union[bytes, bytearray]=None) -> list:
        return self.__tlvListToRaw(pOptionSpecs, pValue)

    def _optionRawToList(self, pOptionSpecs:dict=None, pValue:typing.Union[bytes, bytearray]=None) -> list:
        lRslt = self.__tlvRawToList(pOptionSpecs, pValue, "option")
        if (lRslt): lRslt = [(self.blockOptionType(lTag), lVal) for lTag, lVal in lRslt]
        return lRslt

    @property
    def file(self) -> str:
        return self._file

    @property
    def blockRecordType(self) -> dict:
        return self._blockRecordType

    @property
    def blockRecordSpec(self) -> dict:
        return self._blockRecordSpec

    @property
    def blockOptionType(self) -> dict:
        return self._blockOptionType

    @property
    def blockOptionSpec(self) -> dict:
        return self._blockOptionSpec

    @property
    def blockType(self) -> int:
        return self._blockType

    @property
    def blockLength(self) -> int:
        return self._blockLength

    @property
    def blockByteOrder(self) -> int:
        return self._blockByteOrder

    @blockByteOrder.setter
    def blockByteOrder(self, pValue:BLKByteOrderType) -> None:
        if (not BLKByteOrderType.has_value(pValue.value)): raise PCAPNGException("Failed to set property 'blockByteOrder' of a {f_bt} object. The desired value (== {f_val}) of the property is not in range '[{f_rng}]'.".format(f_bt=self.blockType.name, f_val=pValue, f_rng=BLKByteOrderType.range()))
        self._blockByteOrder = pValue

    @property
    def options(self) -> list:
        # options = [ (optioncode1.1, [optionvalueX, ...]), (optioncode1.2, [optionvalueY, ...]), (optioncode2.1, [optionvalueZ, ...]), ..., (pyPCAPNG.BLKOptionType.ENDOFOPT, []) ]
        return self._blockOptions["lst"]

    @options.setter
    def options(self, pValue:typing.Union[list, type(None)]) -> None:
        if (not isinstance(pValue, (list, type(None)))): raise PCAPNGException("Failed to set property 'options' of a {f_bt} object. The desired value of the property is not of type 'list' or 'NoneType'.".format(f_bt=self.blockType.name))
        if (self.blockByteOrder is None               ): raise PCAPNGException("Failed to set property 'options' of a {f_bt} object. The attribute 'blockByteOrder' is unknown.".format(f_bt=self.blockType.name))
        if (isinstance(pValue, list)):
            lErrors = list(set(self._optionListCheck(self.blockOptionSpec, pValue)))
            if (lErrors): PCAPNGWarning(pMssg="Failed to set property 'options' of a {f_bt} object. The desired value of the property is incorrect. ({f_error})".format(f_error="\n".join(lErrors)), pFile=self.file)
            self._blockOptions = dict(raw=self._optionListToRaw(self.blockOptionSpec, pValue), lst=pValue)
        else:
            self._blockOptions = dict(raw=None, lst=None)

    @property
    def optionsRaw(self) -> bytearray:
        return self._blockOptions["raw"]

    @optionsRaw.setter
    def optionsRaw(self, pValue:typing.Union[bytes, bytearray, type(None)]) -> None:
        if (not isinstance(pValue, (bytes, bytearray, type(None)))): raise PCAPNGException("Failed to set property 'optionsRaw' of a {f_bt} object. The desired value of the property is not of type 'bytes', 'bytearray' or 'NoneType'.".format(f_bt=self.blockType.name))
        if ((len(pValue) % 4) != 0                                ): raise PCAPNGException("Failed to set property 'optionsRaw' of a {f_bt} object. The length of the provided parameter 'pValue' is not a multiple of 4.".format(f_bt=self.blockType.name))
        if (self.blockByteOrder is None                           ): raise PCAPNGException("Failed to set property 'optionsRaw' of a {f_bt} object. The attribute 'blockByteOrder' is unknown.".format(f_bt=self.blockType.name))
        if (isinstance(pValue, (bytes, bytearray))):
            lBlockOptions = self._optionRawToList(self.blockOptionSpec, pValue)
            lErrors       = list(set(self._optionListCheck(self.blockOptionSpec, lBlockOptions)))
            if (lErrors): PCAPNGWarning(pMssg="Failed to set property 'optionsRaw' of a {f_bt} object. The desired value of the property is incorrect. ({f_error})".format(f_bt=self.blockType.name, f_error="\n".join(lErrors)), pFile=self.file)
            self._blockOptions = dict(raw=pValue, lst=lBlockOptions)
        else:
            self._blockOptions = dict(raw=None, lst=None)


class SHB(_GB):
    """
    @brief  PCAPNG Section Header Block
    """

    def __init__(self, pFile=None, **kwargs):
        """
        @brief  Creates a PCAPNG SHB block
        @param  pFile  Name of the file this block is located in. This is only used for informational outputs.
        """
        self._versionMajor  = None
        self._versionMinor  = None
        self._sectionLength = None
        if   (set(kwargs.keys()) == set(["pBlockByteOrder", "pBlockBinData"])): self.__init_shb_bin__(pFile, **kwargs)
        else                                                                  : self.__init_shb_spc__(pFile, **kwargs)

    def __init_shb_spc__(self, pFile=None, pBlockByteOrder:BLKByteOrderType=BLKByteOrderType.NATIVE, pMajorVersion:int=int(1), pMinorVersion:int=int(0), pSectionLength:int=int(0xFFFFFFFFFFFFFFFF), pOptions:list=None) -> None:
        """
        @brief  Creates a PCAPNG SHB block from specific data
        @param  pFile            Name of the file this block is located in. This is only used for informational outputs.
        @param  pBlockByteOrder  Value of type 'BLKByteOrderType' that specifies the desired PCAPNG block byte order.
        @param  pMajorVersion    Value of type 'int' that specifies the number of the current major version of the format.
        @param  pMinorVersion    Value of type 'int' that specifies the number of the current minor version of the format.
        @param  pSectionLength   Value of type 'int' that specifies the number of the length in octets of the section initiated by this SHB.
        @param  pOptions         List of tuples of option key/value pairs. E.g. [(pyPCAPNG.SHBOptionType.HARDWARE, bytes("Z80", encoding="utf-8")), (pyPCAPNG.SHBOptionType.COMMENT, bytes("Comment 1", encoding="utf-8")), (pyPCAPNG.SHBOptionType.COMMENT, bytes("Comment 2", encoding="utf-8")), (pyPCAPNG.SHBOptionType.ENDOFOPT, [])]
        """
        super().__init__(pFile=pFile, pBlockType=BLKType.SHB, pBlockByteOrder=pBlockByteOrder)
        self.versionMajor   = pMajorVersion
        self.versionMinor   = pMinorVersion
        self.sectionLength  = pSectionLength
        self.options        = pOptions

    def __init_shb_bin__(self, pFile=None, pBlockByteOrder:BLKByteOrderType=None, pBlockBinData:typing.Union[bytes, bytearray]=bytes([])) -> None:
        """
        @brief  Creates a PCAPNG SHB block from binary data
        @param  pFile            Name of the file this block is located in. This is only used for informational outputs.
        @param  pBlockByteOrder  Value of type 'BLKByteOrderType' that specifies the desired PCAPNG block byte order.
        @param  pBlockBinData    Value of type 'bytes' or 'bytearray' that specifies the exact binary data of the block.
        """
        if (len(pBlockBinData) < 28): raise PCAPNGException("Failed to create a {f_bt} object. Parameter 'pBlockBinData' does not have the required minimum length.".format(f_bt=str(self.blockType), f_val=type(pBlockBinData)))

        lBlockByteOrder = struct.unpack("@I", pBlockBinData[8:12])[0]
        if   (lBlockByteOrder == 0x1A2B3C4D): self.blockByteOrder = BLKByteOrderType.LITTLE
        elif (lBlockByteOrder == 0x4D3C2B1A): self.blockByteOrder = BLKByteOrderType.BIG
        else                                : raise PCAPNGException("Failed to create a SHB object from binary data that 'Byte-Order Magic' element is wrong.")

        super().__init__(pFile=pFile, pBlockType=BLKType.SHB, pBlockByteOrder=self.blockByteOrder, pBlockBinData=pBlockBinData)

        if ((pBlockByteOrder is not None) and (pBlockByteOrder != self.blockByteOrder)): raise PCAPNGException("Failed to create a {f_bt} object. Attribute 'blockByteOrder' (== {f_val}) extracted from parameter 'pBlockBinData' is not in range '[{f_rng}]'.".format(f_bt=str(pBlockType), f_val=pBlockByteOrder, f_rng=BLKByteOrderType.range()))

        self.versionMajor, self.versionMinor, self.sectionLength = struct.unpack("{f_bo}HHQ".format(f_bo=self.blockByteOrder.value), pBlockBinData[12:24])

        if (24 < (len(pBlockBinData) - 4)):
            self.optionsRaw = pBlockBinData[24:-4]

    @property
    def rawData(self):
        return self._rawData(struct.pack("{f_bo}IHHQ".format(f_bo=self._blockByteOrder.value), int(0x1A2B3C4D), self._versionMajor, self._versionMinor, self._sectionLength) + {True:self.optionsRaw, False:bytes([])}[self.optionsRaw is not None])

    @property
    def versionMajor(self) -> int:
        return self._versionMajor

    @versionMajor.setter
    def versionMajor(self, pValue:int) -> None:
        if (not isinstance(pValue, int)): raise PCAPNGException("Failed to set property 'versionMajor' of a {f_bt} object. The desired value (== {f_val}) is not of type 'int'.".format(f_bt=self.blockType.name, f_val=pValue))
        if (not 0 <= pValue <= 0xFFFF  ): raise PCAPNGException("Failed to set property 'versionMajor' of a {f_bt} object. The desired value (== {f_val}) of the property is not in range '[0,(2^16)-1]'.".format(f_bt=self.blockType.name, f_val=pValue))
        self._versionMajor = pValue

    @property
    def versionMinor(self) -> int:
        return self._versionMinor

    @versionMinor.setter
    def versionMinor(self, pValue:int) -> None:
        if (not isinstance(pValue, int)): raise PCAPNGException("Failed to set property 'versionMinor' of a {f_bt} object. The desired value (== {f_val}) is not of type 'int'.".format(f_bt=self.blockType.name, f_val=pValue))
        if (not 0 <= pValue <= 0xFFFF  ): raise PCAPNGException("Failed to set property 'versionMinor' of a {f_bt} object. The desired value (== {f_val}) of the property is not in range '[0,(2^16)-1]'.".format(f_bt=self.blockType.name, f_val=pValue))
        self._versionMinor = pValue

    @property
    def sectionLength(self) -> int:
        return self._sectionLength

    @sectionLength.setter
    def sectionLength(self, pValue:int) -> None:
        if (not isinstance(pValue, int)          ): raise PCAPNGException("Failed to set property 'sectionLength' of a {f_bt} object. The desired value (== {f_val}) is not of type 'int'.".format(f_bt=self.blockType.name, f_val=pValue))
        if (not 0 <= pValue <= 0xFFFFFFFFFFFFFFFF): raise PCAPNGException("Failed to set property 'sectionLength' of a {f_bt} object. The desired value (== {f_val}) of the property is not in range '[0,(2^64)-1]'.".format(f_bt=self.blockType.name, f_val=pValue))
        self._sectionLength = pValue


class IDB(_GB):
    """
    @brief  PCAPNG Interface Description Block
    """

    def __init__(self, pFile=None, **kwargs):
        self._linkType = None
        self._snapLen  = None
        if (set(kwargs.keys()) == set(["pBlockByteOrder", "pBlockBinData"])): self.__init_idb_bin__(pFile, **kwargs)
        else                                                                : self.__init_idb_spc__(pFile, **kwargs)

    def __init_idb_spc__(self, pFile=None, pBlockByteOrder:BLKByteOrderType=BLKByteOrderType.NATIVE, pLinkType:int=int(1), pSnapLen:int=int(0), pOptions:list=None) -> None:
        """
        @brief  Creates a PCAPNG IDB block from specific data
        @param  pFile            Name of the file this block is located in. This is only used for informational outputs.
        @param  pBlockByteOrder  Value of type 'BLKByteOrderType' that specifies the desired PCAPNG block byte order.
        @param  pLinkType        Value of type '(unsigned) int' that specifies the link layer type of this interface.
        @param  pSnapLen         Value of type '(unsigned) int' that specifies the maximum number of octets captured from each packet. The portion of each packet that exceeds this value will not be stored in the file. A value of zero indicates no limit.
        @param  pOptions         List of tuples of option key/value pairs. E.g. [(pyPCAPNG.IDBOptionType.NAME, bytes("LAN1", encoding="utf-8")), (pyPCAPNG.IDBOptionType.IPV4ADDR, [0xC0, 0xA8, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0x00]), (pyPCAPNG.IDBOptionType.COMMENT, bytes("Comment 2", encoding="utf-8")), (pyPCAPNG.IDBOptionType.ENDOFOPT, [])]
        """
        super().__init__(pFile=pFile, pBlockType=BLKType.IDB, pBlockByteOrder=pBlockByteOrder)
        self.linkType  = pLinkType
        self.snapLen   = pSnapLen
        self.options   = pOptions

    def __init_idb_bin__(self, pFile=None, pBlockByteOrder:BLKByteOrderType=None, pBlockBinData:typing.Union[bytes, bytearray]=bytes([])) -> None:
        """
        @brief  Creates a PCAPNG IDB block from binary data
        @param  pFile            Name of the file this block is located in. This is only used for informational outputs.
        @param  pBlockByteOrder  Value of type 'BLKByteOrderType' that specifies the desired PCAPNG block byte order.
        @param  pBlockBinData    Value of type 'bytes' or 'bytearray' that specifies the exact binary data of the block.
        """
        super().__init__(pFile=pFile, pBlockType=BLKType.IDB, pBlockByteOrder=pBlockByteOrder, pBlockBinData=pBlockBinData)
        if (len(pBlockBinData) < 20): raise PCAPNGException("Failed to create a {f_bt} object. Parameter 'pBlockBinData' does not have the required minimum length.".format(f_bt=str(self.blockType), f_val=type(pBlockBinData)))
        self.linkType, dummy, self.snapLen = struct.unpack("{f_bo}HHI".format(f_bo=pBlockByteOrder.value), pBlockBinData[8:16])
        if (16 < (len(pBlockBinData) - 4)):
            self.optionsRaw = pBlockBinData[16:-4]

    @property
    def rawData(self):
        return self._rawData(struct.pack("{f_bo}HHI".format(f_bo=self.blockByteOrder.value), self.linkType, 0, self.snapLen) + {True:self.optionsRaw, False:bytes([])}[self.optionsRaw is not None])

    @property
    def linkType(self) -> int:
        return self._linkType

    @linkType.setter
    def linkType(self, pValue:int) -> None:
        if (not isinstance(pValue, int)): raise PCAPNGException("Failed to set property 'linkType' of a {f_bt} object. The desired value (== {f_val}) is not of type 'int'.".format(f_bt=self.blockType.name, f_val=pValue))
        if (not 0 <= pValue <= 0xFFFF  ): raise PCAPNGException("Failed to set property 'linkType' of a {f_bt} object. The desired value (== {f_val}) of the property is not in range '[0,(2^16)-1]'.".format(f_bt=self.blockType.name, f_val=pValue))
        self._linkType = pValue

    @property
    def snapLen(self) -> int:
        return self._snapLen

    @snapLen.setter
    def snapLen(self, pValue:int) -> None:
        if (not isinstance(pValue, int)  ): raise PCAPNGException("Failed to set property 'linkType' of a {f_bt} object. The desired value (== {f_val}) is not of type 'int'.".format(f_bt=self.blockType.name, f_val=pValue))
        if (not 0 <= pValue <= 0xFFFFFFFF): raise PCAPNGException("Failed to set property 'linkType' of a {f_bt} object. The desired value (== {f_val}) of the property is not in range '[0,(2^32)-1]'.".format(f_bt=self.blockType.name, f_val=pValue))
        self._snapLen = pValue


class EPB(_GB):
    """
    @brief  PCAPNG Enhanced Packet Block
    """

    def __init__(self, pFile=None, **kwargs):
        self._interfaceId          = None
        self._timestamp            = None
        self._capturedPacketLength = None
        self._originalPacketLength = None
        self._packetData           = None
        if (set(kwargs.keys()) == set(["pBlockByteOrder", "pBlockBinData"])): self.__init_epb_bin__(pFile, **kwargs)
        else                                                                : self.__init_epb_spc__(pFile, **kwargs)

    def __init_epb_spc__(self, pFile=None, pBlockByteOrder:BLKByteOrderType=BLKByteOrderType.NATIVE, pInterfaceId:int=int(0), pTimestamp:int=int(0), pCapturedPacketLength:int=int(0), pOriginalPacketLength:int=int(0), pPacketData:typing.Union[bytes, bytearray]=bytes([]), pOptions:list=None) -> None:
        """
        @brief  Creates a PCAPNG EPB block from specific data
        @param  pFile                  Name of the file this block is located in. This is only used for informational outputs.
        @param  pBlockByteOrder        Value of type 'BLKByteOrderType' that specifies the desired PCAPNG block byte order.
        @param  pInterfaceId           Value of type '(unsigned) int' that specifies the interface on which this packet was received or transmitted.
        @param  pTimestamp             Value of type '(unsigned) int' that specifies the number of units of time that have elapsed since 1970-01-01 00:00:00 UTC.
        @param  pCapturedPacketLength  Value of type '(unsigned) int' that specifies the number of octets captured from the packet (i.e. the length of the Packet Data field). It will be the minimum value among the Original Packet Length and the snapshot length for the interface (SnapLen, defined in Figure 10). The value of this field does not include the padding octets added at the end of the Packet Data field to align the Packet Data field to a 32-bit boundary.
        @param  pOriginalPacketLength  Value of type '(unsigned) int' that specifies the actual length of the packet when it was transmitted on the network. It can be different from the Captured Packet Length if the packet has been truncated by the capture process.
        @param  pPacketData            Value of type 'bytes' or 'bytearray' that specifies payload of the block.
        @param  pOptions               List of tuples of option key/value pairs. E.g. [(pyPCAPNG.EPBOptionType.PACKETID, [0xC0, 0xA8, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0x00]), (pyPCAPNG.EPBOptionType.ENDOFOPT, [])]
        """
        super().__init__(pFile=pFile, pBlockType=BLKType.EPB, pBlockByteOrder=pBlockByteOrder)
        self.interfaceId          = pInterfaceId
        self.timestamp            = pTimestamp
        self.capturedPacketLength = pCapturedPacketLength
        self.originalPacketLength = pOriginalPacketLength
        self.packetData           = pPacketData
        self.options              = pOptions

    def __init_epb_bin__(self, pFile=None, pBlockByteOrder:BLKByteOrderType=None, pBlockBinData:typing.Union[bytes, bytearray]=bytes([])) -> None:
        """
        @brief  Creates a PCAPNG EPB block from binary data
        @param  pFile            Name of the file this block is located in. This is only used for informational outputs.
        @param  pBlockByteOrder  Value of type 'BLKByteOrderType' that specifies the desired PCAPNG block byte order.
        @param  pBlockBinData    Value of type 'bytes' or 'bytearray' that specifies the exact binary data of the block.
        """
        super().__init__(pFile=pFile, pBlockType=BLKType.EPB, pBlockByteOrder=pBlockByteOrder, pBlockBinData=pBlockBinData)
        if (len(pBlockBinData) < 32): raise PCAPNGException("Failed to create a {f_bt} object. Parameter 'pBlockBinData' does not have the required minimum length.".format(f_bt=str(self.blockType), f_val=type(pBlockBinData)))
        self.interfaceId, lTimestampHi, lTimestampLo, self.capturedPacketLength, self.originalPacketLength = struct.unpack("{f_bo}IIIII".format(f_bo=pBlockByteOrder.value), pBlockBinData[8:28])
        self.timestamp  = (lTimestampHi < 32) | lTimestampLo
        if (0 != self.capturedPacketLength): self.packetData = pBlockBinData[28 : (28 + self.capturedPacketLength)]

        if ((28 + self.capturedPacketLength + {True:0, False:(4 - (self.capturedPacketLength % 4))}[(self.capturedPacketLength % 4) == 0]) < (len(pBlockBinData) - 4)):
            self.optionsRaw = pBlockBinData[(28 + self.capturedPacketLength + {True:0, False:(4 - (self.capturedPacketLength % 4))}[(self.capturedPacketLength % 4) == 0]) : -4]

    @property
    def rawData(self):
        vPad = 4 - (len(self.packetData) % 4)
        vPad = bytes([0 for x in range({True:vPad, False:0}[vPad < 4])])
        return self._rawData(struct.pack("{f_bo}IIIII".format(f_bo=self._blockByteOrder.value), self.interfaceId, ((int(self.timestamp) & 0xFFFFFFFF00000000) >> 32), (int(self.timestamp) & 0x00000000FFFFFFFF), self.capturedPacketLength, self.originalPacketLength) + self.packetData + vPad + {True:self.optionsRaw, False:bytes([])}[self.optionsRaw is not None])

    @property
    def interfaceId(self) -> int:
        return self._interfaceId

    @interfaceId.setter
    def interfaceId(self, value:int) -> None:
        if (not isinstance(value, int)  ): raise PCAPNGException("Failed to set property 'interfaceId' of a {f_bt} object. The desired value (== {f_val}) is not of type 'int'.".format(f_bt=self.blockType.name, f_val=value))
        if (not 0 <= value <= 0xFFFFFFFF): raise PCAPNGException("Failed to set property 'interfaceId' of a {f_bt} object. The desired value (== {f_val}) of the property is not in range '[0,(2^32)-1]'.".format(f_bt=self.blockType.name, f_val=value))
        self._interfaceId = value

    @property
    def timestamp(self) -> int:
        return self._timestamp

    @timestamp.setter
    def timestamp(self, value:int) -> None:
        if (not isinstance(value, int)          ): raise PCAPNGException("Failed to set property 'timestamp' of a {f_bt} object. The desired value (== {f_val}) is not of type 'int'.".format(f_bt=self.blockType.name, f_val=value))
        if (not 0 <= value <= 0xFFFFFFFFFFFFFFFF): raise PCAPNGException("Failed to set property 'timestamp' of a {f_bt} object. The desired value (== {f_val}) of the property is not in range '[0,(2^64)-1]'.".format(f_bt=self.blockType.name, f_val=value))
        self._timestamp = value

    @property
    def capturedPacketLength(self) -> int:
        return self._capturedPacketLength

    @capturedPacketLength.setter
    def capturedPacketLength(self, pValue:int) -> None:
        if (not isinstance(pValue, int)  ): raise PCAPNGException("Failed to set property 'capturedPacketLength' of a {f_bt} object. The desired value (== {f_val}) is not of type 'int'.".format(f_bt=self.blockType.name, f_val=pValue))
        if (not 0 <= pValue <= 0xFFFFFFFF): raise PCAPNGException("Failed to set property 'capturedPacketLength' of a {f_bt} object. The desired value (== {f_val}) of the property is not in range '[0,(2^32)-1]'.".format(f_bt=self.blockType.name, f_val=pValue))
        self._capturedPacketLength = pValue

    @property
    def originalPacketLength(self) -> int:
        return self._originalPacketLength

    @originalPacketLength.setter
    def originalPacketLength(self, pValue:int) -> None:
        if (not isinstance(pValue, int)  ): raise PCAPNGException("Failed to set property 'originalPacketLength' of a {f_bt} object. The desired value (== {f_val}) is not of type 'int'.".format(f_bt=self.blockType.name, f_val=pValue))
        if (not 0 <= pValue <= 0xFFFFFFFF): raise PCAPNGException("Failed to set property 'originalPacketLength' of a {f_bt} object. The desired value (== {f_val}) of the property is not in range '[0,(2^32)-1]'.".format(f_bt=self.blockType.name, f_val=pValue))
        self._originalPacketLength = pValue

    @property
    def packetData(self) -> bytes:
        return self._packetData

    @packetData.setter
    def packetData(self, pValue:int) -> None:
        if (not isinstance(pValue, (bytes, bytearray))): raise PCAPNGException("Failed to set property 'packetData' of a {f_bt} object. The desired value is not of type 'bytes' or 'bytearray'.".format(f_bt=self.blockType.name))
        self._packetData = pValue


class SPB(_GB):
    """
    @brief  PCAPNG Simple Packet Block
    """

    def __init__(self, pFile=None, **kwargs):
        self._originalPacketLength = None
        self._packetData           = None
        if (set(kwargs.keys()) == set(["pBlockByteOrder", "pBlockBinData"])): self.__init_spb_bin__(pFile, **kwargs)
        else                                                                : self.__init_spb_spc__(pFile, **kwargs)

    def __init_spb_spc__(self, pFile=None, pBlockByteOrder:BLKByteOrderType=BLKByteOrderType.NATIVE, pOriginalPacketLength:int=int(0), pPacketData:typing.Union[bytes, bytearray]=bytes([])) -> None:
        """
        @brief  Creates a PCAPNG SPB block from specific data
        @param  pFile                  Name of the file this block is located in. This is only used for informational outputs.
        @param  pBlockByteOrder        Value of type 'BLKByteOrderType' that specifies the desired PCAPNG block byte order.
        @param  pOriginalPacketLength  Value of type '(unsigned) int' that specifies the actual length of the packet when it was transmitted on the network. It can be different from the Captured Packet Length if the packet has been truncated by the capture process.
        @param  pPacketData            Value of type 'bytes' or 'bytearray' that specifies payload of the block.
        """
        super().__init__(pFile=pFile, pBlockType=BLKType.SPB, pBlockByteOrder=pBlockByteOrder)
        self.originalPacketLength = pOriginalPacketLength
        self.packetData           = pPacketData

    def __init_spb_bin__(self, pFile=None, pBlockByteOrder:BLKByteOrderType=None, pBlockBinData:typing.Union[bytes, bytearray]=bytes([])) -> None:
        """
        @brief  Creates a PCAPNG SPB block from binary data
        @param  pFile            Name of the file this block is located in. This is only used for informational outputs.
        @param  pBlockByteOrder  Value of type 'BLKByteOrderType' that specifies the desired PCAPNG block byte order.
        @param  pBlockBinData    Value of type 'bytes' or 'bytearray' that specifies the exact binary data of the block.
        """
        super().__init__(pFile=pFile, pBlockType=BLKType.SPB, pBlockByteOrder=pBlockByteOrder, pBlockBinData=pBlockBinData)
        if (len(pBlockBinData) < 32): raise PCAPNGException("Failed to create a {f_bt} object. Parameter 'pBlockBinData' does not have the required minimum length.".format(f_bt=str(self.blockType), f_val=type(pBlockBinData)))
        self.originalPacketLength = struct.unpack("{f_bo}I".format(f_bo=pBlockByteOrder.value), pBlockBinData[8:12])[0]
        if (0 != self.originalPacketLength): self.packetData = pBlockBinData[12 : (12 + self.originalPacketLength)]

    @property
    def rawData(self):
        vPad = 4 - (len(self.packetData) % 4)
        vPad = bytes([0 for x in range({True:vPad, False:0}[vPad < 4])])
        return self._rawData(struct.pack("{f_bo}I".format(f_bo=self._blockByteOrder.value), self.originalPacketLength) + self.packetData + vPad + {True:self.optionsRaw, False:bytes([])}[self.optionsRaw is not None])

    @property
    def originalPacketLength(self) -> int:
        return self._originalPacketLength

    @originalPacketLength.setter
    def originalPacketLength(self, pValue:int) -> None:
        if (not isinstance(pValue, int)  ): raise PCAPNGException("Failed to set property 'originalPacketLength' of a {f_bt} object. The desired value (== {f_val}) is not of type 'int'.".format(f_bt=self.blockType.name, f_val=pValue))
        if (not 0 <= pValue <= 0xFFFFFFFF): raise PCAPNGException("Failed to set property 'originalPacketLength' of a {f_bt} object. The desired value (== {f_val}) of the property is not in range '[0,(2^32)-1]'.".format(f_bt=self.blockType.name, f_val=pValue))
        self._originalPacketLength = pValue

    @property
    def packetData(self) -> bytes:
        return self._packetData

    @packetData.setter
    def packetData(self, pValue:int) -> None:
        if (not isinstance(pValue, (bytes, bytearray))): raise PCAPNGException("Failed to set property 'packetData' of a {f_bt} object. The desired value is not of type 'bytes' or 'bytearray'.".format(f_bt=self.blockType.name))
        self._packetData = pValue


class NRB(_GB):
    """
    @brief  PCAPNG Name Resolution Block
    """

    def __init__(self, pFile=None, **kwargs):
        self._records = dict(raw=None, lst=None)
        if (set(kwargs.keys()) == set(["pBlockByteOrder", "pBlockBinData"])): self.__init_nrb_bin__(pFile, **kwargs)
        else                                                                : self.__init_nrb_spc__(pFile, **kwargs)

    def __init_nrb_spc__(self, pFile=None, pBlockByteOrder:BLKByteOrderType=BLKByteOrderType.NATIVE, pRecords:list=None, pOptions:list=None) -> None:
        """
        @brief  Creates a PCAPNG NRB block from specific data
        @param  pFile                  Name of the file this block is located in. This is only used for informational outputs.
        @param  pBlockByteOrder        Value of type 'BLKByteOrderType' that specifies the desired PCAPNG block byte order.
        @param  pRecords               List of tuples of records key/value pairs. E.g. [(pyPCAPNG.NRBRecordType.IPV4, bytes([0xC0, 0xA8, 0x00, 0x01])+bytes("entries\0", encoding="utf-8")), (pyPCAPNG.NRBRecordType.END, [])]
        @param  pOptions               List of tuples of option key/value pairs. E.g. [(pyPCAPNG.NRBOptionType.DNSIP4ADDR, [0xC0, 0xA8, 0x00, 0x01]), (pyPCAPNG.NRBOptionType.ENDOFOPT, [])]
        """
        super().__init__(pFile=pFile, pBlockType=BLKType.NRB, pBlockByteOrder=pBlockByteOrder)
        self.records  = pRecords
        self.options  = pOptions

    def __init_nrb_bin__(self, pFile=None, pBlockByteOrder:BLKByteOrderType=None, pBlockBinData:typing.Union[bytes, bytearray]=bytes([])) -> None:
        """
        @brief  Creates a PCAPNG NRB block from binary data
        @param  pFile            Name of the file this block is located in. This is only used for informational outputs.
        @param  pBlockByteOrder  Value of type 'BLKByteOrderType' that specifies the desired PCAPNG block byte order.
        @param  pBlockBinData    Value of type 'bytes' or 'bytearray' that specifies the exact binary data of the block.
        """
        super().__init__(pFile=pFile, pBlockType=BLKType.NRB, pBlockByteOrder=pBlockByteOrder, pBlockBinData=pBlockBinData)
        if (len(pBlockBinData) < 12): raise PCAPNGException("Failed to create a {f_bt} object. Parameter 'pBlockBinData' does not have the required minimum length.".format(f_bt=str(self.blockType), f_val=type(pBlockBinData)))
        self._records = dict(raw=None, lst=None)
        lPos  = 8
        while (lPos < (len(pBlockBinData) - 1)):
            lTag, lLen  = struct.unpack("{f_bo}HH".format(f_bo=self.blockByteOrder.value), pBlockBinData[lPos : (lPos + 4)])
            lPad        = ((4 - (lLen % 4)) & 0x3)
            lPos       += 4 + lLen + lPad
            if (lTag == NRBRecordType.END and lLen == 0): break
        self.recordsRaw = pBlockBinData[8:lPos]
        if (lPos < (len(pBlockBinData) - 4)):
            self.optionsRaw = pBlockBinData[lPos:-4]

    @property
    def rawData(self):
        return self._rawData({True:self.recordsRaw, False:bytes([])}[self.recordsRaw is not None] + {True:self.optionsRaw, False:bytes([])}[self.optionsRaw is not None])

    @property
    def records(self) -> list:
        # records = [ (recordcode1.1, recordvalueX), (recordcode1.2, recordvalueY), (recordcode2.1, recordvalueZ), ... ]
        return self._records["lst"]

    @records.setter
    def records(self, pValue) -> None:
        if (not isinstance(pValue, (list, type(None)))): raise PCAPNGException("Failed to set property 'records' of a {f_bt} object. The desired value of the property is not of type 'list' or 'NoneType'.".format(f_bt=self.blockType.name))
        if (self.blockByteOrder is None               ): raise PCAPNGException("Failed to set property 'records' of a {f_bt} object. The attribute 'blockByteOrder' is unknown.".format(f_bt=self.blockType.name))
        if (isinstance(pValue, list)):
            lErrors = self._recordListCheck(NRBRecordSpec, pValue)
            if (lErrors): raise PCAPNGException("Failed to set property 'records' of a {f_bt} object. The desired value of the property is incorrect. ({f_error})".format(f_bt=self.blockType.name, f_error="\n".join(lErrors)))
            self._records = dict(raw=self._recordListToRaw(NRBRecordSpec, pValue), lst=pValue)
        else:
            self._records = dict(raw=None, lst=None)

    @property
    def recordsRaw(self) -> bytearray:
        return self._records["raw"]

    @recordsRaw.setter
    def recordsRaw(self, pValue) -> None:
        if (not isinstance(pValue, (bytes, bytearray, type(None)))): raise PCAPNGException("Failed to set property 'recordsRaw' of a {f_bt} object. The desired value of the property is not of type 'bytes', 'bytearray' or 'NoneType'.".format(f_bt=self.blockType.name))
        if ((len(pValue) % 4) != 0                                ): raise PCAPNGException("Failed to set property 'recordsRaw' of a {f_bt} object. The length of the provided parameter 'pValue' is not a multiple of 4.".format(f_bt=self.blockType.name))
        if (self.blockByteOrder is None                           ): raise PCAPNGException("Failed to set property 'recordsRaw' of a {f_bt} object. The attribute 'blockByteOrder' is unknown.".format(f_bt=self.blockType.name))
        if (isinstance(pValue, (bytes, bytearray))):
            lRecords = self._recordRawToList(NRBRecordSpec, pValue)
            lErrors  = self._recordListCheck(NRBRecordSpec, lRecords)
            if (lErrors): raise PCAPNGException("Failed to set property 'recordsRaw' of a {f_bt} object. The desired value of the property is incorrect. ({f_error})".format(f_error="\n".join(lErrors)))
            self._records = dict(raw=pValue, lst=lRecords)
        else:
            self._records = dict(raw=None, lst=None)


class ISB(_GB):
    """
    @brief  PCAPNG Interface Statistics Block
    """

    def __init__(self, pFile=None, **kwargs):
        self._interfaceId = None
        self._timestamp   = None
        if (set(kwargs.keys()) == set(["pBlockByteOrder", "pBlockBinData"])): self.__init_isb_bin__(pFile, **kwargs)
        else                                                                : self.__init_isb_spc__(pFile, **kwargs)

    def __init_isb_spc__(self, pFile=None, pBlockByteOrder:BLKByteOrderType=BLKByteOrderType.NATIVE, pInterfaceId:int=int(1), pTimestamp:int=int(0), pOptions:list=None) -> None:
        """
        @brief  Creates a PCAPNG ISB block from specific data
        @param  pFile                  Name of the file this block is located in. This is only used for informational outputs.
        @param  pBlockByteOrder        Value of type 'BLKByteOrderType' that specifies the desired PCAPNG block byte order.
        @param  pInterfaceId           Value of type '(unsigned) int' that specifies the interface these statistics refers to; the correct interface will be the one whose Interface Description Block (within the current Section of the file) is identified by same number of this field.
        @param  pTimestamp             Value of type '(unsigned) int' that specifies the time this statistics refers to.
        @param  pOptions               List of tuples of option key/value pairs. E.g. [(pyPCAPNG.ISBOptionType.STARTTIME, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), (pyPCAPNG.ISBOptionType.ENDOFOPT, [])]
        """
        super().__init__(pFile=pFile, pBlockType=BLKType.ISB, pBlockByteOrder=pBlockByteOrder)
        self.interfaceId = pInterfaceId
        self.timestamp   = pTimestamp
        self.options     = pOptions

    def __init_isb_bin__(self, pFile=None, pBlockByteOrder:BLKByteOrderType=None, pBlockBinData:typing.Union[bytes, bytearray]=bytes([])) -> None:
        """
        @brief  Creates a PCAPNG ISB block from binary data
        @param  pFile            Name of the file this block is located in. This is only used for informational outputs.
        @param  pBlockByteOrder  Value of type 'BLKByteOrderType' that specifies the desired PCAPNG block byte order.
        @param  pBlockBinData    Value of type 'bytes' or 'bytearray' that specifies the exact binary data of the block.
        """
        super().__init__(pFile=pFile, pBlockType=BLKType.ISB, pBlockByteOrder=pBlockByteOrder, pBlockBinData=pBlockBinData)
        if (len(pBlockBinData) < 24): raise PCAPNGException("Failed to create a {f_bt} object. Parameter 'pBlockBinData' does not have the required minimum length.".format(f_bt=str(self.blockType), f_val=type(pBlockBinData)))
        self.interfaceId, lTimestampHi, lTimestampLo = struct.unpack("{f_bo}III".format(f_bo=pBlockByteOrder.value), pBlockBinData[8:20])
        self.timestamp  = (lTimestampHi < 32) | lTimestampLo
        if (20 < (len(pBlockBinData) - 4)):
            self.optionsRaw = pBlockBinData[20:-4]

    @property
    def rawData(self):
        return self._rawData(struct.pack("{f_bo}III".format(f_bo=self.blockByteOrder.value), self.interfaceId, ((int(self.timestamp) & 0xFFFFFFFF00000000) >> 32), (int(self.timestamp) & 0x00000000FFFFFFFF)) + {True:self.optionsRaw, False:bytes([])}[self.optionsRaw is not None])

    @property
    def interfaceId(self) -> int:
        return self._interfaceId

    @interfaceId.setter
    def interfaceId(self, value:int) -> None:
        if (not isinstance(value, int)  ): raise PCAPNGException("Failed to set property 'interfaceId' of a {f_bt} object. The desired value (== {f_val}) is not of type 'int'.".format(f_bt=self.blockType.name, f_val=value))
        if (not 0 <= value <= 0xFFFFFFFF): raise PCAPNGException("Failed to set property 'interfaceId' of a {f_bt} object. The desired value (== {f_val}) of the property is not in range '[0,(2^32)-1]'.".format(f_bt=self.blockType.name, f_val=value))
        self._interfaceId = value

    @property
    def timestamp(self) -> int:
        return self._timestamp

    @timestamp.setter
    def timestamp(self, value:int) -> None:
        if (not isinstance(value, int)          ): raise PCAPNGException("Failed to set property 'timestamp' of a {f_bt} object. The desired value (== {f_val}) is not of type 'int'.".format(f_bt=self.blockType.name, f_val=value))
        if (not 0 <= value <= 0xFFFFFFFFFFFFFFFF): raise PCAPNGException("Failed to set property 'timestamp' of a {f_bt} object. The desired value (== {f_val}) of the property is not in range '[0,(2^64)-1]'.".format(f_bt=self.blockType.name, f_val=value))
        self._timestamp = value


class DSB(_GB):
    """
    @brief  PCAPNG Decryption Secrets Block
    """

    def __init__(self, pFile=None, **kwargs):
        self._secretsType   = None
        self._secretsLength = None
        self._secretsData   = None
        if (set(kwargs.keys()) == set(["pBlockByteOrder", "pBlockBinData"])): self.__init_dsb_bin__(pFile, **kwargs)
        else                                                                : self.__init_dsb_spc__(pFile, **kwargs)

    def __init_dsb_spc__(self, pFile=None, pBlockByteOrder:BLKByteOrderType=BLKByteOrderType.NATIVE, pSecretsType:int=int(1), pSecretsLength:int=int(0), pSecretsData:typing.Union[bytes, bytearray]=bytes([]), pOptions:list=None) -> None:
        """
        @brief  Creates a PCAPNG DSB block from specific data
        @param  pFile                  Name of the file this block is located in. This is only used for informational outputs.
        @param  pBlockByteOrder        Value of type 'BLKByteOrderType' that specifies the desired PCAPNG block byte order.
        @param  pSecretsType           Value of type '(unsigned) int' that specifies the identifier that describes the format of the following Secrets data.
        @param  pSecretsLength         Value of type '(unsigned) int' that specifies the size of the following Secrets data, without any padding octets.
        @param  pSecretsData           Value of type 'bytes' or 'bytearray' that specifies payload of the block.
        @param  pOptions               List of tuples of option key/value pairs. E.g. [(pyPCAPNG.DSBOptionType.COMMENT, bytes("FooBar", encoding="utf-8")), (pyPCAPNG.DSBOptionType.ENDOFOPT, [])]
        """
        super().__init__(pFile=pFile, pBlockType=BLKType.DSB, pBlockByteOrder=pBlockByteOrder)
        self.secretsType   = pSecretsType
        self.secretsLength = pSecretsLength
        self.secretsData   = pSecretsData
        self.options       = pOptions

    def __init_dsb_bin__(self, pFile=None, pBlockByteOrder:BLKByteOrderType=None, pBlockBinData:typing.Union[bytes, bytearray]=bytes([])) -> None:
        """
        @brief  Creates a PCAPNG DSB block from binary data
        @param  pFile            Name of the file this block is located in. This is only used for informational outputs.
        @param  pBlockByteOrder  Value of type 'BLKByteOrderType' that specifies the desired PCAPNG block byte order.
        @param  pBlockBinData    Value of type 'bytes' or 'bytearray' that specifies the exact binary data of the block.
        """
        super().__init__(pFile=pFile, pBlockType=BLKType.DSB, pBlockByteOrder=pBlockByteOrder, pBlockBinData=pBlockBinData)
        if (len(pBlockBinData) < 20): raise PCAPNGException("Failed to create a {f_bt} object. Parameter 'pBlockBinData' does not have the required minimum length.".format(f_bt=str(self.blockType), f_val=type(pBlockBinData)))
        self.secretsType, self.secretsLength, = struct.unpack("{f_bo}II".format(f_bo=pBlockByteOrder.value), pBlockBinData[8:16])
        self.secretsData                      = pBlockBinData[16 : (16 + self.secretsLength)]
        if ((16 + self.secretsLength + 4 - (self.secretsLength % 4)) < (len(pBlockBinData) - 4)):
            self.optionsRaw = pBlockBinData[(16 + self.secretsLength + 4 - (self.secretsLength % 4)) : -4]

    @property
    def rawData(self):
        vPad = 4 - (len(self.secretsData) % 4)
        vPad = bytes([0 for x in range({True:vPad, False:0}[vPad < 4])])
        return self._rawData(struct.pack("{f_bo}II".format(f_bo=self.blockByteOrder.value), self.secretsType, self.secretsLength) + self.secretsData + vPad + {True:self.optionsRaw, False:bytes([])}[self.optionsRaw is not None])

    @property
    def secretsType(self) -> int:
        return self._secretsType

    @secretsType.setter
    def secretsType(self, value:int) -> None:
        if (not isinstance(value, int)  ): raise PCAPNGException("Failed to set property 'secretsType' of a {f_bt} object. The desired value (== {f_val}) is not of type 'int'.".format(f_bt=self.blockType.name, f_val=value))
        if (not 0 <= value <= 0xFFFFFFFF): raise PCAPNGException("Failed to set property 'secretsType' of a {f_bt} object. The desired value (== {f_val}) of the property is not in range '[0,(2^32)-1]'.".format(f_bt=self.blockType.name, f_val=value))
        self._secretsType = value

    @property
    def secretsLength(self) -> int:
        return self._secretsLength

    @secretsLength.setter
    def secretsLength(self, value:int) -> None:
        if (not isinstance(value, int)  ): raise PCAPNGException("Failed to set property 'secretsLength' of a {f_bt} object. The desired value (== {f_val}) is not of type 'int'.".format(f_bt=self.blockType.name, f_val=value))
        if (not 0 <= value <= 0xFFFFFFFF): raise PCAPNGException("Failed to set property 'secretsLength' of a {f_bt} object. The desired value (== {f_val}) of the property is not in range '[0,(2^32)-1]'.".format(f_bt=self.blockType.name, f_val=value))
        self._secretsLength = value

    @property
    def secretsData(self) -> bytes:
        return self._secretsData

    @secretsData.setter
    def secretsData(self, pValue:int) -> None:
        if (not isinstance(pValue, (bytes, bytearray))): raise PCAPNGException("Failed to set property 'secretsData' of a {f_bt} object. The desired value is not of type 'bytes' or 'bytearray'.".format(f_bt=self.blockType.name))
        self._secretsData = pValue


class CB0(_GB):
    """
    @brief  PCAPNG Custom Block, type 0x00000BAD
    """
    # https://www.iana.org/assignments/enterprise-numbers/

    def __init__(self, pFile=None, **kwargs):
        self._privateEnterpriseNumber = None
        self._packetData              = None
        if (set(kwargs.keys()) == set(["pBlockByteOrder", "pBlockBinData"])): self.__init_cb0_bin__(pFile, **kwargs)
        else                                                                : self.__init_cb0_spc__(pFile, **kwargs)

    def __init_cb0_spc__(self, pFile=None, pBlockByteOrder:BLKByteOrderType=BLKByteOrderType.NATIVE, pPrivateEnterpriseNumber:int=int(0), pPacketData:typing.Union[bytes, bytearray]=bytes([]), pOptions:list=None) -> None:
        """
        @brief  Creates a PCAPNG CB0 block from specific data
        @param  pFile                     Name of the file this block is located in. This is only used for informational outputs.
        @param  pBlockByteOrder           Value of type 'BLKByteOrderType' that specifies the desired PCAPNG block byte order.
        @param  pPrivateEnterpriseNumber  Value of type '(unsigned) int' that specifies the IANA-assigned Private Enterprise Number identifying the organization which defined the Custom Block.
        @param  pPacketData               Value of type 'bytes' or 'bytearray' that specifies payload of the block.
        @param  pOptions                  List of tuples of option key/value pairs. E.g. [(pyPCAPNG.CB0OptionType.COMMENT, bytes("FooBar", encoding="utf-8")), (pyPCAPNG.CB0OptionType.ENDOFOPT, [])]
        """
        super().__init__(pFile=pFile, pBlockType=BLKType.CB0, pBlockByteOrder=pBlockByteOrder)
        self.privateEnterpriseNumber = pPrivateEnterpriseNumber
        self.packetData              = pPacketData

    def __init_cb0_bin__(self, pFile=None, pBlockByteOrder:BLKByteOrderType=None, pBlockBinData:typing.Union[bytes, bytearray]=bytes([])) -> None:
        """
        @brief  Creates a PCAPNG CB0 block from binary data
        @param  pFile            Name of the file this block is located in. This is only used for informational outputs.
        @param  pBlockByteOrder  Value of type 'BLKByteOrderType' that specifies the desired PCAPNG block byte order.
        @param  pBlockBinData    Value of type 'bytes' or 'bytearray' that specifies the exact binary data of the block.
        """
        super().__init__(pFile=pFile, pBlockType=BLKType.CB0, pBlockByteOrder=pBlockByteOrder, pBlockBinData=pBlockBinData)
        if (len(pBlockBinData) < 16): raise PCAPNGException("Failed to create a {f_bt} object. Parameter 'pBlockBinData' does not have the required minimum length.".format(f_bt=str(self.blockType), f_val=type(pBlockBinData)))
        self.privateEnterpriseNumber = struct.unpack("{f_bo}I".format(f_bo=pBlockByteOrder.value), pBlockBinData[8:12])[0]
        self.packetData              = pBlockBinData[12:-4]

    @property
    def rawData(self):
        vPad = 4 - (len(self.packetData) % 4)
        vPad = bytes([0 for x in range({True:vPad, False:0}[vPad < 4])])
        return self._rawData(struct.pack("{f_bo}I".format(f_bo=self.blockByteOrder.value), self.privateEnterpriseNumber) + self.packetData + vPad + {True:self.optionsRaw, False:bytes([])}[self.optionsRaw is not None])

    @property
    def privateEnterpriseNumber(self) -> int:
        return self._privateEnterpriseNumber

    @privateEnterpriseNumber.setter
    def privateEnterpriseNumber(self, pValue:int) -> None:
        if (not isinstance(pValue, int)  ): raise PCAPNGException("Failed to set property 'privateEnterpriseNumber' of a {f_bt} object. The desired value (== {f_val}) is not of type 'int'.".format(f_bt=self.blockType.name, f_val=pValue))
        if (not 0 <= pValue <= 0xFFFFFFFF): raise PCAPNGException("Failed to set property 'privateEnterpriseNumber' of a {f_bt} object. The desired value (== {f_val}) of the property is not in range '[0,(2^32)-1]'.".format(f_bt=self.blockType.name, f_val=pValue))
        self._privateEnterpriseNumber = pValue


class CB1(_GB):
    """
    @brief  PCAPNG Custom Block, type 0x40000BAD
    """
    # https://www.iana.org/assignments/enterprise-numbers/

    def __init__(self, pFile=None, **kwargs):
        self._privateEnterpriseNumber = None
        self._packetData              = None
        if (set(kwargs.keys()) == set(["pBlockByteOrder", "pBlockBinData"])): self.__init_cb1_bin__(pFile, **kwargs)
        else                                                                : self.__init_cb1_spc__(pFile, **kwargs)

    def __init_cb1_spc__(self, pFile=None, pBlockByteOrder:BLKByteOrderType=BLKByteOrderType.NATIVE, pPrivateEnterpriseNumber:int=int(0), pPacketData:typing.Union[bytes, bytearray]=bytes([]), pOptions:list=None) -> None:
        """
        @brief  Creates a PCAPNG CB1 block from specific data
        @param  pFile                     Name of the file this block is located in. This is only used for informational outputs.
        @param  pBlockByteOrder           Value of type 'BLKByteOrderType' that specifies the desired PCAPNG block byte order.
        @param  pPrivateEnterpriseNumber  Value of type '(unsigned) int' that specifies the IANA-assigned Private Enterprise Number identifying the organization which defined the Custom Block.
        @param  pPacketData               Value of type 'bytes' or 'bytearray' that specifies payload of the block.
        @param  pOptions                  List of tuples of option key/value pairs. E.g. [(pyPCAPNG.CB1OptionType.COMMENT, bytes("FooBar", encoding="utf-8")), (pyPCAPNG.CB1OptionType.ENDOFOPT, [])]
        """
        super().__init__(pFile=pFile, pBlockType=BLKType.CB1, pBlockByteOrder=pBlockByteOrder)
        self.privateEnterpriseNumber = pPrivateEnterpriseNumber
        self.packetData              = pPacketData

    def __init_cb1_bin__(self, pFile=None, pBlockByteOrder:BLKByteOrderType=None, pBlockBinData:typing.Union[bytes, bytearray]=bytes([])) -> None:
        """
        @brief  Creates a PCAPNG CB1 block from binary data
        @param  pFile            Name of the file this block is located in. This is only used for informational outputs.
        @param  pBlockByteOrder  Value of type 'BLKByteOrderType' that specifies the desired PCAPNG block byte order.
        @param  pBlockBinData    Value of type 'bytes' or 'bytearray' that specifies the exact binary data of the block.
        """
        super().__init__(pFile=pFile, pBlockType=BLKType.CB1, pBlockByteOrder=pBlockByteOrder, pBlockBinData=pBlockBinData)
        if (len(pBlockBinData) < 16): raise PCAPNGException("Failed to create a {f_bt} object. Parameter 'pBlockBinData' does not have the required minimum length.".format(f_bt=str(self.blockType), f_val=type(pBlockBinData)))
        self.privateEnterpriseNumber = struct.unpack("{f_bo}I".format(f_bo=pBlockByteOrder.value), pBlockBinData[8:12])[0]
        self.packetData              = pBlockBinData[12:-4]

    @property
    def rawData(self):
        vPad = 4 - (len(self.packetData) % 4)
        vPad = bytes([0 for x in range({True:vPad, False:0}[vPad < 4])])
        return self._rawData(struct.pack("{f_bo}I".format(f_bo=self.blockByteOrder.value), self.privateEnterpriseNumber) + self.packetData + vPad + {True:self.optionsRaw, False:bytes([])}[self.optionsRaw is not None])

    @property
    def privateEnterpriseNumber(self) -> int:
        return self._privateEnterpriseNumber

    @privateEnterpriseNumber.setter
    def privateEnterpriseNumber(self, pValue:int) -> None:
        if (not isinstance(pValue, int)  ): raise PCAPNGException("Failed to set property 'privateEnterpriseNumber' of a {f_bt} object. The desired value (== {f_val}) is not of type 'int'.".format(f_bt=self.blockType.name, f_val=pValue))
        if (not 0 <= pValue <= 0xFFFFFFFF): raise PCAPNGException("Failed to set property 'privateEnterpriseNumber' of a {f_bt} object. The desired value (== {f_val}) of the property is not in range '[0,(2^32)-1]'.".format(f_bt=self.blockType.name, f_val=pValue))
        self._privateEnterpriseNumber = pValue


####################################################################################################


class PCAPNGWriter(object):
    """
    @brief  Class for creating PCAPNG capture files
    """

    def __init__(self, pPcap:str, pMode:str="w", pBo:BLKByteOrderType=BLKByteOrderType.NATIVE, pAF:int=None) -> None:
        """
        @brief  Creates a PCAPNGWriter instance
        @param  pPcap  Name of the PCAPNG file that shall be used to store data.
        @param  pMode  Optional string that specifies the mode in which the file 'pPcap' is opened.
                       - 'w' .. open for writing a new file (DEFAULT)
                       - 'a' .. open for appending to an existing file
        @param  pBo    Optional string that specifies the endianness that shall be used for PCAPNG
                       block parameters.
        @param  pAF    Automatically flush at each 'pAF'th added block.
        """
        if (not isinstance(pPcap, str)                   ): raise PCAPNGException("Parameter 'pPcap' is not of type 'str'.")
        if (not isinstance(pMode, str)                   ): raise PCAPNGException("Parameter 'pMode' is not of type 'str'.")
        if (pMode not in ["w", "a"]                      ): raise PCAPNGException("Parameter 'pMode' is not in range [w, a].")
        if (not isinstance(pBo, BLKByteOrderType)        ): raise PCAPNGException("Parameter 'pBo' is not of type 'BLKByteOrderType'.")
        if (not isinstance(pAF, tuple([int, type(None)]))): raise PCAPNGException("Parameter 'pAF' is not of type 'int' or 'None'.")
        self._file  = pPcap
        self._pcap  = open(pPcap, "{f_mode}b".format(f_mode=pMode))
        self._bo    = pBo
        self._blks  = []
        self._idbs  = []
        self._af    = pAF
        self._afcnt = 0

    def __del__(self) -> None:
        if (    (hasattr(self, '_pcap'))
            and (self._pcap is not None)
           ):
            self.flush()
            self._pcap.close()

    def __autoflush(self):
        self._afcnt += 1
        if (    (self._af is not None   )
            and (self._af == self._afcnt)
           ):
            self.flush()
            self._afcnt = 0

    def flush(self) -> None:
        while self._blks:
            self._pcap.write(self._blks.pop(0).rawData)
        self._blks.clear()

    def open(self) -> bool:
        vResult = False
        if (self._pcap is None):
            self._pcap = open(pPcap, "{f_mode}b".format(f_mode=pMode))
            vResult = True
        return vResult

    def close(self) -> None:
        vResult = False
        if (self._pcap is not None):
            self.flush()
            self._pcap.close()
            vResult = True
        return vResult

    def addSHB(self, pMajorVersion:int=None, pMinorVersion:int=None, pOptions:list=None) -> None:
        """
        @brief  Add a 'Section Header Block' (SHB) to a PCAPNG file
        @param  pMajorVersion  Optional integer that specifies the desired PCAPNG format major version
                               number to be used in the section. (DEFAULT == 1)
        @param  pMinorVersion  Optional integer that specifies the desired PCAPNG format minor version
                               number to be used in the section. (DEFAULT == 0)
        @param  pOptions       Optional list of block parameters. E.g. '[(pyPCAPNG.SHBOptionType.HARDWARE, bytes("Z80", encoding="utf-8")), (pyPCAPNG.SHBOptionType.COMMENT, bytes("Comment 1", encoding="utf-8")), (pyPCAPNG.SHBOptionType.COMMENT, bytes("Comment 2", encoding="utf-8")), (pyPCAPNG.SHBOptionType.ENDOFOPT, [])]'.
        """
        if (self._pcap is None                                                                            ): raise PCAPNGException("No file.")
        if (not isinstance(pMajorVersion, tuple([int, type(None)]))                                       ): raise PCAPNGException("Parameter 'pMajorVersion' is not of type 'int' or 'None'.")
        if (    isinstance(pMajorVersion, int)                      and (not 1 <= pMajorVersion <= 0xFFFF)): raise PCAPNGException("Parameter 'pMajorVersion' is not in range '1 <= x <= 0xFFFF'.")
        if (not isinstance(pMinorVersion, tuple([int, type(None)]))                                       ): raise PCAPNGException("Parameter 'pMinorVersion' is not of type 'int' or 'None'.")
        if (    isinstance(pMinorVersion, int)                      and (not 0 <= pMinorVersion <= 0xFFFF)): raise PCAPNGException("Parameter 'pMinorVersion' is not in range '1 <= x <= 0xFFFF'.")
        vBlk = SHB(pBlockByteOrder=self._bo,
                   pMajorVersion={True:int(1), False:pMajorVersion}[pMajorVersion is None],
                   pMinorVersion={True:int(0), False:pMinorVersion}[pMinorVersion is None],
                   pSectionLength=int(0xFFFFFFFFFFFFFFFF),
                   pOptions=pOptions
                  )
        self._idbs = []
        self._blks.append(vBlk)
        self.__autoflush()
        return vBlk

    def addIDB(self, pLinkType:int=None, pSnapLen:int=None, pOptions:list=None) -> None:
        """
        @brief  Add a 'Interface Description Block' (IDB) to a PCAPNG file
        @param  pLinkType  Optional unsigned value that defines the link layer type of this interface.
                           The list of Standardized Link Layer Type codes is available in
                           [https://www.tcpdump.org/linktypes.html].
        @param  pSnapLen   Optional unsigned value indicating the maximum number of octets captured
                           from each packet. The portion of each packet that exceeds this value
                           will not be stored in the file. A value of zero indicates no limit.
        @param  pOptions   Optional list of block parameters. E.g. '[(pyPCAPNG.IDBOptionType.NAME, bytes("LAN1", encoding="utf-8")), (pyPCAPNG.IDBOptionType.IPV4ADDR, [0xC0, 0xA8, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0x00]), (pyPCAPNG.IDBOptionType.COMMENT, bytes("Comment 2", encoding="utf-8")), (pyPCAPNG.IDBOptionType.ENDOFOPT, [])]'.
        """
        if (self._pcap is None                                                                       ): raise PCAPNGException("No file.")
        if (not isinstance(pLinkType, tuple([int, type(None)]))                                      ): raise PCAPNGException("Parameter 'pLinkType' is not of type 'int'.")
        if (    isinstance(pLinkType, int)                      and (not 0 <= pLinkType < 0xFFFF)    ): raise PCAPNGException("Parameter 'pLinkType' is notin range '[0,(2^16)-1]'.")
        if (not isinstance(pSnapLen,  tuple([int, type(None)]))                                      ): raise PCAPNGException("Parameter 'pSnapLen' is not of type 'int'.")
        if (    isinstance(pSnapLen,  int)                      and (not 0 <= pSnapLen  < 0xFFFFFFFF)): raise PCAPNGException("Parameter 'pSnapLen' is notin range '[0,(2^32)-1]'.")
        vBlk = IDB(pBlockByteOrder = self._bo,
                   pLinkType       = {True:int(0), False:pLinkType}[pLinkType is None],
                   pSnapLen        = {True:int(0), False:pSnapLen }[pSnapLen  is None],
                   pOptions        = pOptions
                  )
        self._idbs.append(vBlk)
        self._blks.append(vBlk)
        self.__autoflush()
        return vBlk

    def addEPB(self, pPacketData:bytes, pInterfaceId:int=None, pTimestamp:int=None, pOriginalPacketLength:int=None, pCapturedPacketLength:int=None, pOptions:list=None) -> None:
        """
        @brief  Add a 'Enhanced Package Block' (EPB) to a PCAPNG file
        @param  pPacketData            The payload of the block.
        @param  pInterfaceId           Optional unsigned value that defines the interface on which this packet was received or transmitted.
        @param  pTimestamp             Optional unsigned value that defines the number of units of time that have elapsed since 1970-01-01 00:00:00 UTC.
        @param  pOriginalPacketLength  Optional unsigned value that defines the actual length of the packet when it was transmitted on the network. It can be different from the Captured Packet Length if the packet has been truncated by the capture process.
        @param  pCapturedPacketLength  Optional unsigned value that defines the number of octets captured from the packet (i.e. the length of the Packet Data field). It will be the minimum value among the Original Packet Length and the snapshot length for the interface (SnapLen, defined in Figure 10). The value of this field does not include the padding octets added at the end of the Packet Data field to align the Packet Data field to a 32-bit boundary.
        @param  pOptions               Optional list of block parameters. E.g. '[(pyPCAPNG.EPBOptionType.PACKETID, [0xC0, 0xA8, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0x00]), (pyPCAPNG.EPBOptionType.ENDOFOPT, [])]'.
        """
        if (self._pcap is None                                                                                               ): raise PCAPNGException("No file.")
        if (not isinstance(pInterfaceId,          tuple([int, type(None)]))                                                  ): raise PCAPNGException("Parameter 'pInterfaceId' is not of type 'int' or 'None'.")
        if (    isinstance(pInterfaceId,          int)                      and (not 0 <= pInterfaceId < len(self._idbs))    ): raise PCAPNGException("Parameter 'pInterfaceId' is not in range '[0,{f_nrOfIDBs}]'.".format(f_nrOfIDBs=len(self._idbs) - 1))
        if (not isinstance(pTimestamp,            tuple([int, type(None)]))                                                  ): raise PCAPNGException("Parameter 'pTimestamp' is not of type 'int' or 'None'.")
        if (    isinstance(pTimestamp,            int)                      and (not 0 <= pTimestamp < 0xFFFFFFFFFFFFFFFF)   ): raise PCAPNGException("Parameter 'pTimestamp' is not in range '[0,(2^64)-1]'.")
        if (not isinstance(pCapturedPacketLength, tuple([int, type(None)]))                                                  ): raise PCAPNGException("Parameter 'pCapturedPacketLength' is not of type 'int' or 'None'.")
        if (    isinstance(pCapturedPacketLength, int)                      and (not 0 <= pCapturedPacketLength < 0xFFFFFFFF)): raise PCAPNGException("Parameter 'pCapturedPacketLength' is not in range '[0,(2^32)-1]'.")
        if (not isinstance(pOriginalPacketLength, tuple([int, type(None)]))                                                  ): raise PCAPNGException("Parameter 'pOriginalPacketLength' is not of type 'int' or 'None'.")
        if (    isinstance(pOriginalPacketLength, int)                      and (not 0 <= pOriginalPacketLength < 0xFFFFFFFF)): raise PCAPNGException("Parameter 'pOriginalPacketLength' is not in range '[0,(2^32)-1]'.")
        if (not isinstance(pPacketData,           bytes)                                                                     ): raise PCAPNGException("Parameter 'pPacketData' is not of type 'bytes'.")
        if (    isinstance(pPacketData,           bytes)                    and (not 0 <= len(pPacketData)      < 0xFFFFFFFF)): raise PCAPNGException("Parameter 'pPacketData' is not of length '[0,(2^32)-1]'.")
        vBlk = EPB(pBlockByteOrder       = self._bo,
                   pInterfaceId          = {True:int(0),                False:pInterfaceId         }[pInterfaceId          is None],
                   pTimestamp            = {True:int(0),                False:pTimestamp           }[pTimestamp            is None],
                   pCapturedPacketLength = {True:int(len(pPacketData)), False:pCapturedPacketLength}[pCapturedPacketLength is None],
                   pOriginalPacketLength = {True:int(len(pPacketData)), False:pOriginalPacketLength}[pOriginalPacketLength is None],
                   pPacketData           = pPacketData,
                   pOptions              = pOptions
                  )
        self._blks.append(vBlk)
        self.__autoflush()
        return vBlk

    def addSPB(self, pPacketData:bytes, pOriginalPacketLength:int=None) -> None:
        """
        @brief  Add a 'Simple Package Block' (SPB) to a PCAPNG file
        @param  pPacketData            The payload of the block.
        @param  pOriginalPacketLength  Optional unsigned value that defines the actual length of the packet when it was transmitted on the network. It can be different from the Captured Packet Length if the packet has been truncated by the capture process.
        """
        if (self._pcap is None                                                                                               ): raise PCAPNGException("No file.")
        if (not isinstance(pOriginalPacketLength, tuple([int, type(None)]))                                                  ): raise PCAPNGException("Parameter 'pOriginalPacketLength' is not of type 'int' or 'None'.")
        if (    isinstance(pOriginalPacketLength, int)                      and (not 0 <= pCapturedPacketLength < 0xFFFFFFFF)): raise PCAPNGException("Parameter 'pOriginalPacketLength' is not in range '[0,(2^32)-1]'.")
        if (not isinstance(pPacketData,           bytes)                                                                     ): raise PCAPNGException("Parameter 'pPacketData' is not of type 'bytes'.")
        if (    isinstance(pPacketData,           bytes)                    and (not 0 <= len(pPacketData)      < 0xFFFFFFFF)): raise PCAPNGException("Parameter 'pPacketData' is not of length '[0,(2^32)-1]'.")
        vBlk = SPB(pBlockByteOrder       = self._bo,
                   pOriginalPacketLength = {True:len(pPacketData), False:pOriginalPacketLength}[pOriginalPacketLength is None],
                   pPacketData           = pPacketData
                  )
        self._blks.append(vBlk)
        self.__autoflush()
        return vBlk

    def addNRB(self, pRecords:list=None, pOptions:list=None) -> None:
        """
        @brief  Add a 'Name Resolution Block' (NRB) to a PCAPNG file
        @param  pRecords  The list of block records. E.g. '[(pyPCAPNG.NRBRecordType.IPV4, bytes([0xC0, 0xA8, 0x00, 0x01])+bytes("entries\0", encoding="utf-8")), (pyPCAPNG.NRBRecordType.END, [])]'.
        @param  pOptions  Optional list of block parameters. E.g. '[(pyPCAPNG.NRBOptionType.DNSIP4ADDR, [0xC0, 0xA8, 0x00, 0x01]), (pyPCAPNG.NRBOptionType.ENDOFOPT, [])]'.
        """
        if (self._pcap is None                                                                ): raise PCAPNGException("No file.")
        if (not isinstance(pRecords, list)                                                    ): raise PCAPNGException("Parameter 'pRecords' is not of type 'list'.")
        if (    isinstance(pRecords, list) and (len(pRecords) == 0)                           ): raise PCAPNGException("Parameter 'pRecords' is not of length '>= 1'.")
        if (    isinstance(pRecords, list) and (pRecords[-1]  != (NRBRecordType.END, []))     ): raise PCAPNGException("Parameter 'pRecords' does not end with entry '(NRBRecordType.END, [])'.")
        if (    isinstance(pRecords, list) and (pRecords.count((NRBRecordType.END, [])) != 1 )): raise PCAPNGException("Parameter 'pRecords' contains entry '(NRBRecordType.END, [])' not exactly one time.")
        vBlk = NRB(pBlockByteOrder = self._bo,
                   pRecords        = pRecords,
                   pOptions        = pOptions
                  )
        self._blks.append(vBlk)
        self.__autoflush()
        return vBlk

    def addISB(self, pInterfaceId:int=None, pTimestamp:int=None, pOptions:list=None) -> None:
        """
        @brief  Add a 'Interface Statistics Block' (ISB) to a PCAPNG file
        @param  pInterfaceId  Optional unsigned value that defines the interface these statistics refers to; the correct interface will be the one whose Interface Description Block (within the current Section of the file) is identified by same number of this field.
        @param  pTimestamp    Optional unsigned value that defines the time this statistics refers to.
        @param  pOptions      Optional list of block parameters. E.g. '[(pyPCAPNG.ISBOptionType.STARTTIME, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), (pyPCAPNG.ISBOptionType.ENDOFOPT, [])]'.
        """
        if (self._pcap is None                                                                                   ): raise PCAPNGException("No file.")
        if (not isinstance(pInterfaceId, tuple([int, type(None)]))                                               ): raise PCAPNGException("Parameter 'pInterfaceId' is not of type 'int' or 'None'")
        if (    isinstance(pInterfaceId, int)                     and (not 0 <= pInterfaceId < len(self._idbs))  ): raise PCAPNGException("Parameter 'pInterfaceId' is not in range '[0,{f_nrOfIDBs}]'.".format(f_nrOfIDBs=len(self._idbs) - 1))
        if (not isinstance(pTimestamp,   tuple([int, type(None)]))                                               ): raise PCAPNGException("Parameter 'pTimestamp' is not of type 'int' or 'None'.")
        if (    isinstance(pTimestamp,   int)                      and (not 0 <= pTimestamp < 0xFFFFFFFFFFFFFFFF)): raise PCAPNGException("Parameter 'pTimestamp' is not in range '[0,(2^64)-1]'.")
        vBlk = ISB(pBlockByteOrder = self._bo,
                   pInterfaceId    = {True:int(0), False:pInterfaceId}[pInterfaceId is None],
                   pTimestamp      = {True:int(0), False:pTimestamp  }[pTimestamp   is None],
                   pOptions        = pOptions
                  )
        self._blks.append(vBlk)
        self.__autoflush()
        return vBlk

    def addDSB(self, pSecretsData:bytes, pSecretsType:int=None, pSecretsLength:int=None, pOptions:list=None) -> None:
        """
        @brief  Add a 'Decryption Secrets Block' (DSB) to a PCAPNG file
        @param  pSecretsData    The payload of the block.
        @param  pSecretsType    Optional unsigned value that defines the identifier that describes the format of the following Secrets data.
        @param  pSecretsLength  Optional unsigned value that defines the size of the following Secrets data, without any padding octets.
        @param  pOptions        Optional list of block parameters. E.g. '[(DSBOptionType.COMMENT, bytes("FooBar", encoding="utf-8")), (DSBOptionType.ENDOFOPT, [])]'.
        """
        if (self._pcap is None                                                                                     ): raise PCAPNGException("No file.")
        if (not isinstance(pSecretsType,   tuple([int, type(None)]))                                               ): raise PCAPNGException("Parameter 'pSecretsType' is not of type 'int' or 'None'.")
        if (    isinstance(pSecretsLength, int)                      and (not 0 <=     pSecretsType   < 0xFFFFFFFF)): raise PCAPNGException("Parameter 'pSecretsType' is not in range '[0,(2^32)-1]'.")
        if (not isinstance(pSecretsLength, tuple([int, type(None)]))                                               ): raise PCAPNGException("Parameter 'pSecretsLength' is not of type 'int' or 'None'.")
        if (    isinstance(pSecretsLength, int)                      and (not 0 <=     pSecretsLength < 0xFFFFFFFF)): raise PCAPNGException("Parameter 'pSecretsType' is not in range '[0,(2^32)-1]'.")
        if (not isinstance(pSecretsData,   bytes)                                                                  ): raise PCAPNGException("Parameter 'pSecretsData' is not of type 'bytes'.")
        if (    isinstance(pSecretsData,   bytes)                    and (not 0 <= len(pSecretsData)  < 0xFFFFFFFF)): raise PCAPNGException("Parameter 'pSecretsData' is not of length '[0,(2^32)-1]'.")
        vBlk = DSB(pBlockByteOrder = self._bo,
                   pSecretsType    = {True:int(0),            False:pSecretsType  }[pSecretsType   is None],
                   pSecretsLength  = {True:len(pSecretsData), False:pSecretsLength}[pSecretsLength is None],
                   pSecretsData    = pSecretsData,
                   pOptions        = pOptions
                  )
        self._blks.append(vBlk)
        self.__autoflush()
        return vBlk

    def addCB0(self, pPacketData:bytes, pPrivateEnterpriseNumber:int=None, pOptions:list=None) -> None:
        """
        @brief  Add a 'Decryption Secrets Block' (CB0) to a PCAPNG file
        @param  pPacketData               The payload of the block.
        @param  pPrivateEnterpriseNumber  Optional unsigned value that defines the IANA-assigned Private Enterprise Number identifying the organization which defined the Custom Block.
        @param  pOptions                  Optional list of block parameters. E.g. '[(CB0OptionType.COMMENT, bytes("FooBar", encoding="utf-8")), (CB0OptionType.ENDOFOPT, [])]'.
        """
        if (self._pcap is None                                                                                                     ): raise PCAPNGException("No file.")
        if (not isinstance(pPrivateEnterpriseNumber, tuple([int, type(None)]))                                                     ): raise PCAPNGException("Parameter 'pPrivateEnterpriseNumber' is not of type 'int' or 'None'.")
        if (    isinstance(pPrivateEnterpriseNumber, int)                      and (not 0 <= pPrivateEnterpriseNumber < 0xFFFFFFFF)): raise PCAPNGException("Parameter 'pPrivateEnterpriseNumber' is not in range '[0,(2^32)-1]'.")
        if (not isinstance(pPacketData,              bytes)                                                                        ): raise PCAPNGException("Parameter 'pPacketData' is not of type 'bytes'.")
        if (    isinstance(pPacketData,              bytes)                    and (not 0 <= len(pPacketData)         < 0xFFFFFFFF)): raise PCAPNGException("Parameter 'pPacketData' is not of length '[0,(2^32)-1]'.")
        vBlk = CB0(pBlockByteOrder          = self._bo,
                   pPrivateEnterpriseNumber = {True:int(0), False:pPrivateEnterpriseNumber}[pPrivateEnterpriseNumber is None],
                   pPacketData              = pPacketData,
                   pOptions                 = pOptions
                  )
        self._blks.append(vBlk)
        self.__autoflush()
        return vBlk

    def addCB1(self, pPacketData:bytes, pPrivateEnterpriseNumber:int=int(1), pOptions:list=None) -> None:
        """
        @brief  Add a 'Decryption Secrets Block' (CB0) to a PCAPNG file
        @param  pPacketData               The payload of the block.
        @param  pPrivateEnterpriseNumber  Optional unsigned value that defines the IANA-assigned Private Enterprise Number identifying the organization which defined the Custom Block.
        @param  pOptions                  Optional list of block parameters. E.g. '[(CB1OptionType.COMMENT, bytes("FooBar", encoding="utf-8")), (CB1OptionType.ENDOFOPT, [])]'.
        """
        if (self._pcap is None                                                                                                     ): raise PCAPNGException("No file.")
        if (not isinstance(pPrivateEnterpriseNumber, tuple([int, type(None)]))                                                     ): raise PCAPNGException("Parameter 'pPrivateEnterpriseNumber' is not of type 'int' or 'None'.")
        if (    isinstance(pPrivateEnterpriseNumber, int)                      and (not 0 <= pPrivateEnterpriseNumber < 0xFFFFFFFF)): raise PCAPNGException("Parameter 'pPrivateEnterpriseNumber' is not in range '[0,(2^32)-1]'.")
        if (not isinstance(pPacketData,              bytes)                                                                        ): raise PCAPNGException("Parameter 'pPacketData' is not of type 'bytes'.")
        if (    isinstance(pPacketData,              bytes)                    and (not 0 <= len(pPacketData)         < 0xFFFFFFFF)): raise PCAPNGException("Parameter 'pPacketData' is not of length '[0,(2^32)-1]'.")
        vBlk = CB1(pBlockByteOrder          = self._bo,
                   pPrivateEnterpriseNumber = {True:int(0), False:pPrivateEnterpriseNumber}[pPrivateEnterpriseNumber is None],
                   pPacketData              = pPacketData,
                   pOptions                 = pOptions
                  )
        self._blks.append(vBlk)
        self.__autoflush()
        return vBlk

    def getInterfaceId(self, pIDB):
        """
        @brief  Returns the InterfaceId of a given IDB.
        @param  pIDB  The IDB the Interface shall be returned for.
        """
        if (not isinstance(pIDB, IDB)): raise PCAPNGException("Parameter 'pIDB' is not of type 'IDB'")
        return self._idbs.index(pIDB)

    @property
    def file(self):
        return self._file


class PCAPNGReader(object):
    """
    @brief  Class for reading PCAPNG capture files
    """

    def __init__(self, pPcap:str, pBufSize:int=8) -> None:
        """
        @brief  Creates a PCAPNGReader instance
        @param  pPcap     Name of the PCAPNG file that shall be read.
        @param  pBufSize  Internal buffer size in 'MB' to be used for reading the specified PCAPNG file.
        """
        if (not isinstance(pPcap, str)    ): raise PCAPNGException("Parameter 'pPcap' is not of type 'str'.")
        if (not os.path.exists(pPcap)     ): raise PCAPNGException("Parameter 'pPcap' is not an existiting file system object.")
        if (not os.path.isfile(pPcap)     ): raise PCAPNGException("Parameter 'pPcap' is not a file.")
        if (not isinstance(pBufSize, int) ): raise PCAPNGException("Parameter 'pBufSize' is not of type 'int'.")
        if (pBufSize < 1                  ): raise PCAPNGException("Parameter 'pBufSize' is not '>= 1'.")

        self._pcapFile = pPcap
        self._pcapHndl = open(pPcap, "rb", buffering=(pBufSize * 1048576))
        self._pcapSize = None
        self._shb      = []

        self._pcapHndl.seek(0, io.SEEK_END)
        self._pcapSize = self._pcapHndl.tell()
        self._pcapHndl.seek(0, io.SEEK_SET)

    def __del__(self) -> None:
        if (    (hasattr(self, '_pcap')    )
            and (self._pcapHndl is not None)
           ):
            self._pcapHndl.close()

    def __iter__(self):
        self._pcapHndl.seek(0, io.SEEK_SET)
        return self

    def __next__(self):
        lRslt           = None
        lBlockMap       = {BLKType.SHB: SHB,
                           BLKType.IDB: IDB,
                           BLKType.EPB: EPB,
                           BLKType.SPB: SPB,
                           BLKType.NRB: NRB,
                           BLKType.ISB: ISB,
                           BLKType.DSB: DSB,
                           BLKType.CB0: CB0,
                           BLKType.CB1: CB1,
                          }
        lBlockData      = None
        lBlockType      = None
        lBlockLength    = None
        lBlockByteOrder = BLKByteOrderType.NATIVE
        if ((self._pcapHndl.tell() + 12) <= self._pcapSize):
            lBlockData = self._pcapHndl.peek(12)[:12]
            lBlockType = struct.unpack("@I", lBlockData[0:4])[0]
            if (lBlockType == BLKType.SHB):
                lBlockByteOrder = struct.unpack("@I", lBlockData[8:12])[0]
                if   (lBlockByteOrder == 0x1A2B3C4D): lBlockByteOrder = BLKByteOrderType.LITTLE
                elif (lBlockByteOrder == 0x4D3C2B1A): lBlockByteOrder = BLKByteOrderType.BIG
                else                                : raise StopIteration("Failed to create a SHB object from binary data. The 'Byte-Order Magic' element is wrong.")
            elif (    (lBlockType != BLKType.SHB)
                  and (self._shb                )
                 ):
                lBlockByteOrder = self._shb[-1].blockByteOrder
                lBlockType      = struct.unpack("{f_bo}I".format(f_bo=lBlockByteOrder.value), lBlockData[0:4])[0]
            lBlockLength = struct.unpack("{f_bo}I".format(f_bo=lBlockByteOrder.value), lBlockData[4:8])[0]
            try:
                if   (lBlockMap[lBlockType] is not None): lRslt = lBlockMap[lBlockType](pFile=self._pcapFile, pBlockByteOrder=lBlockByteOrder, pBlockBinData=self._pcapHndl.read(lBlockLength))
                else                                    : self._pcapHndl.read(4)
                if   (isinstance(lRslt, SHB)           ): self._shb.append(lRslt)
            except KeyError:
                self._pcapHndl.read(4)
            except PCAPNGException as e:
                print("PCAPNGException", e)
                raise StopIteration(e)
        else:
            raise StopIteration
        return lRslt


####################################################################################################


if ( __name__ == '__main__' ):

    import re
    import time

    try:
        import pycodestyle
        STYLECHECK = True
    except:
        STYLECHECK = False

    # ----------------------------------------------------------------------------------------------
    print("\n\033[1;38;2;0;128;255m" + "#"*128 + "\n# PCAPNG WRITE TEST\n" + "#"*128 + "\033[0m\n")
    vTimestamp = time.time_ns()
    vTgtBlks   = []
    vPcapNgHdl = PCAPNGWriter("writer_test.pcapng", pMode="w")
    vTgtBlks.append(vPcapNgHdl.addSHB(pMajorVersion=1, pMinorVersion=0))
    Ifc1 = vPcapNgHdl.addIDB(pLinkType=1, pSnapLen=0, pOptions=[(IDBOptionType.TSRESOL, [9]), (IDBOptionType.NAME, bytes("LAN1", encoding="utf-8")), (IDBOptionType.IPV4ADDR, [0xC0, 0xA8, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0x00]), (IDBOptionType.ENDOFOPT, [])])
    Ifc2 = vPcapNgHdl.addIDB(pLinkType=1, pSnapLen=0)
    vTgtBlks.append(Ifc1)
    vTgtBlks.append(Ifc2)
    for i in range(4):
        vTgtBlks.append(vPcapNgHdl.addSPB(pPacketData=IPv4(pData=bytes([i for x in range(i + 1)])).eth))
    for i in range(16):
        if ((i % 2) == 0): vTgtBlks.append(vPcapNgHdl.addEPB(pInterfaceId=vPcapNgHdl.getInterfaceId(Ifc1), pPacketData=IPv4(pData=bytes([i + 1 for x in range(i + 1)])).eth, pTimestamp=int(vTimestamp + (i * 1E9)), pOptions=[(EPBOptionType.PACKETID, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, i]), (EPBOptionType.ENDOFOPT, [])]))
        else             : vTgtBlks.append(vPcapNgHdl.addEPB(pInterfaceId=vPcapNgHdl.getInterfaceId(Ifc2), pPacketData=bytes([i + 1 for x in range(i + 1)]),                 pTimestamp=int(vTimestamp + (i * 1E9))))
    vTgtBlks.append(vPcapNgHdl.addNRB(pRecords=[(NRBRecordType.IPV4, bytes([0xC0, 0xA8, 0x00, 0x01]) + bytes("entries\0", encoding="utf-8")), (NRBRecordType.END, [])], pOptions=[(NRBOptionType.DNSIP4ADDR, [0xC0, 0xA8, 0x00, 0x01]), (NRBOptionType.ENDOFOPT, [])]))
    vTgtBlks.append(vPcapNgHdl.addNRB(pRecords=[(NRBRecordType.IPV4, bytes([0xC0, 0xA8, 0x00, 0x01]) + bytes("entries\0", encoding="utf-8")), (NRBRecordType.END, [])]))
    vTgtBlks.append(vPcapNgHdl.addISB(pInterfaceId=vPcapNgHdl.getInterfaceId(Ifc1), pTimestamp=int(vTimestamp), pOptions=[(ISBOptionType.STARTTIME, struct.pack("II", ((vTimestamp & 0xFFFFFFFF00000000) >> 32), (vTimestamp & 0x00000000FFFFFFFF))), (ISBOptionType.ENDOFOPT, [])]))
    vTgtBlks.append(vPcapNgHdl.addISB(pInterfaceId=vPcapNgHdl.getInterfaceId(Ifc2), pTimestamp=int(vTimestamp)))
    vTgtBlks.append(vPcapNgHdl.addDSB(pSecretsData=bytes([0xAF, 0xFE]), pSecretsType=int(0x544C534B), pOptions=[(DSBOptionType.COMMENT, bytes("FooBar", encoding="utf-8")), (DSBOptionType.ENDOFOPT, [])]))
    vTgtBlks.append(vPcapNgHdl.addDSB(pSecretsData=bytes([0xCA, 0xFE]), pSecretsType=int(0x57474B4C)))
    vTgtBlks.append(vPcapNgHdl.addCB0(pPrivateEnterpriseNumber=int( 128), pPacketData=bytes([0xAF, 0xFE]), pOptions=[(CB0OptionType.COMMENT, bytes("FooBar", encoding="utf-8")), (CB0OptionType.ENDOFOPT, [])]))
    vTgtBlks.append(vPcapNgHdl.addCB0(pPrivateEnterpriseNumber=int( 256), pPacketData=bytes([0xCA, 0xFE])))
    vTgtBlks.append(vPcapNgHdl.addCB1(pPrivateEnterpriseNumber=int( 512), pPacketData=bytes([0xAF, 0xFE]), pOptions=[(CB1OptionType.COMMENT, bytes("FooBar", encoding="utf-8")), (CB1OptionType.ENDOFOPT, [])]))
    vTgtBlks.append(vPcapNgHdl.addCB1(pPrivateEnterpriseNumber=int(1024), pPacketData=bytes([0xCA, 0xFE])))
    del (vPcapNgHdl)

    # ----------------------------------------------------------------------------------------------
    print("\n\033[1;38;2;0;128;255m" + "#"*128 + "\n# PCAPNG READ TEST\n" + "#"*128 + "\033[0m")
    print()
    vActBlks = PCAPNGReader("writer_test.pcapng")
    for i,(vActBlk, vTgtBlk) in enumerate(zip(vActBlks,vTgtBlks)):
        if   (vActBlk.blockType      != vTgtBlk.blockType     ): print("\033[1;38;2;255;0;0mERROR  : type       {:<23s} of {:>2d}. actual block != target block type       {:<23s}\033[0m".format(str(vActBlk.blockType),      i, str(vTgtBlk.blockType)    ))
        elif (vActBlk.blockByteOrder != vTgtBlk.blockByteOrder): print("\033[1;38;2;255;0;0mERROR  : byte order {:<23s} of {:>2d}. actual block != target block byte order {:<23s}\033[0m".format(str(vActBlk.blockByteOrder), i, str(vTgtBlk.blockByteOrder)))

    # ----------------------------------------------------------------------------------------------
    print("\n\033[1;38;2;0;128;255m" + "#"*128 + "\n# PCAPNG READ TEST (ENHANCED)\n" + "#"*128 + "\033[0m")
    for vRoot, vDirs, vFiles in os.walk("./test/pcapng-test-generator"):
        for vFile in vFiles:
            vFile = os.path.abspath(os.path.join(vRoot, vFile))
            if vFile.endswith(".pcapng"):
                vFilePcapNg = vFile
                vFileTxt    = os.path.splitext(vFile)[0] + ".txt"
                print("\n" + "-"*128 + "\n>>> " + vFilePcapNg)
                vTgtDefByteOrder = None
                if   (os.sep + "output_be" + os.sep in vFilePcapNg): vTgtDefByteOrder = BLKByteOrderType.BIG
                elif (os.sep + "output_le" + os.sep in vFilePcapNg): vTgtDefByteOrder = BLKByteOrderType.LITTLE
                with open(vFileTxt) as vFhdl: vTgtBlks = [BLKType[{"CB":"CB0", "DCB":"CB1"}[vBlkTyp.strip()]] if vBlkTyp.strip() in ["CB", "DCB"] else BLKType[vBlkTyp.strip()] for vBlkTyp in re.match(r"Block sequence:\s*(?P<mBlkSeq>.*)", [vLine for vLine in vFhdl.readlines() if vLine != []][-1]).group("mBlkSeq").split(",")]
                vActBlks         = PCAPNGReader(vFile)
                vTgtBlkByteOrder = None
                for i,(vActBlk, vTgtBlkType) in enumerate(zip(vActBlks,vTgtBlks)):
                    if (vActBlk.blockType == BLKType.SHB):
                        vTgtBlkByteOrder = vActBlk.blockByteOrder
                        if (vTgtDefByteOrder != vTgtBlkByteOrder): print("\033[1;38;2;255;128;0mWARNING: byte order {:<23s} of {:>2d}. actual block (SHB) != block byte order specified by folder structure\033[0m".format(str(vActBlk.blockByteOrder), i))
                    if   (vActBlk.blockType      != vTgtBlkType     ): print("\033[1;38;2;255;0;0mERROR  : type       {:<23s} of {:>2d}. actual block != target block type       {:<23s}\033[0m".format(str(vActBlk.blockType),      i, str(vTgtBlkType)     ))
                    elif (vActBlk.blockByteOrder != vTgtBlkByteOrder): print("\033[1;38;2;255;0;0mERROR  : byte order {:<23s} of {:>2d}. actual block != target block byte order {:<23s}\033[0m".format(str(vActBlk.blockByteOrder), i, str(vTgtBlkByteOrder)))

    # ----------------------------------------------------------------------------------------------
    if (STYLECHECK is True):
        print("\n\033[1;38;2;0;128;255m" + "#"*128 + "\n# STYLE CHECK\n" + "#"*128 + "\033[0m\n")
        # https://pycodestyle.pycqa.org/en/latest/intro.html#error-codes

        class TestReport(pycodestyle.StandardReport):
            def get_file_results(self):
                vResult = ""
                self._deferred_print.sort()
                for line_number, offset, code, text, doc in self._deferred_print:
                    vResult += self._fmt % {'path': self.filename,
                                            'row': self.line_offset + line_number, 'col': offset + 1,
                                            'code': code, 'text': text,
                                        } + "\n"

                    if self._show_source:
                        if line_number > len(self.lines):
                            line = ''
                        else:
                            line = self.lines[line_number - 1]
                        vResult += line.rstrip()
                        vResult += "\n" + re.sub(r'\S', ' ', line[:offset]) + '^\n\n'
                    if self._show_pep8 and doc:
                        vResult += '    ' + doc.strip()
                return vResult

        vStyleCheckFile = os.path.abspath(__file__)+".stylecheck"
        vStyleCheckHndl = pycodestyle.StyleGuide(indent_size=4, statistics=True, show_source=True, ignore=["E501"], reporter=TestReport, quiet=True)
        vStyleCheckHndl.check_files([os.path.abspath(__file__)])
        with open(vStyleCheckFile, "w", encoding="utf-8", newline="\n") as vFhdl:
            vFhdl.write(vStyleCheckHndl.options.report.get_file_results())
        print("\n".join(vStyleCheckHndl.options.report.get_statistics()))
        print("\nDetails can be found in {}".format(vStyleCheckFile))

    # ----------------------------------------------------------------------------------------------
    print("\n\033[1;38;2;0;128;255m" + "#"*128 + "\n# PCAPNG TESTS DONE\n" + "#"*128 + "\033[0m\n")

