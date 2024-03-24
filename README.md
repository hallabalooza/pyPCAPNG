# pyPCAPNG

## Abstract

pyPCAPNG is a Python 3 implementation of the PCAP Next Generation Capture File Format.

It is based on https://ietf-opsawg-wg.github.io/draft-ietf-opsawg-pcap/draft-ietf-opsawg-pcapng.html.

## Example

Read a PCAPNG file

```python
import pyPCAPNG
vPCAPNGReader = pyPCAPNG.PCAPNGReader("writer_test.pcapng")
for i,vBlk in enumerate(vPCAPNGReader):
    print(str(vBlk.blockType))
```

Write a PCAPNG file

```python
import pyPCAPNG
vPCAPNGWriter = pyPCAPNG.PCAPNGWriter("writer_test.pcapng", pMode="w")
vPCAPNGWriter.addSHB(pMajorVersion=1, pMinorVersion=0)
vPCAPNGWriter.addIDB(pLinkType=pyPCAPNG.LINKType.RESERVED_01, pSnapLen=0, pOptions=[(pyPCAPNG.IDBOptionType.TSRESOL, [9]), (pyPCAPNG.IDBOptionType.ENDOFOPT, [])])
vPCAPNGWriter.addSPB(pPacketData=bytes([0xDE, 0xAD]))
vPCAPNGWriter.addEPB(pPacketData=bytes([0xBE, 0xEF]), pTimestamp=time.time_ns())
```