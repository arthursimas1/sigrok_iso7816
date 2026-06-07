import sigrokdecode as srd
import struct
from typing import Optional, Tuple, List, Any

class PCAPWriter:
    @staticmethod
    def write_global_header(decoder: 'Decoder') -> None:
        # 1 = DLT_EN10MB (Ethernet)
        pcap_global = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        decoder.put(0, 0, decoder.out_pcap, [0, pcap_global])

    @staticmethod
    def write_packet(decoder: 'Decoder', data: bytes, start_samplenum: int) -> None:
        time_s = start_samplenum / decoder.samplerate
        ts_sec = int(time_s)
        ts_usec = int((time_s - ts_sec) * 1000000)

        # GSMTAP Header (16 bytes)
        gsmtap_hdr = struct.pack('>BBBBHbbIBBBB', 2, 4, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        gsmtap_payload = gsmtap_hdr + bytes(data)

        # UDP Header (8 bytes)
        udp_len = 8 + len(gsmtap_payload)
        udp_hdr = struct.pack('>HHHH', 4729, 4729, udp_len, 0)

        # IPv4 Header (20 bytes)
        ip_len = 20 + udp_len
        ip_hdr_no_csum = struct.pack('>BBHHHBBHII', 0x45, 0, ip_len, 0, 0x4000, 64, 17, 0, 0x7F000001, 0x7F000001)

        # Calculate IP checksum
        s = sum(struct.unpack('>10H', ip_hdr_no_csum))
        s = (s >> 16) + (s & 0xffff)
        s += (s >> 16)
        csum = (~s) & 0xffff

        ip_hdr = struct.pack('>BBHHHBBHII', 0x45, 0, ip_len, 0, 0x4000, 64, 17, csum, 0x7F000001, 0x7F000001)

        # Ethernet Header (14 bytes)
        eth_hdr = struct.pack('>6s6sH', b'\x00'*6, b'\x00'*6, 0x0800)

        packet = eth_hdr + ip_hdr + udp_hdr + gsmtap_payload
        header = struct.pack('<IIII', ts_sec, ts_usec, len(packet), len(packet))

        decoder.put(start_samplenum, decoder.samplenum, decoder.out_pcap, [0, header + packet])


class PhysicalLayer:
    def __init__(self, decoder: 'Decoder') -> None:
        self.d = decoder
        self.etu = 0

    def put_ann(self, ss: int, es: int, ann_class: int, text: List[str]) -> None:
        self.d.put(ss, es, self.d.out_ann, [ann_class, text])

    def read_byte_raw(self, already_at_end_of_start_bit: bool = False) -> Tuple[List[int], int, int, int]:
        if not already_at_end_of_start_bit:
            while True:
                pins = self.d.wait([{1: 'f'}, {0: 'f'}])
                if self.d.matched[1]: return None
                if self.d.matched[0]: break
            self.d.ss_byte = self.d.samplenum

            pins = self.d.wait({'skip': self.etu // 2})
            if pins[1] != 0:
                self.put_ann(self.d.samplenum - (self.etu // 2), self.d.samplenum + (self.etu // 2), 2, ['Invalid Start Bit'])
            self.put_ann(self.d.samplenum - (self.etu // 2), self.d.samplenum + (self.etu // 2), 0, ['S'])

            pins = self.d.wait({'skip': self.etu})
        else:
            self.put_ann(self.d.ss_byte, self.d.ss_byte + self.etu, 0, ['S'])
            pins = self.d.wait({'skip': self.etu // 2})

        bits = []
        for i in range(8):
            bits.append(pins[1])
            self.put_ann(self.d.samplenum - (self.etu // 2), self.d.samplenum + (self.etu // 2), 0, ['%d' % pins[1]])
            pins = self.d.wait({'skip': self.etu})

        parity = pins[1]
        self.put_ann(self.d.samplenum - (self.etu // 2), self.d.samplenum + (self.etu // 2), 0, ['P:%d' % parity])

        pins = self.d.wait({'skip': self.etu})
        if pins[1] != 1:
            self.put_ann(self.d.samplenum - (self.etu // 2), self.d.samplenum + (self.etu // 2), 2, ['Invalid Stop Bit'])
        self.put_ann(self.d.samplenum - (self.etu // 2), self.d.samplenum + (self.etu // 2), 0, ['T'])

        return bits, parity, self.d.ss_byte, self.d.samplenum + (self.etu // 2)

    def bits_to_byte(self, bits: List[int]) -> int:
        val = 0
        if self.d.convention == 'inverse':
            for i in range(8):
                logic_bit = 1 - bits[i]
                val |= (logic_bit << (7 - i))
        else:
            for i in range(8):
                val |= (bits[i] << i)
        return val

    def read_byte(self) -> Optional[Tuple[int, int, int]]:
        res = self.read_byte_raw()
        if res is None: return None
        bits, parity, ss, es = res
        val = self.bits_to_byte(bits)
        
        if self.d.convention == 'inverse':
            expected_parity = 1 - (sum(bits) % 2)
        else:
            expected_parity = sum(bits) % 2

        if parity != expected_parity:
            parity_es = es - self.etu
            parity_ss = parity_es - self.etu
            self.put_ann(parity_ss, parity_es, 2, ['Invalid Parity Bit'])

        self.put_ann(ss, es, 1, ['%02X' % val])
        return val, ss, es

    def safe_read(self) -> Optional[Tuple[int, int, int]]:
        res = self.read_byte()
        if res is not None:
            self.d.last_es = res[2]
        return res
    def wait_for_falling_io(self) -> bool:
        self.d.wait([{1: 'f'}, {0: 'f'}])
        return not self.d.matched[1]

    def wait_for_rising_io(self) -> bool:
        self.d.wait([{1: 'r'}, {0: 'f'}])
        return not self.d.matched[1]


class ProtocolLayer:
    F_TABLE = {
        0: 372, 1: 372, 2: 558, 3: 744, 4: 1116, 5: 1488, 6: 1860,
        9: 512, 10: 768, 11: 1024, 12: 1536, 13: 2048
    }
    D_TABLE = {
        1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 7: 64, 8: 12, 9: 20
    }

    def __init__(self, decoder: 'Decoder') -> None:
        self.d = decoder
        self.phy = PhysicalLayer(decoder)
        self.initial_etu = 0
        self.ts_val = 0
        self.atr_bytes = []
        self.atr_ss_start = 0
        self.protocol = 0
        self.t1_crc = False

    def put_ann(self, ss: int, es: int, ann_class: int, text: List[str]) -> None:
        self.d.put(ss, es, self.d.out_ann, [ann_class, text])

    def parse_atr(self) -> bool:
        if not self.phy.wait_for_falling_io():
            return False
        self.d.ss_byte = self.d.samplenum

        if not self.phy.wait_for_rising_io():
            return False

        self.phy.etu = self.d.samplenum - self.d.ss_byte
        self.initial_etu = self.phy.etu

        res = self.phy.read_byte_raw(already_at_end_of_start_bit=True)
        if res is None: return False

        bits = res[0]
        if bits == [1, 1, 0, 1, 1, 1, 0, 0]:
            self.d.convention = 'direct'
            self.ts_val = 0x3B
        elif bits == [1, 1, 0, 0, 0, 0, 0, 0]:
            self.d.convention = 'inverse'
            self.ts_val = 0x3F
        else:
            self.d.convention = 'direct'
            self.ts_val = self.phy.bits_to_byte(bits)
            self.put_ann(res[2], res[3], 2, ['Invalid TS'])

        self.put_ann(res[2], res[3], 1, ['%02X' % self.ts_val])
        self.put_ann(res[2], res[3], 3, ['TS: %02X' % self.ts_val])

        self.atr_bytes = []
        self.atr_ss_start = self.d.ss_byte
        self.d.last_es = self.d.samplenum

        res = self.phy.safe_read()
        if res is None:
            self.put_ann(self.atr_ss_start, self.d.last_es, 7, ['ATR (Aborted)', 'ATR(A)'])
            return False
        t0, ss, es = res
        self.put_ann(ss, es, 3, ['T0: %02X' % t0])
        self.atr_bytes.append(t0)

        y = t0 >> 4
        k = t0 & 0x0F

        t_protocol = 0
        tck_present = False
        t_current = 0
        self.t1_crc = False

        ta1_val = None
        ta2_present = False

        for i in range(1, 15):
            if y == 0: break
            if y & 1:
                res = self.phy.safe_read()
                if res is None:
                    self.put_ann(self.atr_ss_start, self.d.last_es, 7, ['ATR (Aborted)', 'ATR(A)'])
                    return False
                if i == 1: ta1_val = res[0]
                self.put_ann(res[1], res[2], 3, ['TA%d: %02X' % (i, res[0])])
                self.atr_bytes.append(res[0])
            if y & 2:
                res = self.phy.safe_read()
                if res is None:
                    self.put_ann(self.atr_ss_start, self.d.last_es, 7, ['ATR (Aborted)', 'ATR(A)'])
                    return False
                if i == 2: ta2_present = True
                self.put_ann(res[1], res[2], 3, ['TB%d: %02X' % (i, res[0])])
                self.atr_bytes.append(res[0])
            if y & 4:
                res = self.phy.safe_read()
                if res is None:
                    self.put_ann(self.atr_ss_start, self.d.last_es, 7, ['ATR (Aborted)', 'ATR(A)'])
                    return False
                tc = res[0]
                self.put_ann(res[1], res[2], 3, ['TC%d: %02X' % (i, tc)])
                self.atr_bytes.append(tc)
                if t_current == 1: self.t1_crc = (tc & 1) == 1
            if y & 8:
                res = self.phy.safe_read()
                if res is None:
                    self.put_ann(self.atr_ss_start, self.d.last_es, 7, ['ATR (Aborted)', 'ATR(A)'])
                    return False
                td = res[0]
                self.put_ann(res[1], res[2], 3, ['TD%d: %02X' % (i, td)])
                self.atr_bytes.append(td)
                y = td >> 4
                t_current = td & 0x0F
                if i == 1: t_protocol = t_current
                if t_current > 0: tck_present = True
            else:
                y = 0

        for i in range(k):
            res = self.phy.safe_read()
            if res is None:
                self.put_ann(self.atr_ss_start, self.d.last_es, 7, ['ATR (Aborted)', 'ATR(A)'])
                return False
            self.put_ann(res[1], res[2], 3, ['Hist: %02X' % res[0]])
            self.atr_bytes.append(res[0])

        if tck_present:
            res = self.phy.safe_read()
            if res is None:
                self.put_ann(self.atr_ss_start, self.d.last_es, 7, ['ATR (Aborted)', 'ATR(A)'])
                return False
            self.put_ann(res[1], res[2], 3, ['TCK: %02X' % res[0]])
            self.atr_bytes.append(res[0])

        self.put_ann(self.atr_ss_start, self.d.last_es, 7, ['ATR'])
        self.protocol = t_protocol

        if ta2_present and ta1_val is not None:
            fi = ta1_val >> 4
            di = ta1_val & 0x0F
            if fi in self.F_TABLE and di in self.D_TABLE:
                f = self.F_TABLE[fi]
                d = self.D_TABLE[di]
                self.phy.etu = int(self.initial_etu * (f / d) / 372.0)

        return True

    def decode_command(self) -> bool:
        res = self.phy.safe_read()
        if res is None:
            return False

        val, ss, es = res
        if val == 0xFF:
            return self.decode_pps(val, ss, es)
        else:
            if self.protocol == 0:
                return self.decode_t0(val, ss, es)
            else:
                return self.decode_t1(val, ss, es)

    def decode_pps(self, ppss_val: int, ss: int, es: int) -> bool:
        self.d.last_es = es
        self.put_ann(ss, es, 4, ['PPSS: %02X' % ppss_val])
        ss_pps_start = ss

        # Reader Request
        res = self.phy.safe_read()
        if res is None:
            self.put_ann(ss_pps_start, self.d.last_es, 8, ['PPS Request (Aborted)', 'PPS_REQ(A)'])
            return False
        pps0 = res[0]
        self.put_ann(res[1], res[2], 4, ['PPS0: %02X' % pps0])

        has_pps1 = (pps0 & 0x10) != 0
        has_pps2 = (pps0 & 0x20) != 0
        has_pps3 = (pps0 & 0x40) != 0

        pps1_req = None

        if has_pps1:
            res = self.phy.safe_read()
            if res is None:
                self.put_ann(ss_pps_start, self.d.last_es, 8, ['PPS Request (Aborted)', 'PPS_REQ(A)'])
                return False
            pps1_req = res[0]
            self.put_ann(res[1], res[2], 4, ['PPS1: %02X' % res[0]])
        if has_pps2:
            res = self.phy.safe_read()
            if res is None:
                self.put_ann(ss_pps_start, self.d.last_es, 8, ['PPS Request (Aborted)', 'PPS_REQ(A)'])
                return False
            self.put_ann(res[1], res[2], 4, ['PPS2: %02X' % res[0]])
        if has_pps3:
            res = self.phy.safe_read()
            if res is None:
                self.put_ann(ss_pps_start, self.d.last_es, 8, ['PPS Request (Aborted)', 'PPS_REQ(A)'])
                return False
            self.put_ann(res[1], res[2], 4, ['PPS3: %02X' % res[0]])

        res = self.phy.safe_read()
        if res is None:
            self.put_ann(ss_pps_start, self.d.last_es, 8, ['PPS Request (Aborted)', 'PPS_REQ(A)'])
            return False
        self.put_ann(res[1], res[2], 4, ['PCK: %02X' % res[0]])

        self.put_ann(ss_pps_start, self.d.last_es, 8, ['PPS Request', 'PPS_REQ'])

        # Card Response
        res = self.phy.safe_read()
        if res is None:
            self.put_ann(ss_pps_start, self.d.last_es, 8, ['PPS (No Response)', 'PPS_NO_RSP'])
            return False

        ss_resp_start = res[1]
        self.put_ann(res[1], res[2], 4, ['PPSS: %02X' % res[0]])

        res = self.phy.safe_read()
        if res is None:
            self.put_ann(ss_resp_start, self.d.last_es, 8, ['PPS Response (Aborted)', 'PPS_RSP(A)'])
            return False
        pps0 = res[0]
        self.put_ann(res[1], res[2], 4, ['PPS0: %02X' % pps0])

        has_pps1_r = (pps0 & 0x10) != 0
        has_pps2_r = (pps0 & 0x20) != 0
        has_pps3_r = (pps0 & 0x40) != 0

        pps1_resp = None

        if has_pps1_r:
            res = self.phy.safe_read()
            if res is None:
                self.put_ann(ss_resp_start, self.d.last_es, 8, ['PPS Response (Aborted)', 'PPS_RSP(A)'])
                return False
            pps1_resp = res[0]
            self.put_ann(res[1], res[2], 4, ['PPS1: %02X' % res[0]])
        if has_pps2_r:
            res = self.phy.safe_read()
            if res is None:
                self.put_ann(ss_resp_start, self.d.last_es, 8, ['PPS Response (Aborted)', 'PPS_RSP(A)'])
                return False
            self.put_ann(res[1], res[2], 4, ['PPS2: %02X' % res[0]])
        if has_pps3_r:
            res = self.phy.safe_read()
            if res is None:
                self.put_ann(ss_resp_start, self.d.last_es, 8, ['PPS Response (Aborted)', 'PPS_RSP(A)'])
                return False
            self.put_ann(res[1], res[2], 4, ['PPS3: %02X' % res[0]])

        res = self.phy.safe_read()
        if res is None:
            self.put_ann(ss_resp_start, self.d.last_es, 8, ['PPS Response (Aborted)', 'PPS_RSP(A)'])
            return False
        self.put_ann(res[1], res[2], 4, ['PCK: %02X' % res[0]])

        self.put_ann(ss_resp_start, self.d.last_es, 8, ['PPS Response', 'PPS_RSP'])

        if pps1_req is not None and pps1_req == pps1_resp:
            fi = pps1_resp >> 4
            di = pps1_resp & 0x0F
            if fi in self.F_TABLE and di in self.D_TABLE:
                f = self.F_TABLE[fi]
                d = self.D_TABLE[di]
                self.phy.etu = int(self.initial_etu * (f / d) / 372.0)

        return True

    def decode_t0(self, first_val: int, first_ss: int, first_es: int) -> bool:
        apdu_bytes = [first_val]
        ss_apdu_start = first_ss
        self.d.last_es = first_es

        self.put_ann(first_ss, first_es, 5, ['CLA: %02X' % first_val])

        labels = ['INS', 'P1', 'P2', 'Lc/Le']
        for i in range(4):
            res = self.phy.safe_read()
            if res is None:
                self.put_ann(ss_apdu_start, self.d.last_es, 9, ['T=0 APDU (Aborted)', 'APDU(A)'])
                return False
            val, ss, es = res
            apdu_bytes.append(val)
            self.put_ann(ss, es, 5, ['%s: %02X' % (labels[i], val)])

        cla, ins, p1, p2, p3 = apdu_bytes
        data_len = p3 if p3 != 0 else 256
        data_read = 0

        while True:
            res = self.phy.safe_read()
            if res is None:
                self.put_ann(ss_apdu_start, self.d.last_es, 9, ['T=0 APDU (Aborted)', 'APDU(A)'])
                return False
            pb, ss, es = res

            if pb == 0x60:
                self.put_ann(ss, es, 5, ['NULL'])
            elif (pb & 0xF0) in (0x60, 0x90) and pb not in (0x60, ins, ins ^ 0xFF):
                sw1 = pb
                apdu_bytes.append(sw1)
                self.put_ann(ss, es, 5, ['SW1: %02X' % sw1])
                res = self.phy.safe_read()
                if res is None:
                    self.put_ann(ss_apdu_start, self.d.last_es, 9, ['T=0 APDU (Aborted)', 'APDU(A)'])
                    return False
                sw2, ss2, es2 = res
                apdu_bytes.append(sw2)
                self.put_ann(ss2, es2, 5, ['SW2: %02X' % sw2])
                break
            elif pb == ins:
                self.put_ann(ss, es, 5, ['ACK'])
                for i in range(data_len - data_read):
                    res = self.phy.safe_read()
                    if res is None:
                        self.put_ann(ss_apdu_start, self.d.last_es, 9, ['T=0 APDU (Aborted)', 'APDU(A)'])
                        return False
                    val, s3, e3 = res
                    apdu_bytes.append(val)
                    self.put_ann(s3, e3, 5, ['Data: %02X' % val])
                data_read = data_len
            elif pb == (ins ^ 0xFF):
                self.put_ann(ss, es, 5, ['ACK^FF'])
                res = self.phy.safe_read()
                if res is None:
                    self.put_ann(ss_apdu_start, self.d.last_es, 9, ['T=0 APDU (Aborted)', 'APDU(A)'])
                    return False
                val, s3, e3 = res
                apdu_bytes.append(val)
                self.put_ann(s3, e3, 5, ['Data: %02X' % val])
                data_read += 1
            else:
                self.put_ann(ss, es, 2, ['Unknown PB: %02X' % pb])
                break

        self.put_ann(ss_apdu_start, self.d.last_es, 9, ['T=0 APDU', 'APDU'])
        PCAPWriter.write_packet(self.d, bytes(apdu_bytes), ss_apdu_start)
        return True

    def decode_t1(self, first_val: int, first_ss: int, first_es: int) -> bool:
        block_bytes = [first_val]
        ss_block_start = first_ss
        self.d.last_es = first_es

        self.put_ann(first_ss, first_es, 6, ['NAD: %02X' % first_val])

        res = self.phy.safe_read()
        if res is None:
            self.put_ann(ss_block_start, self.d.last_es, 10, ['T=1 Block (Aborted)', 'Block(A)'])
            return False
        pcb, ss, es = res
        block_bytes.append(pcb)
        self.put_ann(ss, es, 6, ['PCB: %02X' % pcb])

        res = self.phy.safe_read()
        if res is None:
            self.put_ann(ss_block_start, self.d.last_es, 10, ['T=1 Block (Aborted)', 'Block(A)'])
            return False
        length, ss, es = res
        block_bytes.append(length)
        self.put_ann(ss, es, 6, ['LEN: %02X' % length])

        for i in range(length):
            res = self.phy.safe_read()
            if res is None:
                self.put_ann(ss_block_start, self.d.last_es, 10, ['T=1 Block (Aborted)', 'Block(A)'])
                return False
            val, ss, es = res
            block_bytes.append(val)
            self.put_ann(ss, es, 6, ['INF: %02X' % val])

        edc_len = 2 if self.t1_crc else 1
        for i in range(edc_len):
            res = self.phy.safe_read()
            if res is None:
                self.put_ann(ss_block_start, self.d.last_es, 10, ['T=1 Block (Aborted)', 'Block(A)'])
                return False
            val, ss, es = res
            block_bytes.append(val)
            self.put_ann(ss, es, 6, ['EDC: %02X' % val])

        self.put_ann(ss_block_start, self.d.last_es, 10, ['T=1 Block', 'Block'])
        PCAPWriter.write_packet(self.d, bytes(block_bytes), ss_block_start)
        return True


class Decoder(srd.Decoder):
    api_version = 3
    id = 'arthur_iso7816'
    name = 'ISO 7816'
    longname = 'ISO 7816 Smart Card'
    desc = 'ISO 7816 Smart Card protocol decoder'
    license = 'mit'
    inputs = ['logic']
    outputs = ['iso7816', 'pcap']
    tags = ['Smart Card']

    channels = (
        {'id': 'reset', 'name': 'RESET', 'desc': 'Reset'},
        {'id': 'io', 'name': 'I/O', 'desc': 'Data I/O'},
    )

    annotations = (
        ('bit', 'Bit'),
        ('byte', 'Byte'),
        ('warning', 'Warning'),
        ('atr-field', 'ATR Field'),
        ('pps-field', 'PPS Field'),
        ('t0-field', 'T=0 Field'),
        ('t1-field', 'T=1 Field'),
        ('atr', 'ATR'),
        ('pps', 'PPS'),
        ('t0-apdu', 'T=0 APDU'),
        ('t1-block', 'T=1 Block'),
    )

    annotation_rows = (
        ('bits', 'Bits', (0,)),
        ('bytes', 'Bytes', (1,)),
        ('fields', 'Fields', (3, 4, 5, 6)),
        ('groups', 'Groups', (7, 8, 9, 10)),
        ('warnings', 'Warnings', (2,)),
    )

    binary = (
        ('pcap', 'PCAP extraction'),
    )

    def __init__(self) -> None:
        self.reset()
        self.samplerate = 1

    def metadata(self, key: int, value: Any) -> None:
        if key == srd.SRD_CONF_SAMPLERATE:
            self.samplerate = value

    def reset(self) -> None:
        self.state = 'WAIT_RESET'
        self.convention = None
        self.last_es = 0

        self.proto = ProtocolLayer(self)

    def start(self) -> None:
        self.out_ann = self.register(srd.OUTPUT_ANN)
        self.out_pcap = self.register(srd.OUTPUT_BINARY)
        PCAPWriter.write_global_header(self)

    def decode(self) -> None:
        while True:
            if self.state == 'WAIT_RESET':
                pins = self.wait({'skip': 0})
                if pins[0] == 0:
                    self.wait([{0: 'r'}])
                self.state = 'DECODE_ATR'

            elif self.state == 'DECODE_ATR':
                if not self.proto.parse_atr():
                    self.reset()
                else:
                    self.state = 'WAIT_COMMAND'

            elif self.state == 'WAIT_COMMAND':
                if not self.proto.decode_command():
                    self.reset()
