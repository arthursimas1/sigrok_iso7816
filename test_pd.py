import sys
import unittest
from unittest.mock import MagicMock

# --- Mock sigrokdecode ---
srd = MagicMock()
srd.SRD_CONF_SAMPLERATE = 'samplerate'
srd.OUTPUT_ANN = 0
srd.OUTPUT_BINARY = 1
srd.Decoder = object
sys.modules['sigrokdecode'] = srd

from pd import Decoder, PCAPWriter

# --- E2E Test Framework ---
class ISO7816Stream:
    def __init__(self, etu=100):
        self.etu = etu
        self.events = []
        self.time = 0
        self.events.append((0, 0, 1)) # RESET=1
        self.events.append((0, 1, 1)) # IO=1

    def add_delay(self, etus):
        self.time += int(etus * self.etu)

    def add_reset(self, val):
        self.events.append((self.time, 0, val))

    def add_bit(self, val, *, etus=1):
        self.events.append((self.time, 1, val))
        self.time += self.etu * etus

    def add_byte(self, val, *, convention='direct'):
        self.add_bit(0) # Start

        bits = []
        if convention == 'direct':
            for i in range(8): bits.append((val >> i) & 1)
        else:
            for i in range(8): bits.append(1 - ((val >> (7-i)) & 1))

        for b in bits:
            self.add_bit(b)

        parity = sum(bits) % 2
        if convention == 'inverse':
            parity = 1 - parity

        self.add_bit(parity)

        self.add_bit(1, etus=2) # Stop

    def finish(self):
        self.events.sort(key=lambda x: x[0])


class MockSigrokDecoder:
    def __init__(self, decoder, stream: ISO7816Stream):
        self.d = decoder
        self.stream = stream
        self.stream.finish()
        self.d.samplenum = 0
        self.d.matched = [False, False]
        self.pins = [1, 1]

    def wait(self, conds):
        self._update_pins()
        if isinstance(conds, dict) and 'skip' in conds:
            self.d.samplenum += conds['skip']
            self._update_pins()
            return self.pins

        elif isinstance(conds, list):
            for event in self.stream.events:
                t, ch, val = event
                if t <= self.d.samplenum: continue

                matched_idx = -1
                for idx, c in enumerate(conds):
                    if 'skip' in c:
                        if t >= self.d.samplenum + c['skip']:
                            self.d.samplenum += c['skip']
                            self._update_pins()
                            self.d.matched = [False] * len(conds)
                            self.d.matched[idx] = True
                            return self.pins
                        continue

                    for cond_ch, cond_val in c.items():
                        if cond_ch == ch:
                            if (cond_val == 'f' and val == 0) or (cond_val == 'r' and val == 1):
                                matched_idx = idx
                                break
                    if matched_idx != -1: break

                if matched_idx != -1:
                    self.d.samplenum = t
                    self._update_pins()
                    self.d.matched = [False] * len(conds)
                    self.d.matched[matched_idx] = True
                    return self.pins
            raise StopIteration("Stream ended")

    def _update_pins(self):
        for event in self.stream.events:
            t, ch, val = event
            if t <= self.d.samplenum:
                self.pins[ch] = val

# --- Tests ---
class TestPCAPWriter(unittest.TestCase):
    def setUp(self):
        self.decoder = Decoder()
        self.decoder.put = MagicMock()
        self.decoder.metadata(srd.SRD_CONF_SAMPLERATE, 1000000)
        self.decoder.out_pcap = srd.OUTPUT_BINARY
        self.decoder.samplenum = 1500

    def test_write_global_header(self):
        PCAPWriter.write_global_header(self.decoder)
        self.decoder.put.assert_called_once()

    def test_write_packet(self):
        PCAPWriter.write_packet(self.decoder, b'\x00\x01', 1000)
        self.decoder.put.assert_called_once()


class TestPhysicalLayerE2E(unittest.TestCase):
    def setUp(self):
        self.decoder = Decoder()
        self.decoder.put = MagicMock()
        self.decoder.out_ann = srd.OUTPUT_ANN
        self.decoder.out_pcap = srd.OUTPUT_BINARY

    def test_read_byte_raw_direct(self):
        stream = ISO7816Stream(100)
        stream.add_delay(5)
        stream.add_byte(0x3B, convention='direct')
        mock_srd = MockSigrokDecoder(self.decoder, stream)
        self.decoder.wait = mock_srd.wait

        self.decoder.proto.phy.etu = 100
        bits, parity, ss, es = self.decoder.proto.phy.read_byte_raw(already_at_end_of_start_bit=False)
        self.assertEqual(bits, [1, 1, 0, 1, 1, 1, 0, 0])
        self.assertEqual(parity, 1)

    def test_read_byte_raw_inverse(self):
        stream = ISO7816Stream(100)
        stream.add_delay(5)
        stream.add_byte(0x3F, convention='inverse')
        mock_srd = MockSigrokDecoder(self.decoder, stream)
        self.decoder.wait = mock_srd.wait

        self.decoder.proto.phy.etu = 100
        bits, parity, ss, es = self.decoder.proto.phy.read_byte_raw(already_at_end_of_start_bit=False)
        self.assertEqual(bits, [1, 1, 0, 0, 0, 0, 0, 0])
        self.assertEqual(parity, 1)

    def test_wait_for_falling_io(self):
        stream = ISO7816Stream(100)
        stream.add_delay(5)
        stream.add_byte(0xFF) # Starts with falling edge
        mock_srd = MockSigrokDecoder(self.decoder, stream)
        self.decoder.wait = mock_srd.wait

        self.assertTrue(self.decoder.proto.phy.wait_for_falling_io())

class TestProtocolLayerE2E(unittest.TestCase):
    def setUp(self):
        self.decoder = Decoder()
        self.decoder.put = MagicMock()
        self.decoder.out_ann = srd.OUTPUT_ANN
        self.decoder.out_pcap = srd.OUTPUT_BINARY

    def test_parse_atr(self):
        stream = ISO7816Stream(100)
        stream.add_delay(5)
        atr_bytes = [0x3b, 0x9f, 0x94, 0x80, 0x1f, 0xc7, 0x80, 0x31, 0xe0, 0x73, 0xfe, 0x21, 0x13, 0x57, 0x86, 0x81, 0x09, 0x86, 0x98, 0x62, 0x18, 0x80]
        for b in atr_bytes:
            stream.add_byte(b)

        mock_srd = MockSigrokDecoder(self.decoder, stream)
        self.decoder.wait = mock_srd.wait

        self.assertTrue(self.decoder.proto.parse_atr())
        self.assertEqual(self.decoder.proto.protocol, 0)

    def test_decode_pps(self):
        stream = ISO7816Stream(100)
        stream.add_delay(5)
        pps_bytes = [0x10, 0x11, 0xEE, 0xFF, 0x10, 0x11, 0xEE]
        for b in pps_bytes:
            stream.add_byte(b)

        mock_srd = MockSigrokDecoder(self.decoder, stream)
        self.decoder.wait = mock_srd.wait
        self.decoder.proto.phy.etu = 100

        self.assertTrue(self.decoder.proto.decode_pps(0xFF, 0, 10))

    def test_decode_t0(self):
        stream = ISO7816Stream(100)
        stream.add_delay(5)
        t0_bytes = [0xA4, 0x00, 0x00, 0x02, 0xA4, 0x11, 0x22, 0x90, 0x00]
        for b in t0_bytes: stream.add_byte(b)
        mock_srd = MockSigrokDecoder(self.decoder, stream)
        self.decoder.wait = mock_srd.wait
        self.decoder.proto.phy.etu = 100

        self.assertTrue(self.decoder.proto.decode_t0(0x00, 0, 10))

    def test_decode_t1(self):
        stream = ISO7816Stream(100)
        stream.add_delay(5)
        t1_bytes = [0x00, 0x02, 0xAA, 0xBB, 0xCC]
        for b in t1_bytes: stream.add_byte(b)
        mock_srd = MockSigrokDecoder(self.decoder, stream)
        self.decoder.wait = mock_srd.wait
        self.decoder.proto.phy.etu = 100
        self.decoder.proto.t1_crc = False

        self.assertTrue(self.decoder.proto.decode_t1(0x00, 0, 10))

class TestDecoderE2E(unittest.TestCase):
    def setUp(self):
        self.decoder = Decoder()
        self.decoder.register = MagicMock(side_effect=[0, 1])
        self.decoder.put = MagicMock()
        self.decoder.out_ann = srd.OUTPUT_ANN
        self.decoder.out_pcap = srd.OUTPUT_BINARY

    def _run_full_decode(self, atr_bytes, command_bytes, pps_bytes=None):
        stream = ISO7816Stream(100)
        stream.add_reset(0)
        stream.add_delay(10)
        stream.add_reset(1)
        stream.add_delay(10)

        for b in atr_bytes: stream.add_byte(b)
        stream.add_delay(20)

        if pps_bytes:
            for b in pps_bytes: stream.add_byte(b)
            stream.add_delay(20)

        for b in command_bytes: stream.add_byte(b)

        mock_srd = MockSigrokDecoder(self.decoder, stream)
        self.decoder.wait = mock_srd.wait

        with self.assertRaises(StopIteration):
            self.decoder.decode()

        self.assertEqual(self.decoder.state, 'WAIT_COMMAND')

    def test_full_decode_t0_without_pps(self):
        atr_bytes = [0x3B, 0x00] # Simplest ATR
        apdu_bytes = [0xA4, 0x00, 0x00, 0x02, 0xA4, 0x11, 0x22, 0x90, 0x00]
        self._run_full_decode(atr_bytes, apdu_bytes)

    def test_full_decode_t0_with_pps(self):
        atr_bytes = [0x3B, 0x00] # Simplest ATR
        pps_bytes = [0xFF, 0x10, 0x11, 0xEE, 0xFF, 0x10, 0x11, 0xEE]
        apdu_bytes = [0xA4, 0x00, 0x00, 0x02, 0xA4, 0x11, 0x22, 0x90, 0x00]
        self._run_full_decode(atr_bytes, apdu_bytes, pps_bytes=pps_bytes)

    def test_full_decode_t1(self):
        atr_bytes = [0x3B, 0x80, 0x01, 0x01] # ATR indicating T=1
        block_bytes = [0x00, 0x00, 0x00, 0x00] # Block: NAD=00, PCB=00, LEN=00, EDC=00
        self._run_full_decode(atr_bytes, block_bytes)
        self.assertEqual(self.decoder.proto.protocol, 1)

class TestPhysicalLayerErrorScenarios(unittest.TestCase):
    def setUp(self):
        self.decoder = Decoder()
        self.decoder.put = MagicMock()
        self.decoder.out_ann = srd.OUTPUT_ANN
        self.decoder.out_pcap = srd.OUTPUT_BINARY

    def test_read_byte_raw_aborted_by_reset(self):
        stream = ISO7816Stream(100)
        stream.add_delay(5)
        # Instead of adding a byte, we add a reset falling edge
        stream.add_reset(0)
        mock_srd = MockSigrokDecoder(self.decoder, stream)
        self.decoder.wait = mock_srd.wait

        self.decoder.proto.phy.etu = 100
        res = self.decoder.proto.phy.read_byte_raw(already_at_end_of_start_bit=False)
        self.assertIsNone(res)

    def test_read_byte_raw_invalid_start_bit(self):
        stream = ISO7816Stream(100)
        stream.add_delay(5)
        # To make an invalid start bit, we need it to fall (so wait triggers) but then go back to 1 before etu // 2
        stream.events.append((stream.time, 1, 0)) # Start falling edge
        stream.time += 10 # small glitch
        stream.events.append((stream.time, 1, 1)) # Back to 1
        stream.time += 100 * 12 # some delay
        
        mock_srd = MockSigrokDecoder(self.decoder, stream)
        self.decoder.wait = mock_srd.wait
        self.decoder.proto.phy.etu = 100
        
        self.decoder.proto.phy.read_byte_raw(already_at_end_of_start_bit=False)
        put_calls = [call.args[3][1][0] for call in self.decoder.put.mock_calls]
        self.assertIn('Invalid Start Bit', put_calls)

    def test_read_byte_raw_invalid_stop_bit(self):
        stream = ISO7816Stream(100)
        stream.add_delay(5)
        
        # Valid byte but stop bit is 0
        stream.add_bit(0) # Start
        for _ in range(8): stream.add_bit(0)
        stream.add_bit(0) # Parity
        stream.add_bit(0, etus=2) # Invalid Stop (should be 1)
        
        mock_srd = MockSigrokDecoder(self.decoder, stream)
        self.decoder.wait = mock_srd.wait
        self.decoder.proto.phy.etu = 100
        
        self.decoder.proto.phy.read_byte_raw(already_at_end_of_start_bit=False)
        put_calls = [call.args[3][1][0] for call in self.decoder.put.mock_calls]
        self.assertIn('Invalid Stop Bit', put_calls)

    def test_read_byte_parity_error_direct(self):
        stream = ISO7816Stream(100)
        stream.add_delay(5)
        
        # Manually create byte with parity error
        stream.add_bit(0) # Start
        for _ in range(8): stream.add_bit(0) # Data = 0
        stream.add_bit(1) # Invalid parity (even expected, so should be 0)
        stream.add_bit(1, etus=2) # Stop
        
        mock_srd = MockSigrokDecoder(self.decoder, stream)
        self.decoder.wait = mock_srd.wait
        self.decoder.proto.phy.etu = 100
        self.decoder.convention = 'direct'
        
        self.decoder.proto.phy.read_byte()
        put_calls = [call.args[3][1][0] for call in self.decoder.put.mock_calls]
        self.assertIn('Invalid Parity Bit', put_calls)

    def test_read_byte_parity_error_inverse(self):
        stream = ISO7816Stream(100)
        stream.add_delay(5)
        
        # Manually create byte with parity error
        stream.add_bit(0) # Start
        for _ in range(8): stream.add_bit(0) # Data = FF (inverse)
        stream.add_bit(0) # Invalid parity (expected 1 for odd number of total physical 1s)
        stream.add_bit(1, etus=2) # Stop
        
        mock_srd = MockSigrokDecoder(self.decoder, stream)
        self.decoder.wait = mock_srd.wait
        self.decoder.proto.phy.etu = 100
        self.decoder.convention = 'inverse'
        
        self.decoder.proto.phy.read_byte()
        put_calls = [call.args[3][1][0] for call in self.decoder.put.mock_calls]
        self.assertIn('Invalid Parity Bit', put_calls)


class TestProtocolLayerErrorScenarios(unittest.TestCase):
    def setUp(self):
        self.decoder = Decoder()
        self.decoder.put = MagicMock()
        self.decoder.out_ann = srd.OUTPUT_ANN
        self.decoder.out_pcap = srd.OUTPUT_BINARY

    def test_parse_atr_invalid_ts(self):
        stream = ISO7816Stream(100)
        stream.add_delay(5)
        stream.add_byte(0x3A, convention='direct') # Invalid TS
        stream.add_byte(0x00) # T0
        
        mock_srd = MockSigrokDecoder(self.decoder, stream)
        self.decoder.wait = mock_srd.wait

        try:
            self.decoder.proto.parse_atr()
        except StopIteration:
            pass

        put_calls = [call.args[3][1][0] for call in self.decoder.put.mock_calls]
        self.assertIn('Invalid TS', put_calls)

    def test_parse_atr_aborted(self):
        stream = ISO7816Stream(100)
        stream.add_delay(5)
        stream.add_byte(0x3B)
        # T0 is missing, instead a reset occurs
        stream.add_reset(0)

        mock_srd = MockSigrokDecoder(self.decoder, stream)
        self.decoder.wait = mock_srd.wait

        self.assertFalse(self.decoder.proto.parse_atr())
        put_calls = [call.args[3][1][0] for call in self.decoder.put.mock_calls]
        self.assertIn('ATR (Aborted)', put_calls)

    def test_decode_pps_no_response(self):
        stream = ISO7816Stream(100)
        stream.add_delay(5)
        pps_req_bytes = [0x10, 0x11, 0xEE]
        for b in pps_req_bytes:
            stream.add_byte(b)
        stream.add_delay(5)
        stream.add_reset(0) # Reset before response

        mock_srd = MockSigrokDecoder(self.decoder, stream)
        self.decoder.wait = mock_srd.wait
        self.decoder.proto.phy.etu = 100

        self.assertFalse(self.decoder.proto.decode_pps(0xFF, 0, 10))
        put_calls = [call.args[3][1][0] for call in self.decoder.put.mock_calls]
        self.assertIn('PPS (No Response)', put_calls)

    def test_decode_pps_aborted_during_request(self):
        stream = ISO7816Stream(100)
        stream.add_delay(5)
        stream.add_byte(0x10) # PPS0
        stream.add_reset(0)   # Abort before PPS1 or PCK

        mock_srd = MockSigrokDecoder(self.decoder, stream)
        self.decoder.wait = mock_srd.wait
        self.decoder.proto.phy.etu = 100

        self.assertFalse(self.decoder.proto.decode_pps(0xFF, 0, 10))
        put_calls = [call.args[3][1][0] for call in self.decoder.put.mock_calls]
        self.assertIn('PPS Request (Aborted)', put_calls)

    def test_decode_pps_aborted_during_response(self):
        stream = ISO7816Stream(100)
        stream.add_delay(5)
        pps_req_bytes = [0x10, 0x11, 0xEE] # Request
        for b in pps_req_bytes:
            stream.add_byte(b)
        
        stream.add_delay(5)
        stream.add_byte(0xFF) # PPSS response
        stream.add_reset(0)   # Abort during response
        
        mock_srd = MockSigrokDecoder(self.decoder, stream)
        self.decoder.wait = mock_srd.wait
        self.decoder.proto.phy.etu = 100

        self.assertFalse(self.decoder.proto.decode_pps(0xFF, 0, 10))
        put_calls = [call.args[3][1][0] for call in self.decoder.put.mock_calls]
        self.assertIn('PPS Response (Aborted)', put_calls)

    def test_decode_t0_aborted(self):
        stream = ISO7816Stream(100)
        stream.add_delay(5)
        # Send CLA, INS, P1, and then reset
        stream.add_byte(0x00) # INS
        stream.add_byte(0x00) # P1
        stream.add_reset(0)   # Abort
        
        mock_srd = MockSigrokDecoder(self.decoder, stream)
        self.decoder.wait = mock_srd.wait
        self.decoder.proto.phy.etu = 100

        self.assertFalse(self.decoder.proto.decode_t0(0xA4, 0, 10)) # 0xA4 is CLA
        put_calls = [call.args[3][1][0] for call in self.decoder.put.mock_calls]
        self.assertIn('T=0 APDU (Aborted)', put_calls)

    def test_decode_t0_unknown_pb(self):
        stream = ISO7816Stream(100)
        stream.add_delay(5)
        # CLA, INS, P1, P2, P3
        apdu_hdr = [0x00, 0x00, 0x02, 0x05]
        for b in apdu_hdr: stream.add_byte(b)
        
        stream.add_byte(0x55) # Unknown Procedure Byte
        
        mock_srd = MockSigrokDecoder(self.decoder, stream)
        self.decoder.wait = mock_srd.wait
        self.decoder.proto.phy.etu = 100

        self.assertTrue(self.decoder.proto.decode_t0(0xA4, 0, 10))
        put_calls = [call.args[3][1][0] for call in self.decoder.put.mock_calls]
        self.assertIn('Unknown PB: 55', put_calls)

    def test_decode_t1_aborted(self):
        stream = ISO7816Stream(100)
        stream.add_delay(5)
        # PCB only, then abort
        stream.add_byte(0x00)
        stream.add_reset(0)

        mock_srd = MockSigrokDecoder(self.decoder, stream)
        self.decoder.wait = mock_srd.wait
        self.decoder.proto.phy.etu = 100
        self.decoder.proto.t1_crc = False

        self.assertFalse(self.decoder.proto.decode_t1(0x00, 0, 10))
        put_calls = [call.args[3][1][0] for call in self.decoder.put.mock_calls]
        self.assertIn('T=1 Block (Aborted)', put_calls)


class TestDecoderErrorScenarios(unittest.TestCase):
    def setUp(self):
        self.decoder = Decoder()
        self.decoder.register = MagicMock(side_effect=[0, 1])
        self.decoder.put = MagicMock()
        self.decoder.out_ann = srd.OUTPUT_ANN
        self.decoder.out_pcap = srd.OUTPUT_BINARY

    def test_decode_aborted_atr(self):
        stream = ISO7816Stream(100)
        stream.add_reset(0)
        stream.add_delay(10)
        stream.add_reset(1)
        stream.add_delay(10)

        # Incomplete ATR
        stream.add_byte(0x3B)
        stream.add_reset(0) # Abort
        
        mock_srd = MockSigrokDecoder(self.decoder, stream)
        self.decoder.wait = mock_srd.wait

        with self.assertRaises(StopIteration):
            self.decoder.decode()

        self.assertEqual(self.decoder.state, 'WAIT_RESET')

    def test_decode_aborted_command(self):
        stream = ISO7816Stream(100)
        stream.add_reset(0)
        stream.add_delay(10)
        stream.add_reset(1)
        stream.add_delay(10)

        stream.add_byte(0x3B)
        stream.add_byte(0x00) # Complete ATR
        
        stream.add_delay(20)
        stream.add_byte(0xA4) # Start APDU
        stream.add_reset(0)   # Abort APDU
        
        mock_srd = MockSigrokDecoder(self.decoder, stream)
        self.decoder.wait = mock_srd.wait

        with self.assertRaises(StopIteration):
            self.decoder.decode()

        self.assertEqual(self.decoder.state, 'WAIT_RESET')

if __name__ == '__main__':
    unittest.main()
