"""802.11 帧编解码与 Radiotap 的单元测试。"""
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _ctx import OUT  # noqa: E402,F401

from wlanlab import frame as F  # noqa: E402

AP = "02:00:00:00:00:ff"
STA = "02:00:00:00:00:01"
STA2 = "02:00:00:00:00:02"


class TestMacAddress(unittest.TestCase):
    def test_roundtrip(self):
        self.assertEqual(F.bytes_to_mac(F.mac_to_bytes(STA)), STA)

    def test_bytes_order(self):
        self.assertEqual(F.mac_to_bytes("01:02:03:04:05:06"),
                         bytes([1, 2, 3, 4, 5, 6]))

    def test_uppercase_normalised(self):
        self.assertEqual(F.bytes_to_mac(F.mac_to_bytes("AA:BB:CC:DD:EE:FF")),
                         "aa:bb:cc:dd:ee:ff")

    def test_invalid_raises(self):
        for bad in ("", "aa:bb", "zz:00:00:00:00:00", "1:2:3:4:5:6"):
            with self.assertRaises(ValueError):
                F.mac_to_bytes(bad)

    def test_broadcast_is_multicast(self):
        self.assertTrue(F.is_multicast(F.BROADCAST))

    def test_unicast(self):
        self.assertFalse(F.is_multicast(STA))

    def test_multicast_bit(self):
        self.assertTrue(F.is_multicast("01:00:5e:00:00:01"))

    def test_broadcast_value(self):
        self.assertEqual(F.BROADCAST, "ff:ff:ff:ff:ff:ff")


class TestFrameControl(unittest.TestCase):
    def test_encode_two_bytes(self):
        fc = F.FrameControl(type=F.FRAME_TYPE_DATA, subtype=8, to_ds=1)
        self.assertEqual(len(fc.encode()), 2)

    def test_roundtrip_data(self):
        fc = F.FrameControl(type=F.FRAME_TYPE_DATA, subtype=8, to_ds=1,
                            retry=1)
        back = F.FrameControl.decode(fc.encode())
        self.assertEqual(back.type, F.FRAME_TYPE_DATA)
        self.assertEqual(back.subtype, 8)
        self.assertEqual(back.to_ds, 1)
        self.assertEqual(back.retry, 1)

    def test_version_is_zero(self):
        fc = F.FrameControl()
        raw = fc.encode()
        self.assertEqual(raw[0] & 0x03, 0)

    def test_subtype_high_bits(self):
        # Subtype 是 802.11 Frame Control 的 bit 8-11，落在**第二个字节**的低 4 位
        fc = F.FrameControl(type=F.FRAME_TYPE_MGMT, subtype=8)
        self.assertEqual(fc.encode()[1] & 0x0F, 8)

    def test_wire_positions_match_wireshark_masks(self):
        """按 Wireshark ``packet-80211.c`` 的字段掩码逐位验证线格式。

        Wireshark 的掩码是固定的：type 0xF0 / subtype 0xF00 / to_ds 0x1000 /
        from_ds 0x2000 / more_frags 0x4000 / retry 0x8000。
        自己编解码自洽没用——必须落在这些位上，Wireshark 才认。
        """
        import struct

        fc = F.FrameControl(type=F.FRAME_TYPE_DATA, subtype=8,
                            to_ds=1, from_ds=0, more_fragments=0, retry=1)
        (v,) = struct.unpack("<H", fc.encode())
        self.assertEqual(v & 0x00F0, F.FRAME_TYPE_DATA << 4)
        self.assertEqual(v & 0x0F00, 8 << 8)
        self.assertEqual(v & 0x1000, 0x1000)
        self.assertEqual(v & 0x8000, 0x8000)   # wlan.fc.retry == 1 靠这一位

        # QoS Data + ToDS + Retry 的标准值
        self.assertEqual(v, (2 << 4) | (8 << 8) | (1 << 12) | (1 << 15))

        # ACK：type 1 / subtype 13 → Wireshark 的 type_subtype = (13<<4)|1 = 0xD1
        ack_v = struct.unpack("<H", F.ack_frame(STA2).fc.encode())[0]
        self.assertEqual(ack_v & 0x00F0, 1 << 4)
        self.assertEqual(ack_v & 0x0F00, 13 << 8)
        self.assertEqual((ack_v >> 8 & 0xF) << 4 | (ack_v >> 4 & 0xF), 0xD1)

    def test_type_names(self):
        self.assertEqual(F.TYPE_NAMES[0], "Management")
        self.assertEqual(F.TYPE_NAMES[1], "Control")
        self.assertEqual(F.TYPE_NAMES[2], "Data")

    def test_subtype_names(self):
        self.assertEqual(F.SUBTYPE_NAMES[(0, 8)], "Beacon")
        self.assertEqual(F.SUBTYPE_NAMES[(1, 13)], "ACK")
        self.assertEqual(F.SUBTYPE_NAMES[(1, 11)], "RTS")

    def test_describe_mentions_type(self):
        fc = F.FrameControl(type=F.FRAME_TYPE_MGMT, subtype=8)
        self.assertIn("Beacon", fc.describe())

    def test_describe_tods(self):
        fc = F.FrameControl(type=F.FRAME_TYPE_DATA, subtype=0, to_ds=1)
        self.assertIn("ToDS", fc.describe())

    def test_decode_rejects_short(self):
        with self.assertRaises(ValueError):
            F.FrameControl.decode(b"\x00")


class TestMacFrame(unittest.TestCase):
    def test_data_frame_roundtrip(self):
        mf = F.data_frame(STA, STA2, AP, b"payload-123", seq=7)
        back = F.MacFrame.decode(mf.encode())
        self.assertEqual(back.payload, b"payload-123")
        self.assertEqual(back.seq, 7)
        self.assertEqual(back.addr1, STA2)
        self.assertEqual(back.addr2, STA)

    def test_data_header_is_24(self):
        mf = F.data_frame(STA, STA2, AP, b"x")
        self.assertEqual(mf.header_len, 24)

    def test_qos_header_is_26(self):
        mf = F.data_frame(STA, STA2, AP, b"x", tid=6)
        self.assertTrue(mf.is_qos)
        self.assertEqual(mf.header_len, 26)

    def test_qos_tid_roundtrip(self):
        mf = F.data_frame(STA, STA2, AP, b"x", tid=6)
        back = F.MacFrame.decode(mf.encode())
        self.assertEqual(back.qos_tid, 6)

    def test_control_header_is_10(self):
        mf = F.ack_frame(STA)
        self.assertEqual(mf.header_len, 10)
        self.assertEqual(len(mf.encode()), 10)

    def test_ack_roundtrip(self):
        mf = F.ack_frame(STA)
        back = F.MacFrame.decode(mf.encode())
        self.assertEqual(back.fc.type, F.FRAME_TYPE_CTRL)
        self.assertEqual(back.fc.subtype, 13)
        self.assertEqual(back.addr1, STA)

    def test_cts_subtype(self):
        self.assertEqual(F.cts_frame(STA).fc.subtype, 12)

    def test_rts_has_two_addresses(self):
        mf = F.rts_frame(STA2, STA)
        back = F.MacFrame.decode(mf.encode())
        self.assertEqual(back.addr1, STA2)
        self.assertEqual(back.addr2, STA)

    def test_wds_header_is_30(self):
        mf = F.data_frame(STA, STA2, AP, b"x", to_ds=1, from_ds=1)
        self.assertEqual(mf.header_len, 30)

    def test_wds_roundtrip(self):
        mf = F.data_frame(STA, STA2, AP, b"wds", to_ds=1, from_ds=1)
        mf.addr4 = "02:00:00:00:00:09"
        back = F.MacFrame.decode(mf.encode())
        self.assertEqual(back.addr4, "02:00:00:00:00:09")

    def test_seq_frag_packing(self):
        mf = F.data_frame(STA, STA2, AP, b"x", seq=4095)
        mf.frag = 15
        back = F.MacFrame.decode(mf.encode())
        self.assertEqual(back.seq, 4095)
        self.assertEqual(back.frag, 15)

    def test_retry_bit_roundtrip(self):
        mf = F.data_frame(STA, STA2, AP, b"x", retry=1)
        back = F.MacFrame.decode(mf.encode())
        self.assertEqual(back.fc.retry, 1)

    def test_duration_roundtrip(self):
        mf = F.data_frame(STA, STA2, AP, b"x", duration=344)
        back = F.MacFrame.decode(mf.encode())
        self.assertEqual(back.duration, 344)

    def test_describe_contains_macs(self):
        mf = F.data_frame(STA, STA2, AP, b"x")
        d = mf.describe()
        self.assertIn(STA, d)
        self.assertIn(STA2, d)

    def test_decode_rejects_short(self):
        with self.assertRaises(ValueError):
            F.MacFrame.decode(b"\x00\x01")

    def test_broadcast_beacon(self):
        mf = F.beacon_frame(AP, "SSID")
        self.assertEqual(mf.addr1, F.BROADCAST)
        self.assertEqual(mf.fc.type, F.FRAME_TYPE_MGMT)


class TestFCS(unittest.TestCase):
    def test_crc32_known_vector(self):
        self.assertEqual(F.crc32(b"123456789"), 0xCBF43926)

    def test_crc32_empty(self):
        self.assertEqual(F.crc32(b""), 0)

    def test_fcs_len_four_in_frame(self):
        mf = F.data_frame(STA, STA2, AP, b"x")
        raw = F.build_frame(mf, F.Radiotap(flags=F.RT_FLAG_FCS))
        body = raw[F.Radiotap.decode(raw)[1]:]
        self.assertEqual(len(body), mf.header_len + 1 + 4)

    def test_fcs_changes_with_payload(self):
        a = F.fcs32(b"abc")
        b = F.fcs32(b"abd")
        self.assertNotEqual(a, b)

    def test_parse_strips_fcs(self):
        mf = F.data_frame(STA, STA2, AP, b"hello")
        raw = F.build_frame(mf, F.Radiotap(flags=F.RT_FLAG_FCS))
        _, back = F.parse_frame(raw)
        self.assertEqual(back.payload, b"hello")
        self.assertIsNotNone(back.fcs)

    def test_no_fcs_when_flag_absent(self):
        mf = F.data_frame(STA, STA2, AP, b"hello")
        raw = F.build_frame(mf, F.Radiotap(flags=0))
        _, back = F.parse_frame(raw)
        self.assertEqual(back.payload, b"hello")
        self.assertIsNone(back.fcs)

    def test_fcs_verifies(self):
        mf = F.data_frame(STA, STA2, AP, b"verify-me")
        raw = F.build_frame(mf, F.Radiotap(flags=F.RT_FLAG_FCS))
        rt, back = F.parse_frame(raw)
        recomputed = F.fcs32(raw[F.Radiotap.decode(raw)[1]:-4])
        self.assertEqual(recomputed, back.fcs)


class TestRadiotap(unittest.TestCase):
    def test_header_aligned_to_8(self):
        rt = F.Radiotap(tsft=1, flags=F.RT_FLAG_FCS, rate_mbps=54.0,
                        channel=6, signal_dbm=-42)
        self.assertEqual(len(rt.encode()) % 8, 0)

    def test_minimal_header_is_8(self):
        rt = F.Radiotap(tsft=None, flags=None, rate_mbps=None, channel=None,
                        signal_dbm=None)
        self.assertEqual(len(rt.encode()), 8)
        self.assertEqual(rt.present, 0)

    def test_present_bitmap_only_set_fields(self):
        rt = F.Radiotap(tsft=None, flags=None, rate_mbps=6.0, channel=None,
                        signal_dbm=None)
        self.assertEqual(rt.present, F.RT_RATE)
        back, off = F.Radiotap.decode(rt.encode())
        self.assertIsNone(back.tsft)
        self.assertEqual(back.rate_mbps, 6.0)
        self.assertIsNone(back.channel)

    def test_roundtrip_full(self):
        rt = F.Radiotap(tsft=999, flags=F.RT_FLAG_FCS, rate_mbps=24.0,
                        channel=36, signal_dbm=-55)
        back, off = F.Radiotap.decode(rt.encode())
        self.assertEqual(off, len(rt.encode()))
        self.assertEqual(back.tsft, 999)
        self.assertEqual(back.channel, 36)
        self.assertEqual(back.signal_dbm, -55)

    def test_rate_encoding_half_mbps(self):
        rt = F.Radiotap(rate_mbps=5.5)
        back, _ = F.Radiotap.decode(rt.encode())
        self.assertAlmostEqual(back.rate_mbps, 5.5)

    def test_present_bitmap(self):
        rt = F.Radiotap(tsft=1, flags=1, rate_mbps=1.0, channel=1,
                        signal_dbm=-1)
        self.assertEqual(rt.present,
                         F.RT_TSFT | F.RT_FLAGS | F.RT_RATE | F.RT_CHANNEL
                         | F.RT_DBM_ANTENNA_SIGNAL)

    def test_describe(self):
        rt = F.Radiotap(rate_mbps=54.0, channel=6, signal_dbm=-42)
        d = rt.describe()
        self.assertIn("54", d)
        self.assertIn("ch6", d)

    def test_decode_rejects_short(self):
        with self.assertRaises(ValueError):
            F.Radiotap.decode(b"\x00\x00")

    def test_channel_frequency_table(self):
        self.assertEqual(F.CHANNEL_FREQ[1], 2412)
        self.assertEqual(F.CHANNEL_FREQ[6], 2437)
        self.assertEqual(F.CHANNEL_FREQ[36], 5180)

    def test_flags_constants(self):
        self.assertEqual(F.RT_FLAG_FCS, 0x10)
        self.assertEqual(F.RT_FLAG_BAD_FCS, 0x20)
        self.assertEqual(F.RT_FLAG_SHORT_PREAMBLE, 0x02)

    def test_bad_fcs_bit_matches_wireshark_mask(self):
        """碰撞帧必须让 Wireshark 的 ``wlan_radio.fcs_bad == 1`` 命中。

        Wireshark 对 Radiotap Flags 字节的掩码是固定的：
        ``wlan_radio.fcs_present`` 用 0x10，``wlan_radio.fcs_bad`` 用 0x20。
        这个测试把常量钉死在这两个掩码上——写回 0x40（CRC32 位）会立刻失败，
        否则演示时过滤器会静默匹配到 0 帧。
        """
        normal = F.Radiotap(flags=F.RT_FLAG_FCS)
        collided = F.Radiotap(flags=F.RT_FLAG_FCS | F.RT_FLAG_BAD_FCS)

        n_flags = F.parse_frame(F.build_frame(F.ack_frame(STA2), normal))[0].flags
        c_flags = F.parse_frame(F.build_frame(F.ack_frame(STA2), collided))[0].flags

        # 正常帧：fcs_present=1，fcs_bad=0
        self.assertTrue(n_flags & 0x10)
        self.assertFalse(n_flags & 0x20)
        # 碰撞帧：两个位都置——fcs_bad==1 且 fcs_present==1 同时成立
        self.assertTrue(c_flags & 0x10)
        self.assertTrue(c_flags & 0x20)
        # 0x40 是 CRC32 位，绝不能被当成 Bad FCS 一起置
        self.assertFalse(c_flags & 0x40)


class TestBuildParse(unittest.TestCase):
    def test_build_parse_roundtrip(self):
        mf = F.data_frame(STA, STA2, AP, b"abc", seq=5, tid=3)
        raw = F.build_frame(mf, F.Radiotap(rate_mbps=54.0, channel=6))
        rt, back = F.parse_frame(raw)
        self.assertEqual(back.payload, b"abc")
        self.assertEqual(back.seq, 5)
        self.assertEqual(rt.channel, 6)

    def test_all_builders_roundtrip(self):
        frames = [
            F.data_frame(STA, STA2, AP, b"d"),
            F.ack_frame(STA),
            F.cts_frame(STA),
            F.rts_frame(STA2, STA),
            F.beacon_frame(AP, "S"),
            F.probe_request(STA, "S"),
            F.auth_frame(STA, AP),
            F.assoc_request(STA, AP, "S"),
        ]
        for mf in frames:
            raw = F.build_frame(mf, F.Radiotap(flags=F.RT_FLAG_FCS))
            _, back = F.parse_frame(raw)
            self.assertEqual(back.fc.type, mf.fc.type)
            self.assertEqual(back.fc.subtype, mf.fc.subtype)

    def test_build_without_radiotap(self):
        mf = F.data_frame(STA, STA2, AP, b"x")
        raw = F.build_frame(mf)
        self.assertEqual(raw[0], 0)          # radiotap version 0


class TestInformationElements(unittest.TestCase):
    def test_parse_two_ies(self):
        payload = bytes([0, 3]) + b"abc" + bytes([3, 1, 6])
        ies = F.parse_information_elements(payload)
        self.assertEqual(ies, [(0, b"abc"), (3, b"\x06")])

    def test_parse_truncated_stops(self):
        payload = bytes([0, 10]) + b"abc"
        self.assertEqual(F.parse_information_elements(payload), [])

    def test_parse_empty(self):
        self.assertEqual(F.parse_information_elements(b""), [])

    def test_beacon_ies(self):
        mf = F.beacon_frame(AP, "NetLab", channel=11)
        ies = dict(F.mgmt_ies(mf))
        self.assertEqual(ies[0], b"NetLab")
        self.assertEqual(ies[3], bytes([11]))

    def test_beacon_fixed_len_skipped(self):
        mf = F.beacon_frame(AP, "X", channel=1)
        self.assertEqual(F.MGMT_FIXED_LEN[8], 12)
        self.assertEqual(len(F.mgmt_ies(mf)), 2)

    def test_extra_ies_appended(self):
        mf = F.beacon_frame(AP, "X", extra_ies=[(48, b"\x01\x02")])
        ies = dict(F.mgmt_ies(mf))
        self.assertEqual(ies[48], b"\x01\x02")

    def test_probe_request_has_no_fixed_field(self):
        mf = F.probe_request(STA, "MySSID")
        self.assertEqual(F.MGMT_FIXED_LEN[4], 0)
        self.assertEqual(dict(F.mgmt_ies(mf))[0], b"MySSID")

    def test_auth_fixed_len(self):
        mf = F.auth_frame(STA, AP)
        self.assertEqual(F.MGMT_FIXED_LEN[11], 6)
        self.assertEqual(F.mgmt_ies(mf), [])

    def test_auth_seq_num(self):
        mf = F.auth_frame(STA, AP, seq_num=2)
        algo, seqnum, status = struct.unpack("<HHH", mf.payload)
        self.assertEqual(seqnum, 2)
        self.assertEqual(algo, 0)
        self.assertEqual(status, 0)

    def test_assoc_request_ies(self):
        mf = F.assoc_request(STA, AP, "NetLab")
        self.assertEqual(dict(F.mgmt_ies(mf))[0], b"NetLab")

    def test_non_mgmt_has_no_ies(self):
        self.assertEqual(F.mgmt_ies(F.data_frame(STA, STA2, AP, b"x")), [])

    def test_describe_ies(self):
        mf = F.beacon_frame(AP, "NetLab", channel=6)
        desc = F.describe_ies(mf.payload[12:])
        self.assertTrue(any("NetLab" in d for d in desc))
        self.assertTrue(any("ch6" in d for d in desc))

    def test_ie_names_has_ssid(self):
        self.assertEqual(F.IE_NAMES[0], "SSID")
        self.assertEqual(F.IE_NAMES[48], "RSN")


class TestTimingConstants(unittest.TestCase):
    def test_slot_time(self):
        self.assertEqual(F.SLOT_TIME, 9.0)

    def test_sifs(self):
        self.assertEqual(F.SIFS, 16.0)

    def test_difs_relation(self):
        self.assertEqual(F.DIFS, F.SIFS + 2 * F.SLOT_TIME)

    def test_pifs_relation(self):
        self.assertEqual(F.PIFS, F.SIFS + F.SLOT_TIME)

    def test_eifs_larger_than_difs(self):
        self.assertGreater(F.EIFS, F.DIFS)

    def test_cw_bounds(self):
        self.assertEqual(F.CW_MIN, 15)
        self.assertEqual(F.CW_MAX, 1023)

    def test_retry_limit(self):
        self.assertEqual(F.A_RETRY_LIMIT, 7)


if __name__ == "__main__":
    unittest.main(verbosity=2)
