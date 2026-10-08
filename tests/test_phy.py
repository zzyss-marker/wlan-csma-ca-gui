"""物理层空口时间计算的单元测试。"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _ctx import OUT  # noqa: E402,F401

from wlanlab import frame as F  # noqa: E402
from wlanlab import phy  # noqa: E402


class TestConstants(unittest.TestCase):
    def test_preamble_long(self):
        self.assertEqual(phy.PREAMBLE_LONG_US, 20.0)

    def test_preamble_short(self):
        self.assertEqual(phy.PREAMBLE_SHORT_US, 16.0)

    def test_ofdm_symbol(self):
        self.assertEqual(phy.OFDM_SYMBOL_US, 4.0)

    def test_fcs_bytes(self):
        self.assertEqual(phy.FCS_BYTES, 4)

    def test_ndbps_table(self):
        self.assertEqual(phy.NDBPS[6.0], 24)
        self.assertEqual(phy.NDBPS[54.0], 216)

    def test_ndbps_is_rate_times_4(self):
        for rate, n in phy.NDBPS.items():
            self.assertEqual(n, int(rate * 4))

    def test_ht_mcs_table(self):
        self.assertAlmostEqual(phy.HT_MCS[0][0], 6.5)
        self.assertAlmostEqual(phy.HT_MCS[7][0], 65.0)
        self.assertEqual(phy.HT_MCS[7][1], 260)


class TestAirtime(unittest.TestCase):
    def test_airtime_increases_with_length(self):
        self.assertLess(phy.airtime_us(100, 54.0), phy.airtime_us(1000, 54.0))

    def test_airtime_decreases_with_rate(self):
        self.assertGreater(phy.airtime_us(1500, 6.0),
                           phy.airtime_us(1500, 54.0))

    def test_airtime_1500_at_54(self):
        # 20(前导) + 4(SIGNAL) + ceil((16+8+1500*8+6)/216)*4 = 248
        self.assertEqual(phy.airtime_us(1500, 54.0), 248.0)

    def test_airtime_1500_at_6(self):
        self.assertEqual(phy.airtime_us(1500, 6.0), 2036.0)

    def test_airtime_multiple_of_symbol(self):
        for size in (64, 100, 500, 1500, 2304):
            t = phy.airtime_us(size, 24.0)
            self.assertEqual((t - 24.0) % 4.0, 0.0)

    def test_airtime_zero_length_is_header_only(self):
        # 24us 前导+SIGNAL，再加 1 个 OFDM 符号（SERVICE+TAIL 22 bit）
        self.assertEqual(phy.airtime_us(0, 54.0), 28.0)

    def test_include_fcs_false(self):
        # 6 Mbps 时 1500 字节刚好跨过一个 OFDM 符号边界
        self.assertEqual(phy.airtime_us(1500, 6.0, include_fcs=False), 2028.0)
        self.assertEqual(phy.airtime_us(1500, 6.0), 2036.0)

    def test_short_preamble_saves_4us(self):
        self.assertEqual(
            phy.airtime_us(1500, 54.0, phy.PREAMBLE_LONG_US)
            - phy.airtime_us(1500, 54.0, phy.PREAMBLE_SHORT_US), 4.0)

    def test_unknown_rate_raises(self):
        with self.assertRaises(ValueError):
            phy.airtime_us(100, 7.0)

    def test_ack_airtime(self):
        self.assertEqual(phy.ack_airtime_us(24.0), 32.0)

    def test_cts_airtime(self):
        self.assertEqual(phy.cts_airtime_us(24.0), 32.0)

    def test_rts_airtime(self):
        self.assertEqual(phy.rts_airtime_us(24.0), 36.0)
        self.assertEqual(phy.rts_airtime_us(6.0), 60.0)

    def test_rts_shorter_than_data(self):
        self.assertLess(phy.rts_airtime_us(24.0), phy.airtime_us(1500, 54.0))

    def test_control_frames_at_6mbps(self):
        self.assertEqual(phy.ack_airtime_us(6.0), 52.0)


class TestEfficiency(unittest.TestCase):
    def test_efficiency_between_0_and_1(self):
        for size in (44, 100, 500, 1500, 2304):
            e = phy.efficiency(size, 54.0)
            self.assertGreater(e, 0.0)
            self.assertLess(e, 1.0)

    def test_efficiency_grows_with_size(self):
        self.assertLess(phy.efficiency(44, 54.0), phy.efficiency(1500, 54.0))

    def test_efficiency_1500_at_54(self):
        self.assertAlmostEqual(phy.efficiency(1500, 54.0), 0.559, places=3)

    def test_small_frame_is_terrible(self):
        self.assertLess(phy.efficiency(44, 54.0), 0.25)

    def test_goodput_less_than_rate(self):
        for r in (6.0, 24.0, 54.0):
            self.assertLess(phy.goodput_mbps(1500, r), r)

    def test_goodput_1500_at_54(self):
        # 含退避/DIFS/ACK 的真实有效吞吐约 30 Mbps，远低于 48 Mbps 的裸空口值
        self.assertAlmostEqual(phy.goodput_mbps(1500, 54.0), 30.19, places=1)

    def test_goodput_below_bare_airtime_value(self):
        bare = 1500 * 8 / (phy.airtime_us(1500, 54.0) * 1e-6) / 1e6
        self.assertLess(phy.goodput_mbps(1500, 54.0), bare)


class TestTimingBreakdown(unittest.TestCase):
    def test_fields(self):
        tb = phy.timing_breakdown(1500, 54.0)
        self.assertEqual(tb.data_us, 248.0)
        self.assertEqual(tb.ack_us, 32.0)
        self.assertEqual(tb.sifs_us, F.SIFS)
        self.assertEqual(tb.difs_us, F.DIFS)

    def test_total_is_sum(self):
        tb = phy.timing_breakdown(1500, 54.0)
        self.assertAlmostEqual(
            tb.total_us,
            tb.data_us + tb.ack_us + tb.sifs_us + tb.difs_us + tb.backoff_us)

    def test_describe(self):
        d = phy.timing_breakdown(1500, 54.0).describe()
        self.assertIn("data", d)
        self.assertIn("ack", d)

    def test_backoff_is_half_cw_min(self):
        tb = phy.timing_breakdown(1500, 54.0)
        self.assertAlmostEqual(tb.backoff_us, F.CW_MIN / 2 * F.SLOT_TIME)

    def test_total_under_500us(self):
        self.assertLess(phy.timing_breakdown(1500, 54.0).total_us, 500)


class TestRtsOverhead(unittest.TestCase):
    def test_zero_below_threshold(self):
        self.assertEqual(phy.rts_cts_overhead_us(500, rts_threshold=1000), 0.0)

    def test_positive_above_threshold(self):
        self.assertGreater(phy.rts_cts_overhead_us(1500, rts_threshold=500),
                           0.0)

    def test_overhead_is_100us(self):
        # RTS(36) + SIFS(16) + CTS(32) + SIFS(16) = 100us
        self.assertAlmostEqual(
            phy.rts_cts_overhead_us(1500, rts_threshold=0), 100.0, places=1)


class TestScans(unittest.TestCase):
    def test_rate_scan_length(self):
        self.assertEqual(len(phy.rate_scan(1500)), len(phy.NDBPS))

    def test_rate_scan_monotone_goodput(self):
        rows = phy.rate_scan(1500)
        good = [g for _, _, g in rows]
        self.assertEqual(good, sorted(good))

    def test_size_scan_default_length(self):
        self.assertEqual(len(phy.size_scan()), 7)

    def test_size_scan_monotone_airtime(self):
        rows = phy.size_scan()
        t = [x[1] for x in rows]
        self.assertEqual(t, sorted(t))

    def test_aggregation_gain_at_one_is_one(self):
        self.assertAlmostEqual(phy.aggregation_gain(1, 1500), 1.0)

    def test_aggregation_gain_grows(self):
        self.assertLess(phy.aggregation_gain(2, 1500),
                        phy.aggregation_gain(32, 1500))

    def test_aggregation_gain_bounded(self):
        self.assertLess(phy.aggregation_gain(64, 1500), 1.2)

    def test_aggregation_gain_rejects_zero(self):
        with self.assertRaises(ValueError):
            phy.aggregation_gain(0)

    def test_rate_name(self):
        self.assertIn("54", phy.rate_name(54.0))
        self.assertIn("MCS7", phy.rate_name(65.0))


if __name__ == "__main__":
    unittest.main(verbosity=2)
