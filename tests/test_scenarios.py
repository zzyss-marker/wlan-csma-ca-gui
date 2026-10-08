"""7 个实验脚本的端到端测试（含产物文件校验）。"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _ctx import OUT  # noqa: E402,F401

from netcore.pcap import read_pcap  # noqa: E402

from wlanlab import frame as F  # noqa: E402
from wlanlab import scenarios as S  # noqa: E402


class TestRegistry(unittest.TestCase):
    def test_seven_scenarios(self):
        self.assertEqual(len(S.SCENARIOS), 7)

    def test_names(self):
        self.assertEqual(list(S.SCENARIOS),
                         ["frames", "management", "dcf", "hidden", "edca",
                          "airtime", "pcap"])

    def test_all_callable(self):
        for name, fn in S.SCENARIOS.items():
            self.assertTrue(callable(fn), name)

    def test_docstrings(self):
        for name, fn in S.SCENARIOS.items():
            self.assertTrue((fn.__doc__ or "").strip(), name)

    def test_out_dir_exists(self):
        self.assertTrue(os.path.isdir(OUT))


class TestFramesScenario(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = S.exp_frames()

    def test_all_roundtrips_ok(self):
        self.assertTrue(self.r["all_roundtrip_ok"])

    def test_nine_frame_types(self):
        self.assertEqual(len(self.r["frame_matrix"]), 9)

    def test_control_frames_are_10_bytes(self):
        rows = {r["frame"]: r for r in self.r["frame_matrix"]}
        self.assertEqual(rows["ACK"]["total_bytes"], 10)
        self.assertEqual(rows["CTS"]["total_bytes"], 10)
        self.assertEqual(rows["RTS"]["total_bytes"], 16)

    def test_beacon_has_ies(self):
        self.assertEqual(self.r["beacon_ssid"], "NetLab-5G")
        self.assertEqual(self.r["beacon_channel"], 36)

    def test_radiotap_aligned(self):
        self.assertTrue(self.r["radiotap"]["aligned_to_8"])
        self.assertTrue(self.r["radiotap"]["roundtrip_ok"])

    def test_fcs_known_vector(self):
        self.assertTrue(self.r["fcs"]["crc32_known_vector_ok"])

    def test_fcs_bit_flip(self):
        self.assertTrue(self.r["fcs"]["flip_one_bit_changes_crc"])

    def test_pcap_written(self):
        p = os.path.join(OUT, "01_frames.pcap")
        self.assertTrue(os.path.exists(p))
        linktype, packets = read_pcap(p)
        self.assertEqual(linktype, 127)
        self.assertEqual(len(packets), 9)

    def test_png_written(self):
        self.assertTrue(os.path.exists(os.path.join(OUT, "01_frame_sizes.png")))

    def test_json_written(self):
        p = os.path.join(OUT, "01_frames.json")
        self.assertTrue(os.path.exists(p))
        with open(p, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["experiment"], "frames")


class TestManagementScenario(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = S.exp_management()

    def test_nine_steps(self):
        self.assertEqual(self.r["total_frames"], 9)

    def test_handshake_order(self):
        names = [s["frame"] for s in self.r["handshake"]]
        self.assertEqual(names[0], "Beacon")
        self.assertIn("Authentication", names)
        self.assertIn("Association Request", names)
        self.assertEqual(names[-1], "ACK")

    def test_auth_pair(self):
        auths = [s for s in self.r["handshake"] if s["frame"] == "Authentication"]
        self.assertEqual(len(auths), 2)

    def test_mgmt_types_present(self):
        types = self.r["mgmt_frame_types"]
        self.assertIn("Management/Beacon", types)
        self.assertIn("Management/Auth", types)
        self.assertIn("Management/AssocReq", types)

    def test_pcap_parseable(self):
        p = os.path.join(OUT, "02_management.pcap")
        linktype, packets = read_pcap(p)
        self.assertEqual(linktype, 127)
        self.assertEqual(len(packets), 9)
        for pkt in packets:
            F.parse_frame(pkt.data)

    def test_json_written(self):
        self.assertTrue(os.path.exists(os.path.join(OUT, "02_management.json")))


class TestDcfScenario(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = S.exp_dcf(counts=(1, 2, 4, 8))

    def test_four_rows(self):
        self.assertEqual(len(self.r["sweep"]), 4)

    def test_collision_rate_monotone(self):
        rates = [row["collision_rate"] for row in self.r["sweep"]]
        self.assertEqual(rates, sorted(rates))

    def test_single_station_no_collision(self):
        self.assertEqual(self.r["sweep"][0]["collision_rate"], 0.0)

    def test_long_term_fairness_high(self):
        for row in self.r["sweep"]:
            self.assertGreater(row["jain_long"], 0.99)

    def test_short_term_fairness_degrades(self):
        self.assertGreater(self.r["sweep"][1]["jain_short"],
                           self.r["sweep"][-1]["jain_short"])

    def test_backoff_sequence_recorded(self):
        self.assertGreater(len(self.r["backoff_sequence"]["draws"]), 10)

    def test_backoff_within_cw_max(self):
        draws = self.r["backoff_sequence"]["draws"]
        self.assertLessEqual(max(draws), F.CW_MAX)

    def test_png_files(self):
        for name in ("03_dcf_sweep.png", "03_dcf_fairness.png",
                     "03_backoff_sequence.png"):
            self.assertTrue(os.path.exists(os.path.join(OUT, name)), name)

    def test_json_written(self):
        self.assertTrue(os.path.exists(os.path.join(OUT, "03_dcf.json")))


class TestHiddenScenario(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = S.exp_hidden()

    def test_three_node_both_configs(self):
        self.assertEqual(set(self.r["three_node"]), {"no_rts", "rts"})

    def test_hidden_collisions_detected(self):
        self.assertIn("hidden_terminal",
                      self.r["three_node"]["no_rts"]["collision_reasons"])

    def test_nav_freezes_with_rts(self):
        frozen = self.r["three_node"]["rts"]["nav_frozen_us"]
        self.assertGreater(max(frozen), 0.0)

    def test_no_nav_without_rts_for_hidden_station(self):
        frozen = self.r["three_node"]["no_rts"]["nav_frozen_us"]
        self.assertEqual(min(frozen[1:]), 0.0)

    def test_ring_four_rows(self):
        self.assertEqual(len(self.r["ring"]), 4)

    def test_gain_matrix_shape(self):
        gm = self.r["gain_matrix"]
        self.assertEqual(len(gm["gain"]), len(gm["rates"]))
        for row in gm["gain"]:
            self.assertEqual(len(row), len(gm["sizes"]))

    def test_gain_best_at_low_rate_large_frame(self):
        gm = self.r["gain_matrix"]
        i_low = gm["rates"].index(6.0)
        j_big = gm["sizes"].index(2304)
        self.assertGreater(gm["gain"][i_low][j_big], 1.2)

    def test_gain_worst_at_high_rate_small_frame(self):
        gm = self.r["gain_matrix"]
        i_hi = gm["rates"].index(54.0)
        j_small = gm["sizes"].index(500)
        self.assertLess(gm["gain"][i_hi][j_small], 1.0)

    def test_pcap_has_bad_fcs(self):
        self.assertGreater(self.r["pcap"]["bad_fcs_frames"], 0)

    def test_png_files(self):
        for name in ("04_rts_gain_heatmap.png", "04_hidden_ring.png",
                     "04_wasted_airtime.png"):
            self.assertTrue(os.path.exists(os.path.join(OUT, name)), name)

    def test_json_written(self):
        self.assertTrue(os.path.exists(os.path.join(OUT, "04_hidden.json")))


class TestEdcaScenario(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = S.exp_edca()

    def test_delay_ordering(self):
        # delay_ordering 按 ALL_ACS 顺序（BK, BE, VI, VO）排列，
        # 优先级越高时延越低，所以应该是**降序**
        d = self.r["delay_ordering"]
        self.assertEqual(d, sorted(d, reverse=True))
        self.assertGreater(d[0], d[-1])

    def test_vo_bk_ratio(self):
        self.assertGreater(self.r["vo_bk_ratio"], 2.0)

    def test_five_ablations(self):
        self.assertEqual(len(self.r["ablation"]), 5)

    def test_ablation_labels(self):
        labels = [row["config"] for row in self.r["ablation"]]
        self.assertEqual(labels[0], "完整 EDCA")
        self.assertIn("全部关掉（=4 个 DCF 队列）", labels)

    def test_full_edca_beats_homogeneous(self):
        """完整 EDCA 的 VO/BK 时延比必须显著高于"四个 DCF 队列"。

        注意不能拿"关掉 TXOP"那一行来比：关掉 TXOP 后大量 VO 帧
        在 7 次重传后被丢弃，存活帧的时延反而更低（幸存者偏差），
        这是本项目在 README 里明确记录的度量陷阱。
        """
        by_label = {row["config"]: row for row in self.r["ablation"]}
        full = by_label["完整 EDCA"]
        flat = by_label["全部关掉（=4 个 DCF 队列）"]
        r_full = full["bk_delay_us"] / max(full["vo_delay_us"], 1e-9)
        r_flat = flat["bk_delay_us"] / max(flat["vo_delay_us"], 1e-9)
        self.assertGreater(r_full, r_flat)
        self.assertGreater(r_full, 3.0)

    def test_tid_map(self):
        tm = self.r["tid_map"]
        self.assertEqual(tm["AC_VO"], [6, 7])
        self.assertEqual(tm["AC_BK"], [1, 2])

    def test_pcap_tids(self):
        p = os.path.join(OUT, "05_edca.pcap")
        _lt, packets = read_pcap(p)
        tids = set()
        for pkt in packets:
            _rt, mf = F.parse_frame(pkt.data)
            if mf.qos_tid is not None:
                tids.add(mf.qos_tid)
        self.assertTrue(tids <= {0, 2, 5, 6})
        self.assertGreater(len(tids), 1)

    def test_png_files(self):
        for name in ("05_edca_delay.png", "05_edca_ablation.png"):
            self.assertTrue(os.path.exists(os.path.join(OUT, name)), name)

    def test_json_written(self):
        self.assertTrue(os.path.exists(os.path.join(OUT, "05_edca.json")))


class TestAirtimeScenario(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = S.exp_airtime()

    def test_rate_scan_eight_rows(self):
        self.assertEqual(len(self.r["rate_scan"]), 8)

    def test_rate_scan_monotone_goodput(self):
        g = [row["goodput_mbps"] for row in self.r["rate_scan"]]
        self.assertEqual(g, sorted(g))

    def test_size_scan_seven_rows(self):
        self.assertEqual(len(self.r["size_scan"]), 7)

    def test_aggregation_seven_rows(self):
        self.assertEqual(len(self.r["aggregation"]), 7)

    def test_aggregation_gain_grows(self):
        g = [row["gain"] for row in self.r["aggregation"]]
        self.assertEqual(g, sorted(g))

    def test_small_frame_efficiency_terrible(self):
        self.assertLess(self.r["efficiency_44B"], 0.25)

    def test_large_frame_efficiency_better(self):
        self.assertGreater(self.r["efficiency_1500B"],
                           self.r["efficiency_44B"])

    def test_timing_breakdown(self):
        tb = self.r["example_timing"]
        self.assertEqual(tb["data_us"], 248.0)
        self.assertEqual(tb["ack_us"], 32.0)

    def test_single_station_timeline(self):
        self.assertGreater(len(self.r["single_station_timeline"]), 0)

    def test_png_files(self):
        for name in ("06_rate_scan.png", "06_size_scan.png",
                     "06_aggregation.png"):
            self.assertTrue(os.path.exists(os.path.join(OUT, name)), name)

    def test_json_written(self):
        self.assertTrue(os.path.exists(os.path.join(OUT, "06_airtime.json")))


class TestPcapScenario(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = S.exp_pcap()

    def test_linktype_127(self):
        self.assertEqual(self.r["mixed"]["linktype"], 127)

    def test_mixed_pcap_has_frames(self):
        self.assertGreater(self.r["mixed"]["packets"], 50)

    def test_frame_zoo_has_eight_frames(self):
        self.assertEqual(self.r["frame_zoo"]["packets"], 8)

    def test_frame_zoo_covers_all_types(self):
        kinds = self.r["frame_zoo"]["kinds"]
        for k in ("Management/Beacon", "Control/RTS", "Control/CTS",
                  "Control/ACK", "Data/QoS Data"):
            self.assertIn(k, kinds)

    def test_decode_ok(self):
        self.assertTrue(self.r["decode_ok"])
        self.assertGreater(len(self.r["decoded_sample"]), 5)

    def test_decoded_sample_has_bad_fcs(self):
        self.assertTrue(any(d["bad_fcs"] for d in self.r["decoded_sample"]))

    def test_display_filters_listed(self):
        self.assertGreaterEqual(len(self.r["display_filters"]), 10)
        self.assertIn("wlan_radio.fcs_bad == 1", self.r["display_filters"])

    def test_pcaps_readable(self):
        for name in ("07_wlan_full.pcap", "07_wlan_frames.pcap"):
            linktype, packets = read_pcap(os.path.join(OUT, name))
            self.assertEqual(linktype, 127)
            self.assertGreater(len(packets), 0)

    def test_json_written(self):
        self.assertTrue(os.path.exists(os.path.join(OUT, "07_pcap.json")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
