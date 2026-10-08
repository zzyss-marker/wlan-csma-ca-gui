"""802.11e EDCA 的单元测试。"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _ctx import OUT  # noqa: E402,F401

from wlanlab import edca as E  # noqa: E402
from wlanlab import frame as F  # noqa: E402

AP = "02:00:00:00:00:ff"


class TestAccessCategoryParameters(unittest.TestCase):
    def test_four_categories(self):
        self.assertEqual(len(E.ALL_ACS), 4)

    def test_names(self):
        self.assertEqual([a.name for a in E.ALL_ACS],
                         ["AC_BK", "AC_BE", "AC_VI", "AC_VO"])

    def test_aifsn_values(self):
        self.assertEqual(E.AC_BK.aifsn, 7)
        self.assertEqual(E.AC_BE.aifsn, 3)
        self.assertEqual(E.AC_VI.aifsn, 2)
        self.assertEqual(E.AC_VO.aifsn, 2)

    def test_cw_min_values(self):
        self.assertEqual(E.AC_BK.cw_min, 15)
        self.assertEqual(E.AC_BE.cw_min, 15)
        self.assertEqual(E.AC_VI.cw_min, 7)
        self.assertEqual(E.AC_VO.cw_min, 3)

    def test_cw_max_values(self):
        self.assertEqual(E.AC_VO.cw_max, 7)
        self.assertEqual(E.AC_VI.cw_max, 15)
        self.assertEqual(E.AC_BE.cw_max, 1023)
        self.assertEqual(E.AC_BK.cw_max, 1023)

    def test_txop_values(self):
        self.assertEqual(E.AC_VO.txop_us, 1504.0)
        self.assertEqual(E.AC_VI.txop_us, 3008.0)
        self.assertEqual(E.AC_BE.txop_us, 0.0)
        self.assertEqual(E.AC_BK.txop_us, 0.0)

    def test_priority_ordering(self):
        self.assertLess(E.AC_BK.priority, E.AC_BE.priority)
        self.assertLess(E.AC_BE.priority, E.AC_VI.priority)
        self.assertLess(E.AC_VI.priority, E.AC_VO.priority)

    def test_aifs_us_formula(self):
        self.assertEqual(E.AC_VO.aifs_us(), 16.0 + 2 * 9.0)
        self.assertEqual(E.AC_BK.aifs_us(), 16.0 + 7 * 9.0)

    def test_be_aifs_is_difs_plus_one_slot(self):
        # AC_BE 的 AIFSN=3，比 DIFS（AIFSN=2）多等一个时隙
        self.assertEqual(E.AC_BE.aifs_us(), F.DIFS + F.SLOT_TIME)

    def test_vo_aifs_equals_difs(self):
        self.assertEqual(E.AC_VO.aifs_us(), F.DIFS)

    def test_bk_aifs_is_largest(self):
        self.assertGreater(E.AC_BK.aifs_us(), E.AC_BE.aifs_us())

    def test_describe(self):
        d = E.AC_VO.describe()
        self.assertIn("AC_VO", d)
        self.assertIn("AIFSN=2", d)

    def test_by_name_lookup(self):
        self.assertIs(E.AC_BY_NAME["AC_VI"], E.AC_VI)


class TestTidMapping(unittest.TestCase):
    def test_vo_tids(self):
        for tid in (6, 7):
            self.assertIs(E.ac_for_tid(tid), E.AC_VO)

    def test_vi_tids(self):
        for tid in (4, 5):
            self.assertIs(E.ac_for_tid(tid), E.AC_VI)

    def test_be_tids(self):
        for tid in (0, 3):
            self.assertIs(E.ac_for_tid(tid), E.AC_BE)

    def test_bk_tids(self):
        for tid in (1, 2):
            self.assertIs(E.ac_for_tid(tid), E.AC_BK)

    def test_unknown_tid_defaults_be(self):
        self.assertIs(E.ac_for_tid(99), E.AC_BE)

    def test_ac_by_tid_covers_0_to_7(self):
        for tid in range(8):
            self.assertIn(tid, E.AC_BY_TID)

    def test_up_mapping_matches_tid(self):
        self.assertEqual(E.AC_BY_UP, E.AC_BY_TID)

    def test_dscp_ef_is_voice(self):
        self.assertIs(E.ac_for_dscp(46), E.AC_VO)

    def test_dscp_af41_is_video(self):
        self.assertIs(E.ac_for_dscp(34), E.AC_VI)

    def test_dscp_cs1_is_background(self):
        self.assertIs(E.ac_for_dscp(8), E.AC_BK)

    def test_dscp_default_best_effort(self):
        self.assertIs(E.ac_for_dscp(0), E.AC_BE)


class TestAcQueue(unittest.TestCase):
    def test_cw_starts_at_min(self):
        q = E.AcQueue(station="A", mac="02:00:00:00:00:01", ac=E.AC_VO)
        self.assertEqual(q.cw, E.AC_VO.cw_min)

    def test_key_format(self):
        q = E.AcQueue(station="A", mac="02:00:00:00:00:01", ac=E.AC_VO)
        self.assertEqual(q.key, "A/AC_VO")

    def test_collision_doubles_cw(self):
        q = E.AcQueue(station="A", mac="m", ac=E.AC_VO)
        q.on_collision()
        self.assertEqual(q.cw, 2 * E.AC_VO.cw_min + 1)

    def test_cw_capped_at_ac_max(self):
        q = E.AcQueue(station="A", mac="m", ac=E.AC_VO)
        for _ in range(10):
            q.on_collision()
        self.assertEqual(q.cw, E.AC_VO.cw_max)

    def test_virtual_collision_counted_separately(self):
        q = E.AcQueue(station="A", mac="m", ac=E.AC_BE)
        q.on_virtual_collision()
        self.assertEqual(q.virtual_collisions, 1)
        self.assertEqual(q.collisions, 0)

    def test_success_resets(self):
        q = E.AcQueue(station="A", mac="m", ac=E.AC_VI)
        q.on_collision()
        q.on_success()
        self.assertEqual(q.cw, E.AC_VI.cw_min)

    def test_jitter_recorded(self):
        q = E.AcQueue(station="A", mac="m", ac=E.AC_BE)
        q.record_delay(100.0)
        q.record_delay(150.0)
        self.assertEqual(q.jitter_us, [50.0])

    def test_first_delay_has_no_jitter(self):
        q = E.AcQueue(station="A", mac="m", ac=E.AC_BE)
        q.record_delay(100.0)
        self.assertEqual(q.jitter_us, [])

    def test_stats_keys(self):
        q = E.AcQueue(station="A", mac="m", ac=E.AC_BE)
        for k in ("ac", "priority", "avg_delay_us", "p95_delay_us",
                  "avg_jitter_us", "virtual_collisions", "txop_bursts"):
            self.assertIn(k, q.stats())


class TestPercentile(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(E._percentile([], 0.5), 0.0)

    def test_single(self):
        self.assertEqual(E._percentile([7.0], 0.95), 7.0)

    def test_median(self):
        self.assertAlmostEqual(E._percentile([1, 2, 3, 4], 0.5), 2.5)

    def test_p95_high(self):
        vals = list(range(1, 101))
        self.assertGreater(E._percentile(vals, 0.95), 90)

    def test_p0_is_min(self):
        self.assertEqual(E._percentile([5, 1, 9], 0.0), 1)


class TestEdcaSimulator(unittest.TestCase):
    def _run(self, n=3, seed=5, frames=20, **kwargs):
        sim, ap, stas = E.build_edca_bss(n_stations=n, seed=seed, **kwargs)
        for name in stas:
            for ac, tid in ((E.AC_VO, 6), (E.AC_VI, 5), (E.AC_BE, 0),
                            (E.AC_BK, 2)):
                for _ in range(frames):
                    sim.enqueue(name, ac, AP, 1000, tid=tid)
        return sim, sim.run()

    def test_all_frames_finished(self):
        sim, r = self._run()
        self.assertEqual(r["completed_frames"] + r["dropped_frames"],
                         r["target_frames"])

    def test_all_four_acs_present(self):
        _sim, r = self._run()
        self.assertEqual(set(r["per_ac"]), {"AC_BK", "AC_BE", "AC_VI", "AC_VO"})

    def test_voice_lowest_delay(self):
        _sim, r = self._run()
        vo = r["per_ac"]["AC_VO"]["avg_delay_us"]
        bk = r["per_ac"]["AC_BK"]["avg_delay_us"]
        self.assertLess(vo, bk)

    def test_priority_ordering_of_delay(self):
        _sim, r = self._run()
        d = [r["per_ac"][k]["avg_delay_us"]
             for k in ("AC_VO", "AC_VI", "AC_BE", "AC_BK")]
        self.assertEqual(d, sorted(d))

    def test_vo_bk_ratio_above_two(self):
        _sim, r = self._run()
        ratio = (r["per_ac"]["AC_BK"]["avg_delay_us"]
                 / r["per_ac"]["AC_VO"]["avg_delay_us"])
        self.assertGreater(ratio, 2.0)

    def test_aifs_values_in_result(self):
        _sim, r = self._run()
        self.assertEqual(r["per_ac"]["AC_VO"]["aifs_us"], 34.0)
        self.assertEqual(r["per_ac"]["AC_BK"]["aifs_us"], 79.0)

    def test_homogeneous_removes_priority(self):
        _sim, full = self._run()
        _sim2, flat = self._run(homogeneous=True)
        full_ratio = (full["per_ac"]["AC_BK"]["avg_delay_us"]
                      / full["per_ac"]["AC_VO"]["avg_delay_us"])
        flat_ratio = (flat["per_ac"]["AC_BK"]["avg_delay_us"]
                      / flat["per_ac"]["AC_VO"]["avg_delay_us"])
        self.assertGreater(full_ratio, flat_ratio)

    def test_disabling_cw_raises_voice_delay(self):
        _sim, full = self._run()
        _sim2, no_cw = self._run(enable_cw=False)
        self.assertGreater(no_cw["per_ac"]["AC_VO"]["avg_delay_us"],
                           full["per_ac"]["AC_VO"]["avg_delay_us"])

    def test_disabling_aifs_raises_background_relative_delay(self):
        _sim, full = self._run()
        _sim2, no_aifs = self._run(enable_aifs=False)
        self.assertGreater(no_aifs["per_ac"]["AC_BE"]["avg_delay_us"],
                           full["per_ac"]["AC_BE"]["avg_delay_us"])

    def test_txop_bursts_happen_for_voice(self):
        _sim, r = self._run()
        bursts = sum(q["txop_bursts"] for q in r["per_queue"]
                     if q["ac"] == "AC_VO")
        self.assertGreater(bursts, 0)

    def test_no_txop_bursts_when_disabled(self):
        _sim, r = self._run(enable_txop=False)
        self.assertEqual(sum(q["txop_bursts"] for q in r["per_queue"]), 0)

    def test_no_txop_for_best_effort(self):
        _sim, r = self._run()
        self.assertEqual(sum(q["txop_bursts"] for q in r["per_queue"]
                             if q["ac"] == "AC_BE"), 0)

    def test_virtual_collisions_occur(self):
        _sim, r = self._run()
        self.assertGreater(sum(q["virtual_collisions"] for q in r["per_queue"]),
                           0)

    def test_deterministic(self):
        _s1, r1 = self._run(seed=9)
        _s2, r2 = self._run(seed=9)
        self.assertEqual(r1["elapsed_us"], r2["elapsed_us"])

    def test_different_seeds_differ(self):
        _s1, r1 = self._run(seed=1)
        _s2, r2 = self._run(seed=2)
        self.assertNotEqual(r1["elapsed_us"], r2["elapsed_us"])

    def test_throughput_below_nominal(self):
        _sim, r = self._run()
        self.assertLess(r["throughput_mbps"], 54.0)

    def test_channel_utilization_bounded(self):
        _sim, r = self._run()
        self.assertLess(r["channel_utilization"], 1.0)

    def test_p95_at_least_average(self):
        _sim, r = self._run()
        for ac in ("AC_VO", "AC_VI", "AC_BE", "AC_BK"):
            self.assertGreaterEqual(r["per_ac"][ac]["p95_delay_us"],
                                    r["per_ac"][ac]["avg_delay_us"])

    def test_mac_registered(self):
        sim, ap, stas = E.build_edca_bss(2, seed=1)
        self.assertEqual(sim.macs["AP"], AP)
        self.assertEqual(sim.macs["STA-A"], "02:00:00:00:00:01")

    def test_macs_not_shared_between_instances(self):
        a, _ap, _stas = E.build_edca_bss(1, seed=1)
        b, _ap2, _stas2 = E.build_edca_bss(3, seed=1)
        self.assertEqual(len(a.macs), 2)
        self.assertEqual(len(b.macs), 4)

    def test_queue_for_reuses_queue(self):
        sim, ap, stas = E.build_edca_bss(1, seed=1)
        q1 = sim.queue_for("STA-A", E.AC_VO)
        q2 = sim.queue_for("STA-A", E.AC_VO)
        self.assertIs(q1, q2)

    def test_queue_mac_is_set(self):
        sim, ap, stas = E.build_edca_bss(1, seed=1)
        q = sim.queue_for("STA-A", E.AC_VO)
        self.assertEqual(q.mac, "02:00:00:00:00:01")

    def test_voice_has_more_collisions_than_background(self):
        """CWmin=3 很激进：VO 用更高的碰撞率换更低的时延。"""
        _sim, r = self._run(frames=30)
        self.assertGreater(r["per_ac"]["AC_VO"]["collision_rate"],
                           r["per_ac"]["AC_BK"]["collision_rate"])

    def test_timeline_has_tid(self):
        sim, r = self._run(frames=5)
        rows = sim.timeline()
        self.assertTrue(all("tid" in row for row in rows))

    def test_pcap_frames_parse(self):
        sim, r = self._run(frames=5)
        frames = sim.pcap_frames()
        self.assertGreater(len(frames), 0)
        for _t, raw in frames[:5]:
            _rt, mf = F.parse_frame(raw)
            self.assertIn(mf.fc.type, (F.FRAME_TYPE_DATA, F.FRAME_TYPE_CTRL))

    def test_pcap_tids_cover_all_acs(self):
        sim, r = self._run(frames=5)
        tids = set()
        for _t, raw in sim.pcap_frames():
            _rt, mf = F.parse_frame(raw)
            if mf.qos_tid is not None:
                tids.add(mf.qos_tid)
        self.assertEqual(tids, {0, 2, 5, 6})

    def test_collision_trace_reasons(self):
        sim, r = self._run(frames=30)
        reasons = {t["reason"] for t in r["collision_trace"]}
        self.assertTrue(reasons <= {"virtual_collision", "hidden_terminal",
                                    "same_slot"})

    def test_single_station_no_air_collisions(self):
        sim, ap, stas = E.build_edca_bss(1, seed=1)
        for ac, tid in ((E.AC_VO, 6), (E.AC_VI, 5), (E.AC_BE, 0), (E.AC_BK, 2)):
            for _ in range(10):
                sim.enqueue("STA-A", ac, AP, 500, tid=tid)
        r = sim.run()
        self.assertEqual(r["dropped_frames"], 0)
        self.assertEqual(sum(v["collisions"] for v in r["per_ac"].values()), 0)

    def test_single_station_still_has_virtual_collisions(self):
        sim, ap, stas = E.build_edca_bss(1, seed=1)
        for ac, tid in ((E.AC_VO, 6), (E.AC_VI, 5), (E.AC_BE, 0), (E.AC_BK, 2)):
            for _ in range(10):
                sim.enqueue("STA-A", ac, AP, 500, tid=tid)
        r = sim.run()
        self.assertGreater(sum(v["virtual_collisions"]
                               for v in r["per_ac"].values()), 0)

    def test_traffic_mix_helper(self):
        sim, ap, stas = E.build_edca_bss(2, seed=1)
        E.traffic_mix(sim, stas, AP, n_vo=3, n_vi=2, n_be=1, n_bk=1)
        self.assertEqual(sim._target, 2 * (3 + 2 + 1 + 1))

    def test_empty_run_terminates(self):
        sim, ap, stas = E.build_edca_bss(2, seed=1)
        r = sim.run()
        self.assertEqual(r["completed_frames"], 0)

    def test_priority_field_in_per_ac(self):
        _sim, r = self._run(frames=5)
        self.assertEqual(r["per_ac"]["AC_VO"]["priority"], 3)
        self.assertEqual(r["per_ac"]["AC_BK"]["priority"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
