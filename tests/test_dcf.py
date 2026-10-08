"""DCF 离散事件仿真的单元测试。"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _ctx import OUT  # noqa: E402,F401

from wlanlab import dcf as D  # noqa: E402
from wlanlab import frame as F  # noqa: E402
from wlanlab import phy  # noqa: E402

AP = "02:00:00:00:00:ff"


def make_sim(n=2, seed=42, **kwargs):
    return D.build_bss(n_stations=n, spacing_m=20.0, seed=seed, **kwargs)


def fill(sim, stas, frames=30, size=1500, ap=None):
    ap = ap or sim.stations[0]
    for s in stas:
        for _ in range(frames):
            sim.enqueue(s, ap.mac, size)


class TestJain(unittest.TestCase):
    def test_perfect_fairness(self):
        self.assertAlmostEqual(D.jain([10, 10, 10]), 1.0)

    def test_one_dominant(self):
        self.assertAlmostEqual(D.jain([100, 0, 0]), 1 / 3, places=6)

    def test_two_equal(self):
        self.assertAlmostEqual(D.jain([5, 5]), 1.0)

    def test_empty(self):
        self.assertEqual(D.jain([]), 0.0)

    def test_all_zero(self):
        self.assertEqual(D.jain([0, 0]), 0.0)

    def test_between_bounds(self):
        for vals in ([1, 2, 3], [1, 1, 100], [7, 7, 7, 7]):
            j = D.jain(vals)
            self.assertGreater(j, 0.0)
            self.assertLessEqual(j, 1.0)

    def test_scale_invariant(self):
        self.assertAlmostEqual(D.jain([1, 2, 3]), D.jain([10, 20, 30]))


class TestStation(unittest.TestCase):
    def test_initial_state(self):
        st = D.Station(name="A", mac="02:00:00:00:00:01")
        self.assertEqual(st.cw, F.CW_MIN)
        self.assertIsNone(st.backoff)
        self.assertFalse(st.pending)

    def test_enqueue_marks_pending(self):
        st = D.Station(name="A", mac="02:00:00:00:00:01")
        st.enqueue(D.PendingFrame("a", "b", b"x"), 0.0)
        self.assertTrue(st.pending)

    def test_draw_backoff_in_range(self):
        st = D.Station(name="A", mac="02:00:00:00:00:01")
        import random
        rng = random.Random(1)
        for _ in range(200):
            v = st.draw_backoff(rng)
            self.assertGreaterEqual(v, 0)
            self.assertLessEqual(v, st.cw)

    def test_collision_doubles_cw(self):
        st = D.Station(name="A", mac="02:00:00:00:00:01")
        st.on_collision()
        self.assertEqual(st.cw, 2 * F.CW_MIN + 1)

    def test_cw_capped(self):
        st = D.Station(name="A", mac="02:00:00:00:00:01")
        for _ in range(20):
            st.on_collision()
        self.assertEqual(st.cw, F.CW_MAX)

    def test_success_resets_cw(self):
        st = D.Station(name="A", mac="02:00:00:00:00:01")
        st.on_collision()
        st.on_success()
        self.assertEqual(st.cw, F.CW_MIN)

    def test_retransmit_counter(self):
        st = D.Station(name="A", mac="02:00:00:00:00:01")
        st.on_collision()
        st.on_collision()
        self.assertEqual(st.retransmits, 2)

    def test_mac_len_is_26_plus_payload(self):
        pf = D.PendingFrame("a", "b", b"\x00" * 100)
        self.assertEqual(pf.mac_len, 126)

    def test_stats_keys(self):
        st = D.Station(name="A", mac="02:00:00:00:00:01")
        for k in ("station", "successes", "collisions", "collision_rate",
                  "avg_backoff_slots", "nav_frozen_us", "dropped"):
            self.assertIn(k, st.stats())

    def test_collision_rate_zero_when_no_attempts(self):
        st = D.Station(name="A", mac="02:00:00:00:00:01")
        self.assertEqual(st.stats()["collision_rate"], 0.0)


class TestChannelModel(unittest.TestCase):
    def test_can_hear_within_range(self):
        sim = D.DcfSimulator(range_m=100)
        a = sim.add_station("A", "02:00:00:00:00:01", x=0)
        b = sim.add_station("B", "02:00:00:00:00:02", x=50)
        self.assertTrue(sim.can_hear(a, b))
        self.assertTrue(sim.can_hear(b, a))

    def test_cannot_hear_beyond_range(self):
        sim = D.DcfSimulator(range_m=100)
        a = sim.add_station("A", "02:00:00:00:00:01", x=0)
        c = sim.add_station("C", "02:00:00:00:00:03", x=160)
        self.assertFalse(sim.can_hear(a, c))

    def test_self_never_hears(self):
        sim = D.DcfSimulator()
        a = sim.add_station("A", "02:00:00:00:00:01")
        self.assertFalse(sim.can_hear(a, a))

    def test_receivers_excludes_self(self):
        sim, ap, stas = make_sim(2)
        self.assertNotIn(stas[0], sim._receivers(stas[0]))

    def test_collides_two_visible_senders(self):
        sim, ap, stas = make_sim(2)
        self.assertTrue(sim._collides(stas))

    def test_no_collision_when_mutually_hidden_without_shared_rx(self):
        sim = D.DcfSimulator(range_m=50)
        a = sim.add_station("A", "02:00:00:00:00:01", x=0)
        b = sim.add_station("B", "02:00:00:00:00:02", x=200)
        self.assertFalse(sim._collides([a, b]))

    def test_hidden_terminals_do_collide_at_ap(self):
        sim, ap, a, c = D.build_hidden_terminal()
        self.assertFalse(sim.can_hear(a, c))
        self.assertTrue(sim.can_hear(a, ap))
        self.assertTrue(sim.can_hear(c, ap))
        self.assertTrue(sim._collides([a, c]))

    def test_ring_neighbours_are_hidden(self):
        sim, ap, stas = D.build_hidden_ring(n_stations=4, radius_m=80.0)
        for i in range(len(stas)):
            for j in range(i + 1, len(stas)):
                self.assertFalse(sim.can_hear(stas[i], stas[j]),
                                 f"{stas[i].name} 不该听到 {stas[j].name}")
                self.assertTrue(sim.can_hear(stas[i], ap))

    def test_ring_spacing_math(self):
        import math
        self.assertAlmostEqual(2 * 80 * math.sin(math.pi / 4), 113.137, places=3)


class TestAirtimeHelpers(unittest.TestCase):
    def test_data_airtime_matches_phy(self):
        sim = D.DcfSimulator(rate_mbps=54.0)
        self.assertEqual(sim.data_airtime(1500), phy.airtime_us(1500, 54.0))

    def test_ack_airtime(self):
        sim = D.DcfSimulator(ctrl_rate_mbps=24.0)
        self.assertEqual(sim.ack_airtime(), phy.ack_airtime_us(24.0))

    def test_rts_shorter_than_cts_equal_here(self):
        sim = D.DcfSimulator()
        self.assertLess(sim.rts_airtime(), sim.data_airtime(1500))

    def test_cts_airtime_positive(self):
        self.assertGreater(D.DcfSimulator().cts_airtime(), 0)


class TestSimulationBasics(unittest.TestCase):
    def test_single_station_all_frames_delivered(self):
        sim, ap, stas = make_sim(1)
        fill(sim, stas, frames=20)
        r = sim.run()
        self.assertEqual(r["completed_frames"], 20)
        self.assertEqual(r["dropped_frames"], 0)

    def test_single_station_no_collisions(self):
        sim, ap, stas = make_sim(1)
        fill(sim, stas, frames=20)
        r = sim.run()
        self.assertEqual(r["collisions"], 0)

    def test_two_stations_all_delivered(self):
        sim, ap, stas = make_sim(2)
        fill(sim, stas, frames=25)
        r = sim.run()
        self.assertEqual(r["completed_frames"] + r["dropped_frames"], 50)

    def test_deterministic_with_same_seed(self):
        a = make_sim(4, seed=7)
        fill(a[0], a[2], frames=15)
        b = make_sim(4, seed=7)
        fill(b[0], b[2], frames=15)
        self.assertEqual(a[0].run()["elapsed_us"], b[0].run()["elapsed_us"])

    def test_different_seed_differs(self):
        a = make_sim(4, seed=1)
        fill(a[0], a[2], frames=15)
        b = make_sim(4, seed=2)
        fill(b[0], b[2], frames=15)
        self.assertNotEqual(a[0].run()["elapsed_us"],
                            b[0].run()["elapsed_us"])

    def test_no_frames_terminates(self):
        sim, ap, stas = make_sim(2)
        r = sim.run()
        self.assertEqual(r["completed_frames"], 0)

    def test_throughput_below_nominal_rate(self):
        sim, ap, stas = make_sim(1)
        fill(sim, stas, frames=30)
        r = sim.run()
        self.assertLess(r["throughput_mbps"], 54.0)

    def test_channel_utilization_below_one(self):
        sim, ap, stas = make_sim(4)
        fill(sim, stas, frames=30)
        self.assertLess(sim.run()["channel_utilization"], 1.0)

    def test_attempts_consistency(self):
        sim, ap, stas = make_sim(3)
        fill(sim, stas, frames=20)
        r = sim.run()
        self.assertEqual(r["attempts"],
                         r["completed_frames"] + r["collisions"])

    def test_collisions_increase_with_stations(self):
        rates = []
        for n in (1, 4, 8):
            sim, ap, stas = make_sim(n, seed=5)
            fill(sim, stas, frames=40)
            rates.append(sim.run()["collision_rate"])
        self.assertLess(rates[0], rates[1])
        self.assertLess(rates[1], rates[2])

    def test_throughput_degrades_at_high_density(self):
        t2 = None
        t16 = None
        for n in (2, 16):
            sim, ap, stas = make_sim(n, seed=5)
            fill(sim, stas, frames=60)
            r = sim.run()
            if n == 2:
                t2 = r["throughput_mbps"]
            else:
                t16 = r["throughput_mbps"]
        self.assertGreater(t2, t16)

    def test_elapsed_grows_with_stations(self):
        e = []
        for n in (1, 8):
            sim, ap, stas = make_sim(n, seed=5)
            fill(sim, stas, frames=40)
            e.append(sim.run()["elapsed_us"])
        self.assertLess(e[0], e[1])

    def test_avg_backoff_grows_with_collisions(self):
        b = []
        for n in (1, 8):
            sim, ap, stas = make_sim(n, seed=5)
            fill(sim, stas, frames=40)
            r = sim.run()
            b.append(sum(s["avg_backoff_slots"] for s in r["per_station"]) / n)
        self.assertLess(b[0], b[1])


class TestFairness(unittest.TestCase):
    def test_long_term_fairness_is_one(self):
        sim, ap, stas = make_sim(4)
        fill(sim, stas, frames=30)
        self.assertAlmostEqual(sim.run()["jain_fairness"], 1.0, places=4)

    def test_short_term_fairness_degrades(self):
        # 短时公平性只看前 25% 的成功传输，样本小、方差大，
        # 必须拉开站点数差距（2 vs 16）才能稳定观察到退化。
        vals = []
        for n in (2, 16):
            sim, ap, stas = make_sim(n, seed=5)
            fill(sim, stas, frames=80)
            vals.append(sim.run()["jain_fairness_short_term"])
        self.assertGreater(vals[0], vals[1])

    def test_short_term_between_zero_and_one(self):
        sim, ap, stas = make_sim(6)
        fill(sim, stas, frames=40)
        j = sim.run()["jain_fairness_short_term"]
        self.assertGreater(j, 0.0)
        self.assertLessEqual(j, 1.0)

    def test_short_term_empty_sim(self):
        sim, ap, stas = make_sim(2)
        self.assertEqual(sim.short_term_fairness(), 0.0)

    def test_short_term_fraction_one_equals_long_term(self):
        sim, ap, stas = make_sim(4)
        fill(sim, stas, frames=30)
        sim.run()
        self.assertAlmostEqual(sim.short_term_fairness(1.0),
                               sim.result()["jain_fairness"], places=6)

    def test_all_stations_get_some_frames(self):
        sim, ap, stas = make_sim(6)
        fill(sim, stas, frames=40)
        r = sim.run()
        for row in r["per_station"]:
            if row["station"] == "AP":
                continue
            self.assertGreater(row["successes"], 0)


class TestHiddenTerminal(unittest.TestCase):
    def test_hidden_terminal_causes_collisions(self):
        sim, ap, a, c = D.build_hidden_terminal(seed=7, rts_threshold=0)
        for _ in range(120):
            sim.enqueue(a, ap.mac, 1500)
            sim.enqueue(c, ap.mac, 1500)
        sim.run()
        reasons = {t["reason"] for t in sim._collision_trace}
        self.assertIn("hidden_terminal", reasons)

    def test_no_hidden_collisions_when_all_visible(self):
        sim, ap, stas = make_sim(3, seed=7)
        fill(sim, stas, frames=40)
        sim.run()
        reasons = {t["reason"] for t in sim._collision_trace}
        self.assertNotIn("hidden_terminal", reasons)

    def test_nav_freezes_stations_with_rts(self):
        sim, ap, a, c = D.build_hidden_terminal(seed=7, use_rts=True,
                                                rts_threshold=0)
        for _ in range(120):
            sim.enqueue(a, ap.mac, 1500)
            sim.enqueue(c, ap.mac, 1500)
        r = sim.run()
        frozen = [s["nav_frozen_us"] for s in r["per_station"]]
        self.assertGreater(max(frozen), 0.0)

    def test_hidden_station_is_frozen_by_cts(self):
        """C 听不到 A，但听得到 AP 的 CTS —— 这正是 RTS/CTS 救场的地方。"""
        sim, ap, a, c = D.build_hidden_terminal(seed=7, use_rts=True,
                                                rts_threshold=0)
        for _ in range(120):
            sim.enqueue(a, ap.mac, 1500)
            sim.enqueue(c, ap.mac, 1500)
        sim.run()
        self.assertGreater(c.nav_frozen_us, 0.0)
        self.assertGreater(ap.nav_frozen_us, 0.0)

    def test_rts_reduces_wasted_airtime_in_ring(self):
        wasted = {}
        for rts in (False, True):
            sim, ap, stas = D.build_hidden_ring(n_stations=8, seed=13,
                                                use_rts=rts, rts_threshold=0,
                                                rate_mbps=6.0)
            for s in stas:
                for _ in range(80):
                    sim.enqueue(s, ap.mac, 2304)
            wasted[rts] = sim.run()["wasted_ratio"]
        self.assertLess(wasted[True], wasted[False])

    def test_rts_wins_at_low_rate_large_frames(self):
        thr = {}
        for rts in (False, True):
            sim, ap, stas = D.build_hidden_ring(n_stations=8, seed=13,
                                                use_rts=rts, rts_threshold=0,
                                                rate_mbps=6.0)
            for s in stas:
                for _ in range(80):
                    sim.enqueue(s, ap.mac, 2304)
            thr[rts] = sim.run()["throughput_mbps"]
        self.assertGreater(thr[True], thr[False])

    def test_rts_loses_at_high_rate_small_frames(self):
        thr = {}
        for rts in (False, True):
            sim, ap, stas = D.build_hidden_ring(n_stations=8, seed=13,
                                                use_rts=rts, rts_threshold=0,
                                                rate_mbps=54.0)
            for s in stas:
                for _ in range(80):
                    sim.enqueue(s, ap.mac, 200)
            thr[rts] = sim.run()["throughput_mbps"]
        self.assertLess(thr[True], thr[False])

    def test_rts_threshold_disables_rts_for_small_frames(self):
        sim, ap, a, c = D.build_hidden_terminal(seed=7, use_rts=True,
                                                rts_threshold=2000)
        for _ in range(60):
            sim.enqueue(a, ap.mac, 500)
            sim.enqueue(c, ap.mac, 500)
        sim.run()
        self.assertFalse(any(e.kind == "rts" for e in sim.events))

    def test_rts_emitted_above_threshold(self):
        sim, ap, a, c = D.build_hidden_terminal(seed=7, use_rts=True,
                                                rts_threshold=0)
        for _ in range(60):
            sim.enqueue(a, ap.mac, 1500)
            sim.enqueue(c, ap.mac, 1500)
        sim.run()
        self.assertTrue(any(e.kind == "rts" for e in sim.events))
        self.assertTrue(any(e.kind == "cts" for e in sim.events))

    def test_rts_phase_collision_is_short(self):
        sim, ap, stas = D.build_hidden_ring(n_stations=6, seed=13,
                                            use_rts=True, rts_threshold=0)
        for s in stas:
            for _ in range(80):
                sim.enqueue(s, ap.mac, 1500)
        sim.run()
        reasons = {t["reason"] for t in sim._collision_trace}
        self.assertTrue(reasons & {"rts_phase", "same_slot"})


class TestPcapExport(unittest.TestCase):
    def test_pcap_frames_not_empty(self):
        sim, ap, stas = make_sim(2)
        fill(sim, stas, frames=10)
        sim.run()
        self.assertGreater(len(sim.pcap_frames()), 0)

    def test_pcap_has_ack_frames(self):
        sim, ap, stas = make_sim(2)
        fill(sim, stas, frames=10)
        sim.run()
        kinds = set()
        for _t, raw in sim.pcap_frames():
            _, mf = F.parse_frame(raw)
            kinds.add(mf.fc.subtype_name)
        self.assertIn("ACK", kinds)
        self.assertIn("QoS Data", kinds)

    def test_collision_frames_marked_bad_fcs(self):
        sim, ap, a, c = D.build_hidden_terminal(seed=7, rts_threshold=0)
        for _ in range(80):
            sim.enqueue(a, ap.mac, 1500)
            sim.enqueue(c, ap.mac, 1500)
        sim.run()
        bad = 0
        for _t, raw in sim.pcap_frames():
            rt, _mf = F.parse_frame(raw)
            if rt.flags & F.RT_FLAG_BAD_FCS:
                bad += 1
        self.assertGreater(bad, 0)

    def test_retry_bit_set_on_retransmission(self):
        sim, ap, a, c = D.build_hidden_terminal(seed=7, rts_threshold=0)
        for _ in range(80):
            sim.enqueue(a, ap.mac, 1500)
            sim.enqueue(c, ap.mac, 1500)
        sim.run()
        retries = sum(1 for _t, raw in sim.pcap_frames()
                      if F.parse_frame(raw)[1].fc.retry)
        self.assertGreater(retries, 0)

    def test_pcap_timestamps_monotone_in_seconds(self):
        sim, ap, stas = make_sim(2)
        fill(sim, stas, frames=10)
        sim.run()
        ts = [t for t, _ in sim.pcap_frames()]
        self.assertEqual(ts, sorted(ts))
        self.assertLess(max(ts), 1.0)

    def test_timeline_has_expected_keys(self):
        sim, ap, stas = make_sim(1)
        fill(sim, stas, frames=5)
        sim.run()
        row = sim.timeline()[0]
        for k in ("t_start_us", "t_end_us", "kind", "src", "dst", "length"):
            self.assertIn(k, row)


class TestEdgeCases(unittest.TestCase):
    def test_max_time_stops_run(self):
        sim, ap, stas = make_sim(8)
        fill(sim, stas, frames=200)
        r = sim.run(max_time_us=1000.0)
        self.assertLess(r["elapsed_us"], 100000.0)

    def test_drop_after_retry_limit(self):
        sim = D.DcfSimulator(seed=3, max_retries=0)
        ap = sim.add_station("AP", AP, is_ap=True)
        a = sim.add_station("A", "02:00:00:00:00:01", x=0)
        b = sim.add_station("B", "02:00:00:00:00:02", x=10)
        for _ in range(40):
            sim.enqueue(a, ap.mac, 1500)
            sim.enqueue(b, ap.mac, 1500)
        r = sim.run()
        self.assertGreater(r["dropped_frames"], 0)

    def test_finished_counter_matches_target(self):
        sim, ap, stas = make_sim(3)
        fill(sim, stas, frames=20)
        r = sim.run()
        self.assertEqual(r["completed_frames"] + r["dropped_frames"],
                         r["target_frames"])

    def test_result_keys(self):
        sim, ap, stas = make_sim(2)
        fill(sim, stas, frames=5)
        r = sim.run()
        for k in ("seed", "throughput_mbps", "collision_rate", "wasted_us",
                  "wasted_ratio", "jain_fairness", "per_station", "rts_cts"):
            self.assertIn(k, r)

    def test_wasted_ratio_zero_without_collisions(self):
        sim, ap, stas = make_sim(1)
        fill(sim, stas, frames=20)
        self.assertEqual(sim.run()["wasted_ratio"], 0.0)

    def test_larger_frames_take_longer(self):
        times = []
        for size in (200, 1500):
            sim, ap, stas = make_sim(1)
            fill(sim, stas, frames=20, size=size)
            times.append(sim.run()["elapsed_us"])
        self.assertLess(times[0], times[1])

    def test_lower_rate_takes_longer(self):
        times = []
        for rate in (54.0, 6.0):
            sim, ap, stas = make_sim(1, rate_mbps=rate)
            fill(sim, stas, frames=10)
            times.append(sim.run()["elapsed_us"])
        self.assertLess(times[0], times[1])

    def test_delay_recorded_per_station(self):
        sim, ap, stas = make_sim(2)
        fill(sim, stas, frames=10)
        r = sim.run()
        for row in r["per_station"]:
            if row["station"] != "AP":
                self.assertGreater(row["avg_delay_us"], 0.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
