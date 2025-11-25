# =============================================================
# src/feature_extractor.py (VERSÃO FINAL - 3 FEATURES)
# =============================================================
import pandas as pd
from config import FEATURES

class FlowAggregator:
    def __init__(self):
        self.flows = {}

    def _get_key_from_pyshark_pkt(self, pkt):
        try:
            if not all(layer in pkt for layer in ['ip', pkt.transport_layer]):
                return None

            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            proto = pkt.transport_layer
            sport = pkt[proto].srcport
            dport = pkt[proto].dstport

            if int(sport) > int(dport):
                return f"{src_ip}:{sport}-{dst_ip}:{dport}|{proto}"
            else:
                return f"{dst_ip}:{dport}-{src_ip}:{sport}|{proto}"
        except AttributeError:
            return None

    def add_packet(self, pkt):
        key = self._get_key_from_pyshark_pkt(pkt)
        if key is None:
            return

        try:
            timestamp = float(pkt.sniff_timestamp)

            flow = self.flows.get(key)
            if flow is None:
                self.flows[key] = {
                    'start_time': timestamp,
                    'last_time': timestamp,
                    'pkts': 1,
                    'flow_key': key
                }
            else:
                flow['pkts'] += 1
                flow['last_time'] = timestamp
        except Exception:
            pass

    def finalize_dataframe(self) -> pd.DataFrame:
        rows = []
        for key, flow in self.flows.items():
            duration = flow['last_time'] - flow['start_time']
            duration = max(duration, 1e-6)

            rows.append({
                'flow_key': flow['flow_key'],
                'duration_s': duration,
                'tot_pkts': flow['pkts'],
                'pkts_per_sec': flow['pkts'] / duration,
            })

        if not rows:
            return pd.DataFrame(columns=FEATURES + ['flow_key'])

        return pd.DataFrame(rows)