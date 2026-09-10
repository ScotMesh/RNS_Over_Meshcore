# Sideband service plugin: MeshCore raw-payload tunnel
#
# Loads MeshCore_Raw_Interface.py from the same directory as this file and
# registers it with the Reticulum instance Sideband is running, so an LXMF
# client can sit directly on a MeshCore mesh with no config-file edits.
#
# Install:
#   1. Copy this file AND Interface/MeshCore_Raw_Interface.py into your
#      Sideband plugins directory (Settings -> Plugins -> plugin directory).
#   2. Edit the CONFIG block below.
#   3. Enable "Service plugins" in Sideband settings and restart Sideband.
#
# Sideband exec's every .py file in the plugin directory and expects each to
# define plugin_class; the interface module sets plugin_class = None for that
# reason, so it is safe to sit alongside this file.
#
# Android: the APK ships neither pyserial nor bleak, so only transport = tcp
# works there (e.g. an openHop virtual companion on the LAN). Desktop Sideband
# can use serial and ble too, or simply put the module in ~/.reticulum/interfaces
# and configure it in ~/.reticulum/config like any other interface.

import os
import RNS
from RNS.Interfaces.Interface import Interface

CONFIG = {
    "name":           "MeshCore Raw",
    "transport":      "tcp",          # tcp | serial | ble
    "host":           "127.0.0.1",
    "tcp_port":       5000,
    "port":           "/dev/ttyUSB0",
    "baudrate":       115200,
    "ble_name":       "",
    "ble_address":    "",
    "channel_idx":    0,
    "channel_name":   "RNSTunnel",
    "channel_secret": "00000000000000000000000000000000",   # openssl rand -hex 16
    "can_route":      "no",           # a phone is an edge node
    "mode":           "full",
}

MODULE_FILE = "MeshCore_Raw_Interface.py"


class MeshCoreRawServicePlugin(SidebandServicePlugin):
    service_name = "meshcore_raw"

    def _find_module(self):
        candidates = []
        try:
            plugins_path = self.get_sideband().config.get("command_plugins_path")
            if plugins_path:
                candidates.append(os.path.join(plugins_path, MODULE_FILE))
        except Exception:
            pass
        candidates.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), MODULE_FILE)
                          if "__file__" in globals() else MODULE_FILE)
        for path in candidates:
            if os.path.isfile(path):
                return path
        raise FileNotFoundError(f"{MODULE_FILE} not found next to the plugin (looked in {candidates})")

    def start(self):
        path = self._find_module()
        RNS.log(f"MeshCore raw plugin: loading interface from {path}", RNS.LOG_NOTICE)

        # Same globals RNS's own external-interface loader provides.
        g = {"RNS": RNS, "Interface": Interface, "__name__": "MeshCore_Raw_Interface"}
        with open(path) as fh:
            exec(compile(fh.read(), path, "exec"), g)
        interface_class = g["interface_class"]

        cfg = dict(CONFIG)
        iface = interface_class(RNS.Transport, cfg)

        # Mirror RNS.Reticulum._add_interface() for a runtime-added interface.
        mode_names = {"full": "MODE_FULL", "access_point": "MODE_ACCESS_POINT", "ap": "MODE_ACCESS_POINT",
                      "boundary": "MODE_BOUNDARY", "gateway": "MODE_GATEWAY", "roaming": "MODE_ROAMING"}
        mode_attr = mode_names.get(str(cfg.get("mode", "full")).lower(), "MODE_FULL")
        iface.mode = getattr(Interface, mode_attr, getattr(Interface, "MODE_FULL", 0x01))
        iface.OUT = True
        iface.ifac_size = iface.DEFAULT_IFAC_SIZE
        iface.ifac_netname = None
        iface.ifac_netkey = None
        iface.announce_cap = RNS.Reticulum.ANNOUNCE_CAP / 100.0
        for attr in ("announce_rate_target", "announce_rate_grace", "announce_rate_penalty"):
            setattr(iface, attr, None)
        for fn in ("optimise_mtu",):
            if hasattr(iface, fn):
                try:
                    getattr(iface, fn)()
                except Exception:
                    pass

        if hasattr(RNS.Transport, "add_interface"):
            RNS.Transport.add_interface(iface)
        else:
            RNS.Transport.interfaces.append(iface)
        if hasattr(iface, "final_init"):
            try:
                iface.final_init()
            except Exception:
                pass

        self.iface = iface
        RNS.log(f"MeshCore raw plugin: {iface} registered", RNS.LOG_NOTICE)
        super().start()

    def stop(self):
        try:
            self.iface.detach()
        except Exception:
            pass
        super().stop()


plugin_class = MeshCoreRawServicePlugin
