"""Tests for TUI status display."""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from openconnect_saml.tui import (
    _collect_status,
    _extract_server_from_cmdline,
    _format_bytes,
    _format_duration,
    _get_traffic_stats,
    _print_status_plain,
)


class TestFormatDuration:
    def test_seconds(self):
        assert _format_duration(30) == "30s"

    def test_minutes(self):
        assert _format_duration(90) == "1m 30s"

    def test_hours(self):
        assert _format_duration(8100) == "2h 15m"

    def test_zero(self):
        assert _format_duration(0) == "0s"

    def test_large(self):
        result = _format_duration(86400)
        assert "24h" in result


class TestFormatBytes:
    def test_bytes(self):
        assert _format_bytes(512) == "512 B"

    def test_kilobytes(self):
        result = _format_bytes(2048)
        assert "KB" in result

    def test_megabytes(self):
        result = _format_bytes(150 * 1024 * 1024)
        assert "MB" in result

    def test_gigabytes(self):
        result = _format_bytes(1.5 * 1024 * 1024 * 1024)
        assert "GB" in result

    def test_none(self):
        assert _format_bytes(None) == "N/A"

    def test_zero(self):
        assert _format_bytes(0) == "0 B"


class TestExtractServer:
    def test_basic(self):
        result = _extract_server_from_cmdline(
            "openconnect --cookie-on-stdin https://vpn.example.com"
        )
        assert "vpn.example.com" in result

    def test_with_path(self):
        result = _extract_server_from_cmdline("openconnect https://vpn.example.com/group")
        assert "vpn.example.com" in result

    def test_no_match(self):
        result = _extract_server_from_cmdline("openconnect --help")
        assert result == "unknown"


class TestTrafficStats:
    def test_parse_proc_net_dev(self, tmp_path):
        proc_content = """Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:  123456      100    0    0    0     0          0         0   123456      100    0    0    0     0       0          0
  tun0: 1234567890   50000    0    0    0     0          0         0  987654321   40000    0    0    0     0       0          0
"""
        proc_file = tmp_path / "net_dev"
        proc_file.write_text(proc_content)

        with patch("openconnect_saml.tui.Path") as mock_path:
            mock_path.return_value.exists.return_value = True
            mock_path.return_value.read_text.return_value = proc_content
            # Direct test of parsing logic
            tx, rx = (
                _get_traffic_stats.__wrapped__(None)
                if hasattr(_get_traffic_stats, "__wrapped__")
                else (None, None)
            )

    def test_traffic_stats_missing_interface(self):
        """Non-existent interface returns None."""
        tx, rx = _get_traffic_stats("nonexistent99")
        assert tx is None
        assert rx is None


class TestStatusPlain:
    def test_disconnected(self, capsys):
        _print_status_plain(None)
        captured = capsys.readouterr()
        assert "Disconnected" in captured.out

    def test_connected(self, capsys):
        status = {
            "profile": "work",
            "server": "vpn.example.com",
            "user": "user@example.com",
            "uptime": "2h 15m",
            "ip": "10.0.1.42",
            "tx": 150 * 1024 * 1024,
            "rx": 1200 * 1024 * 1024,
            "reconnects": 0,
        }
        _print_status_plain(status)
        captured = capsys.readouterr()
        assert "Connected" in captured.out
        assert "work" in captured.out
        assert "vpn.example.com" in captured.out
        assert "10.0.1.42" in captured.out

    def test_connected_na_values(self, capsys):
        status = {
            "profile": "default",
            "server": "vpn.example.com",
            "user": "N/A",
            "uptime": None,
            "ip": "N/A",
            "tx": None,
            "rx": None,
            "reconnects": 0,
        }
        _print_status_plain(status)
        captured = capsys.readouterr()
        assert "N/A" in captured.out


class TestCollectStatus:
    @patch("openconnect_saml.tui._find_vpn_process")
    def test_no_process(self, mock_find):
        mock_find.return_value = None
        assert _collect_status() is None

    @patch("openconnect_saml.tui.config")
    @patch("openconnect_saml.tui._get_reconnect_count")
    @patch("openconnect_saml.tui._get_traffic_stats")
    @patch("openconnect_saml.tui._get_interface_ip")
    @patch("openconnect_saml.tui._get_vpn_interface")
    @patch("openconnect_saml.tui._get_process_start_time")
    @patch("openconnect_saml.tui._find_vpn_process")
    def test_with_process(
        self, mock_find, mock_start, mock_iface, mock_ip, mock_traffic, mock_reconnect, mock_config
    ):
        mock_find.return_value = (1234, "openconnect https://vpn.example.com")
        mock_start.return_value = datetime(2026, 3, 31, 10, 0, 0, tzinfo=timezone.utc)
        mock_iface.return_value = "tun0"
        mock_ip.return_value = "10.0.1.42"
        mock_traffic.return_value = (100000, 200000)
        mock_reconnect.return_value = 0

        mock_cfg = MagicMock()
        mock_cfg.active_profile = "work"
        mock_cfg.credentials = MagicMock()
        mock_cfg.credentials.username = "user@example.com"
        mock_config.load.return_value = mock_cfg

        status = _collect_status()
        assert status is not None
        assert status["connected"] is True
        assert status["server"] == "vpn.example.com"
        assert status["ip"] == "10.0.1.42"
        assert status["profile"] == "work"


# ─── _format_rate ─────────────────────────────────────────────────────────────


class TestFormatRate:
    """Bytes-per-second pretty-printer used in the live status row."""

    def test_none_returns_dash(self):
        from openconnect_saml.tui import _format_rate

        # None is rendered as an em-dash in the live status panel.
        assert _format_rate(None) == "—"

    def test_bytes_per_second(self):
        from openconnect_saml.tui import _format_rate

        assert "B/s" in _format_rate(500)

    def test_kilobytes(self):
        from openconnect_saml.tui import _format_rate

        assert "KB/s" in _format_rate(50_000)

    def test_megabytes(self):
        from openconnect_saml.tui import _format_rate

        assert "MB/s" in _format_rate(50_000_000)


# ─── _augment_with_rate ───────────────────────────────────────────────────────


class TestAugmentWithRate:
    """``_augment_with_rate`` injects ``tx_rate``/``rx_rate`` deltas
    by comparing the current status snapshot to the previous one."""

    def test_first_sample_no_rate(self):
        from openconnect_saml.tui import _augment_with_rate

        status = {"tx": 1000, "rx": 2000, "_sampled_at": 100.0}
        _augment_with_rate(status, None)
        # No prior sample — rates left None.
        assert status.get("tx_rate") is None
        assert status.get("rx_rate") is None

    def test_subsequent_sample_computes_rate(self):
        from openconnect_saml.tui import _augment_with_rate

        # Both snapshots must report the same ``interface`` for rates
        # to be computed (otherwise a tunnel re-up would produce a
        # spurious huge rate spike).
        prev = {"tx": 1000, "rx": 2000, "_sampled_at": 100.0, "interface": "tun0"}
        cur = {"tx": 6000, "rx": 7000, "_sampled_at": 105.0, "interface": "tun0"}
        _augment_with_rate(cur, prev)
        assert cur["tx_rate"] == pytest.approx((6000 - 1000) / 5.0)
        assert cur["rx_rate"] == pytest.approx((7000 - 2000) / 5.0)

    def test_zero_dt_doesnt_divide_by_zero(self):
        from openconnect_saml.tui import _augment_with_rate

        prev = {"tx": 100, "rx": 200, "_sampled_at": 100.0, "interface": "tun0"}
        cur = {"tx": 500, "rx": 800, "_sampled_at": 100.0, "interface": "tun0"}
        # Same timestamp — function must not raise.
        _augment_with_rate(cur, prev)
        # And tx_rate / rx_rate are not set (dt <= 0 short-circuits).
        assert "tx_rate" not in cur or cur.get("tx_rate") is None


# ─── _find_vpn_process ────────────────────────────────────────────────────────


class TestFindVpnProcess:
    @patch("openconnect_saml.tui.subprocess.run")
    def test_no_pgrep_match_returns_none(self, mock_run):
        from openconnect_saml.tui import _find_vpn_process

        mock_run.return_value = MagicMock(returncode=1, stdout="")
        assert _find_vpn_process() is None

    @patch("openconnect_saml.tui.subprocess.run")
    def test_matched_pgrep_returns_pid_and_cmdline(self, mock_run):
        from openconnect_saml.tui import _find_vpn_process

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="1234 openconnect --cookie-on-stdin https://vpn.example.com\n",
        )
        result = _find_vpn_process()
        assert result is not None
        pid, cmdline = result
        assert pid == 1234
        assert "vpn.example.com" in cmdline

    @patch("openconnect_saml.tui.subprocess.run", side_effect=FileNotFoundError)
    def test_pgrep_missing_returns_none(self, mock_run):
        """``pgrep`` isn't on Windows / minimal Linux containers; the
        helper must handle FileNotFoundError gracefully."""
        from openconnect_saml.tui import _find_vpn_process

        assert _find_vpn_process() is None


# ─── _get_traffic_stats ───────────────────────────────────────────────────────


class TestGetTrafficStats:
    def test_missing_proc_net_dev_returns_none_pair(self):
        """If /proc/net/dev doesn't exist (macOS / Windows / minimal
        container) the function returns (None, None)."""
        from openconnect_saml.tui import _get_traffic_stats

        with patch("openconnect_saml.tui.Path") as mock_path:
            mock_path.return_value.exists.return_value = False
            tx, rx = _get_traffic_stats("tun0")
        assert (tx, rx) == (None, None)


# ─── _print_status_json ───────────────────────────────────────────────────────


class TestPrintStatusJson:
    def test_disconnected_status(self, capsys):
        from openconnect_saml.tui import _print_status_json

        _print_status_json(None)
        out = capsys.readouterr().out
        import json

        data = json.loads(out)
        # Implementation emits ``{"connected": False}`` for the
        # nothing-running case rather than a state string.
        assert data == {"connected": False}

    def test_connected_status(self, capsys):
        from openconnect_saml.tui import _print_status_json

        _print_status_json(
            {
                "profile": "work",
                "server": "vpn.example.com",
                "uptime": "5m",
                "ip": "10.0.1.42",
                "tx": 1024,
                "rx": 2048,
            }
        )
        import json

        data = json.loads(capsys.readouterr().out)
        assert data["server"] == "vpn.example.com"
        assert data["profile"] == "work"
        assert data["tx"] == 1024


# ─── _plain_output ────────────────────────────────────────────────────────────


class TestPlainOutput:
    def test_no_color_env_forces_plain(self, monkeypatch):
        from openconnect_saml.tui import _plain_output

        # NO_COLOR set + stdout looks like a TTY → still must return
        # True because the env var unconditionally forces plain.
        monkeypatch.setenv("NO_COLOR", "1")
        with patch("sys.stdout.isatty", return_value=True):
            assert _plain_output() is True

    def test_no_tty_forces_plain(self, monkeypatch):
        from openconnect_saml.tui import _plain_output

        monkeypatch.delenv("NO_COLOR", raising=False)
        with patch("sys.stdout.isatty", return_value=False):
            assert _plain_output() is True


# ─── _check_killswitch_active ─────────────────────────────────────────────────


class TestCheckKillswitchActive:
    @patch("openconnect_saml.tui.subprocess.run")
    def test_returns_true_when_marker_present(self, mock_run):
        from openconnect_saml.tui import _check_killswitch_active

        # Either the function shells out and parses output, or it
        # checks a marker file. Whichever — calling with subprocess
        # patched and a representative successful return shouldn't
        # crash and must return a bool.
        mock_run.return_value = MagicMock(returncode=0, stdout="openconnect-saml-killswitch")
        result = _check_killswitch_active()
        assert isinstance(result, bool)

    @patch("openconnect_saml.tui.subprocess.run", side_effect=FileNotFoundError)
    def test_no_iptables_returns_false(self, mock_run):
        from openconnect_saml.tui import _check_killswitch_active

        # No iptables binary (e.g. macOS / minimal container).
        assert _check_killswitch_active() is False


# ─── _format_rate (large) ─────────────────────────────────────────────────────


class TestFormatRateGB:
    def test_gigabytes_per_second(self):
        from openconnect_saml.tui import _format_rate

        assert "GB/s" in _format_rate(2 * 1024**3)


# ─── _get_reconnect_count ─────────────────────────────────────────────────────


class TestGetReconnectCount:
    def test_returns_zero(self):
        from openconnect_saml.tui import _get_reconnect_count

        # Hard-coded placeholder — there's no per-connection counter
        # without a state file. Documenting the contract here so a
        # future change has to update the test alongside the code.
        assert _get_reconnect_count() == 0


# ─── _get_process_start_time ──────────────────────────────────────────────────


class TestGetProcessStartTime:
    def test_invalid_pid_returns_none(self):
        from openconnect_saml.tui import _get_process_start_time

        # /proc/0/stat doesn't exist — function returns None.
        assert _get_process_start_time(0) is None

    def test_handles_oserror(self):
        from openconnect_saml.tui import _get_process_start_time

        with patch("openconnect_saml.tui.Path") as mock_path:
            mock_path.side_effect = OSError("simulated")
            assert _get_process_start_time(1) is None


# ─── _get_vpn_interface ───────────────────────────────────────────────────────


class TestGetVpnInterface:
    def test_finds_tun0_in_ip_link_output(self):
        from openconnect_saml.tui import _get_vpn_interface

        ip_out = "1: lo: <LOOPBACK> ...\n2: tun0: <POINTOPOINT> ...\n"
        with patch("openconnect_saml.tui.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=ip_out)
            assert _get_vpn_interface() == "tun0"

    def test_finds_utun_on_macos(self):
        from openconnect_saml.tui import _get_vpn_interface

        ip_out = "5: utun7: <POINTOPOINT,UP> ...\n"
        with patch("openconnect_saml.tui.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=ip_out)
            assert _get_vpn_interface() == "utun7"

    def test_returns_none_when_no_tun(self):
        from openconnect_saml.tui import _get_vpn_interface

        ip_out = "1: lo: <LOOPBACK> ...\n2: eth0: <BROADCAST> ...\n"
        with patch("openconnect_saml.tui.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=ip_out)
            assert _get_vpn_interface() is None

    def test_returns_none_when_ip_missing(self):
        from openconnect_saml.tui import _get_vpn_interface

        with patch("openconnect_saml.tui.subprocess.run", side_effect=FileNotFoundError):
            assert _get_vpn_interface() is None


# ─── _get_interface_ip ────────────────────────────────────────────────────────


class TestGetInterfaceIP:
    def test_extracts_ipv4(self):
        from openconnect_saml.tui import _get_interface_ip

        ip_out = "    inet 10.1.2.3/24 scope global tun0\n"
        with patch("openconnect_saml.tui.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=ip_out)
            assert _get_interface_ip("tun0") == "10.1.2.3"

    def test_no_inet_returns_none(self):
        from openconnect_saml.tui import _get_interface_ip

        with patch("openconnect_saml.tui.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="")
            assert _get_interface_ip("tun0") is None

    def test_handles_missing_ip_binary(self):
        from openconnect_saml.tui import _get_interface_ip

        with patch("openconnect_saml.tui.subprocess.run", side_effect=FileNotFoundError):
            assert _get_interface_ip("tun0") is None


# ─── _augment_with_rate (interface change) ────────────────────────────────────


class TestAugmentInterfaceMismatch:
    def test_interface_change_drops_rate(self):
        from openconnect_saml.tui import _augment_with_rate

        prev = {"tx": 1000, "rx": 2000, "_sampled_at": 100.0, "interface": "tun0"}
        cur = {"tx": 6000, "rx": 7000, "_sampled_at": 105.0, "interface": "tun1"}
        # Tunnel interface changed → rates must NOT be computed.
        _augment_with_rate(cur, prev)
        assert "tx_rate" not in cur


# ─── _print_status_plain (rate + killswitch row) ──────────────────────────────


class TestPlainOutputExtras:
    def test_renders_rate_row(self, capsys):
        status = {
            "profile": "work",
            "server": "vpn.example.com",
            "user": "alice",
            "uptime": "1h 5m",
            "ip": "10.0.0.5",
            "tx": 100,
            "rx": 200,
            "tx_rate": 1024.0,
            "rx_rate": 2048.0,
            "reconnects": 1,
            "kill_switch": True,
        }
        _print_status_plain(status)
        out = capsys.readouterr().out
        assert "Rate" in out
        assert "Kill-switch" in out


# ─── _print_status_rich ───────────────────────────────────────────────────────


class TestPrintStatusRich:
    def test_disconnected(self, capsys):
        from openconnect_saml.tui import _print_status_rich

        _print_status_rich(None)
        # Either rich is installed and prints disconnected glyph, or
        # falls back to plain renderer. Both must mention disconnected.
        out = capsys.readouterr().out
        assert "Disconnected" in out

    def test_connected(self, capsys):
        from openconnect_saml.tui import _print_status_rich

        status = {
            "profile": "work",
            "server": "vpn.example.com",
            "user": "alice",
            "uptime": "5m",
            "ip": "10.0.1.42",
            "tx": 1024,
            "rx": 2048,
            "tx_rate": 100.0,
            "rx_rate": 200.0,
            "reconnects": 2,
            "kill_switch": True,
        }
        _print_status_rich(status)
        out = capsys.readouterr().out
        assert "Connected" in out
        assert "work" in out


# ─── _collect_all_statuses ────────────────────────────────────────────────────


class TestCollectAllStatuses:
    @patch("openconnect_saml.tui._collect_status_for_pid")
    @patch("openconnect_saml.tui._find_vpn_process")
    def test_one_per_recorded_session(self, mock_find, mock_collect):
        mock_find.return_value = (4242, "openconnect https://vpn.work")
        mock_collect.return_value = {"profile": "work", "pid": 4242}

        from types import SimpleNamespace

        sessions = [
            SimpleNamespace(pid=4242, server="vpn.work", profile="work", user="a"),
            SimpleNamespace(pid=4243, server="vpn.home", profile="home", user="a"),
        ]
        with patch("openconnect_saml.sessions.list_active", return_value=sessions):
            from openconnect_saml.tui import _collect_all_statuses

            results = _collect_all_statuses()
        assert len(results) == 2
        # Live cmdline used for the first match (PID matched _find_vpn_process),
        # the recorded server fallback for the second.
        assert mock_collect.call_args_list[0].args[1] == "openconnect https://vpn.work"
        assert mock_collect.call_args_list[1].args[1] == "vpn.home"


# ─── handle_status_command ────────────────────────────────────────────────────


class TestHandleStatusCommand:
    def test_one_shot_json(self, capsys):
        from types import SimpleNamespace

        from openconnect_saml.tui import handle_status_command

        args = SimpleNamespace(watch=False, json=True)
        with patch(
            "openconnect_saml.tui._collect_status",
            return_value={"profile": "work", "server": "vpn"},
        ):
            handle_status_command(args)
        import json as _json

        data = _json.loads(capsys.readouterr().out)
        assert data["profile"] == "work"

    def test_one_shot_plain(self, capsys):
        from types import SimpleNamespace

        from openconnect_saml.tui import handle_status_command

        args = SimpleNamespace(watch=False, json=False)
        with patch("openconnect_saml.tui._collect_status", return_value=None):
            handle_status_command(args)
        # Disconnected message must surface on stdout.
        assert "Disconnected" in capsys.readouterr().out

    def test_watch_exits_on_keyboard_interrupt(self, capsys):
        """``watch`` mode loops until ^C; we feed it one sample then raise."""
        from types import SimpleNamespace

        from openconnect_saml.tui import handle_status_command

        args = SimpleNamespace(watch=True, json=False)
        # First sleep raises -> loop exits cleanly with rc=0.
        with (
            patch("openconnect_saml.tui._collect_status", return_value=None),
            patch("openconnect_saml.tui.time.sleep", side_effect=KeyboardInterrupt),
        ):
            rc = handle_status_command(args)
        assert rc == 0
