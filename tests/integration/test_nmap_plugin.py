"""
Integration Tests: Nmap Plugin
==============================

Tests the NmapPlugin with a mock tool that simulates
XML output without requiring Nmap to be installed.
"""

from __future__ import annotations

import pytest
import pytest_asyncio

from core.exceptions import ToolUnavailableError
from tools.common import HostInfo, PortInfo
from tests.integration.conftest import MockNmapPlugin


class TestNmapHealthCheck:
    """Tests for Nmap health check."""

    @pytest.mark.asyncio
    async def test_health_check_healthy(self) -> None:
        """Verify health check returns healthy when available."""
        plugin = MockNmapPlugin()
        plugin.set_available(True)
        health = await plugin.health_check()
        assert health["healthy"] is True
        assert health["available"] is True
        assert health["version"] == "7.95-test"

    @pytest.mark.asyncio
    async def test_health_check_unavailable(self) -> None:
        """Verify health check returns unhealthy when unavailable."""
        plugin = MockNmapPlugin()
        plugin.set_available(False)
        health = await plugin.health_check()
        assert health["healthy"] is False
        assert health["available"] is False


class TestNmapExecution:
    """Tests for Nmap execution."""

    @pytest.mark.asyncio
    async def test_execute_returns_bytes(self) -> None:
        """Verify execute method yields bytes."""
        plugin = MockNmapPlugin()
        result = b""
        async for chunk in plugin.execute(targets=["scanme.nmap.org"]):
            result += chunk
        assert len(result) > 0
        assert isinstance(result, bytes)

    @pytest.mark.asyncio
    async def test_execute_with_single_target(self) -> None:
        """Verify execute works with a single target."""
        plugin = MockNmapPlugin()
        chunks = []
        async for chunk in plugin.execute(targets=["192.168.1.1"]):
            chunks.append(chunk)
        output = b"".join(chunks)
        assert b"192.168.1.1" in output

    @pytest.mark.asyncio
    async def test_execute_with_multiple_targets(self) -> None:
        """Verify execute works with multiple targets."""
        plugin = MockNmapPlugin()
        chunks = []
        async for chunk in plugin.execute(
            targets=["target1.com", "target2.com"]
        ):
            chunks.append(chunk)
        # Each target execution yields its own XML
        assert len(chunks) >= 1

    @pytest.mark.asyncio
    async def test_execute_failure_raises(self) -> None:
        """Verify execution failure raises an exception."""
        plugin = MockNmapPlugin()
        plugin.set_fail_next(True)
        with pytest.raises(RuntimeError, match="Simulated Nmap execution failure"):
            async for _ in plugin.execute(targets=["fail-target"]):
                pass

    @pytest.mark.asyncio
    async def test_tracks_execution_count(self) -> None:
        """Verify execution count is tracked."""
        plugin = MockNmapPlugin()
        async for _ in plugin.execute(targets=["test1"]):
            pass
        async for _ in plugin.execute(targets=["test2"]):
            pass
        assert plugin._execution_count == 2


class TestNmapParsing:
    """Tests for Nmap output parsing."""

    @pytest.mark.asyncio
    async def test_parse_returns_hosts(self) -> None:
        """Verify parse returns list of HostInfo objects."""
        plugin = MockNmapPlugin()
        output = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95">
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames><hostname name="test.example.com" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" method="table" conf="3"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        hosts = await plugin.parse(output)
        assert len(hosts) == 1
        assert isinstance(hosts[0], HostInfo)

    @pytest.mark.asyncio
    async def test_parse_extracts_host_details(self) -> None:
        """Verify parse extracts correct host details."""
        plugin = MockNmapPlugin()
        output = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95">
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <hostnames><hostname name="server.example.com" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="nginx" version="1.24.0" method="table" conf="3"/>
      </port>
    </ports>
    <os><osmatch name="Linux 5.x" accuracy="95"/></os>
    <distance value="2"/>
  </host>
</nmaprun>"""
        hosts = await plugin.parse(output)
        host = hosts[0]
        assert host.ip == "10.0.0.1"
        assert host.status == "up"
        assert "server.example.com" in host.hostnames
        assert len(host.ports) == 1
        assert host.os == "Linux 5.x"
        assert host.os_accuracy == 95
        assert host.distance == 2

    @pytest.mark.asyncio
    async def test_parse_extracts_port_details(self) -> None:
        """Verify parse extracts correct port details."""
        plugin = MockNmapPlugin()
        output = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95">
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache" version="2.4.41" extrainfo="Ubuntu" method="table" conf="3"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="filtered" reason="no-response"/>
        <service name="ssh" method="table" conf="3"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        hosts = await plugin.parse(output)
        host = hosts[0]
        assert len(host.ports) == 2

        # Open port
        port_80 = host.ports[0]
        assert port_80.port == 80
        assert port_80.protocol == "tcp"
        assert port_80.state == "open"
        assert port_80.service == "http"
        assert port_80.service_product == "Apache"
        assert port_80.service_version == "2.4.41"

        # Filtered port
        port_22 = host.ports[1]
        assert port_22.port == 22
        assert port_22.state == "filtered"

    @pytest.mark.asyncio
    async def test_parse_empty_output(self) -> None:
        """Verify parse returns empty list for empty output."""
        plugin = MockNmapPlugin()
        hosts = await plugin.parse(b"")
        assert hosts == []

    @pytest.mark.asyncio
    async def test_parse_malformed_xml(self) -> None:
        """Verify parse handles malformed XML gracefully."""
        plugin = MockNmapPlugin()
        hosts = await plugin.parse(b"not valid xml at all")
        # Should return empty list, not crash
        assert hosts == []


class TestNmapOpenPortsProperty:
    """Tests for HostInfo.open_ports property."""

    def test_open_ports_filter(self) -> None:
        """Verify open_ports property returns only open ports."""
        host = HostInfo(
            ip="10.0.0.1",
            ports=[
                PortInfo(port=22, state="open"),
                PortInfo(port=80, state="open"),
                PortInfo(port=443, state="open"),
                PortInfo(port=25, state="filtered"),
                PortInfo(port=3306, state="closed"),
            ],
        )
        open_ports = host.open_ports
        assert len(open_ports) == 3
        assert all(p.state == "open" for p in open_ports)

    def test_open_ports_empty(self) -> None:
        """Verify open_ports returns empty list when none open."""
        host = HostInfo(
            ip="10.0.0.1",
            ports=[PortInfo(port=22, state="filtered")],
        )
        assert host.open_ports == []


class TestMockNmapPluginState:
    """Tests for MockNmapPlugin state management."""

    def test_availability_toggle(self) -> None:
        """Verify availability can be toggled."""
        plugin = MockNmapPlugin()
        assert plugin._available is True
        plugin.set_available(False)
        assert plugin._available is False
        plugin.set_available(True)
        assert plugin._available is True

    def test_fail_next_toggle(self) -> None:
        """Verify fail_next flag works."""
        plugin = MockNmapPlugin()
        assert plugin._fail_next is False
        plugin.set_fail_next(True)
        assert plugin._fail_next is True
        # After setting, flag should exist
        plugin.set_fail_next(False)
        assert plugin._fail_next is False

