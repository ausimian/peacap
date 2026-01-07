defmodule Peacap.LinuxTest do
  @moduledoc """
  Linux-specific tests for packet capture.

  On Linux loopback (lo), packets use DLT_EN10MB (Ethernet) format:
  - 14-byte Ethernet header (6 dst + 6 src + 2 ethertype)
  - MACs are zeroed, ethertype is 0x0800 for IPv4, 0x86DD for IPv6
  - Then the IP packet follows
  """
  use ExUnit.Case

  @moduletag :linux

  @loopback "lo"

  describe "select notification" do
    # On Linux, select() works reliably for BPF - no polling workaround needed
    test "receives packets via select callback" do
      require BPF

      # Start capture before generating any traffic
      program = BPF.compile(fn <<_::binary>> -> true end)
      {:ok, pid} = Peacap.start(@loopback, program)

      # Wait a moment to ensure initial read has completed and select is registered
      Process.sleep(50)

      # Generate traffic - should trigger the select callback
      generate_ping()

      # Should receive packets via select notification
      assert_receive {:peacap_packet, ^pid, packet}, 2000
      assert is_binary(packet)

      Peacap.stop(pid)
    end
  end

  describe "BPF filtering" do
    test "filter accepts matching IPv4 packets" do
      require BPF

      # On Linux loopback, packets have 14-byte Ethernet header
      # Ethertype 0x0800 = IPv4
      # Accept only IPv4 packets
      program =
        BPF.compile(fn
          <<_dst::48, _src::48, 0x08, 0x00, 4::4, _::4, _::binary>> -> true
        end)

      {:ok, pid} = Peacap.start(@loopback, program)

      # Generate IPv4 traffic
      generate_ping()

      # Should receive IPv4 packets
      assert_receive {:peacap_packet, ^pid, packet}, 1000

      # Verify it's an IPv4 packet (Ethernet header + IPv4)
      <<_dst::48, _src::48, ethertype::16, version::4, _::4, _::binary>> = packet
      assert ethertype == 0x0800
      assert version == 4

      Peacap.stop(pid)
    end

    test "filter rejects non-matching packets" do
      require BPF

      # Only accept IPv6 packets (ethertype 0x86DD)
      # This should reject IPv4 ping traffic
      program =
        BPF.compile(fn
          <<_dst::48, _src::48, 0x86, 0xDD, 6::4, _::4, _::binary>> -> true
        end)

      {:ok, pid} = Peacap.start(@loopback, program)

      # Generate IPv4 traffic (ping to 127.0.0.1)
      generate_ping()

      # Should NOT receive any packets (IPv4 filtered out)
      refute_receive {:peacap_packet, ^pid, _packet}, 500

      Peacap.stop(pid)
    end

    test "filter by ICMP protocol" do
      require BPF

      # IPv4 ICMP: Ethernet header (14 bytes) + IPv4 header with protocol = 1
      program =
        BPF.compile(fn
          <<_dst::48, _src::48, 0x08, 0x00, 4::4, ihl::4, _tos::8, _len::16, _id::16,
            _flags_frag::16, _ttl::8, proto::8, _::binary>>
          when proto == 1 and ihl >= 5 ->
            true
        end)

      {:ok, pid} = Peacap.start(@loopback, program)

      # Generate ICMP traffic (ping)
      generate_ping()

      # Should receive ICMP packets
      assert_receive {:peacap_packet, ^pid, packet}, 1000

      # Verify protocol is ICMP (1)
      # Ethernet (14 bytes = 112 bits) + IP header offset to protocol (9 bytes = 72 bits)
      <<_eth::112, _::72, proto::8, _::binary>> = packet
      assert proto == 1

      Peacap.stop(pid)
    end

    test "multi-clause filter" do
      require BPF

      # Accept either:
      # - IPv4 ICMP (proto = 1)
      # - IPv4 UDP (proto = 17)
      program =
        BPF.compile(fn
          <<_dst::48, _src::48, 0x08, 0x00, 4::4, _ihl::4, _tos::8, _len::16, _id::16, _flags::16,
            _ttl::8, 1::8, _::binary>> ->
            true

          <<_dst::48, _src::48, 0x08, 0x00, 4::4, _ihl::4, _tos::8, _len::16, _id::16, _flags::16,
            _ttl::8, 17::8, _::binary>> ->
            true
        end)

      {:ok, pid} = Peacap.start(@loopback, program)

      # Generate ICMP traffic
      generate_ping()

      # Should receive packets
      assert_receive {:peacap_packet, ^pid, packet}, 1000

      # Verify it's ICMP or UDP
      <<_eth::112, _::72, proto::8, _::binary>> = packet
      assert proto in [1, 17]

      Peacap.stop(pid)
    end
  end

  describe "options" do
    test "snaplen limits capture size" do
      require BPF

      program = BPF.compile(fn <<_::binary>> -> true end)

      # Capture only first 20 bytes
      {:ok, pid} = Peacap.start(@loopback, program, snaplen: 20)

      generate_ping()

      assert_receive {:peacap_packet, ^pid, packet}, 1000
      assert byte_size(packet) <= 20

      Peacap.stop(pid)
    end
  end

  # Helper functions

  defp generate_ping do
    spawn(fn ->
      System.cmd("ping", ["-c", "2", "-i", "0.1", "127.0.0.1"], stderr_to_stdout: true)
    end)

    Process.sleep(50)
  end
end
