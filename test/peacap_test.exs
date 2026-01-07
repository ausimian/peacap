defmodule PeacapTest do
  use ExUnit.Case

  # On macOS loopback (lo0), packets have a 4-byte header:
  # - Bytes 0-3: Address family (AF_INET=2 for IPv4, AF_INET6=30 for IPv6)
  # Then the IP packet follows.
  #
  # So to match IPv4 packets, we need to check:
  # - Bytes 0-3: <<2, 0, 0, 0>> (AF_INET in little-endian on macOS)
  # - Byte 4: version nibble should be 4

  @loopback "lo0"

  describe "error handling" do
    test "returns error for non-existent interface" do
      require BPF

      program = BPF.compile(fn <<_::binary>> -> true end)
      assert {:error, _reason} = Peacap.start("nonexistent0", program)
    end
  end

  describe "select notification" do
    # On macOS, BPF select() is unreliable - it often doesn't fire even when
    # packets are available. This is a known limitation documented in
    # pcap_get_selectable_fd(3). The poll timer workaround handles this.
    @tag :skip
    test "receives packets via select callback after initial read drains" do
      require BPF

      # Start capture before generating any traffic
      # This ensures the initial read will find no packets and register for select
      # Use a long poll_interval to ensure packets arrive via select, not the poll timer
      program = BPF.compile(fn <<_::binary>> -> true end)
      {:ok, pid} = Peacap.start(@loopback, program, poll_interval: 60_000)

      # Wait a moment to ensure initial read has completed and select is registered
      Process.sleep(50)

      # Now generate traffic - this should trigger the select callback
      # Use more packets to ensure BPF buffer fills enough to trigger select
      generate_ping_burst()

      # Should receive packets delivered via the select notification path
      # (not the poll timer, since we set it to 60 seconds)
      assert_receive {:peacap_packet, ^pid, packet}, 2000
      assert is_binary(packet)

      Peacap.stop(pid)
    end
  end

  describe "basic capture" do
    test "captures packets on loopback" do
      require BPF

      # Accept all packets
      program = BPF.compile(fn <<_::binary>> -> true end)
      {:ok, pid} = Peacap.start(@loopback, program)

      # Generate traffic
      generate_ping()

      # Should receive at least one packet
      assert_receive {:peacap_packet, ^pid, packet}, 1000
      assert is_binary(packet)
      assert byte_size(packet) > 0

      Peacap.stop(pid)
    end

    test "stops cleanly" do
      require BPF

      program = BPF.compile(fn <<_::binary>> -> true end)
      {:ok, pid} = Peacap.start(@loopback, program)

      ref = Process.monitor(pid)
      Peacap.stop(pid)

      assert_receive {:DOWN, ^ref, :process, ^pid, :normal}, 1000
    end

    test "cleans up when owner dies" do
      require BPF

      program = BPF.compile(fn <<_::binary>> -> true end)

      # Start capture from a temporary process
      test_pid = self()

      owner =
        spawn(fn ->
          {:ok, pid} = Peacap.start(@loopback, program)
          send(test_pid, {:started, pid})

          receive do
            :stop -> :ok
          end
        end)

      assert_receive {:started, capture_pid}, 1000
      ref = Process.monitor(capture_pid)

      # Kill the owner
      Process.exit(owner, :kill)

      # Capture should terminate
      assert_receive {:DOWN, ^ref, :process, ^capture_pid, _reason}, 1000
    end
  end

  describe "BPF filtering" do
    test "filter accepts matching packets" do
      require BPF

      # On macOS loopback, first 4 bytes are AF family
      # AF_INET = 2 (little-endian: <<2, 0, 0, 0>>)
      # Accept only IPv4 packets (AF_INET followed by version 4)
      program =
        BPF.compile(fn
          <<2, 0, 0, 0, 4::4, _::4, _::binary>> -> true
        end)

      {:ok, pid} = Peacap.start(@loopback, program)

      # Generate IPv4 traffic
      generate_ping()

      # Should receive IPv4 packets
      assert_receive {:peacap_packet, ^pid, packet}, 1000

      # Verify it's an IPv4 packet (loopback header + IPv4)
      <<af::32-little, version::4, _::4, _::binary>> = packet
      assert af == 2
      assert version == 4

      Peacap.stop(pid)
    end

    test "filter rejects non-matching packets" do
      require BPF

      # Only accept IPv6 packets (AF_INET6 = 30 on macOS)
      # This should reject IPv4 ping traffic
      program =
        BPF.compile(fn
          <<30, 0, 0, 0, 6::4, _::4, _::binary>> -> true
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

      # IPv4 ICMP: AF_INET (2), IPv4 version (4), protocol at byte 9 of IP header = 1
      # Loopback header (4 bytes) + IP header offset 9 = byte 13
      program =
        BPF.compile(fn
          <<2, 0, 0, 0, 4::4, ihl::4, _tos::8, _len::16, _id::16, _flags_frag::16, _ttl::8,
            proto::8, _::binary>>
          when proto == 1 and ihl >= 5 ->
            true
        end)

      {:ok, pid} = Peacap.start(@loopback, program)

      # Generate ICMP traffic (ping)
      generate_ping()

      # Should receive ICMP packets
      assert_receive {:peacap_packet, ^pid, packet}, 1000

      # Verify protocol is ICMP (1)
      <<2, 0, 0, 0, _::72, proto::8, _::binary>> = packet
      assert proto == 1

      Peacap.stop(pid)
    end

    test "filter by packet size" do
      require BPF

      # Only accept packets larger than 50 bytes
      program =
        BPF.compile(fn
          <<_::binary>> = pkt when byte_size(pkt) > 50 -> true
        end)

      {:ok, pid} = Peacap.start(@loopback, program)

      # Generate traffic - ping packets are typically ~84 bytes on loopback
      generate_ping()

      packets = collect_packets(pid, 500)

      # All received packets should be > 50 bytes
      assert length(packets) > 0

      for packet <- packets do
        assert byte_size(packet) > 50
      end

      Peacap.stop(pid)
    end

    test "multi-clause filter" do
      require BPF

      # Accept either:
      # - IPv4 ICMP (proto = 1)
      # - IPv4 UDP (proto = 17)
      program =
        BPF.compile(fn
          <<2, 0, 0, 0, 4::4, _ihl::4, _tos::8, _len::16, _id::16, _flags::16, _ttl::8, 1::8,
            _::binary>> ->
            true

          <<2, 0, 0, 0, 4::4, _ihl::4, _tos::8, _len::16, _id::16, _flags::16, _ttl::8, 17::8,
            _::binary>> ->
            true
        end)

      {:ok, pid} = Peacap.start(@loopback, program)

      # Generate ICMP traffic
      generate_ping()

      # Should receive packets
      assert_receive {:peacap_packet, ^pid, packet}, 1000

      # Verify it's ICMP or UDP
      <<2, 0, 0, 0, _::72, proto::8, _::binary>> = packet
      assert proto in [1, 17]

      Peacap.stop(pid)
    end
  end

  describe "options" do
    @tag :skip
    # macOS BPF on loopback doesn't respect small snaplen values
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

  describe "resource cleanup" do
    test "BPF device is released after stop" do
      require BPF

      program = BPF.compile(fn <<_::binary>> -> true end)

      # Check no BPF devices open initially
      assert bpf_device_count() == 0

      # Start capture - should open a BPF device
      {:ok, pid} = Peacap.start(@loopback, program)
      assert bpf_device_count() == 1

      # Stop capture - should release the BPF device
      Peacap.stop(pid)
      Process.sleep(50)
      assert bpf_device_count() == 0
    end

    test "BPF device is released after multiple cycles" do
      require BPF

      program = BPF.compile(fn <<_::binary>> -> true end)

      # Run multiple start/stop cycles
      for _ <- 1..5 do
        {:ok, pid} = Peacap.start(@loopback, program)
        assert bpf_device_count() == 1
        Peacap.stop(pid)
        Process.sleep(50)
        assert bpf_device_count() == 0
      end
    end

    test "BPF device is released when owner dies" do
      require BPF

      program = BPF.compile(fn <<_::binary>> -> true end)
      test_pid = self()

      assert bpf_device_count() == 0

      owner =
        spawn(fn ->
          {:ok, pid} = Peacap.start(@loopback, program)
          send(test_pid, {:started, pid})

          receive do
            :stop -> :ok
          end
        end)

      assert_receive {:started, capture_pid}, 1000
      assert bpf_device_count() == 1

      # Kill owner - BPF device should be released
      ref = Process.monitor(capture_pid)
      Process.exit(owner, :kill)
      assert_receive {:DOWN, ^ref, :process, ^capture_pid, _}, 1000

      Process.sleep(50)
      assert bpf_device_count() == 0
    end

    test "BPF device is released when GenServer is killed" do
      require BPF

      program = BPF.compile(fn <<_::binary>> -> true end)

      assert bpf_device_count() == 0

      {:ok, pid} = Peacap.start(@loopback, program)
      assert bpf_device_count() == 1

      # Kill the GenServer directly
      ref = Process.monitor(pid)
      Process.exit(pid, :kill)
      assert_receive {:DOWN, ^ref, :process, ^pid, :killed}, 1000

      Process.sleep(50)
      assert bpf_device_count() == 0
    end
  end

  # Helper functions

  defp bpf_device_count do
    {output, 0} = System.cmd("lsof", ["-p", "#{System.pid()}"])

    output
    |> String.split("\n")
    |> Enum.count(fn line -> String.contains?(line, "/dev/bpf") end)
  end

  defp generate_ping do
    # Run ping in background to generate loopback traffic
    spawn(fn ->
      System.cmd("ping", ["-c", "2", "-i", "0.1", "127.0.0.1"], stderr_to_stdout: true)
    end)

    # Give it a moment to start
    Process.sleep(50)
  end

  defp generate_ping_burst do
    # Generate more traffic to fill the BPF buffer and trigger select
    spawn(fn ->
      System.cmd("ping", ["-c", "10", "-i", "0.01", "127.0.0.1"], stderr_to_stdout: true)
    end)

    # Give it a moment to start
    Process.sleep(100)
  end

  defp collect_packets(pid, timeout_ms) do
    collect_packets(pid, timeout_ms, [])
  end

  defp collect_packets(pid, timeout_ms, acc) do
    receive do
      {:peacap_packet, ^pid, packet} ->
        collect_packets(pid, timeout_ms, [packet | acc])
    after
      timeout_ms -> Enum.reverse(acc)
    end
  end
end
