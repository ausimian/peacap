defmodule Peacap.CommonTest do
  use ExUnit.Case

  @loopback (case :os.type() do
               {:unix, :darwin} -> "lo0"
               {:unix, :linux} -> "lo"
               _ -> "lo"
             end)

  describe "error handling" do
    test "returns error for non-existent interface" do
      require BPF

      program = BPF.compile(fn <<_::binary>> -> true end)
      assert {:error, _reason} = Peacap.start("nonexistent0", program)
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
  end

  describe "resource cleanup" do
    test "handle is released after stop" do
      require BPF

      program = BPF.compile(fn <<_::binary>> -> true end)

      # Start capture
      {:ok, pid} = Peacap.start(@loopback, program)

      # Stop capture - should release resources
      Peacap.stop(pid)
      Process.sleep(50)

      # If we can start another capture, resources were released
      {:ok, pid2} = Peacap.start(@loopback, program)
      Peacap.stop(pid2)
    end

    test "handle is released after multiple cycles" do
      require BPF

      program = BPF.compile(fn <<_::binary>> -> true end)

      # Run multiple start/stop cycles
      for _ <- 1..5 do
        {:ok, pid} = Peacap.start(@loopback, program)
        Peacap.stop(pid)
        Process.sleep(50)
      end

      # If we get here without error, resources were properly released
      assert true
    end

    test "handle is released when owner dies" do
      require BPF

      program = BPF.compile(fn <<_::binary>> -> true end)
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

      # Kill owner - handle should be released
      ref = Process.monitor(capture_pid)
      Process.exit(owner, :kill)
      assert_receive {:DOWN, ^ref, :process, ^capture_pid, _}, 1000

      Process.sleep(50)

      # Verify we can start a new capture (resources released)
      {:ok, pid} = Peacap.start(@loopback, program)
      Peacap.stop(pid)
    end

    test "handle is released when GenServer is killed" do
      require BPF

      program = BPF.compile(fn <<_::binary>> -> true end)

      {:ok, pid} = Peacap.start(@loopback, program)

      # Kill the GenServer directly
      ref = Process.monitor(pid)
      Process.exit(pid, :kill)
      assert_receive {:DOWN, ^ref, :process, ^pid, :killed}, 1000

      Process.sleep(50)

      # Verify we can start a new capture (resources released)
      {:ok, pid2} = Peacap.start(@loopback, program)
      Peacap.stop(pid2)
    end
  end

  # Helper functions

  defp generate_ping do
    # Run ping in background to generate loopback traffic
    spawn(fn ->
      System.cmd("ping", ["-c", "2", "-i", "0.1", "127.0.0.1"], stderr_to_stdout: true)
    end)

    # Give it a moment to start
    Process.sleep(50)
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
