defmodule Peacap do
  @moduledoc """
  Packet capture using libpcap with BPF filtering.

  ## Usage

      program = BPF.compile(fn <<_::binary>> -> true end)
      {:ok, pid} = Peacap.start("en0", program)

      # Packets delivered as messages to caller:
      # {:peacap_packet, pid, packet_binary}

      receive do
        {:peacap_packet, ^pid, packet} ->
          IO.inspect(packet, label: "captured")
      end

      Peacap.stop(pid)

  ## Options

    * `:snaplen` - Maximum bytes to capture per packet (default: 65535)
    * `:promisc` - Enable promiscuous mode (default: false)
    * `:poll_interval` - Polling interval for macOS workaround in ms (default: 100)

  """

  use GenServer, restart: :temporary
  use TypedStruct

  @doc false
  def child_spec(arg), do: super(arg)

  @default_snaplen 65535
  @default_poll_interval 100

  @typedoc false
  typedstruct do
    field(:resource, reference())
    field(:owner, pid())
  end

  @doc """
  Starts packet capture on the given interface with the specified BPF filter.

  Returns `{:ok, pid}` on success or `{:error, reason}` on failure.
  Captured packets are sent to the calling process as `{:peacap_packet, pid, binary}`.

  ## Error Handling

  If an error occurs while reading packets, the capture GenServer will terminate.
  The caller may monitor the returned pid to detect unexpected termination:

      {:ok, pid} = Peacap.start("en0", program)
      ref = Process.monitor(pid)

      receive do
        {:peacap_packet, ^pid, packet} -> handle_packet(packet)
        {:DOWN, ^ref, :process, ^pid, reason} -> handle_error(reason)
      end

  ## Arguments

    * `interface` - Network interface name (e.g., `"en0"`, `"lo0"`, `"eth0"`)
    * `program` - A compiled BPF program from `BPF.compile/1`
    * `opts` - Keyword list of options

  ## Options

    * `:snaplen` - Maximum bytes to capture per packet. Packets larger than this
      will be truncated. Default: `65535` (captures full packets up to jumbo frames).

    * `:promisc` - When `true`, puts the interface in promiscuous mode to capture
      all packets on the network segment, not just those addressed to this host.
      Requires appropriate permissions. Default: `false`.

    * `:poll_interval` - Polling interval in milliseconds for the macOS BPF
      buffering workaround. On macOS, the BPF device may buffer packets and not
      trigger `select()` notifications reliably. This timer ensures packets are
      read periodically. Only used on macOS. Default: `100`.

  ## Examples

      # Capture all packets
      program = BPF.compile(fn <<_::binary>> -> true end)
      {:ok, pid} = Peacap.start("en0", program)

      # Capture with promiscuous mode and smaller snaplen
      {:ok, pid} = Peacap.start("en0", program, promisc: true, snaplen: 1500)

  """
  @spec start(String.t(), BPF.Program.t(), keyword()) :: {:ok, pid()} | {:error, term()}
  def start(interface, %BPF.Program{} = program, opts \\ []) do
    owner = self()
    Peacap.Application.start_trace(interface, program, owner, opts)
  end

  @doc """
  Stops the packet capture.
  """
  @spec stop(pid()) :: :ok
  def stop(pid) do
    GenServer.stop(pid)
  end

  @doc false
  def start_link(args) do
    GenServer.start_link(__MODULE__, args, hibernate_after: 15_000)
  end

  # GenServer callbacks

  @impl true
  def init({interface, program, owner, opts}) do
    snaplen = Keyword.get(opts, :snaplen, @default_snaplen)
    promisc = Keyword.get(opts, :promisc, false)
    poll_interval = Keyword.get(opts, :poll_interval, @default_poll_interval)

    bytes = BPF.Program.assemble(program)

    with {:ok, resource} <- Peacap.NIF.open(interface, snaplen, promisc),
         :ok <- Peacap.NIF.set_filter(resource, bytes) do
      # Monitor the owner process
      Process.monitor(owner)

      # Start polling timer on macOS
      if :os.type() == {:unix, :darwin} do
        {:ok, _} = :timer.send_interval(poll_interval, :poll)
      end

      state = %__MODULE__{resource: resource, owner: owner}

      # Initiate first read
      {:ok, state, {:continue, :read}}
    else
      {:error, reason} ->
        {:stop, reason}
    end
  end

  @impl true
  def handle_continue(:read, state) do
    read_packets(state)
    {:noreply, state}
  end

  @impl true
  def handle_info({:"$peacap", _resource, :select, _ref}, state) do
    # File descriptor is ready for reading
    read_packets(state)
    {:noreply, state}
  end

  @impl true
  def handle_info(:poll, state) do
    # Periodic poll for macOS BPF buffering workaround
    read_packets(state)
    {:noreply, state}
  end

  @impl true
  def handle_info({:DOWN, _ref, :process, pid, _reason}, %{owner: pid} = state) do
    # Owner process died, shut down
    {:stop, :normal, state}
  end

  @impl true
  def terminate(_reason, state) do
    Peacap.NIF.close(state.resource)
  end

  # Read all available packets and send to owner
  defp read_packets(state) do
    case Peacap.NIF.recv(state.resource, :nowait) do
      {:ok, packet} ->
        send(state.owner, {:peacap_packet, self(), packet})
        # Try to read more packets
        read_packets(state)

      {:select, _ref} ->
        # No more packets available, wait for next notification
        :ok

      {:error, reason} ->
        {:stop, reason}
    end
  end
end
