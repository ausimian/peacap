# Peacap

Packet capture for Elixir using libpcap with BPF filtering.

## Features

- Async packet delivery using `enif_select`
- BPF filter support via the [bpf](https://hex.pm/packages/bpf) library
- Owner process monitoring with automatic cleanup
- macOS BPF buffering workaround

## Usage

```elixir
require BPF

# Compile a BPF filter to accept all packets
program = BPF.compile(fn <<_::binary>> -> true end)

# Start capturing on an interface
{:ok, pid} = Peacap.start("en0", program)

# Packets are delivered as messages
receive do
  {:peacap_packet, ^pid, packet} ->
    IO.inspect(packet, label: "captured")
end

# Stop capturing
Peacap.stop(pid)
```

## Installation

Add `peacap` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:peacap, "~> 0.1.0"}
  ]
end
```

### Requirements

**Build time:** libpcap headers and libraries must be installed.

```bash
# macOS (included with Xcode Command Line Tools)
xcode-select --install

# Debian/Ubuntu
sudo apt-get install libpcap-dev

# Fedora/RHEL
sudo dnf install libpcap-devel
```

**Runtime:** libpcap must be installed on the target system.

### Running Tests

```bash
# macOS - no special privileges needed for loopback
mix test

# Linux - requires sudo or CAP_NET_RAW
sudo mix test

# Or grant capability to the beam executable (find path with iex first)
# iex> IO.puts("#{:code.root_dir()}/erts-#{:erlang.system_info(:version)}/bin/beam.smp")
sudo setcap cap_net_raw=eip /usr/lib/erlang/erts-*/bin/beam.smp
mix test
```

## License

MIT License - see [LICENSE.md](LICENSE.md)
