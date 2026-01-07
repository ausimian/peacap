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

Requires libpcap to be installed on your system.

## License

MIT License - see [LICENSE.md](LICENSE.md)
