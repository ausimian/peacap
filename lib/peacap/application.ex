defmodule Peacap.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    DynamicSupervisor.start_link(strategy: :one_for_one, name: Peacap.Supervisor)
  end

  @spec start_trace(String.t(), BPF.Program.t(), pid(), keyword()) ::
          {:ok, pid()} | {:error, term()}
  def start_trace(interface, bpf_program, owner, opts) do
    DynamicSupervisor.start_child(
      Peacap.Supervisor,
      {Peacap, {interface, bpf_program, owner, opts}}
    )
  end
end
