defmodule Peacap.NIF do
  @moduledoc false
  @on_load :load_nif

  def load_nif do
    path = :filename.join(:code.priv_dir(:peacap), ~c"peacap_nif")
    :erlang.load_nif(path, 0)
  end

  @spec open(String.t(), integer(), boolean()) ::
          {:ok, reference()} | {:error, term()}
  def open(interface, snaplen, promisc) do
    promisc_int = if promisc, do: 1, else: 0
    nif_open(String.to_charlist(interface), snaplen, promisc_int)
  end

  defp nif_open(_interface, _snaplen, _promisc), do: :erlang.nif_error(:not_loaded)

  @spec set_filter(reference(), binary()) :: :ok | {:error, term()}
  def set_filter(_resource, _bpf_bytes), do: :erlang.nif_error(:not_loaded)

  @spec recv(reference(), :nowait) :: {:ok, binary()} | {:select, reference()} | {:error, term()}
  def recv(_resource, _flags), do: :erlang.nif_error(:not_loaded)

  @spec close(reference()) :: :ok | {:error, term()}
  def close(_resource), do: :erlang.nif_error(:not_loaded)
end
