defmodule Peacap.MixProject do
  use Mix.Project

  @version "0.1.0"

  def project do
    [
      app: :peacap,
      version: @version,
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      compilers: [:elixir_make] ++ Mix.compilers(),
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.post": :test,
        "coveralls.html": :test
      ],
      deps: deps(),

      # Docs
      name: "Peacap",
      description: "Packet capture for Elixir using libpcap with BPF filtering",
      source_url: "https://github.com/ausimian/peacap",
      docs: [
        main: "Peacap",
        extras: ["README.md", "LICENSE.md"],
        source_ref: "#{@version}"
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger],
      mod: {Peacap.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:bpf, "~> 0.1.1"},
      {:elixir_make, "~> 0.9", runtime: false},
      {:ex_doc, "~> 0.35", only: :dev, runtime: false},
      {:excoveralls, "~> 0.18", only: :test},
      {:typedstruct, "~> 0.5", runtime: false}
    ]
  end
end
