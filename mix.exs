defmodule PeaCap.MixProject do
  use Mix.Project

  def project do
    [
      app: :peacap,
      version: "0.1.0",
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      compilers: [:elixir_make] ++ Mix.compilers(),
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.post": :test,
        "coveralls.html": :test
      ],
      deps: deps()
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
      {:excoveralls, "~> 0.18", only: :test},
      {:typedstruct, "~> 0.5", runtime: false}
    ]
  end
end
