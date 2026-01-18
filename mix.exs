defmodule Peacap.MixProject do
  use Mix.Project

  @version "0.1.1"

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
      aliases: aliases(),

      # Hex
      package: package(),

      # Docs
      name: "Peacap",
      description: "Packet capture for Elixir using libpcap with BPF filtering",
      source_url: "https://github.com/ausimian/peacap",
      docs: [
        main: "Peacap",
        extras: ["README.md", "CHANGELOG.md", "LICENSE.md"],
        source_ref: "#{@version}"
      ]
    ]
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/ausimian/peacap"},
      files: ~w(lib c_src Makefile mix.exs README.md CHANGELOG.md LICENSE.md)
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
      {:bpf, "~> 0.1"},
      {:elixir_make, "~> 0.9", runtime: false},
      {:ex_doc, "~> 0.35", only: :dev, runtime: false},
      {:excoveralls, "~> 0.18", only: :test},
      {:typedstruct, "~> 0.5", runtime: false},
      {:expublish, "~> 2.5", only: [:dev], runtime: false}
    ]
  end

  def aliases do
    [
      "expublish.major": &expublish("expublish.major", &1),
      "expublish.minor": &expublish("expublish.minor", &1),
      "expublish.patch": &expublish("expublish.patch", &1),
      "expublish.stable": &expublish("expublish.stable", &1),
      "expublish.rc": &expublish("expublish.rc", &1),
      "expublish.beta": &expublish("expublish.beta", &1),
      "expublish.alpha": &expublish("expublish.alpha", &1)
    ]
  end

  defp expublish(task, args) do
    common = ["--tag-prefix", "", "--commit-prefix", "Version", "--branch", ""]

    if "--no-dry-run" in args do
      Mix.Task.run(task, common ++ args)
    else
      Mix.Task.run(task, ["--dry-run" | common] ++ args)
    end
  end
end
