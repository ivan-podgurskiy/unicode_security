defmodule UnicodeSecurity.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/ivan-podgurskiy/unicode_security"

  def project do
    [
      app: :unicode_security,
      version: @version,
      elixir: "~> 1.14",
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: deps(),
      name: "UnicodeSecurity",
      description: "Unicode identifier spoofing and ambiguity detection for Elixir.",
      package: package(),
      source_url: @source_url,
      docs: docs(),
      test_coverage: [summary: [threshold: 100]],
      dialyzer: [
        plt_add_apps: [:ex_unit, :mix],
        plt_local_path: "priv/plts/local.plt",
        plt_core_path: "priv/plts/core.plt"
      ]
    ]
  end

  def application, do: [extra_applications: extra_applications(Mix.env())]

  defp elixirc_paths(:dev), do: ["lib", "dev"]
  defp elixirc_paths(:test), do: ["lib", "dev", "test/support"]
  defp elixirc_paths(_environment), do: ["lib"]

  defp extra_applications(environment) when environment in [:dev, :test],
    do: [:inets, :ssl]

  defp extra_applications(_environment), do: []

  defp deps do
    [
      {:stream_data, "~> 1.1", only: [:dev, :test]},
      {:ex_doc, "~> 0.37.0", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: :dev, runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false}
    ]
  end

  defp package do
    [
      files: ~w(lib .formatter.exs mix.exs README.md LICENSE CHANGELOG.md THIRD_PARTY_NOTICES.md),
      licenses: ["MIT"],
      links: %{"GitHub" => @source_url},
      maintainers: ["Ivan Podgurskiy"]
    ]
  end

  defp docs do
    [
      main: "UnicodeSecurity",
      source_ref: "v#{@version}",
      source_url: @source_url,
      extras: ["README.md", "CHANGELOG.md", "LICENSE", "THIRD_PARTY_NOTICES.md"]
    ]
  end
end
