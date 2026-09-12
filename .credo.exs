%{
  configs: [
    %{
      name: "default",
      files: %{included: ["{lib,dev,scripts,bench,test}/**/*.{ex,exs}", "mix.exs"]}
    }
  ]
}
