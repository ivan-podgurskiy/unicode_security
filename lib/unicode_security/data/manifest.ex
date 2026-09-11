defmodule UnicodeSecurity.Data.Manifest do
  @moduledoc false

  @spec get() :: map()
  def get,
    do: %{
      release_status: :draft,
      sources: [
        %{
          name: "DerivedCombiningClass.txt",
          url: "https://www.unicode.org/Public/18.0.0/ucd/extracted/DerivedCombiningClass.txt",
          version: "18.0.0",
          bytes: 186_280,
          sha256: "ef6b2611cfb660dba3f6b458b9eb4b05f44ed2417302ee7749d7f0f348793121",
          status: :draft
        },
        %{
          name: "NormalizationTest.txt",
          url: "https://www.unicode.org/Public/18.0.0/ucd/NormalizationTest.txt",
          version: "18.0.0",
          bytes: 2_863_708,
          sha256: "25a50d816764b04abfb4a646d3eb2b2a803284c3873d9a06757b94fe4513dde3",
          status: :draft
        },
        %{
          name: "UnicodeData.txt",
          url: "https://www.unicode.org/Public/18.0.0/ucd/UnicodeData.txt",
          version: "18.0.0",
          bytes: 2_243_593,
          sha256: "0736451de439ae7baf1425136617da495e09ee5afbe6e394374db7009ea08950",
          status: :draft
        },
        %{
          name: "confusables.txt",
          url: "https://www.unicode.org/Public/draft/security/confusables.txt",
          version: "18.0.0",
          bytes: 763_128,
          sha256: "6ed3ee967c9dfdf6677d563c9985182fbc50a2efb7d6059cd57b2e2ce18f5b92",
          status: :draft
        }
      ]
    }
end
