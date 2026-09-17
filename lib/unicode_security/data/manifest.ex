defmodule UnicodeSecurity.Data.Manifest do
  @moduledoc false

  @spec get() :: map()
  def get,
    do: %{
      release_status: :draft,
      sources: [
        %{
          name: "BidiBrackets.txt",
          url: "https://www.unicode.org/Public/18.0.0/ucd/BidiBrackets.txt",
          version: "18.0.0",
          bytes: 8_992,
          sha256: "4b3b62e4a14b84ee752808c810c602534921c09a4a1bf78cfbee566d66c125b3",
          status: :draft
        },
        %{
          name: "BidiCharacterTest.txt",
          url: "https://www.unicode.org/Public/18.0.0/ucd/BidiCharacterTest.txt",
          version: "18.0.0",
          bytes: 6_880_771,
          sha256: "045b24d2c8ab066951bd32fe8c6b4de34647f72b5b1c7df0265f24ab53573e01",
          status: :draft
        },
        %{
          name: "BidiMirroring.txt",
          url: "https://www.unicode.org/Public/18.0.0/ucd/BidiMirroring.txt",
          version: "18.0.0",
          bytes: 27_352,
          sha256: "cd47918b28b73c3be37d730d0f48ab11e862afef9eb11d85ad832be9fb6c7f8f",
          status: :draft
        },
        %{
          name: "BidiTest.txt",
          url: "https://www.unicode.org/Public/18.0.0/ucd/BidiTest.txt",
          version: "18.0.0",
          bytes: 7_959_988,
          sha256: "9af2f882a4ab50912e388f069a673b94eacd82fa6d07d20a3ff7f3c759e905aa",
          status: :draft
        },
        %{
          name: "DerivedBidiClass.txt",
          url: "https://www.unicode.org/Public/18.0.0/ucd/extracted/DerivedBidiClass.txt",
          version: "18.0.0",
          bytes: 176_412,
          sha256: "d9e23222522551348ea1ccfbb4f62efbf98982afb95840f8959c08ed992c5607",
          status: :draft
        },
        %{
          name: "DerivedCombiningClass.txt",
          url: "https://www.unicode.org/Public/18.0.0/ucd/extracted/DerivedCombiningClass.txt",
          version: "18.0.0",
          bytes: 186_280,
          sha256: "ef6b2611cfb660dba3f6b458b9eb4b05f44ed2417302ee7749d7f0f348793121",
          status: :draft
        },
        %{
          name: "DerivedCoreProperties.txt",
          url: "https://www.unicode.org/Public/18.0.0/ucd/DerivedCoreProperties.txt",
          version: "18.0.0",
          bytes: 1_159_889,
          sha256: "09c928886a178fcafd93c29e4bd59073a058e5a100b716d425cb563ab50f68c9",
          status: :draft
        },
        %{
          name: "DerivedJoiningType.txt",
          url: "https://www.unicode.org/Public/18.0.0/ucd/extracted/DerivedJoiningType.txt",
          version: "18.0.0",
          bytes: 41_024,
          sha256: "e2408ff2c92b175b0f7bf62c989bbb54c7b077528fe31f8d69b96fa09e7d61ed",
          status: :draft
        },
        %{
          name: "DerivedNormalizationProps.txt",
          url: "https://www.unicode.org/Public/18.0.0/ucd/DerivedNormalizationProps.txt",
          version: "18.0.0",
          bytes: 1_396_877,
          sha256: "98ac7f67d985fe781e317f6182e885e94cabb0c314769e6dd73e48b226931ccd",
          status: :draft
        },
        %{
          name: "IdentifierStatus.txt",
          url: "https://www.unicode.org/Public/draft/security/IdentifierStatus.txt",
          version: "18.0.0",
          bytes: 148_042,
          sha256: "5863c7d99ca18f213c41c7318aa5528bebfb6d32ec0f1d5944e37192c119aebd",
          status: :draft
        },
        %{
          name: "IdentifierType.txt",
          url: "https://www.unicode.org/Public/draft/security/IdentifierType.txt",
          version: "18.0.0",
          bytes: 534_017,
          sha256: "fa24851acc669e58670e354e7b98a4ec8f52a809ec4f80524b6a60efdb868831",
          status: :draft
        },
        %{
          name: "IndicSyllabicCategory.txt",
          url: "https://www.unicode.org/Public/18.0.0/ucd/IndicSyllabicCategory.txt",
          version: "18.0.0",
          bytes: 86_842,
          sha256: "a2b3aacf6b3e7bad4ca351ef985d9543825e20280ff280c25f646d9bc4ce304c",
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
          name: "PropList.txt",
          url: "https://www.unicode.org/Public/18.0.0/ucd/PropList.txt",
          version: "18.0.0",
          bytes: 149_040,
          sha256: "f438f532e8737bb8a2702126cdf9c4af5e357c58c7acf9d9eb2fc7c1a1d955d6",
          status: :draft
        },
        %{
          name: "PropertyValueAliases.txt",
          url: "https://www.unicode.org/Public/18.0.0/ucd/PropertyValueAliases.txt",
          version: "18.0.0",
          bytes: 83_536,
          sha256: "06c4c8eaf7b0bf34abe73b113da1215bd784ac254d4c223600b90267caa4bbbd",
          status: :draft
        },
        %{
          name: "ScriptExtensions.txt",
          url: "https://www.unicode.org/Public/18.0.0/ucd/ScriptExtensions.txt",
          version: "18.0.0",
          bytes: 21_145,
          sha256: "5c9d34a922f687726f2a8bcf57d49f905987e51f1b21b58c95a00fbe255cec23",
          status: :draft
        },
        %{
          name: "Scripts.txt",
          url: "https://www.unicode.org/Public/18.0.0/ucd/Scripts.txt",
          version: "18.0.0",
          bytes: 196_089,
          sha256: "0071fd81b6aeae25f6e8bce8efec3066a6476a91b49bdb2f52dc76e817862a6a",
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
