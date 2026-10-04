alias UnicodeSecurity.UnicodeData.Generator
alias UnicodeSecurity.UnicodeData.Source

project_root = Path.expand("..", __DIR__)
source_directory = Source.directory(project_root)
output_directory = Path.join(project_root, "lib/unicode_security/data")

# Verify the complete lock before any generated file is written.
manifest_path = Generator.generate_manifest!(source_directory, output_directory)
Mix.shell().info("generated #{Path.relative_to(manifest_path, project_root)}")

output_path = Generator.generate!(source_directory, output_directory)
Mix.shell().info("generated #{Path.relative_to(output_path, project_root)}")

confusables_path = Generator.generate_confusables!(source_directory, output_directory)
Mix.shell().info("generated #{Path.relative_to(confusables_path, project_root)}")

bidi_path = Generator.generate_bidi!(source_directory, output_directory)
Mix.shell().info("generated #{Path.relative_to(bidi_path, project_root)}")

scripts_path = Generator.generate_scripts!(source_directory, output_directory)
Mix.shell().info("generated #{Path.relative_to(scripts_path, project_root)}")

identifier_path = Generator.generate_identifier!(source_directory, output_directory)
Mix.shell().info("generated #{Path.relative_to(identifier_path, project_root)}")

numbers_path = Generator.generate_numbers!(source_directory, output_directory)
Mix.shell().info("generated #{Path.relative_to(numbers_path, project_root)}")

for path <- [
      Generator.generate_profile!(source_directory, output_directory),
      Generator.generate_composition!(source_directory, output_directory),
      Generator.generate_idna!(source_directory, output_directory)
    ] do
  Mix.shell().info("generated #{Path.relative_to(path, project_root)}")
end
