alias UnicodeSecurity.UnicodeData.Generator

project_root = Path.expand("..", __DIR__)
source_directory = Path.join(project_root, "priv/unicode/18.0.0-draft")
output_directory = Path.join(project_root, "lib/unicode_security/data")

output_path = Generator.generate!(source_directory, output_directory)
Mix.shell().info("generated #{Path.relative_to(output_path, project_root)}")

confusables_path = Generator.generate_confusables!(source_directory, output_directory)
Mix.shell().info("generated #{Path.relative_to(confusables_path, project_root)}")

manifest_path = Generator.generate_manifest!(source_directory, output_directory)
Mix.shell().info("generated #{Path.relative_to(manifest_path, project_root)}")
