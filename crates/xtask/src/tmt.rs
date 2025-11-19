use anyhow::{Context, Result};
use camino::Utf8Path;
use fn_error_context::context;

// Generation markers for integration.fmf
const PLAN_MARKER_BEGIN: &str = "# BEGIN GENERATED PLANS\n";
const PLAN_MARKER_END: &str = "# END GENERATED PLANS\n";

/// Parse tmt metadata from a test file
/// Looks for:
/// # number: N
/// # tmt:
/// #   <yaml content>
fn parse_tmt_metadata(content: &str) -> Result<Option<TmtMetadata>> {
    let mut number = None;
    let mut in_tmt_block = false;
    let mut yaml_lines = Vec::new();

    for line in content.lines().take(50) {
        let trimmed = line.trim();

        // Look for "# number: N" line
        if let Some(rest) = trimmed.strip_prefix("# number:") {
            number = Some(rest.trim().parse::<u32>()
                .context("Failed to parse number field")?);
            continue;
        }

        if trimmed == "# tmt:" {
            in_tmt_block = true;
            continue;
        } else if in_tmt_block {
            // Stop if we hit a line that doesn't start with #, or is just "#"
            if !trimmed.starts_with('#') || trimmed == "#" {
                break;
            }
            // Remove the leading # and preserve indentation
            if let Some(yaml_line) = line.strip_prefix('#') {
                yaml_lines.push(yaml_line);
            }
        }
    }

    let Some(number) = number else {
        return Ok(None);
    };

    let yaml_content = yaml_lines.join("\n");
    let extra: serde_yaml::Value = if yaml_content.trim().is_empty() {
        serde_yaml::Value::Mapping(serde_yaml::Mapping::new())
    } else {
        serde_yaml::from_str(&yaml_content)
            .with_context(|| format!("Failed to parse tmt metadata YAML:\n{}", yaml_content))?
    };

    Ok(Some(TmtMetadata { number, extra }))
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
struct TmtMetadata {
    /// Test number for ordering and naming
    number: u32,
    /// All other fmf attributes (summary, duration, adjust, require, etc.)
    /// Note: summary and duration are typically required by fmf
    #[serde(flatten)]
    extra: serde_yaml::Value,
}

#[derive(Debug)]
struct TestDef {
    number: u32,
    name: String,
    test_command: String,
    /// All fmf attributes to pass through (summary, duration, adjust, etc.)
    extra: serde_yaml::Value,
}

/// Generate tmt/plans/integration.fmf from test definitions
#[context("Updating TMT integration.fmf")]
pub(crate) fn update_integration() -> Result<()> {
    // Define tests in order
    let mut tests = vec![];

    // Scan for test-*.nu and test-*.sh files in tmt/tests/booted/
    let booted_dir = Utf8Path::new("tmt/tests/booted");

    for entry in std::fs::read_dir(booted_dir)? {
        let entry = entry?;
        let path = entry.path();
        let Some(filename) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };

        // Extract stem (filename without "test-" prefix and extension)
        let Some(stem) = filename
            .strip_prefix("test-")
            .and_then(|s| s.strip_suffix(".nu").or_else(|| s.strip_suffix(".sh")))
        else {
            continue;
        };

        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Reading {}", filename))?;

        let metadata = parse_tmt_metadata(&content)
            .with_context(|| format!("Parsing tmt metadata from {}", filename))?
            .with_context(|| format!("Missing tmt metadata in {}", filename))?;

        // Remove number prefix if present (e.g., "01-readonly" -> "readonly", "26-examples-build" -> "examples-build")
        let display_name = stem
            .split_once('-')
            .and_then(|(prefix, suffix)| {
                if prefix.chars().all(|c| c.is_ascii_digit()) {
                    Some(suffix.to_string())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| stem.to_string());

        // Derive relative path from booted_dir
        let relative_path = path
            .strip_prefix("tmt/tests/")
            .with_context(|| format!("Failed to get relative path for {}", filename))?;

        // Determine test command based on file extension
        let extension = if filename.ends_with(".nu") {
            "nu"
        } else if filename.ends_with(".sh") {
            "bash"
        } else {
            anyhow::bail!("Unsupported test file extension: {}", filename);
        };

        let test_command = format!("{} {}", extension, relative_path.display());

        tests.push(TestDef {
            number: metadata.number,
            name: display_name,
            test_command,
            extra: metadata.extra,
        });
    }

    // Sort tests by number
    tests.sort_by_key(|t| t.number);

    // Generate single tests.fmf file
    let tests_dir = Utf8Path::new("tmt/tests");
    let tests_fmf_path = tests_dir.join("tests.fmf");
    let mut tests_content = String::new();

    // Add generated code marker
    tests_content.push_str("# THIS IS GENERATED CODE - DO NOT EDIT\n");
    tests_content.push_str("# Generated by: cargo xtask tmt\n");
    tests_content.push_str("\n");

    for test in &tests {
        tests_content.push_str(&format!("/test-{:02}-{}:\n", test.number, test.name));

        // Serialize all fmf attributes from metadata (summary, duration, adjust, etc.)
        if let serde_yaml::Value::Mapping(map) = &test.extra {
            if !map.is_empty() {
                let extra_yaml = serde_yaml::to_string(&test.extra)
                    .context("Serializing extra metadata")?;
                for line in extra_yaml.lines() {
                    if !line.trim().is_empty() {
                        tests_content.push_str(&format!("  {}\n", line));
                    }
                }
            }
        }

        // Add the test command (derived from file type, not in metadata)
        if test.test_command.contains('\n') {
            tests_content.push_str("  test: |\n");
            for line in test.test_command.lines() {
                tests_content.push_str(&format!("    {}\n", line));
            }
        } else {
            tests_content.push_str(&format!("  test: {}\n", test.test_command));
        }

        tests_content.push_str("\n");
    }

    // Only write if content changed
    let needs_update = match std::fs::read_to_string(&tests_fmf_path) {
        Ok(existing) => existing != tests_content,
        Err(_) => true,
    };

    if needs_update {
        std::fs::write(&tests_fmf_path, tests_content)
            .context("Writing tests.fmf")?;
        println!("Generated {}", tests_fmf_path);
    } else {
        println!("Unchanged: {}", tests_fmf_path);
    }

    // Generate plans section (at root level, no indentation)
    let mut plans_section = String::new();
    for test in &tests {
        plans_section.push_str(&format!("/plan-{:02}-{}:\n", test.number, test.name));

        // Extract summary from extra metadata
        if let serde_yaml::Value::Mapping(map) = &test.extra {
            if let Some(summary) = map.get(&serde_yaml::Value::String("summary".to_string())) {
                if let Some(summary_str) = summary.as_str() {
                    plans_section.push_str(&format!("  summary: {}\n", summary_str));
                }
            }
        }

        plans_section.push_str("  discover:\n");
        plans_section.push_str("    how: fmf\n");
        plans_section.push_str("    test:\n");
        plans_section.push_str(&format!("      - /tmt/tests/tests/test-{:02}-{}\n", test.number, test.name));

        // Extract and serialize adjust section if present
        if let serde_yaml::Value::Mapping(map) = &test.extra {
            if let Some(adjust) = map.get(&serde_yaml::Value::String("adjust".to_string())) {
                let adjust_yaml = serde_yaml::to_string(adjust)
                    .context("Serializing adjust metadata")?;
                plans_section.push_str("  adjust:\n");
                for line in adjust_yaml.lines() {
                    if !line.trim().is_empty() {
                        plans_section.push_str(&format!("  {}\n", line));
                    }
                }
            }
        }

        plans_section.push_str("\n");
    }

    // Update integration.fmf with generated plans
    let output_path = Utf8Path::new("tmt/plans/integration.fmf");
    let existing_content = std::fs::read_to_string(output_path)
        .context("Reading integration.fmf")?;

    // Replace plans section
    let (before_plans, rest) = existing_content.split_once(PLAN_MARKER_BEGIN)
        .context("Missing # BEGIN GENERATED PLANS marker in integration.fmf")?;
    let (_old_plans, after_plans) = rest.split_once(PLAN_MARKER_END)
        .context("Missing # END GENERATED PLANS marker in integration.fmf")?;

    let new_content = format!(
        "{}{}{}{}{}",
        before_plans, PLAN_MARKER_BEGIN, plans_section, PLAN_MARKER_END, after_plans
    );

    // Only write if content changed
    let needs_update = match std::fs::read_to_string(output_path) {
        Ok(existing) => existing != new_content,
        Err(_) => true,
    };

    if needs_update {
        std::fs::write(output_path, new_content)?;
        println!("Generated {}", output_path);
    } else {
        println!("Unchanged: {}", output_path);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tmt_metadata_basic() {
        let content = r#"# number: 1
# tmt:
#   summary: Execute booted readonly/nondestructive tests
#   duration: 30m
#
# Run all readonly tests in sequence
use tap.nu
"#;

        let metadata = parse_tmt_metadata(content).unwrap().unwrap();
        assert_eq!(metadata.number, 1);

        // Verify extra fields are captured
        let extra = metadata.extra.as_mapping().unwrap();
        assert_eq!(
            extra.get(&serde_yaml::Value::String("summary".to_string())),
            Some(&serde_yaml::Value::String("Execute booted readonly/nondestructive tests".to_string()))
        );
        assert_eq!(
            extra.get(&serde_yaml::Value::String("duration".to_string())),
            Some(&serde_yaml::Value::String("30m".to_string()))
        );
    }

    #[test]
    fn test_parse_tmt_metadata_with_adjust() {
        let content = r#"# number: 27
# tmt:
#   summary: Execute custom selinux policy test
#   duration: 30m
#   adjust:
#     - when: running_env != image_mode
#       enabled: false
#       because: these tests require features only available in image mode
#
use std assert
"#;

        let metadata = parse_tmt_metadata(content).unwrap().unwrap();
        assert_eq!(metadata.number, 27);

        // Verify adjust section is in extra
        let extra = metadata.extra.as_mapping().unwrap();
        assert!(extra.contains_key(&serde_yaml::Value::String("adjust".to_string())));
    }

    #[test]
    fn test_parse_tmt_metadata_no_metadata() {
        let content = r#"# Just a comment
use std assert
"#;

        let result = parse_tmt_metadata(content).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_tmt_metadata_shell_script() {
        let content = r#"# number: 26
# tmt:
#   summary: Test bootc examples build scripts
#   duration: 45m
#   adjust:
#     - when: running_env != image_mode
#       enabled: false
#
#!/bin/bash
set -eux
"#;

        let metadata = parse_tmt_metadata(content).unwrap().unwrap();
        assert_eq!(metadata.number, 26);

        let extra = metadata.extra.as_mapping().unwrap();
        assert_eq!(
            extra.get(&serde_yaml::Value::String("duration".to_string())),
            Some(&serde_yaml::Value::String("45m".to_string()))
        );
        assert!(extra.contains_key(&serde_yaml::Value::String("adjust".to_string())));
    }
}
