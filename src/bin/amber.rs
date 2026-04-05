use std::path::PathBuf;

use amber::AmberError;
use amber::cli::{
    ExistsMode, ScrubOptions, SealOptions, SealProgress, UnsealOptions, UnsealProgress,
    append_command, archive_error_is_locked, archive_info, assert_archive_clean_for_harden,
    default_repaired_output_path, format_scrub_summary, list_archive, parse_part_size,
    rebuild_command, repair_command_with_progress, scrub_archives, scrub_summary_json,
    seal_archive_with_progress, unseal_archive_with_progress, verify_archive,
};
use amber::harden::append_amcf_parity;
use clap::{Parser, Subcommand};
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(name = "amber", about = "Amber archive tool")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Seal {
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        keyfile: Option<PathBuf>,
        #[arg(long)]
        compress: bool,
        #[arg(long, value_parser = parse_part_size)]
        part_size: Option<u64>,
        #[arg(long)]
        quiet: bool,
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
    List {
        archive: PathBuf,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        keyfile: Option<PathBuf>,
    },
    Info {
        archive: PathBuf,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        keyfile: Option<PathBuf>,
    },
    Unseal {
        archive: PathBuf,
        #[arg(long, default_value = ".")]
        outdir: PathBuf,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        keyfile: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = ExistsArg::Rename)]
        exists: ExistsArg,
        #[arg(long)]
        quiet: bool,
        #[arg()]
        paths: Vec<String>,
    },
    Verify {
        archive: PathBuf,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        keyfile: Option<PathBuf>,
    },
    Append {
        archive: PathBuf,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        keyfile: Option<PathBuf>,
        #[arg(required = true)]
        inputs: Vec<PathBuf>,
    },
    Rebuild {
        archive: PathBuf,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        keyfile: Option<PathBuf>,
    },
    Harden {
        archive: PathBuf,
        #[arg(long = "extra-parity-percent", value_parser = parse_extra_parity_percent, default_value = "3")]
        extra_parity_ppm: usize,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        keyfile: Option<PathBuf>,
    },
    Repair {
        archive: PathBuf,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        keyfile: Option<PathBuf>,
        #[arg(long)]
        safe: bool,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    Scrub {
        #[arg(long, short = 'r')]
        recursive: bool,
        #[arg(long, short = 'j', default_value_t = 4)]
        jobs: usize,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        keyfile: Option<PathBuf>,
        #[arg(long)]
        repair: bool,
        #[arg(long)]
        safe: bool,
        #[arg(long, default_value_t = 0)]
        harden_extra: usize,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        quiet: bool,
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum ExistsArg {
    Overwrite,
    Skip,
    Rename,
    Fail,
}

fn main() {
    let args = Args::parse();
    let code = match run(args) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("{}", render_generic_error(&err));
            2
        }
    };
    std::process::exit(code);
}

fn format_repair_report(
    result: &amber::repair::ECCRepairResult,
    repaired_copy_path: Option<&std::path::Path>,
) -> String {
    let mut lines = Vec::new();
    if let Some(path) = repaired_copy_path {
        lines.push(format!("Repaired copy written to: {}", path.display()));
    }
    lines.push(format!(
        "Repair summary: {} repaired ({} AMCF), {} unrepaired",
        result.amcf_repaired.len(),
        result.amcf_repaired.len(),
        result.remaining_corrupted.len()
    ));
    if result.detected_data_chunks > 0 {
        lines.push(format!(
            "Detected damaged data chunks: {}",
            result.detected_data_chunks
        ));
    }
    if !result.amcf_repaired.is_empty() {
        lines.push(format!("AMCF repaired symbols: {:?}", result.amcf_repaired));
    }
    if !result.remaining_corrupted.is_empty() {
        if result.remaining_data_chunks > 0 {
            lines.push(format!(
                "Remaining damaged data chunks: {}",
                result.remaining_data_chunks
            ));
        }
        lines.push(format!(
            "Unrepaired symbols: {:?}",
            result.remaining_corrupted
        ));
        lines.push(
            "Reason: surviving ECC was insufficient to recover the remaining corrupted symbols."
                .into(),
        );
        lines.push("This archive is still damaged.".into());
    }
    if result.amcf_repaired.is_empty() && result.remaining_corrupted.is_empty() {
        lines.push("No corruption detected".into());
    }
    if let Some(count) = result.rebuilt_index_parity_symbols {
        if count == 0 {
            lines.push("Rebuilt index metadata".into());
        } else {
            lines.push(format!(
                "Rebuilt index metadata ({count} AMCF parity symbol(s))"
            ));
        }
    }
    lines.join("\n")
}

fn parse_extra_parity_percent(value: &str) -> Result<usize, String> {
    let text = value.trim();
    if text.is_empty() {
        return Err("extra parity percent must not be empty".into());
    }
    if text.starts_with('-') {
        return Err("extra parity percent must be non-negative".into());
    }
    let (whole_part, frac_part) = match text.split_once('.') {
        Some((whole, frac)) => (whole, Some(frac)),
        None => (text, None),
    };
    if whole_part.is_empty() || !whole_part.bytes().all(|b| b.is_ascii_digit()) {
        return Err("invalid extra parity percent".into());
    }
    let whole = whole_part
        .parse::<u64>()
        .map_err(|_| "invalid extra parity percent".to_string())?;
    let frac_digits = frac_part.unwrap_or("");
    if !frac_digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err("invalid extra parity percent".into());
    }
    if frac_digits.len() > 4 {
        return Err("extra parity percent supports at most 4 decimal places".into());
    }
    let mut frac_scaled = 0u64;
    if !frac_digits.is_empty() {
        let frac = frac_digits
            .parse::<u64>()
            .map_err(|_| "invalid extra parity percent".to_string())?;
        let scale = 10u64.pow((4 - frac_digits.len()) as u32);
        frac_scaled = frac
            .checked_mul(scale)
            .ok_or_else(|| "extra parity percent is too large".to_string())?;
    }
    let ppm = whole
        .checked_mul(10_000)
        .and_then(|value| value.checked_add(frac_scaled))
        .ok_or_else(|| "extra parity percent is too large".to_string())?;
    usize::try_from(ppm).map_err(|_| "extra parity percent is too large".into())
}

fn run(args: Args) -> Result<i32, AmberError> {
    match args.command {
        Command::Seal {
            paths,
            output,
            password,
            keyfile,
            compress,
            part_size,
            quiet,
        } => {
            let started = Instant::now();
            let summary = seal_archive_with_progress(
                &paths,
                &SealOptions {
                    output,
                    password,
                    keyfile,
                    compress,
                    part_size,
                },
                |event| {
                    match event {
                        SealProgress::SealingInput(path) => println!("Sealing {}", path.display()),
                        SealProgress::SealingFile {
                            archive_path,
                            processed_bytes,
                            total_bytes,
                        } => {
                            if !quiet {
                                let pct = (processed_bytes as f64) * 100.0 / (total_bytes as f64);
                                println!(" {pct:6.2}% sealing: {archive_path}");
                            }
                        }
                        SealProgress::Finalizing => {
                            println!(" Finalizing (AMCF global parity, anchors, index)...");
                        }
                    }
                },
            )?;
            let dt = started.elapsed().as_secs_f64().max(0.000_001);
            let mib = summary.processed_bytes as f64 / (1024.0 * 1024.0);
            let mbps = mib / dt;
            let total_pct = (100.0 / 12.0) + 17.0;
            println!(
                "Done: {} files, {} dirs, {} links; {:.2} MiB in {:.1}s; {:.2} MiB/s; ECC=archival (~{:.2}% total parity, AMCF-ECC); compression={}",
                summary.file_count,
                summary.dir_count,
                summary.symlink_count,
                mib,
                dt,
                mbps,
                total_pct,
                if compress { "deflate" } else { "off" }
            );
            if part_size.is_some() {
                println!("Multipart output: {}.001 ...", summary.output_path.display());
            }
            Ok(0)
        }
        Command::List {
            archive,
            password,
            keyfile,
        } => {
            let summary = list_archive(&archive, password.as_deref(), keyfile.as_deref())?;
            if summary.anchor_fail_count > 0 {
                eprintln!(
                    "Warning: {}/{} anchor(s) could not be read. Anchors are not critical; run 'amber rebuild' to fix anchor references.",
                    summary.anchor_fail_count, summary.anchor_total_count,
                );
            }
            for entry in summary.entries {
                match (entry.kind, entry.symlink_target.as_deref()) {
                    (0, _) => println!("file\t{}\t{}", entry.size, entry.path),
                    (2, Some(target)) => println!("symlink\t-> {}\t{}", target, entry.path),
                    (1, _) => println!("dir\t{}", entry.path),
                    (_, _) => println!("{}\t{}", entry.kind, entry.path),
                }
            }
            Ok(0)
        }
        Command::Info {
            archive,
            password,
            keyfile,
        } => {
            let info = match archive_info(&archive, password.as_deref(), keyfile.as_deref()) {
                Ok(info) => info,
                Err(err) => return Err(rewrite_read_only_error(&archive, err)),
            };
            println!("Archive: {}", info.path.display());
            println!("  Version: {}.{}", info.version_major, info.version_minor);
            println!("  UUID: {}", info.uuid_hex);
            println!("  Created: {}", info.created_sec);
            println!("  Flags: {}", info.flags);
            if let Some(chunk_size) = info.default_chunk_size {
                println!("  Default chunk size: {chunk_size}");
            } else {
                println!("  Default chunk size: N/A");
            }
            if let Some(codec) = info.default_codec {
                println!("  Default codec: {codec}");
            } else {
                println!("  Default codec: N/A");
            }
            if let Some(part_size) = info.multipart_part_size {
                println!("  Multipart part size: {part_size}");
            }
            println!("  Segments: {}", info.segment_count);
            println!("  Entries: {}", info.entry_count);
            println!("    Files: {}", info.file_count);
            println!("    Directories: {}", info.dir_count);
            println!("    Symlinks: {}", info.symlink_count);
            Ok(0)
        }
        Command::Unseal {
            archive,
            outdir,
            password,
            keyfile,
            exists,
            quiet,
            paths,
        } => {
            let started = Instant::now();
            let summary = match unseal_archive_with_progress(
                &archive,
                &UnsealOptions {
                    outdir,
                    password,
                    keyfile,
                    paths,
                    exists: match exists {
                        ExistsArg::Overwrite => ExistsMode::Overwrite,
                        ExistsArg::Skip => ExistsMode::Skip,
                        ExistsArg::Rename => ExistsMode::Rename,
                        ExistsArg::Fail => ExistsMode::Fail,
                    },
                },
                |event| match event {
                    UnsealProgress::StartArchive(path) => println!("Unsealing {}", path.display()),
                    UnsealProgress::CreatingDir { archive_path } => {
                        println!("   creating: {archive_path}/");
                    }
                    UnsealProgress::Symlinking {
                        archive_path,
                        target,
                    } => {
                        println!("  symlinking: {archive_path} -> {target}");
                    }
                    UnsealProgress::SkippingExisting { archive_path } => {
                        println!("    skipping: {archive_path} (exists)");
                    }
                    UnsealProgress::RenamedTo { path } => {
                        println!("       note: renamed to {}", path.display());
                    }
                    UnsealProgress::UnsealingFile {
                        archive_path,
                        processed_files,
                        total_files,
                    } => {
                        if !quiet {
                            println!(
                                " unsealing: {:>4}/{:<4} {}",
                                processed_files, total_files, archive_path
                            );
                        }
                    }
                },
            ) {
                Ok(summary) => summary,
                Err(err) => return Err(rewrite_read_only_error(&archive, err)),
            };
            let dt = started.elapsed().as_secs_f64().max(0.000_001);
            let mib = summary.processed_bytes as f64 / (1024.0 * 1024.0);
            let mbps = mib / dt;
            let symlink_summary = if summary.total_symlinks == 0 {
                summary.created_symlinks.to_string()
            } else {
                format!("{}/{}", summary.created_symlinks, summary.total_symlinks)
            };
            println!(
                "Done: extracted {}/{} files ({:.2} MiB) in {:.1}s; {:.2} MiB/s; dirs={} symlinks={}; skipped={} renamed={}",
                summary.extracted_files,
                summary.total_files,
                mib,
                dt,
                mbps,
                summary.created_dirs,
                symlink_summary,
                summary.skipped_entries,
                summary.renamed_entries
            );
            Ok(0)
        }
        Command::Verify {
            archive,
            password,
            keyfile,
        } => {
            println!("Verifying {}", archive.display());
            let summary = match verify_archive(&archive, password.as_deref(), keyfile.as_deref()) {
                Ok(summary) => summary,
                Err(err) => return Err(rewrite_verify_error(&archive, err)),
            };
            if summary.anchor_fail_count > 0 {
                eprintln!(
                    "Warning: {}/{} anchor(s) could not be read. Anchors are not critical; run 'amber rebuild' to fix anchor references.",
                    summary.anchor_fail_count, summary.anchor_total_count,
                );
            }
            println!("{}", if summary.ok { "OK" } else { "FAIL" });
            Ok(if summary.ok { 0 } else { 1 })
        }
        Command::Append {
            archive,
            inputs,
            password,
            keyfile,
        } => {
            println!(
                " Appending files to {} and rewriting index...",
                archive.display()
            );
            append_command(&archive, &inputs, password.as_deref(), keyfile.as_deref())?;
            Ok(0)
        }
        Command::Rebuild {
            archive,
            password,
            keyfile,
        } => {
            println!("Rebuilding {}", archive.display());
            let backup = rebuild_command(&archive, password.as_deref(), keyfile.as_deref())?;
            println!(
                "Rebuilt archive committed. Backup written to: {}",
                backup.display()
            );
            Ok(0)
        }
        Command::Harden {
            archive,
            extra_parity_ppm,
            password,
            keyfile,
        } => {
            println!("Hardening {}", archive.display());
            assert_archive_clean_for_harden(&archive, password.as_deref(), keyfile.as_deref())?;
            println!(
                " Rewriting archive with ~{:.2}% additional AMCF parity...",
                extra_parity_ppm as f64 / 10000.0
            );
            let added =
                append_amcf_parity(
                    &archive,
                    extra_parity_ppm,
                    password.as_deref(),
                    keyfile.as_deref(),
                )?;
            println!("Added {added} AMCF parity symbol(s)");
            Ok(0)
        }
        Command::Repair {
            archive,
            password,
            keyfile,
            safe,
            output,
        } => {
            let effective_safe = safe || output.is_some();
            let mut progress = |msg: String| {
                println!("{msg}");
            };
            let result = repair_command_with_progress(
                &archive,
                effective_safe,
                password.as_deref(),
                keyfile.as_deref(),
                output.as_deref(),
                Some(&mut progress),
            )?;
            let display_path = if effective_safe {
                if output.is_none() {
                    Some(default_repaired_output_path(&archive)?)
                } else {
                    result.output_path.clone()
                }
            } else {
                None
            };
            println!("{}", format_repair_report(&result, display_path.as_deref()));
            Ok(0)
        }
        Command::Scrub {
            paths,
            recursive,
            jobs,
            password,
            keyfile,
            repair,
            safe,
            harden_extra,
            json,
            quiet,
        } => {
            let summary = scrub_archives(
                &paths,
                &ScrubOptions {
                    recursive,
                    jobs,
                    password,
                    keyfile,
                    repair,
                    safe,
                    harden_extra,
                },
            )?;
            if json {
                println!("{}", scrub_summary_json(&summary)?);
            } else {
                println!("{}", format_scrub_summary(&summary, quiet));
            }
            Ok(if summary.failed == 0 { 0 } else { 1 })
        }
    }
}

fn rewrite_verify_error(path: &std::path::Path, err: AmberError) -> AmberError {
    if archive_error_is_locked(path, &err) {
        return AmberError::Invalid(
            "LOCKED: encrypted archive requires correct --password/--keyfile (or encrypted metadata is damaged).".into(),
        );
    }
    if err.is_rebuild_index_candidate() {
        return AmberError::Invalid(
            "Verification failed due to index corruption. This command is read-only.\nHint: run 'amber repair --safe' to rebuild the index and attempt recovery.".into(),
        );
    }
    err
}

fn rewrite_read_only_error(path: &std::path::Path, err: AmberError) -> AmberError {
    if archive_error_is_locked(path, &err) {
        return AmberError::Invalid(
            "LOCKED: encrypted archive requires correct --password/--keyfile (or encrypted metadata is damaged).".into(),
        );
    }
    if err.is_rebuild_index_candidate() {
        return AmberError::Invalid(
            "Index appears inconsistent or corrupted. This command is read-only.\nHint: run 'amber repair --safe' to rebuild the index and attempt recovery.".into(),
        );
    }
    err
}

fn render_generic_error(err: &AmberError) -> String {
    let msg = err.to_string();
    let lower = msg.to_ascii_lowercase();
    if lower.contains("password or keyfile required") || lower.contains("password required") {
        return "Error: Archive is encrypted. Provide --password and/or --keyfile.".into();
    }
    format!("Error: {msg}")
}

#[cfg(test)]
#[path = "../tests/bin_amber.rs"]
mod tests;
