use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::error::AmberResult;
use crate::globalparity::{
    GLOBAL_PARITY_SCHEME_AMCF, MIN_TOTAL_PARITY_ROWS_FLOOR, require_canonical_global_parity_scheme,
};
use crate::mutation::{RewritePlan, rewrite_archive_in_place};
use crate::reader::ArchiveReader;

pub fn append_amcf_parity(
    path: impl AsRef<Path>,
    extra_ppm: usize,
    password: Option<&str>,
    keyfile: Option<&Path>,
) -> AmberResult<usize> {
    append_global_parity(
        path,
        extra_ppm,
        GLOBAL_PARITY_SCHEME_AMCF,
        password,
        keyfile,
    )
}

pub fn append_global_parity(
    path: impl AsRef<Path>,
    extra_ppm: usize,
    scheme: &str,
    password: Option<&str>,
    keyfile: Option<&Path>,
) -> AmberResult<usize> {
    let mut reader = ArchiveReader::new_with_credentials(
        path.as_ref(),
        password.map(str::to_owned),
        keyfile.map(Path::to_path_buf),
    );
    reader.open()?;
    if !reader.verify()? {
        return Err(crate::error::AmberError::Invalid(
            "Verification failed before hardening.".into(),
        ));
    }

    let scheme = require_canonical_global_parity_scheme(scheme)
        .map_err(crate::error::AmberError::Invalid)?
        .to_owned();
    let added_rows = Arc::new(Mutex::new(0usize));
    let added_rows_capture = Arc::clone(&added_rows);
    let extra_ppm_capture = extra_ppm;
    let scheme_capture = scheme.clone();

    rewrite_archive_in_place(
        path,
        password,
        keyfile,
        Some(&move |reader: &ArchiveReader, plan: RewritePlan| {
            let target_total = target_total_rows(reader, extra_ppm_capture);
            let data_count = reader.symbols.iter().filter(|sym| !sym.is_parity).count();
            *added_rows_capture
                .lock()
                .expect("added_rows mutex poisoned") =
                target_total.saturating_sub(reader.amcf_parities.len());
            let epsilon_ppm = if data_count == 0 {
                0
            } else {
                (target_total * 1_000_000).div_ceil(data_count)
            };
            Ok(RewritePlan {
                default_chunk_size: plan.default_chunk_size,
                default_codec: plan.default_codec,
                password: plan.password,
                keyfile: plan.keyfile,
                part_size: plan.part_size,
                amcf_epsilon_ppm: epsilon_ppm,
                min_total_parity_rows: Some(target_total),
                global_parity_scheme: scheme_capture.clone(),
            })
        }),
        None,
    )?;

    Ok(*added_rows.lock().expect("added_rows mutex poisoned"))
}

fn target_total_rows(reader: &ArchiveReader, extra_ppm: usize) -> usize {
    let data_count = reader.symbols.iter().filter(|sym| !sym.is_parity).count();
    let existing_total = reader.amcf_parities.len();
    let added = (if data_count >= 2 { 2 } else { 1 }).max(data_count * extra_ppm / 1_000_000);
    (existing_total + added).max(MIN_TOTAL_PARITY_ROWS_FLOOR)
}

#[cfg(test)]
#[path = "tests/harden.rs"]
mod tests;
