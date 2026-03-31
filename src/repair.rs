use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::amcfadaptive::sample_amcf_combination;
use crate::archiveio::{LogicalArchiveReader, canonical_archive_base_path};
use crate::codec::Codec;
use crate::constants::RTYPE_CHUNK;
use crate::error::{AmberError, AmberResult};
use crate::gf256::{gf_add_bytes, gf_inv, gf_mul, gf_mul_bytes};
use crate::hashutil::blake3_32;
use crate::mutation::mutate_archive_via_work_copy;
use crate::reader::{ArchiveReader, SymbolInfo};
use crate::records::{parse_chunk_header_ext, read_record_at};
use crate::recover::rebuild_index;
use crate::tlv::{get_list, get_map, get_string, get_u64};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ECCRepairResult {
    pub amcf_repaired: Vec<u64>,
    pub remaining_corrupted: Vec<u64>,
    pub detected_data_chunks: usize,
    pub remaining_data_chunks: usize,
    pub output_path: Option<PathBuf>,
    pub rebuilt_index_parity_symbols: Option<usize>,
}

pub fn repair_archive(
    path: impl AsRef<Path>,
    password: Option<&str>,
    keyfile: Option<&Path>,
    output_path: Option<&Path>,
) -> AmberResult<ECCRepairResult> {
    repair_archive_with_progress(path, password, keyfile, output_path, None)
}

pub fn repair_archive_with_progress(
    path: impl AsRef<Path>,
    password: Option<&str>,
    keyfile: Option<&Path>,
    output_path: Option<&Path>,
    mut progress: Option<&mut dyn FnMut(String)>,
) -> AmberResult<ECCRepairResult> {
    let final_target = output_path
        .map(Path::to_path_buf)
        .unwrap_or(canonical_archive_base_path(path.as_ref())?);
    let result = mutate_archive_via_work_copy(
        path.as_ref(),
        &final_target,
        password,
        keyfile,
        |work_path| repair_work_archive(work_path, password, keyfile, &mut progress),
        Some(|repair_result: &ECCRepairResult| repair_result.remaining_data_chunks == 0),
    )?;
    if result.remaining_data_chunks == 0 {
        let mut result = result;
        result.output_path = Some(final_target);
        return Ok(result);
    }
    Ok(result)
}

pub fn detect_corrupted_symbols(
    reader: &ArchiveReader,
    file_handle: &mut LogicalArchiveReader,
) -> AmberResult<BTreeSet<u64>> {
    let mut corrupted = BTreeSet::new();
    let mut chunk_symbols: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for sym in &reader.symbols {
        if sym.is_parity {
            continue;
        }
        chunk_symbols
            .entry(sym.record_offset)
            .or_default()
            .push(sym.symbol_index);
    }
    let mut chunk_verification: BTreeMap<u64, bool> = BTreeMap::new();
    for sym in &reader.symbols {
        if sym.length == 0 {
            continue;
        }
        let (payload, plain_len) = load_symbol_data(reader, file_handle, sym)?;
        let Some(payload) = payload else {
            corrupted.insert(sym.symbol_index);
            continue;
        };
        if plain_len == 0 {
            corrupted.insert(sym.symbol_index);
            continue;
        }
        if sym.tag32 != [0u8; 32] && blake3_32(&payload[..plain_len]) != sym.tag32 {
            corrupted.insert(sym.symbol_index);
            continue;
        }
        if !sym.is_parity {
            let status = if let Some(status) = chunk_verification.get(&sym.record_offset) {
                *status
            } else {
                let status = verify_chunk_integrity(reader, file_handle, sym.record_offset);
                chunk_verification.insert(sym.record_offset, status);
                status
            };
            if !status && let Some(impacted) = chunk_symbols.get(&sym.record_offset) {
                corrupted.extend(impacted.iter().copied());
            }
        }
    }
    Ok(corrupted)
}

fn detect_corrupted_symbols_with_progress(
    reader: &ArchiveReader,
    file_handle: &mut LogicalArchiveReader,
    progress: &mut Option<&mut dyn FnMut(String)>,
) -> AmberResult<BTreeSet<u64>> {
    let mut corrupted = BTreeSet::new();
    let mut chunk_symbols: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    let total = reader.symbols.len();
    let progress_step = 1024usize;
    let small_scan = total <= progress_step;
    if total > 0 {
        if small_scan {
            emit_progress(progress, format!("repair: scanning {total} symbols"));
        } else {
            emit_progress(progress, format!("repair: scanning symbols (0/{total})"));
        }
    }
    for sym in &reader.symbols {
        if sym.is_parity {
            continue;
        }
        chunk_symbols
            .entry(sym.record_offset)
            .or_default()
            .push(sym.symbol_index);
    }
    let mut chunk_verification: BTreeMap<u64, bool> = BTreeMap::new();
    let mut last_report = 0usize;
    for (i, sym) in reader.symbols.iter().enumerate() {
        if sym.length == 0 {
            continue;
        }
        let (payload, plain_len) = load_symbol_data(reader, file_handle, sym)?;
        let Some(payload) = payload else {
            corrupted.insert(sym.symbol_index);
            continue;
        };
        if plain_len == 0 {
            corrupted.insert(sym.symbol_index);
            continue;
        }
        if sym.tag32 != [0u8; 32] && blake3_32(&payload[..plain_len]) != sym.tag32 {
            corrupted.insert(sym.symbol_index);
            continue;
        }
        if !sym.is_parity {
            let status = if let Some(status) = chunk_verification.get(&sym.record_offset) {
                *status
            } else {
                let status = verify_chunk_integrity(reader, file_handle, sym.record_offset);
                chunk_verification.insert(sym.record_offset, status);
                status
            };
            if !status && let Some(impacted) = chunk_symbols.get(&sym.record_offset) {
                corrupted.extend(impacted.iter().copied());
            }
        }
        let scanned = i + 1;
        if !small_scan && scanned < total && scanned.saturating_sub(last_report) >= progress_step {
            emit_progress(progress, format!("repair: scanning symbols ({scanned}/{total})"));
            last_report = scanned;
        }
    }
    Ok(corrupted)
}

fn repair_work_archive(
    target: &Path,
    password: Option<&str>,
    keyfile: Option<&Path>,
    progress: &mut Option<&mut dyn FnMut(String)>,
) -> AmberResult<ECCRepairResult> {
    match open_reader(target, password, keyfile) {
        Ok(reader) => {
            if has_inconsistent_ecc_metadata(&reader) {
                let rebuilt = rebuild_index(target, password, keyfile)?;
                emit_progress(
                    progress,
                    format!("repair: rebuilt index ({rebuilt} AMCF parity symbol(s)) before repair"),
                );
                let reader = open_reader(target, password, keyfile)?;
                let mut result = repair_archive_in_place(&reader, target, progress)?;
                result.rebuilt_index_parity_symbols = Some(rebuilt);
                Ok(result)
            } else {
                repair_archive_in_place(&reader, target, progress)
            }
        }
        Err(err) if err.is_rebuild_index_candidate() => {
            let rebuilt = rebuild_index(target, password, keyfile)?;
            emit_progress(
                progress,
                format!("repair: rebuilt index ({rebuilt} AMCF parity symbol(s)) and attempted repair"),
            );
            let reader = open_reader(target, password, keyfile)?;
            let mut result = repair_archive_in_place(&reader, target, progress)?;
            result.rebuilt_index_parity_symbols = Some(rebuilt);
            Ok(result)
        }
        Err(err) => Err(err),
    }
}

fn repair_archive_in_place(
    reader: &ArchiveReader,
    path: &Path,
    progress: &mut Option<&mut dyn FnMut(String)>,
) -> AmberResult<ECCRepairResult> {
    let mut result = ECCRepairResult::default();
    let mut fh = LogicalArchiveReader::open_path_rw(path)?;
    let mut corrupted = detect_corrupted_symbols_with_progress(reader, &mut fh, progress)?;
    if corrupted.is_empty() {
        emit_progress(progress, "repair: no corruption detected".to_owned());
        return Ok(result);
    }
    result.detected_data_chunks = count_damaged_data_chunks(reader, &corrupted);
    if !reader.amcf_parities.is_empty() {
        emit_progress(
            progress,
            format!(
                "repair: detected {} corrupted symbol(s), attempting AMCF",
                corrupted.len()
            ),
        );
        let amcf_fixed = repair_amcf(reader, &mut fh, &corrupted, progress)?;
        result.amcf_repaired = amcf_fixed.clone();
        for fixed in amcf_fixed {
            corrupted.remove(&fixed);
        }
    } else {
        emit_progress(
            progress,
            format!(
                "repair: detected {} corrupted symbol(s), but archive has no AMCF parity",
                corrupted.len()
            ),
        );
    }
    fh.flush()?;
    fh.sync()?;
    if result.amcf_repaired.is_empty() {
        emit_progress(progress, "repair: no symbol writeback performed".to_owned());
    } else {
        emit_progress(progress, "repair: writeback complete".to_owned());
    }
    result.remaining_corrupted = corrupted.iter().copied().collect();
    result.remaining_data_chunks = count_damaged_data_chunks(reader, &corrupted);
    Ok(result)
}

fn verify_chunk_integrity(
    reader: &ArchiveReader,
    fh: &mut LogicalArchiveReader,
    record_offset: u64,
) -> bool {
    let record = match read_record_at(fh, record_offset, reader.decryptor.as_ref()) {
        Ok(record) => record,
        Err(_) => return false,
    };
    if record.rtype != RTYPE_CHUNK {
        return false;
    }
    let (_entry_id, _chunk_index, ulen, codec_id, _flags, tag32, _aux) =
        match parse_chunk_header_ext(&record.header_ext) {
            Ok(parsed) => parsed,
            Err(_) => return false,
        };
    let raw = match Codec::new(codec_id).decompress(&record.payload, Some(ulen as usize)) {
        Ok(raw) => raw,
        Err(_) => return false,
    };
    blake3_32(&raw) == tag32
}

fn repair_amcf(
    reader: &ArchiveReader,
    fh: &mut LogicalArchiveReader,
    corrupted: &BTreeSet<u64>,
    progress: &mut Option<&mut dyn FnMut(String)>,
) -> AmberResult<Vec<u64>> {
    let unknowns = corrupted
        .iter()
        .copied()
        .filter(|idx| !reader.symbols[*idx as usize].is_parity)
        .collect::<Vec<_>>();
    if unknowns.is_empty() {
        return Ok(Vec::new());
    }
    let unknown_pos = unknowns
        .iter()
        .enumerate()
        .map(|(pos, idx)| (*idx, pos))
        .collect::<BTreeMap<_, _>>();

    let group_data_indices = build_group_data_indices(reader)?;
    let mut equations: Vec<(BTreeMap<usize, u8>, bytearray::ByteArray)> = Vec::new();
    let mut symbol_cache: BTreeMap<u64, Option<Vec<u8>>> = BTreeMap::new();

    for parity in &reader.amcf_parities {
        if corrupted.contains(&parity.symbol_index) {
            continue;
        }
        let (data_indices, _scheme) =
            group_data_indices.get(&parity.seed_base).ok_or_else(|| {
                AmberError::Invalid("Global parity references unknown seed_base".into())
            })?;
        let combo = sample_amcf_combination(
            &parity.seed_base,
            parity.seed_id as usize,
            data_indices,
            parity.row_count as usize,
        )
        .map_err(AmberError::Invalid)?;
        let rhs_bytes =
            match read_symbol_cached(reader, fh, parity.symbol_index, &mut symbol_cache)? {
                Some(bytes) => bytes,
                None => continue,
            };
        let mut rhs = bytearray::ByteArray::from(rhs_bytes);
        let mut coeffs = BTreeMap::new();
        let mut has_unknown = false;
        let mut skip_eq = false;
        for (sym_index, coeff) in combo {
            let data = match read_symbol_cached(reader, fh, sym_index as u64, &mut symbol_cache)? {
                Some(bytes) => bytes,
                None => {
                    skip_eq = true;
                    break;
                }
            };
            if corrupted.contains(&(sym_index as u64)) {
                if let Some(pos) = unknown_pos.get(&(sym_index as u64)) {
                    let prev = coeffs.get(pos).copied().unwrap_or(0);
                    coeffs.insert(*pos, prev ^ coeff);
                    has_unknown = true;
                }
            } else {
                gf_add_bytes(rhs.as_mut_slice(), &gf_mul_bytes(&data, coeff));
            }
        }
        if skip_eq || !has_unknown {
            continue;
        }
        equations.push((coeffs, rhs));
    }
    if equations.is_empty() {
        emit_progress(progress, "repair: AMCF had no usable equations".to_owned());
        return Ok(Vec::new());
    }
    emit_progress(
        progress,
        format!("repair: AMCF solving {} equations", equations.len()),
    );

    let mut solutions: BTreeMap<usize, Vec<u8>> = BTreeMap::new();
    let mut var_to_eqs: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (i, (coeffs, _)) in equations.iter().enumerate() {
        for (pos, coeff) in coeffs {
            if *coeff != 0 {
                var_to_eqs.entry(*pos).or_default().push(i);
            }
        }
    }
    let mut q = VecDeque::new();
    for (i, (coeffs, _)) in equations.iter().enumerate() {
        if coeffs.values().filter(|&&c| c != 0).count() == 1 {
            q.push_back(i);
        }
    }
    while let Some(ei) = q.pop_front() {
        let (coeffs, rhs) = &equations[ei];
        let singles = coeffs
            .iter()
            .filter_map(|(pos, coeff)| (*coeff != 0).then_some((*pos, *coeff)))
            .collect::<Vec<_>>();
        if singles.len() != 1 {
            continue;
        }
        let (pos, coeff) = singles[0];
        if solutions.contains_key(&pos) {
            continue;
        }
        let inv = gf_inv(coeff);
        let value = gf_mul_bytes(rhs.as_slice(), inv);
        solutions.insert(pos, value.clone());
        if let Some(impacted) = var_to_eqs.get(&pos).cloned() {
            for ej in impacted {
                if ej == ei {
                    continue;
                }
                let (cdict, rr) = &mut equations[ej];
                if let Some(cc) = cdict.get(&pos).copied()
                    && cc != 0
                {
                    gf_add_bytes(rr.as_mut_slice(), &gf_mul_bytes(&value, cc));
                    cdict.insert(pos, 0);
                    if cdict.values().filter(|&&c| c != 0).count() == 1 {
                        q.push_back(ej);
                    }
                }
            }
        }
    }
    if !solutions.is_empty() {
        emit_progress(
            progress,
            format!("repair: global peel solved {}/{}", solutions.len(), unknowns.len()),
        );
    }

    let mut repaired = Vec::new();
    if solutions.len() == unknowns.len() {
        emit_progress(
            progress,
            format!("repair: AMCF solved all unknowns ({})", unknowns.len()),
        );
        for (pos, data_bytes) in solutions {
            let sym_index = unknowns[pos];
            write_repaired_symbol(reader, fh, sym_index, &data_bytes, &mut repaired, progress)?;
        }
        repaired.sort_unstable();
        repaired.dedup();
        if !repaired.is_empty() {
            emit_progress(
                progress,
                format!("repair: AMCF repaired {} symbol(s)", repaired.len()),
            );
        }
        return Ok(repaired);
    }

    let residual_vars = (0..unknowns.len())
        .filter(|pos| !solutions.contains_key(pos))
        .collect::<Vec<_>>();
    if residual_vars.is_empty() {
        return Ok(repaired);
    }
    if residual_vars.len() > 32 {
        repaired.sort_unstable();
        repaired.dedup();
        return Ok(repaired);
    }
    emit_progress(
        progress,
        format!(
            "repair: AMCF running elimination on {} residual vars",
            residual_vars.len()
        ),
    );

    let var_index = residual_vars
        .iter()
        .enumerate()
        .map(|(i, pos)| (*pos, i))
        .collect::<BTreeMap<_, _>>();
    let mut a = Vec::new();
    let mut b = Vec::new();
    for (coeffs, mut rhs) in equations {
        let mut row = vec![0u8; residual_vars.len()];
        let mut nz = 0usize;
        for (pos, coeff) in &coeffs {
            if *coeff != 0
                && let Some(index) = var_index.get(pos)
            {
                row[*index] ^= *coeff;
                nz += 1;
            }
        }
        if nz == 0 {
            continue;
        }
        if !solutions.is_empty() {
            for (spos, sval) in &solutions {
                if let Some(cc) = coeffs.get(spos).copied()
                    && cc != 0
                {
                    gf_add_bytes(rhs.as_mut_slice(), &gf_mul_bytes(sval, cc));
                }
            }
        }
        a.push(row);
        b.push(rhs);
    }
    let mut pivots = vec![None; residual_vars.len()];
    let mut r = 0usize;
    let m = a.len();
    let nvars = residual_vars.len();
    for c in 0..nvars {
        let mut pivot = None;
        for (i, row) in a.iter().enumerate().skip(r).take(m.saturating_sub(r)) {
            if row[c] != 0 {
                pivot = Some(i);
                break;
            }
        }
        let Some(pivot) = pivot else { continue };
        if pivot != r {
            a.swap(r, pivot);
            b.swap(r, pivot);
        }
        let inv = gf_inv(a[r][c]);
        for j in c..nvars {
            if a[r][j] != 0 {
                a[r][j] = gf_mul(a[r][j], inv);
            }
        }
        b[r] = bytearray::ByteArray::from(gf_mul_bytes(b[r].as_slice(), inv));
        for i in 0..m {
            if i == r {
                continue;
            }
            let factor = a[i][c];
            if factor != 0 {
                for j in c..nvars {
                    if a[r][j] != 0 {
                        a[i][j] ^= gf_mul(a[r][j], factor);
                    }
                }
                let rhs_contrib = gf_mul_bytes(b[r].as_slice(), factor);
                gf_add_bytes(b[i].as_mut_slice(), &rhs_contrib);
            }
        }
        pivots[c] = Some(r);
        r += 1;
        if r == m {
            break;
        }
    }
    let mut x: Vec<Option<Vec<u8>>> = vec![None; nvars];
    for c in (0..nvars).rev() {
        let Some(pr) = pivots[c] else { continue };
        let mut rhs = b[pr].clone();
        for k in c + 1..nvars {
            if let Some(sol) = &x[k] {
                let coeff = a[pr][k];
                if coeff != 0 {
                    gf_add_bytes(rhs.as_mut_slice(), &gf_mul_bytes(sol, coeff));
                }
            }
        }
        x[c] = Some(rhs.into_vec());
    }
    for (c, sol) in x.into_iter().enumerate() {
        if let Some(sol) = sol {
            solutions.insert(residual_vars[c], sol);
        }
    }
    for (pos, data_bytes) in solutions {
        let sym_index = unknowns[pos];
        if corrupted.contains(&sym_index) {
            write_repaired_symbol(reader, fh, sym_index, &data_bytes, &mut repaired, progress)?;
        }
    }
    repaired.sort_unstable();
    repaired.dedup();
    if !repaired.is_empty() {
        emit_progress(
            progress,
            format!("repair: AMCF repaired {} symbol(s)", repaired.len()),
        );
    }
    Ok(repaired)
}

fn write_repaired_symbol(
    reader: &ArchiveReader,
    fh: &mut LogicalArchiveReader,
    sym_index: u64,
    data_bytes: &[u8],
    repaired: &mut Vec<u64>,
    progress: &mut Option<&mut dyn FnMut(String)>,
) -> AmberResult<()> {
    let symbol = &reader.symbols[sym_index as usize];
    let actual = &data_bytes[..symbol.length as usize];
    if symbol.tag32 != [0u8; 32] && blake3_32(actual) != symbol.tag32 {
        return Ok(());
    }
    fh.seek(SeekFrom::Start(symbol.offset))?;
    fh.write_all(actual)?;
    repaired.push(sym_index);
    emit_progress(progress, format!("repair: AMCF repaired symbol {sym_index}"));
    Ok(())
}

fn emit_progress(progress: &mut Option<&mut dyn FnMut(String)>, msg: String) {
    if let Some(progress) = progress.as_deref_mut() {
        progress(msg);
    }
}

fn count_damaged_data_chunks(reader: &ArchiveReader, symbol_indices: &BTreeSet<u64>) -> usize {
    let mut chunk_offsets = BTreeSet::new();
    for idx in symbol_indices {
        let sym = &reader.symbols[*idx as usize];
        if sym.is_parity {
            continue;
        }
        chunk_offsets.insert(sym.record_offset);
    }
    chunk_offsets.len()
}

fn build_group_data_indices(
    reader: &ArchiveReader,
) -> AmberResult<BTreeMap<[u8; 16], (Vec<usize>, String)>> {
    let mut group_data_indices = BTreeMap::new();
    let Some(index) = reader.index.as_ref() else {
        return Ok(group_data_indices);
    };
    let Some(groups) = get_list(index, "ecc_groups") else {
        return Ok(group_data_indices);
    };
    for group in groups {
        let Some(amcf) = get_map(group, "amcf") else {
            continue;
        };
        let seed_base = reader.amcf_parities.first().map(|_| [0u8; 16]);
        let stored_scheme = get_string(amcf, "scheme").ok_or_else(|| {
            AmberError::Invalid("Global parity metadata is missing its scheme".into())
        })?;
        let scheme = stored_scheme.to_owned();
        let mut data_indices = get_list(group, "symbols")
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|sym| !crate::tlv::get_bool(sym, "is_parity").unwrap_or(false))
            .filter_map(|sym| get_u64(&sym, "symbol_index").map(|v| v as usize))
            .collect::<Vec<_>>();
        data_indices.sort_unstable();
        if let Some(seed_base_bytes) = crate::tlv::get_bytes(amcf, "seed_base") {
            if seed_base_bytes.len() != 16 {
                return Err(AmberError::Invalid(
                    "Global parity seed_base must be 16 bytes".into(),
                ));
            }
            let mut seed = [0u8; 16];
            seed.copy_from_slice(seed_base_bytes);
            group_data_indices.insert(seed, (data_indices.clone(), scheme.clone()));
        } else if let Some(seed) = seed_base {
            group_data_indices.insert(seed, (data_indices.clone(), scheme.clone()));
        }
        if let Some(parity_rows) = get_list(amcf, "parity") {
            for item in parity_rows {
                if let Some(seed_base_bytes) = crate::tlv::get_bytes(item, "seed_base") {
                    if seed_base_bytes.len() != 16 {
                        return Err(AmberError::Invalid(
                            "Global parity seed_base must be 16 bytes".into(),
                        ));
                    }
                    let mut seed = [0u8; 16];
                    seed.copy_from_slice(seed_base_bytes);
                    group_data_indices.insert(seed, (data_indices.clone(), scheme.clone()));
                }
            }
        }
    }
    Ok(group_data_indices)
}

fn open_reader(
    target: &Path,
    password: Option<&str>,
    keyfile: Option<&Path>,
) -> AmberResult<ArchiveReader> {
    let mut reader = ArchiveReader::new_with_credentials(
        target,
        password.map(str::to_owned),
        keyfile.map(Path::to_path_buf),
    );
    reader.open()?;
    Ok(reader)
}

fn has_inconsistent_ecc_metadata(reader: &ArchiveReader) -> bool {
    reader.symbols.iter().any(|sym| sym.is_parity) && reader.amcf_parities.is_empty()
}

fn read_symbol_cached(
    reader: &ArchiveReader,
    fh: &mut LogicalArchiveReader,
    sym_index: u64,
    cache: &mut BTreeMap<u64, Option<Vec<u8>>>,
) -> AmberResult<Option<Vec<u8>>> {
    if let Some(value) = cache.get(&sym_index) {
        return Ok(value.clone());
    }
    let value = read_symbol(reader, fh, &reader.symbols[sym_index as usize])?;
    cache.insert(sym_index, value.clone());
    Ok(value)
}

fn read_symbol(
    reader: &ArchiveReader,
    fh: &mut LogicalArchiveReader,
    symbol: &SymbolInfo,
) -> AmberResult<Option<Vec<u8>>> {
    let (payload, _plain_len) = load_symbol_data(reader, fh, symbol)?;
    Ok(payload)
}

fn load_symbol_data(
    reader: &ArchiveReader,
    fh: &mut LogicalArchiveReader,
    symbol: &SymbolInfo,
) -> AmberResult<(Option<Vec<u8>>, usize)> {
    if reader.decryptor.is_some() && symbol.is_parity {
        let record = match read_record_at(fh, symbol.record_offset, reader.decryptor.as_ref()) {
            Ok(record) => record,
            Err(_) => return Ok((None, 0)),
        };
        if record.rtype != RTYPE_CHUNK {
            return Ok((None, 0));
        }
        let plain_len = record.payload.len().min(reader.symbol_size as usize);
        let mut buf = vec![0u8; reader.symbol_size as usize];
        buf[..plain_len].copy_from_slice(&record.payload[..plain_len]);
        return Ok((Some(buf), plain_len));
    }
    fh.seek(SeekFrom::Start(symbol.offset))?;
    let mut data = vec![0u8; symbol.length as usize];
    let read = fh.read(&mut data)?;
    if read != symbol.length as usize {
        return Ok((None, 0));
    }
    let mut buf = vec![0u8; reader.symbol_size as usize];
    buf[..symbol.length as usize].copy_from_slice(&data);
    Ok((Some(buf), symbol.length as usize))
}

mod bytearray {
    #[derive(Clone, Debug)]
    pub struct ByteArray(pub Vec<u8>);

    impl ByteArray {
        pub fn as_slice(&self) -> &[u8] {
            &self.0
        }
        pub fn as_mut_slice(&mut self) -> &mut [u8] {
            &mut self.0
        }
        pub fn into_vec(self) -> Vec<u8> {
            self.0
        }
    }

    impl From<Vec<u8>> for ByteArray {
        fn from(value: Vec<u8>) -> Self {
            Self(value)
        }
    }
}

#[cfg(test)]
#[path = "tests/repair.rs"]
mod tests;
