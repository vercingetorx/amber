use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::archiveio::{LogicalArchiveReader, canonical_archive_base_path};
use crate::codec::Codec;
use crate::constants::RTYPE_CHUNK;
use crate::error::{AmberError, AmberResult};
use crate::gf65536::{gf65536_add_bytes, gf65536_inv, gf65536_mul, gf65536_mul_bytes};
use crate::hashutil::blake3_32;
use crate::mds::sample_mds_combination;
use crate::mutation::mutate_archive_via_work_copy;
use crate::reader::{ArchiveReader, SymbolInfo};
use crate::records::{parse_chunk_header_ext, read_record_at_bounded};
use crate::recover::rebuild_index;
use crate::tlv::{get_list, get_map, get_string, get_u64};

type RepairEquation = (BTreeMap<usize, u16>, bytearray::ByteArray);

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ECCRepairResult {
    pub repaired_data: Vec<u64>,
    pub repaired_parity: Vec<u64>,
    pub remaining_data: Vec<u64>,
    pub remaining_parity: Vec<u64>,
    pub detected_data_chunks: usize,
    pub remaining_data_chunks: usize,
    pub output_path: Option<PathBuf>,
    pub rebuilt_index_parity_symbols: Option<usize>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ArchiveHealth {
    pub payload_ok: bool,
    pub parity_ok: bool,
    pub damaged_data: Vec<u64>,
    pub damaged_parity: Vec<u64>,
    pub damaged_data_chunks: usize,
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
        Some(|repair_result: &ECCRepairResult| {
            repair_result.remaining_data_chunks == 0 && repair_result.remaining_parity.is_empty()
        }),
    )?;
    if result.remaining_data_chunks == 0 && result.remaining_parity.is_empty() {
        let mut result = result;
        result.output_path = Some(final_target);
        return Ok(result);
    }
    Ok(result)
}

pub fn inspect_archive_health(
    path: impl AsRef<Path>,
    password: Option<&str>,
    keyfile: Option<&Path>,
) -> AmberResult<ArchiveHealth> {
    let path = path.as_ref();
    let mut reader = open_reader(path, password, keyfile)?;
    let payload_ok = reader.verify()?;
    let mut fh = LogicalArchiveReader::open_path(path)?;
    let corrupted = detect_corrupted_symbols(&reader, &mut fh)?;
    let (damaged_data, damaged_parity) = classify_symbol_ids(&reader, &corrupted);
    let damaged_data_chunks = count_damaged_data_chunks(&reader, &corrupted);
    Ok(ArchiveHealth {
        payload_ok,
        parity_ok: damaged_parity.is_empty(),
        damaged_data,
        damaged_parity,
        damaged_data_chunks,
    })
}

pub fn detect_corrupted_symbols(
    reader: &ArchiveReader,
    file_handle: &mut LogicalArchiveReader,
) -> AmberResult<BTreeSet<u64>> {
    let mut progress = None;
    detect_corrupted_symbols_inner(reader, file_handle, &mut progress)
}

fn detect_corrupted_symbols_with_progress(
    reader: &ArchiveReader,
    file_handle: &mut LogicalArchiveReader,
    progress: &mut Option<&mut dyn FnMut(String)>,
) -> AmberResult<BTreeSet<u64>> {
    detect_corrupted_symbols_inner(reader, file_handle, progress)
}

fn detect_corrupted_symbols_inner(
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
                    format!("repair: rebuilt index ({rebuilt} MDS parity symbol(s)) before repair"),
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
                format!("repair: rebuilt index ({rebuilt} MDS parity symbol(s)) and attempted repair"),
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
    if !reader.mds_parities.is_empty() {
        emit_progress(
            progress,
            format!(
                "repair: detected {} corrupted symbol(s), attempting MDS",
                corrupted.len()
            ),
        );
        let repaired = repair_mds(reader, &mut fh, &corrupted, progress)?;
        let repaired_set = repaired.iter().copied().collect::<BTreeSet<_>>();
        (result.repaired_data, result.repaired_parity) = classify_symbol_ids(reader, &repaired_set);
        for fixed in repaired {
            corrupted.remove(&fixed);
        }
        if count_damaged_data_chunks(reader, &corrupted) == 0 {
            let repaired = repair_mds_parity(reader, &mut fh, &corrupted, progress)?;
            let repaired_set = repaired.iter().copied().collect::<BTreeSet<_>>();
            let (_data, mut repaired_parity) = classify_symbol_ids(reader, &repaired_set);
            result.repaired_parity.append(&mut repaired_parity);
            result.repaired_parity.sort_unstable();
            result.repaired_parity.dedup();
            for fixed in repaired {
                corrupted.remove(&fixed);
            }
        }
    } else {
        emit_progress(
            progress,
            format!(
                "repair: detected {} corrupted symbol(s), but archive has no MDS parity",
                corrupted.len()
            ),
        );
    }
    fh.flush()?;
    fh.sync()?;
    if result.repaired_data.is_empty() && result.repaired_parity.is_empty() {
        emit_progress(progress, "repair: no symbol writeback performed".to_owned());
    } else {
        emit_progress(progress, "repair: writeback complete".to_owned());
    }
    (result.remaining_data, result.remaining_parity) = classify_symbol_ids(reader, &corrupted);
    result.remaining_data_chunks = count_damaged_data_chunks(reader, &corrupted);
    Ok(result)
}

fn repair_mds_parity(
    reader: &ArchiveReader,
    fh: &mut LogicalArchiveReader,
    corrupted: &BTreeSet<u64>,
    progress: &mut Option<&mut dyn FnMut(String)>,
) -> AmberResult<Vec<u64>> {
    let parity_unknowns = corrupted
        .iter()
        .copied()
        .filter(|idx| reader.symbols[*idx as usize].is_parity)
        .collect::<Vec<_>>();
    if parity_unknowns.is_empty() {
        return Ok(Vec::new());
    }

    let group_data_indices = build_group_data_indices(reader)?;
    let parity_by_symbol = reader
        .mds_parities
        .iter()
        .map(|parity| (parity.symbol_index, parity))
        .collect::<BTreeMap<_, _>>();
    let mut symbol_cache: BTreeMap<u64, Option<Vec<u8>>> = BTreeMap::new();
    let mut repaired = Vec::new();

    for sym_index in parity_unknowns {
        let parity = parity_by_symbol.get(&sym_index).ok_or_else(|| {
            AmberError::Invalid(format!(
                "MDS parity symbol {sym_index} is missing parity metadata"
            ))
        })?;
        let (data_indices, _scheme) =
            group_data_indices.get(&parity.seed_base).ok_or_else(|| {
                AmberError::Invalid("Global parity references unknown seed_base".into())
            })?;
        let combo = sample_mds_combination(
            parity.seed_id as usize,
            data_indices,
            parity.row_count as usize,
        )
        .map_err(AmberError::Invalid)?;

        let mut parity_bytes = vec![0u8; reader.symbol_size as usize];
        let mut complete = true;
        for (data_sym, coeff) in combo {
            let Some(data) = read_symbol_cached(reader, fh, data_sym as u64, &mut symbol_cache)?
            else {
                complete = false;
                break;
            };
            let product = gf65536_mul_bytes(&data, coeff, reader.symbol_size as usize);
            gf65536_add_bytes(&mut parity_bytes, &product);
        }
        if !complete {
            emit_progress(
                progress,
                format!("repair: MDS could not recompute parity symbol {sym_index}"),
            );
            continue;
        }
        write_repaired_symbol(reader, fh, sym_index, &parity_bytes, &mut repaired, progress)?;
    }

    repaired.sort_unstable();
    repaired.dedup();
    if !repaired.is_empty() {
        emit_progress(
            progress,
            format!("repair: MDS repaired {} parity symbol(s)", repaired.len()),
        );
    }
    Ok(repaired)
}

fn verify_chunk_integrity(
    reader: &ArchiveReader,
    fh: &mut LogicalArchiveReader,
    record_offset: u64,
) -> bool {
    let Some(max_payload_len) = expected_record_payload_len(reader, record_offset) else {
        return false;
    };
    let record = match read_record_at_bounded(
        fh,
        record_offset,
        reader.decryptor.as_ref(),
        max_payload_len,
    ) {
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

fn expected_record_payload_len(reader: &ArchiveReader, record_offset: u64) -> Option<u64> {
    reader
        .entries
        .iter()
        .filter(|entry| entry.kind == 0)
        .flat_map(|entry| entry.chunks.iter())
        .find(|chunk| chunk.offset == record_offset)
        .map(|chunk| chunk.payload_len)
}

fn repair_mds(
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
    let mut equations: Vec<RepairEquation> = Vec::new();
    let mut symbol_cache: BTreeMap<u64, Option<Vec<u8>>> = BTreeMap::new();

    for parity in &reader.mds_parities {
        if corrupted.contains(&parity.symbol_index) {
            continue;
        }
        let (data_indices, _scheme) =
            group_data_indices.get(&parity.seed_base).ok_or_else(|| {
                AmberError::Invalid("Global parity references unknown seed_base".into())
            })?;
        let combo = sample_mds_combination(
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
            if corrupted.contains(&(sym_index as u64)) {
                if let Some(pos) = unknown_pos.get(&(sym_index as u64)) {
                    let prev = coeffs.get(pos).copied().unwrap_or(0);
                    coeffs.insert(*pos, prev ^ coeff);
                    has_unknown = true;
                }
                continue;
            }
            let data = match read_symbol_cached(reader, fh, sym_index as u64, &mut symbol_cache)? {
                Some(bytes) => bytes,
                None => {
                    skip_eq = true;
                    break;
                }
            };
            let product = gf65536_mul_bytes(&data, coeff, rhs.as_slice().len());
            gf65536_add_bytes(rhs.as_mut_slice(), &product);
        }
        if skip_eq || !has_unknown {
            continue;
        }
        equations.push((coeffs, rhs));
    }
    if equations.is_empty() {
        emit_progress(progress, "repair: MDS had no usable equations".to_owned());
        return Ok(Vec::new());
    }
    emit_progress(
        progress,
        format!("repair: MDS solving {} equations", equations.len()),
    );
    let original_equations = equations.clone();

    if unknowns.len() == 1 {
        let sym_index = unknowns[0];
        let mut repaired = Vec::new();
        for (coeffs, rhs) in &equations {
            let coeff = coeffs.get(&0).copied().unwrap_or(0);
            if coeff == 0 {
                continue;
            }
            let candidate =
                gf65536_mul_bytes(rhs.as_slice(), gf65536_inv(coeff), rhs.as_slice().len());
            if write_repaired_data_solution(
                reader,
                fh,
                &[(sym_index, candidate)],
                &mut repaired,
                progress,
            )? {
                repaired.sort_unstable();
                repaired.dedup();
                emit_progress(
                    progress,
                    format!("repair: MDS repaired {} symbol(s)", repaired.len()),
                );
                return Ok(repaired);
            }
        }
    }

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
        let inv = gf65536_inv(coeff);
        let value = gf65536_mul_bytes(rhs.as_slice(), inv, rhs.as_slice().len());
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
                    let product = gf65536_mul_bytes(&value, cc, rr.as_slice().len());
                    gf65536_add_bytes(rr.as_mut_slice(), &product);
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
            format!("repair: MDS solved all unknowns ({})", unknowns.len()),
        );
        let candidates = solutions
            .into_iter()
            .map(|(pos, data_bytes)| (unknowns[pos], data_bytes))
            .collect::<Vec<_>>();
        if !write_repaired_data_solution(reader, fh, &candidates, &mut repaired, progress)? {
            for candidates in mds_candidate_solutions(
                &original_equations,
                &unknowns,
                &BTreeMap::new(),
                corrupted,
            ) {
                if write_repaired_data_solution(reader, fh, &candidates, &mut repaired, progress)? {
                    break;
                }
            }
        }
        repaired.sort_unstable();
        repaired.dedup();
        if !repaired.is_empty() {
            emit_progress(
                progress,
                format!("repair: MDS repaired {} symbol(s)", repaired.len()),
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
            "repair: MDS running validated elimination on {} residual vars",
            residual_vars.len()
        ),
    );

    for candidates in mds_candidate_solutions(&original_equations, &unknowns, &solutions, corrupted) {
        if write_repaired_data_solution(reader, fh, &candidates, &mut repaired, progress)? {
            break;
        }
    }
    repaired.sort_unstable();
    repaired.dedup();
    if !repaired.is_empty() {
        emit_progress(
            progress,
            format!("repair: MDS repaired {} symbol(s)", repaired.len()),
        );
    }
    Ok(repaired)
}

fn mds_candidate_solutions(
    equations: &[RepairEquation],
    unknowns: &[u64],
    known_solutions: &BTreeMap<usize, Vec<u8>>,
    corrupted: &BTreeSet<u64>,
) -> Vec<Vec<(u64, Vec<u8>)>> {
    let mut candidates = Vec::new();
    let omitted = BTreeSet::new();
    if let Some(solution) = solve_mds_equation_subset(equations, unknowns.len(), known_solutions, &omitted)
    {
        candidates.push(solution_to_candidates(solution, unknowns, corrupted));
    }

    for omit in 0..equations.len() {
        let omitted = BTreeSet::from([omit]);
        if let Some(solution) =
            solve_mds_equation_subset(equations, unknowns.len(), known_solutions, &omitted)
        {
            candidates.push(solution_to_candidates(solution, unknowns, corrupted));
        }
    }
    candidates
}

fn solution_to_candidates(
    solutions: BTreeMap<usize, Vec<u8>>,
    unknowns: &[u64],
    corrupted: &BTreeSet<u64>,
) -> Vec<(u64, Vec<u8>)> {
    solutions
        .into_iter()
        .filter_map(|(pos, data_bytes)| {
            let sym_index = unknowns[pos];
            corrupted.contains(&sym_index).then_some((sym_index, data_bytes))
        })
        .collect()
}

fn solve_mds_equation_subset(
    equations: &[RepairEquation],
    unknown_count: usize,
    known_solutions: &BTreeMap<usize, Vec<u8>>,
    omitted_equations: &BTreeSet<usize>,
) -> Option<BTreeMap<usize, Vec<u8>>> {
    let residual_vars = (0..unknown_count)
        .filter(|pos| !known_solutions.contains_key(pos))
        .collect::<Vec<_>>();
    if residual_vars.is_empty() {
        return Some(known_solutions.clone());
    }

    let var_index = residual_vars
        .iter()
        .enumerate()
        .map(|(i, pos)| (*pos, i))
        .collect::<BTreeMap<_, _>>();
    let mut a = Vec::new();
    let mut b = Vec::new();
    for (eq_index, (coeffs, rhs)) in equations.iter().enumerate() {
        if omitted_equations.contains(&eq_index) {
            continue;
        }
        let mut rhs = rhs.clone();
        let mut row = vec![0u16; residual_vars.len()];
        let mut nz = 0usize;
        for (pos, coeff) in coeffs {
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
        for (spos, sval) in known_solutions {
            if let Some(cc) = coeffs.get(spos).copied()
                && cc != 0
            {
                let product = gf65536_mul_bytes(sval, cc, rhs.as_slice().len());
                gf65536_add_bytes(rhs.as_mut_slice(), &product);
            }
        }
        a.push(row);
        b.push(rhs);
    }
    solve_dense_system(a, b).map(|residual_solution| {
        let mut solutions = known_solutions.clone();
        for (i, value) in residual_solution.into_iter().enumerate() {
            solutions.insert(residual_vars[i], value);
        }
        solutions
    })
}

fn solve_dense_system(
    mut a: Vec<Vec<u16>>,
    mut b: Vec<bytearray::ByteArray>,
) -> Option<Vec<Vec<u8>>> {
    if a.is_empty() {
        return None;
    }
    let m = a.len();
    let nvars = a[0].len();
    let mut pivots = vec![None; nvars];
    let mut r = 0usize;
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
        let inv = gf65536_inv(a[r][c]);
        for j in c..nvars {
            if a[r][j] != 0 {
                a[r][j] = gf65536_mul(a[r][j], inv);
            }
        }
        b[r] = bytearray::ByteArray::from(gf65536_mul_bytes(
            b[r].as_slice(),
            inv,
            b[r].as_slice().len(),
        ));
        for i in 0..m {
            if i == r {
                continue;
            }
            let factor = a[i][c];
            if factor != 0 {
                for j in c..nvars {
                    if a[r][j] != 0 {
                        a[i][j] ^= gf65536_mul(a[r][j], factor);
                    }
                }
                let rhs_contrib =
                    gf65536_mul_bytes(b[r].as_slice(), factor, b[r].as_slice().len());
                gf65536_add_bytes(b[i].as_mut_slice(), &rhs_contrib);
            }
        }
        pivots[c] = Some(r);
        r += 1;
        if r == m {
            break;
        }
    }
    if pivots.iter().any(Option::is_none) {
        return None;
    }
    let mut x = vec![Vec::new(); nvars];
    for (c, pr) in pivots.into_iter().enumerate() {
        x[c] = b[pr?].clone().into_vec();
    }
    Some(x)
}

fn write_repaired_data_solution(
    reader: &ArchiveReader,
    fh: &mut LogicalArchiveReader,
    candidates: &[(u64, Vec<u8>)],
    repaired: &mut Vec<u64>,
    progress: &mut Option<&mut dyn FnMut(String)>,
) -> AmberResult<bool> {
    if candidates.is_empty() {
        return Ok(false);
    }
    let mut originals = Vec::with_capacity(candidates.len());
    let mut impacted_chunks = BTreeSet::new();
    for (sym_index, data_bytes) in candidates {
        let symbol = &reader.symbols[*sym_index as usize];
        if symbol.is_parity {
            return Err(AmberError::Invalid(
                "data repair solution contained a parity symbol".into(),
            ));
        }
        if data_bytes.len() < symbol.length as usize {
            return Err(AmberError::Invalid(
                "MDS repair candidate is shorter than symbol length".into(),
            ));
        }
        fh.seek(SeekFrom::Start(symbol.offset))?;
        let mut original = vec![0u8; symbol.length as usize];
        let read = fh.read(&mut original)?;
        if read != original.len() {
            return Ok(false);
        }
        originals.push((*sym_index, original));
        impacted_chunks.insert(symbol.record_offset);
    }

    for (sym_index, data_bytes) in candidates {
        let symbol = &reader.symbols[*sym_index as usize];
        fh.seek(SeekFrom::Start(symbol.offset))?;
        fh.write_all(&data_bytes[..symbol.length as usize])?;
    }
    fh.flush()?;

    let valid = impacted_chunks
        .iter()
        .all(|record_offset| verify_chunk_integrity(reader, fh, *record_offset));
    if !valid {
        for (sym_index, original) in originals {
            let symbol = &reader.symbols[sym_index as usize];
            fh.seek(SeekFrom::Start(symbol.offset))?;
            fh.write_all(&original)?;
        }
        fh.flush()?;
        return Ok(false);
    }

    for (sym_index, _data_bytes) in candidates {
        repaired.push(*sym_index);
        emit_progress(progress, format!("repair: MDS repaired symbol {sym_index}"));
    }
    Ok(true)
}

fn write_repaired_symbol(
    reader: &ArchiveReader,
    fh: &mut LogicalArchiveReader,
    sym_index: u64,
    data_bytes: &[u8],
    repaired: &mut Vec<u64>,
    progress: &mut Option<&mut dyn FnMut(String)>,
) -> AmberResult<bool> {
    let symbol = &reader.symbols[sym_index as usize];
    let actual = &data_bytes[..symbol.length as usize];
    if symbol.tag32 != [0u8; 32] && blake3_32(actual) != symbol.tag32 {
        return Ok(false);
    }
    fh.seek(SeekFrom::Start(symbol.offset))?;
    fh.write_all(actual)?;
    repaired.push(sym_index);
    emit_progress(progress, format!("repair: MDS repaired symbol {sym_index}"));
    Ok(true)
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

fn classify_symbol_ids(
    reader: &ArchiveReader,
    symbol_indices: &BTreeSet<u64>,
) -> (Vec<u64>, Vec<u64>) {
    let mut data = Vec::new();
    let mut parity = Vec::new();
    for idx in symbol_indices {
        let sym = &reader.symbols[*idx as usize];
        if sym.is_parity {
            parity.push(*idx);
        } else {
            data.push(*idx);
        }
    }
    (data, parity)
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
        let Some(mds) = get_map(group, "mds") else {
            continue;
        };
        let seed_base = reader.mds_parities.first().map(|_| [0u8; 16]);
        let stored_scheme = get_string(mds, "scheme").ok_or_else(|| {
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
        if let Some(seed_base_bytes) = crate::tlv::get_bytes(mds, "seed_base") {
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
        if let Some(parity_rows) = get_list(mds, "parity") {
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
    reader.symbols.iter().any(|sym| sym.is_parity) && reader.mds_parities.is_empty()
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
        let record = match read_record_at_bounded(
            fh,
            symbol.record_offset,
            reader.decryptor.as_ref(),
            symbol.length,
        ) {
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
