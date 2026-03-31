use crate::error::{AmberError, AmberResult};

pub fn validate_archive_path(path: &str) -> AmberResult<String> {
    validate_relative_path(path, "Path")
}

pub fn validate_symlink_target(target: &str) -> AmberResult<String> {
    validate_relative_path(target, "Symlink target")
}

fn validate_relative_path(path: &str, noun: &str) -> AmberResult<String> {
    if path.contains('\0') {
        return Err(AmberError::Invalid(format!("{noun} may not contain NUL")));
    }
    let normalized = path.replace('\\', "/");
    if normalized.is_empty() {
        return Err(AmberError::Invalid(format!("{noun} may not be empty")));
    }
    if normalized.starts_with('/') || normalized.starts_with('\\') {
        return Err(AmberError::Invalid(format!("{noun} may not be absolute")));
    }
    if normalized.len() >= 2
        && normalized.as_bytes()[1] == b':'
        && normalized.as_bytes()[0].is_ascii_alphabetic()
    {
        return Err(AmberError::Invalid(format!("{noun} may not be absolute")));
    }
    let parts: Vec<&str> = normalized
        .split('/')
        .filter(|segment| !segment.is_empty() && *segment != ".")
        .collect();
    if parts.is_empty() {
        return Err(AmberError::Invalid(format!("{noun} may not be empty")));
    }
    if parts.contains(&"..") {
        return Err(AmberError::Invalid(format!("{noun} may not contain '..'")));
    }
    Ok(parts.join("/"))
}

#[cfg(test)]
#[path = "tests/pathutil.rs"]
mod tests;
