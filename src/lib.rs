pub mod amcfadaptive;
pub mod amcfcompute;
pub mod amcfspatial;
pub mod append;
pub mod archiveio;
pub mod chunkemit;
pub mod cli;
pub mod codec;
pub mod constants;
pub mod coprime;
pub mod corrupt;
pub mod crc32c;
pub mod ecc;
pub mod encryption;
pub mod entryutil;
pub mod error;
pub mod gf256;
pub mod globalparity;
pub mod harden;
pub mod hashutil;
pub mod inputscan;
pub mod mutation;
pub mod pathutil;
pub mod reader;
pub mod rebuild;
pub mod records;
pub mod recover;
pub mod repair;
pub mod superblock;
pub mod tlv;
pub mod trailer;
pub mod writer;

pub use archiveio::{
    ArchiveSegment, LogicalArchiveAppender, LogicalArchiveReader, LogicalArchiveWriter,
    assert_archive_output_path_clear, canonical_archive_base_path, discover_archive_segment_paths,
    is_multipart_segment_path, multipart_segment_path,
};
pub use error::{AmberError, AmberResult};
