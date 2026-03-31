    use super::{validate_archive_path, validate_symlink_target};

    #[test]
    fn validate_archive_path_accepts_normal_relative_path() {
        assert_eq!(
            validate_archive_path("docs/readme.txt").unwrap(),
            "docs/readme.txt"
        );
    }

    #[test]
    fn validate_archive_path_rejects_absolute_and_traversal_paths() {
        assert!(
            validate_archive_path("/etc/passwd")
                .unwrap_err()
                .to_string()
                .contains("absolute")
        );
        assert!(
            validate_archive_path(r"C:\Windows\win.ini")
                .unwrap_err()
                .to_string()
                .contains("absolute")
        );
        assert!(
            validate_archive_path("../escape.txt")
                .unwrap_err()
                .to_string()
                .contains("..")
        );
    }

    #[test]
    fn validate_symlink_target_rejects_absolute_and_traversal_targets() {
        assert_eq!(
            validate_symlink_target("notes/latest").unwrap(),
            "notes/latest"
        );
        assert!(
            validate_symlink_target("/etc/shadow")
                .unwrap_err()
                .to_string()
                .contains("absolute")
        );
        assert!(
            validate_symlink_target(r"C:\temp\secret")
                .unwrap_err()
                .to_string()
                .contains("absolute")
        );
        assert!(
            validate_symlink_target("../outside")
                .unwrap_err()
                .to_string()
                .contains("..")
        );
    }
