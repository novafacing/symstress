"""
Test cases for the symstress module.
"""

from collections import defaultdict
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZipFile
from pprint import pprint

from pytest import fixture

from symstress.parse.cparse import CParse
from symstress.binaryninja.symbols import BinjaSymbols


@fixture
def lwip_source() -> Path:
    """
    Extract the lwip source to a temporary directory and return the path.
    """
    LWIP_SOURCE_PATH = Path(__file__).with_name("sources") / "lwip-2.1.3.zip"
    with TemporaryDirectory() as td:
        with ZipFile(LWIP_SOURCE_PATH, "r") as zf:
            zf.extractall(td)
            yield (Path(td) / "lwip-2.1.3").resolve()


@fixture
def coreutils_source() -> Path:
    """
    Extract the coreutils source to a temporary directory and return the path.
    """
    LWIP_SOURCE_PATH = Path(__file__).with_name("sources") / "coreutils-master.zip"
    with TemporaryDirectory() as td:
        with ZipFile(LWIP_SOURCE_PATH, "r") as zf:
            zf.extractall(td)
            yield (Path(td) / "coreutils-master").resolve()


def test_lwip_onefile(lwip_source: Path) -> None:
    """
    Test lwip simple string variable.
    """
    source_file = lwip_source / "src" / "netif" / "ppp" / "chap-new.c"
    assert source_file.exists(), f"Source file {source_file} not found."
    parser = CParse()
    parser.parse(source_file)
    strings = parser.map_symbols()
    assert strings == {
        "chap_auth_peer": {
            "CHAP: peer authentication already started!",
            "CHAP digest 0x%x requested but not available",
        },
        "chap_auth_with_peer": {
            "CHAP digest 0x%x requested but not available",
            "CHAP: authentication with peer already started!",
        },
        "chap_verify_response": {"No CHAP secret found for authenticating %q"},
        "chap_respond": {"%.*v", "No CHAP secret found for authenticating us to %q"},
        "chap_handle_status": {
            "%s: %.*v",
            "CHAP authentication succeeded",
            "CHAP authentication failed",
            "%s",
        },
        "chap_protrej": {"CHAP authentication failed due to protocol-reject"},
        "chap_print_pkt": {
            ">, name = ",
            " <",
            " %.2x",
            " %s",
            "%.2x",
            " code=0x%x",
            " id=0x%x",
        },
    }


def test_lwip_allfiles(lwip_source: Path) -> None:
    """
    Test lwip simple string variable.
    """
    parser = CParse()
    for source_file in (lwip_source / "src").rglob("**/*.c"):
        assert source_file.exists(), f"Source file {source_file} not found."
        parser.parse(source_file)
        parser.update_mapping()

    assert len(parser.mapping) == 806, "Wrong number of symbols found."


def test_coreutils_onefile(coreutils_source: Path) -> None:
    """
    Test coreutils simple string variable.
    """
    parser = CParse()
    for source_file in (coreutils_source / "src").rglob("**/*.c"):
        assert source_file.exists(), f"Source file {source_file} not found."
        parser.parse(source_file)
        parser.update_mapping()

    assert parser.mapping == {
        "abformat_init": {"%.*s%s%s", "%s", "--classify", "--color", "--hyperlink"},
        "abmon_init": {"--classify", "--color", "--hyperlink"},
        "add_field_list": {", \t"},
        "add_file_name": {"extra operand %s"},
        "add_line_number": {"%*d"},
        "add_tab_stop": {"tabs are too far apart"},
        "advance_input_after_read_error": {
            "%s: cannot seek",
            "cannot work around kernel bug " "after all",
            "invalid status level",
            "offset overflow while reading " "file %s",
            "standard input",
            "warning: invalid file offset " "after failed read",
        },
        "all_digits_p": {"0123456789"},
        "alloc_field": {"field used"},
        "alloc_ibuf": {" bytes (%s)", "memory exhausted by input buffer of size %"},
        "alloc_obuf": {
            " bytes (%s)",
            "invalid conversion",
            "memory exhausted by output buffer of size %",
        },
        "and": {"-a"},
        "announce_mkdir": {"creating directory %s"},
        "any_live_files": {"--follow"},
        "append_normal_char": {"+AcCdst"},
        "append_range": {
            "range-endpoints of '%s-%s' are in reverse " "collating sequence order"
        },
        "apply_mode": {
            " byte stdio buffer\n",
            "could not set buffering of %s to mode %s\n",
            "failed to allocate a %",
            "invalid buffering mode %s for %s\n",
        },
        "apply_settings": {
            "%s: error setting %s",
            "drain",
            "invalid argument %s",
            "invalid line discipline %s",
            "ispeed",
            "ospeed",
        },
        "apply_translations": {"invalid conversion"},
        "async_safe_die": {"\n", ": errno "},
        "avx2_supported": {
            "%s",
            "avx2 support not detected",
            "failed to get cpuid",
            "using avx2 hardware support",
        },
        "badfieldspec": {"%s: invalid field specification %s"},
        "batch_convert": {
            "%a %b %e %H:%M:%S %Z %Y",
            "%s",
            "%s.%N",
            "invalid date %s",
            "standard input",
        },
        "beyond": {"missing argument after %s"},
        "binary_operator": {
            "!=",
            "%s: unknown binary operator",
            "-ef does not accept -l",
            "-l",
            "-nt does not accept -l",
            "-ot does not accept -l",
        },
        "binop": {
            "!=",
            "-ef",
            "-eq",
            "-ge",
            "-gt",
            "-le",
            "-lt",
            "-ne",
            "-nt",
            "-ot",
            "==",
        },
        "block_cleanup_and_chld": {"warning: sigprocmask"},
        "buf_init_from_stdin": {"read error"},
        "build_spec_list": {
            "%s: equivalence class operand must be a " "single character",
            "\\",
            "\\a",
            "\\b",
            "\\f",
            "\\n",
            "\\r",
            "\\t",
            "\\v",
            "invalid character class %s",
            "missing character class name '[::]'",
            "missing equivalence class character '[==]'",
        },
        "build_type_arg": {"%s"},
        "bytes_chunk_extract": {"%s"},
        "bytes_split": {"%s"},
        "calculate_columns": {"--classify", "--color", "--hyperlink"},
        "card_of_complement": {"+AcCdst"},
        "cat": {"cannot do ioctl on %s", "%s", "write error"},
        "change_attributes": {
            "cannot change ownership of %s",
            "cannot change permissions of %s",
        },
        "change_file_context": {
            "can't apply partial context to unlabeled " "file %s",
            "failed to change context of %s to %s",
            "failed to get security context of %s",
        },
        "change_file_owner": {
            "%s",
            "cannot access %s",
            "cannot dereference %s",
            "cannot read directory %s",
            "changing group of %s",
            "changing ownership of %s",
        },
        "change_timestamps": {"cannot set timestamps for %s"},
        "char_to_clump": {"%03o"},
        "check": {"standard error", "%s: %s:%s: disorder: "},
        "check_and_close": {"%s", "standard input", "write error", "rb"},
        "check_file": {
            "%s",
            "--all-repeated",
            "--group",
            "error reading %s",
            "too many repeated lines",
        },
        "check_for_offset": {"%s: integer expected after delimiter"},
        "check_format_conv_type": {
            "invalid conversion specifier in " "suffix: %c",
            "invalid conversion specifier in " "suffix: \\%.3o",
            "invalid flags in conversion " "specification: %%%c%c",
            "missing conversion specifier in " "suffix",
        },
        "check_fspec": {"%s: file truncated", "write error"},
        "check_inputs": {"cannot read"},
        "check_order": {
            "%s:%",
            ": is not sorted: %.*s",
            "file %d is not in sorted order",
        },
        "check_output": {"open failed"},
        "check_selinux_attr": {"security.selinux"},
        "chown_files": {"fts_read failed", "fts_close failed"},
        "cleanup": {
            "%d",
            "closing input file %s",
            "closing output file %s",
            "sending signal %s to command %s",
            "standard input",
            "standard output",
        },
        "clear_files": {"--classify", "--color", "--hyperlink"},
        "close_fd": {"closing %s (fd=%d)"},
        "close_file": {"%s"},
        "close_output_file": {"%s", "write error for %s", "%s\n"},
        "closeout": {
            "%d",
            "%s",
            "unknown status from command (0x%X)",
            "waiting for child process",
            "with FILE=%s, exit %d from command: %s",
            "with FILE=%s, signal %s from command: %s",
        },
        "compare_files": {"%s%s%s%s%s%s%s%c", "%s", "total"},
        "compare_random": {
            "invalid number after ','",
            "invalid number after '-'",
            "invalid number after '.'",
            "invalid number at field start",
        },
        "compile_regex": {"%s (for regexp %s)"},
        "compute_context_from_mask": {"failed to create security context: " "%s"},
        "copy_attr_allerror": {
            "backing up %s might destroy source;  %s " "not copied",
            "backing up %s might destroy source;  %s " "not moved",
        },
        "copy_attr_error": {
            "backing up %s might destroy source;  %s not " "copied",
            "backing up %s might destroy source;  %s not " "moved",
        },
        "copy_dir": {"cannot access %s"},
        "copy_internal": {
            "%s -> %s (unbackup)\n",
            "%s and %s are the same file",
            "%s has unknown file type",
            "%s: can make relative symbolic links only in " "current directory",
            "-r not specified; omitting directory %s",
            "backing up %s might destroy source;  %s not " "copied",
            "backing up %s might destroy source;  %s not " "moved",
            "cannot backup %s",
            "cannot copy a directory, %s, into itself, %s",
            "cannot copy cyclic symbolic link %s",
            "cannot create directory %s",
            "cannot create fifo %s",
            "cannot create special file %s",
            "cannot create symbolic link %s",
            "cannot create symbolic link %s to %s",
            "cannot move %s to %s",
            "cannot move %s to a subdirectory of itself, %s",
            "cannot move directory onto non-directory: %s " "-> %s",
            "cannot overwrite directory %s with " "non-directory",
            "cannot overwrite non-directory %s with " "directory %s",
            "cannot read symbolic link %s",
            "cannot remove %s",
            "cannot stat %s",
            "cannot un-backup %s",
            "copied ",
            "created directory %s\n",
            "failed to preserve ownership for %s",
            "inter-device move failed: %s to %s; unable to " "remove target",
            "omitting directory %s",
            "preserving permissions for %s",
            "preserving times for %s",
            "removed %s\n",
            "renamed ",
            "setting permissions for %s",
            "specified more than once",
            "warning: source directory %s ",
            "warning: source file %s specified more than " "once",
            "will not copy %s through just-created symlink " "%s",
            "will not create hard link %s to directory %s",
            "will not overwrite just-created %s with %s",
        },
        "copy_reg": {
            "cannot create regular file %s",
            "cannot fstat %s",
            "cannot lseek %s",
            "cannot open %s for reading",
            "cannot remove %s",
            "failed to clone %s from %s",
            "failed to extend %s",
            "not writing through dangling symlink %s",
            "removed %s\n",
            "skipping file %s, as it was replaced while being " "copied",
        },
        "copy_to_temp": {"%s: read error", "%s: write error"},
        "cp_option_init": {"POSIXLY_CORRECT"},
        "create": {
            "%s would overwrite input; aborting",
            "%s: error truncating",
            "-c",
            "/bin/sh",
            "FILE",
            "SHELL",
            "closing input pipe",
            "closing output pipe",
            "closing prior pipe",
            "creating file %s\n",
            "executing with FILE=%s\n",
            "failed to close input pipe",
            "failed to create pipe",
            'failed to run command: "%s -c %s"',
            "failed to set FILE environment variable",
            "failed to stat %s",
            "fork system call failed",
            "moving input pipe",
        },
        "create_hard_link": {"cannot create hard link %s to %s", "removed %s\n"},
        "create_hole": {"cannot lseek %s", "error deallocating %s"},
        "create_output_file": {"%s"},
        "cut_file": {"%s"},
        "cwrite": {"%s"},
        "dc_parse_file": {"%s"},
        "dc_parse_stream": {
            "%s:%lu: invalid line;  missing second token",
            "%s:%lu: unrecognized keyword %s",
            "<internal>",
            "COLOR",
            "EIGHTBIT",
            "OPTIONS",
            "TERM",
            "none",
        },
        "dd_copy": {
            " bytes",
            " in output file %s",
            "%s: cannot skip to specified offset",
            "cannot fstat %s",
            "error reading %s",
            "error writing %s",
            "failed to truncate to %",
            "fdatasync failed for %s",
            "fsync failed for %s",
            "invalid conversion",
            "invalid status level",
            "standard input",
            "standard output",
            "writing to %s",
        },
        "decode_field_spec": {
            "invalid field specifier: %s",
            "invalid file number in field spec: %s",
        },
        "decode_format_string": {
            "\\0",
            "\\a",
            "\\b",
            "\\f",
            "\\n",
            "\\r",
            "\\t",
            "\\v",
            "del",
        },
        "decode_one_format": {
            " doesn't provide a %lu-byte integral type",
            " floating point type",
            "%%*%s",
            "%%*.%d%s",
            "\\0",
            "\\a",
            "\\b",
            "\\f",
            "\\n",
            "\\r",
            "\\t",
            "\\v",
            "del",
            "invalid character '%c' in type string %s",
            "invalid type string %s",
            "invalid type string %s;\n",
            "invalid type string %s;\nthis system",
            "ld",
            "lo",
            "lu",
            "lx",
            "this system doesn't provide a %lu-byte",
        },
        "decode_output_arg": {
            "Avail",
            "Size",
            "invalid field",
            "option --output: field %s unknown",
            "option --output: field %s used more than " "once",
        },
        "decode_preserve_arg": {
            "--no-preserve",
            "--preserve",
            "all",
            "context",
            "links",
            "mode",
            "ownership",
            "timestamps",
            "xattr",
        },
        "decode_switches": {
            "  - +FORMAT (e.g., +%H:%M) for a " "'date'-style",
            "  - [posix-]%s\n",
            " format\n",
            " in environment variable COLUMNS: %s",
            " in environment variable TABSIZE: %s",
            "%%%02x",
            "%*s ",
            "%*s, %*s ",
            "%Y-%m-%d ",
            "%Y-%m-%d %H:%M",
            "%Y-%m-%d %H:%M:%S.%N %z",
            "%m-%d %H:%M",
            "%s %*s ",
            "%s: %s",
            "*=>@|",
            "*~",
            "--classify",
            "--color",
            "--dired and --zero are incompatible",
            "--format",
            "--hyperlink",
            "--indicator-style",
            "--quoting-style",
            "--sort",
            "--time",
            ".*~",
            "BLOCK_SIZE",
            "COLUMNS",
            "LS_BLOCK_SIZE",
            "LS_COLORS",
            "TABSIZE",
            "TIME_STYLE",
            "Valid arguments are:\n",
            "abcdfghiklmnopqrstuvw:xABCDFGHI:LNQRST:UXZ1",
            "asnrvmpio",
            "extra operand %s",
            "full-iso",
            "ignoring invalid tab size",
            "ignoring invalid width",
            "invalid line width",
            "invalid tab size",
            "invalid time style format %s",
            "locale",
            "posix-",
            "time style",
        },
        "define_all_fields": {"$%&#_{}\\", ":%"},
        "delete_all_files": {"%s"},
        "describe_change": {
            "%s could not be accessed\n",
            "changed group of %s from %s to %s\n",
            "changed ownership of %s from %s to %s\n",
            "failed to change group of %s from %s to %s\n",
            "failed to change group of %s to %s\n",
            "failed to change mode of %s from %04lo (%s) " "to %04lo (%s)\n",
            "failed to change ownership of %s\n",
            "failed to change ownership of %s from %s to " "%s\n",
            "failed to change ownership of %s to %s\n",
            "group of %s retained as %s\n",
            "mode of %s changed from %04lo (%s) to %04lo " "(%s)\n",
            "mode of %s retained as %04lo (%s)\n",
            "neither symbolic link %s nor referent has " "been changed\n",
            "no change to ownership of %s\n",
            "ownership of %s retained\n",
            "ownership of %s retained as %s\n",
        },
        "detect_loop": {"%s"},
        "dev_ino_hash": {
            "%%%02x",
            "%*s ",
            "%*s, %*s ",
            "%s %*s ",
            "*=>@|",
            "LS_COLORS",
        },
        "diagnose_copy_fd_failure": {
            "%s: file has shrunk too much",
            "error reading %s",
            "standard input",
        },
        "diagnose_leading_hyphen": {
            "--interactive",
            "Try '%s ./%s' to remove the file " "%s.\n",
        },
        "different": {"invalid number of bytes to compare"},
        "digest_break_file": {"$%&#_{}\\"},
        "digest_check": {
            " computed checksum did NOT match",
            " computed checksums did NOT match",
            " line is improperly formatted",
            " lines are improperly formatted",
            " listed file could not be read",
            " listed files could not be read",
            "%s",
            "%s: %",
            "%s: no file was verified",
            "%s: no properly formatted checksum lines found",
            "%s: read error",
            "%s: too many checksum lines",
            ": %s\n",
            ": improperly formatted %s checksum line",
            "FAILED",
            "FAILED open or read",
            "OK",
            "WARNING: %",
            "standard input",
        },
        "digest_file": {"invalid length", "%s", "--algorithm", "rb"},
        "digest_word_file": {"$%&#_{}\\"},
        "dired_dump_obstack": {
            " %",
            "%%%02x",
            "%*",
            "%*s ",
            "%*s, %*s ",
            "%s %*s ",
            "*=>@|",
            "--classify",
            "--color",
            "--hyperlink",
            "LS_COLORS",
        },
        "dired_indent": {"  "},
        "dired_outbuf": {"%*"},
        "dired_outbyte": {"%*"},
        "disable_core_dumps": {"warning: disabling core dumps failed"},
        "display_changed": {
            "%s",
            "%s = %s;",
            "-%s",
            "eof",
            "eol",
            "flush",
            "line = %d;",
            "min",
            "min = %lu; time = %lu;\n",
            "swtch",
        },
        "display_recoverable": {"%lx:%lx:%lx:%lx", ":%lx"},
        "display_speed": {
            "%lu\n",
            "%lu %lu\n",
            "ispeed %lu baud; ospeed %lu baud;",
            "speed %lu baud;",
        },
        "display_window_size": {
            "%d %d\n",
            "%s",
            "%s: no size information for this device",
            "rows %d; columns %d;",
        },
        "do_copy": {
            "%s -> %s\n",
            "..",
            "and --no-target-directory (-T)",
            "cannot combine --target-directory (-t) ",
            "extra operand %s",
            "missing destination file operand after %s",
            "missing file operand",
            "target %s",
            "target directory %s",
            "with --parents, the destination must be a directory",
        },
        "do_decode": {"read error", "write error", "invalid input"},
        "do_encode": {"read error", "write error"},
        "do_ftruncate": {
            " * %",
            " byte blocks for file %s",
            " bytes",
            "%s has unusable, apparently negative size",
            "cannot fstat %s",
            "cannot get the size of %s",
            "failed to truncate %s at %",
            "overflow extending size of file %s",
            "overflow in %",
        },
        "do_link": {
            " ~ ",
            "%s and %s are the same file",
            "%s%s%s %c> %s\n",
            "%s: cannot overwrite directory",
            "%s: hard link not allowed for directory",
            "%s: replace %s? ",
            "backup type",
            "cannot backup %s",
            "cannot un-backup %s",
            "failed to access %s",
            "failed to create hard link %s",
            "failed to create hard link %s => %s",
            "failed to create hard link to %.0s%s",
            "failed to create symbolic link %s",
            "failed to create symbolic link %s -> %s",
            "will not overwrite just-created %s with %s",
        },
        "do_stat": {
            "",
            "    ID: %-8i Namelen: %-7l Type: %T\n",
            '  File: "%n"\n',
            "  File: %N\n" "  Size: %-10s\tBlocks: %-10b IO Block: %-6o %F\n",
            " Birth: %w\n",
            "%s%s",
            "Access: %x\n",
            "Access: (%04a/%10.10A)  Uid: (%5u/%8U)   Gid: " "(%5g/%8G)\n",
            "Block size: %-10s Fundamental block size: %S\n",
            "Blocks: Total: %-10b Free: %-10f Available: %a\n",
            "Change: %z\n",
            "Context: %C\n",
            "Device: %Hd,%Ld\tInode: %-10i  Links: %-5h Device " "type: %Hr,%Lr\n",
            "Device: %Hd,%Ld\tInode: %-10i  Links: %h\n",
            "Inodes: Total: %-10c Free: %d\n",
            "Modify: %y\n",
            "cannot stat %s",
            "cannot stat standard input",
            "cannot statx %s",
        },
        "do_statfs": {
            "",
            "    ID: %-8i Namelen: %-7l Type: %T\n",
            '  File: "%n"\n',
            "  File: %N\n" "  Size: %-10s\tBlocks: %-10b IO Block: %-6o %F\n",
            " Birth: %w\n",
            " in file system mode",
            "%s%s",
            "Access: %x\n",
            "Access: (%04a/%10.10A)  Uid: (%5u/%8U)   Gid: " "(%5g/%8G)\n",
            "Block size: %-10s Fundamental block size: %S\n",
            "Blocks: Total: %-10b Free: %-10f Available: %a\n",
            "Change: %z\n",
            "Context: %C\n",
            "Device: %Hd,%Ld\tInode: %-10i  Links: %-5h Device " "type: %Hr,%Lr\n",
            "Device: %Hd,%Ld\tInode: %-10i  Links: %h\n",
            "Inodes: Total: %-10c Free: %d\n",
            "Modify: %y\n",
            "cannot read file system information for %s",
            "using %s to denote standard input does not work",
        },
        "do_wipefd": {
            "%s: error truncating",
            "%s: file has negative size",
            "%s: fstat failed",
            "%s: invalid file type",
        },
        "dopass": {
            "%s: cannot rewind",
            "%s: error writing at offset %s",
            "%s: file too large",
            "%s: lseek failed",
            "%s: pass %lu/%lu (%s)...",
            "%s: pass %lu/%lu (%s)...%s",
            "%s: pass %lu/%lu (%s)...%s/%s %d%%",
        },
        "dosync": {"%s: fdatasync failed", "%s: fsync failed"},
        "double_to_human": {
            "  after rounding, value=%Lf * %0.f ^ %u\n",
            "  no scaling, returning (grouped) value: " "%'.*Lf\n",
            "  no scaling, returning value: %.*Lf\n",
            "  returning value: %s\n",
            "  scaled value to %Lf * %0.f ^ %u\n",
            ".*Lf",
            ".*Lf%s",
            "0%ld",
            "double_to_human:\n",
            "failed to prepare value '%Lf' for printing",
        },
        "du_files": {"fts_read failed: %s", "fts_close failed"},
        "dump_hexl_mode_trailer": {"  >"},
        "dump_remainder": {"error reading %s"},
        "dump_strings": {"\\r", "\\b", "\\t", "\\f", "\\n", "\\v", "\\a"},
        "elide_tail_bytes_file": {"standard input"},
        "elide_tail_bytes_pipe": {
            "%s: number of bytes is too large",
            "HEAD_TAIL_PIPE_BYTECOUNT_THRESHOLD " "must be at least 2 * READ_BUFSIZE",
            "error reading %s",
            "standard input",
        },
        "elide_tail_lines_file": {"standard input"},
        "elide_tail_lines_pipe": {"standard input", "error reading %s"},
        "elide_tail_lines_seekable": {"error reading %s"},
        "elseek": {
            "%s: cannot seek to offset %s",
            "%s: cannot seek to relative offset %s",
            "standard input",
        },
        "emit_tab_list_info": {
            "                     The last specified "
            "position can be prefixed with '/'\n"
            "                     to specify a tab "
            "size to use after the last\n"
            "                     explicitly specified "
            "tab stop.  Also a prefix of '+'\n"
            "                     can be used to align "
            "remaining tab stops relative to\n"
            "                     the last specified "
            "tab stop instead of the first column\n",
            "  -t, --tabs=LIST  use comma separated " "list of tab positions.\n",
        },
        "emit_verbose": {" (backup: %s)", "%s -> %s"},
        "es_match": {"+AcCdst"},
        "excise": {"cannot remove %s", "removed %s\n", "removed directory %s\n"},
        "expand": {"input line is too long", "write error"},
        "extract_dirs_from_files": {"--classify", "--color", "--hyperlink"},
        "factor_using_squfof": {"squfof queue overflow"},
        "file_escape_init": {"--classify", "--color", "--hyperlink"},
        "file_lines": {"error reading %s"},
        "file_name_free": {"/."},
        "file_name_prepend": {"/."},
        "fillbuf": {"read failed"},
        "find_bracketed_repeat": {
            "\\",
            "\\a",
            "\\b",
            "\\f",
            "\\n",
            "\\r",
            "\\t",
            "\\v",
            "invalid repeat count %s in [c*n] " "construct",
        },
        "find_dir_entry": {
            "..",
            "cannot open directory %s",
            "couldn't find directory entry in %s with " "matching i-node",
            "failed to chdir to %s",
            "failed to stat %s",
            "reading directory %s",
        },
        "find_occurs_in_text": {
            "$%&#_{}\\",
            "error: regular expression has a match of " "length zero: %s",
        },
        "fix_output_parameters": {"$%&#_{}\\", "--format"},
        "fmt": {"read error", "%s"},
        "fmt_paragraph": {"invalid width"},
        "fold_file": {"%s", "invalid number of columns"},
        "follow_fstatat": {"/dev/stdin"},
        "format_address_std": {"0123456789abcdef"},
        "format_to_mask": {
            "",
            "    ID: %-8i Namelen: %-7l Type: %T\n",
            '  File: "%n"\n',
            "  File: %N\n" "  Size: %-10s\tBlocks: %-10b IO Block: %-6o " "%F\n",
            " Birth: %w\n",
            "%s%s",
            "Access: %x\n",
            "Access: (%04a/%10.10A)  Uid: (%5u/%8U)   Gid: " "(%5g/%8G)\n",
            "Block size: %-10s Fundamental block size: " "%S\n",
            "Blocks: Total: %-10b Free: %-10f Available: " "%a\n",
            "Change: %z\n",
            "Context: %C\n",
            "Device: %Hd,%Ld\tInode: %-10i  Links: %-5h " "Device type: %Hr,%Lr\n",
            "Device: %Hd,%Ld\tInode: %-10i  Links: %h\n",
            "Inodes: Total: %-10c Free: %d\n",
            "Modify: %y\n",
        },
        "format_user_or_group": {"%*"},
        "free_pending_ent": {
            "%%%02x",
            "%*s ",
            "%*s, %*s ",
            "%s %*s ",
            "*=>@|",
            "LS_COLORS",
        },
        "fremote": {
            "cannot determine location of %s. ",
            "reverting to polling",
            "unexpected return value from is_local_fs_type",
        },
        "generate_all_output": {"--format"},
        "get_dev": {
            "%.0f%%",
            "%s",
            "/auto/",
            "/tmp_mnt/",
            "bad field_type",
            "empty cell",
            "unhandled field",
        },
        "get_device": {"cannot access %s: over-mounted by another device"},
        "get_field_list": {"Avail", "Capacity", "Size", "invalid header_mode"},
        "get_field_values": {"POSIXLY_CORRECT"},
        "get_first_line_in_buffer": {"input disappeared"},
        "get_funky_string": {
            "%%%02x",
            "%*s ",
            "%*s, %*s ",
            "%s %*s ",
            "*=>@|",
            "LS_COLORS",
        },
        "get_header": {"blocks", "%s-%s", "POSIXLY_CORRECT"},
        "get_ids": {"invalid user %s", "invalid group %s"},
        "get_line": {"read error"},
        "get_link_name": {"cannot read symbolic link %s"},
        "get_point": {"lofs", "%s"},
        "get_reldate": {"invalid date format %s"},
        "get_spec_stats": {"too many characters in set"},
        "get_type_indicator": {"--indicator-style"},
        "getenv_quoting_style": {
            " of environment variable QUOTING_STYLE: " "%s",
            "--classify",
            "--color",
            "--hyperlink",
            "QUOTING_STYLE",
            "ignoring invalid value",
            "ignoring invalid value of environment ",
            "variable QUOTING_STYLE: %s",
        },
        "getfilecon_cache": {"security.SMACK64"},
        "getoptarg": {
            "'-%c' extra characters or invalid number in the " "argument: %s"
        },
        "gobble_file": {
            "%s",
            "--indicator-style",
            "cannot access %s",
            "error canonicalizing %s",
            "unlabeled",
        },
        "guess_shell_syntax": {"SHELL", "tcsh", "csh"},
        "handle_line_error": {
            "\n",
            " on repetition %s\n",
            "%s: %s: line number out of range",
        },
        "has_uuid_suffix": {"-0123456789abcdefABCDEF"},
        "head": {"standard input", "cannot fstat %s"},
        "head_bytes": {"standard input", "error reading %s"},
        "head_file": {
            "cannot open %s for reading",
            "failed to close %s",
            "standard input",
        },
        "head_lines": {"standard input", "error reading %s"},
        "homogeneous_spec_list": {"+AcCdst"},
        "if": {"%s", "%s: error setting %s", "invalid line discipline %s"},
        "incompatible_options": {"options '-%s' are incompatible"},
        "init_column_info": {
            "%%%02x",
            "%*s ",
            "%*s, %*s ",
            "%s %*s ",
            "*=>@|",
            "--classify",
            "--color",
            "--hyperlink",
            "LS_COLORS",
        },
        "init_fps": {"standard input"},
        "init_header": {
            "%Y-%m-%d %H:%M",
            "%b %e %H:%M %Y",
            "%s.%09d",
            "POSIXLY_CORRECT",
            "TZ",
        },
        "init_parameters": {"page width too narrow"},
        "initialize_ordering_vector": {"--classify", "--color", "--hyperlink"},
        "initialize_regex": {"\n", "[.?!][]\"')}]*\\($\\|\t\\|  \\)[ \t\n]*"},
        "inittables": {
            "invalid number after ','",
            "invalid number after '-'",
            "invalid number after '.'",
            "invalid number at field start",
        },
        "install_file_in_file": {"cannot unlink %s", "cannot stat %s"},
        "install_signal_handlers": {"POSIXLY_CORRECT"},
        "integer_arg": {"invalid integer argument", "bB"},
        "integer_overflow": {"integer overflow"},
        "io_error": {"write error"},
        "iread": {
            " byte); ",
            " bytes); ",
            "invalid input flag",
            "invalid status level",
            "suggest iflag=fullblock",
            "warning: partial read (%",
        },
        "is_char_class_member": {"+AcCdst"},
        "is_colored": {"00"},
        "is_equiv_class_member": {"+AcCdst"},
        "isdir": {"cannot stat %s"},
        "iswnbspace": {"POSIXLY_CORRECT"},
        "isz85": {".-:+=^!/*?&<>()[]{}@%$#"},
        "iwrite": {
            "failed to turn off O_DIRECT: %s",
            "invalid conversion",
            "invalid output flag",
            "invalid status level",
            "standard output",
        },
        "key_warnings": {
            " -",
            "%snumbers use %s as a decimal point in this " "locale",
            "-k ",
            "consider also specifying 'b'",
            "decimal point in numbers",
            "field separator %s is treated as a ",
            "group separator in numbers",
            "in this locale is not supported",
            "key %lu has zero width and will be ignored",
            "key %lu is numeric and spans multiple fields",
            "leading blanks are significant in key %lu; ",
            "minus sign in numbers",
            "note ",
            "obsolescent key %s used; consider %s instead",
            "option '-%s' is ignored",
            "option '-r' only applies to last-resort " "comparison",
            "options '-%s' are ignored",
            "plus sign in numbers",
            "the multi-byte number group separator ",
        },
        "known_term_type": {"TERM ", "TERM"},
        "launch_program": {
            "--coreutils-prog-shebang=",
            "--coreutils-prog=",
            "coreutils.h",
        },
        "lbuf_flush": {"%s", "write error"},
        "length_of_file_name_and_frills": {"--indicator-style"},
        "line_bytes_split": {"%s"},
        "line_cost": {"invalid width"},
        "lines_chunk_split": {"%s", "write error"},
        "lines_rr": {"%s", "write error"},
        "lines_split": {"%s"},
        "list_entries_who": {"%s%s", "\n# users=%lu\n"},
        "list_signal_handling": {
            "%-10s (%2d): %s%s%s\n",
            "BLOCK",
            "IGNORE",
            "failed to get signal process mask",
        },
        "list_signals": {"%d\n"},
        "long_time_expected_width": {"TZ"},
        "lseek_copy": {
            "%s: write failed",
            "cannot lseek %s",
            "error deallocating %s",
            "failed to extend %s",
        },
        "main": {
            "",
            "\t",
            "\n",
            "\n},\n",
            "\r",
            "\x1b[",
            "    ID: %-8i Namelen: %-7l Type: %T\n",
            "   arg[%d]= %s\n",
            "  %s\n",
            '  File: "%n"\n',
            "  File: %N\n" "  Size: %-10s\tBlocks: %-10b IO Block: %-6o %F\n",
            " (%lu-byte) blocks",
            " Birth: %w\n",
            " Symbolic link not followed",
            " argument recursively? ",
            " argument? ",
            " arguments recursively? ",
            " arguments? ",
            " bytes",
            " in output file %s",
            " indefinitely is ineffective",
            " it may not be absolute",
            " specify a mode with non-permission bits",
            " when printing equal width strings",
            "#include <stdint.h>\n\n",
            "%0.Lf",
            "%02x",
            "%08x\n",
            "%N",
            "%Y-%m-%d",
            "%Y-%m-%d %H:%M",
            "%Y-%m-%d %H:%M:%S%:z",
            "%Y-%m-%d %H:%M:%S.%N %z",
            "%Y-%m-%d %H:%M:%S.%N%:z",
            "%Y-%m-%dT%H%:z",
            "%Y-%m-%dT%H:%M%:z",
            "%Y-%m-%dT%H:%M:%S%:z",
            "%Y-%m-%dT%H:%M:%S,%N%:z",
            "%a %b %e %H:%M:%S %Z %Y",
            "%b %e %H:%M",
            "%b %e %H:%M %Y",
            "%d\n",
            '%d: fmt="%s" in_width=%d out_width=%d pad=%d\n',
            "%lu\n",
            "%s",
            "%s\n",
            "%s (%s) = ",
            "%s : ",
            "%s is too large",
            "%s may be used only on a SELinux kernel",
            "%s was specified but %s was not",
            "%s%c",
            "%s%d %.2f%% %.2f%%\n",
            "%s%s",
            "%s-%lu (%s) = ",
            "%s.%N",
            "%s: %s",
            "%s: cannot determine file size",
            "%s: couldn't reset non-blocking mode",
            "%s: input file is output file",
            "%s: invalid start value for hexadecimal suffix",
            "%s: invalid start value for numerical suffix",
            "%s: multiple signals specified",
            "%s: no such user",
            "%s: read error",
            "%s: remove %",
            "%s: unable to perform all requested operations",
            "%s:%lu: %s",
            "%s:%lu: invalid zero-length file name",
            "'\n",
            "'--pages=FIRST_PAGE[:LAST_PAGE]' missing argument",
            "'-N NUMBER' invalid starting line number",
            "'-W PAGE_WIDTH' invalid number of characters",
            "'-l PAGE_LENGTH' invalid number of lines",
            "'-o MARGIN' invalid line offset",
            "'-w PAGE_WIDTH' invalid number of characters",
            "';\nexport LS_COLORS\n",
            "'touch -t %04ld%02d%02d%02d%02d.%02d'",
            "+AcCdst",
            "+as:z",
            "+f:s:w",
            "+i:o:e:",
            "+iu:0",
            "+k:s:v",
            "+n:",
            "+pP",
            "+r:t:u:l:c",
            ",\n  0x%08x, 0x%08x, 0x%08x, 0x%08x, 0x%08x",
            ",0123456789at:",
            "--",
            "--algorithm",
            "--all-repeated",
            "--cached",
            "--check",
            "--check is not supported with " "--algorithm={bsd,sysv,crc}",
            "--classify",
            "--color",
            "--context (-Z) works only on ",
            "--context (-Z) works only on an SELinux-enabled kernel",
            "--coreutils-prog-shebang=",
            "--coreutils-prog=",
            "--data needs at least one argument",
            "--endian",
            "--filter does not process a chunk extracted to stdout",
            "--follow",
            "--format",
            "--from",
            "--group",
            "--group is mutually exclusive with -c/-d/-D/-u",
            "--grouping cannot be combined with --format",
            "--header ignored with command-line input",
            "--help",
            "--hyperlink",
            "--indicator-style",
            "--interactive",
            "--invalid",
            "--io-blocks",
            "--iso-8601",
            "--length is only supported with --algorithm=blake2b",
            "--no-preserve-root",
            "--output",
            "--output-error",
            "--print-database (-p)",
            "--reference",
            "--reflink",
            "--reflink can be used only with --sparse=auto",
            "--remove",
            "--rfc-3339",
            "--round",
            "--size",
            "--sort",
            "--sparse",
            "--tag does not support --text mode",
            "--time",
            "--to",
            "--version",
            "-0123456789Dcdf:is:uw:z",
            "-P",
            "-R --dereference requires either -H or -L",
            "-R -h requires -P",
            "-T",
            "-a:e:i1:2:j:o:t:v:z",
            "-agF:",
            "-drain",
            "-i",
            "-n",
            "//DIRED-OPTIONS// --quoting-style=%s\n",
            "//DIRED//",
            "//SUBDIRED//",
            "/bin/sh",
            "/dev/null",
            "/tmp",
            "0123456789",
            "0123456789C:a:b:del:n:t:ux",
            "0123456789abcdef",
            "0123456789cstuw:p:g:",
            "0::1::2::3::4::5::6::7::",
            "0abd:chHklmst:xB:DLPSX:",
            "0x%02x: 0x%02x\n",
            "123z",
            ">=",
            "AF:GM:ORS:TW:b:i:fg:o:trw:",
            "Access: %x\n",
            "Access: (%04a/%10.10A)  Uid: (%5u/%8U)   Gid: " "(%5g/%8G)\n",
            "BLAKE2b",
            "BLAKE2bp",
            "BLAKE2s",
            "BLAKE2sp",
            "Block size: %-10s Fundamental block size: %S\n",
            "Blocks: Total: %-10b Free: %-10f Available: %a\n",
            "Change: %z\n",
            "Context: %C\n",
            "Could not close `%s': %s\n",
            "Could not open `%s': %s\n",
            "DF_BLOCK_SIZE",
            "DU_BLOCK_SIZE",
            "Device: %Hd,%Ld\tInode: %-10i  Links: %-5h Device type: " "%Hr,%Lr\n",
            "Device: %Hd,%Ld\tInode: %-10i  Links: %h\n",
            "EgGkKmMPtTYZ0",
            "Failed to hash `%s'\n",
            "Fifos do not have major and minor device numbers.",
            "HLPRcfhv",
            "HLPRhvu:r:t:l:",
            "HOME",
            "Inodes: Total: %-10c Free: %d\n",
            "Invalid function name: `%s'\n",
            "Invalid length argument: %lu\n",
            "Invalid length argument: `%s'\n",
            "Invalid number",
            "LP",
            "LS_COLORS='",
            "Maximum digest length for %s is %lu\n",
            "Modify: %y\n",
            "Only one string may be given when ",
            "POSIXLY_CORRECT",
            "Produces a list of odd primes <= LIMIT\n",
            "Rcfvr::w::x::X::s::t::u::g::o::a::,::+::=::",
            "SHELL",
            "Special files require major and minor device numbers.",
            "TIME_STYLE",
            "TMPDIR",
            "TZ",
            "TZ=UTC0",
            "Two strings must be given when ",
            "Two strings must be given when translating.",
            "UNAME_MACHINE",
            "UNAME_NODENAME",
            "UNAME_RELEASE",
            "UNAME_SYSNAME",
            "UNAME_VERSION",
            "Usage: %s LIMIT\n",
            "WARNING: ignoring --preserve-context; ",
            "WARNING: ignoring --strip-program option as -s option " "was ",
            "Warning: ",
            "X --debug",
            "\\0",
            "a command must be given with an adjustment",
            "a:l:",
            "a:l:bctwz",
            "aB:iF:hHklmPTt:vx:",
            "abdfHilLnprst:uvxPRS:TZ",
            "abdlmpqrstuwHT",
            "acd:fhmr:t:",
            "agnruzGZ",
            "aip",
            "all",
            "an SELinux/SMACK-enabled kernel",
            "an input delimiter may be specified only when operating " "on fields",
            "and --no-target-directory",
            "and --no-target-directory (-T)",
            "appending output to %s",
            "argument must be a format string beginning with '+'",
            "arm",
            "auto",
            "b:c:d:f:nsz",
            "bEGKkMmPTYZ0",
            "backup type",
            "bcCsDdg:m:o:pt:TvS:Z",
            "bcp",
            "bctwz",
            "bdfinrst:vFLPS:T",
            "benstuvAET",
            "bfint:uvS:TZ",
            "blake2b",
            "blake2bp",
            "blake2s",
            "blake2sp",
            "block special files not supported",
            "both deleting and squeezing repeats.",
            "both files cannot be standard input",
            "brs:",
            "built without xattr support",
            "c:fLt",
            "c:n:qvz0123456789",
            "cC",
            "can't get process context",
            "cannot both summarize and show all entries",
            "cannot change directory to %s",
            "cannot change root directory to %s",
            "cannot chdir to root directory",
            "cannot combine --target-directory ",
            "cannot combine --target-directory (-t) ",
            "cannot combine -e and -i options",
            "cannot combine mode and --reference options",
            "cannot combine signal with -l or -t",
            "cannot create fifo %s",
            "cannot create link %s to %s",
            "cannot determine hostname",
            "cannot do --relative without --symbolic",
            "cannot find name for user ID %lu",
            "cannot follow %s by name",
            "cannot fstat %s",
            "cannot get effective GID",
            "cannot get effective UID",
            "cannot get niceness",
            "cannot get real GID",
            "cannot get real UID",
            "cannot get system name",
            "cannot get the size of %s",
            "cannot make both hard and symbolic links",
            "cannot open %s for reading",
            "cannot open %s for writing",
            "cannot preserve extended attributes, cp is ",
            "cannot preserve security context ",
            'cannot print "only" of more than one choice',
            "cannot print only names or real IDs in default format",
            "cannot print security context when user specified",
            "cannot read file names from %s",
            "cannot read realtime clock",
            "cannot read table of mounted file systems",
            "cannot set %s",
            "cannot set date",
            "cannot set hostname; this system lacks the " "functionality",
            "cannot set name to %s",
            "cannot set niceness",
            "cannot set permissions of %s",
            "cannot set target context and preserve it",
            "cannot specify --null (-0) with command",
            "cannot specify both --data and --file-system",
            "cannot specify both printing across and printing in " "parallel",
            "cannot specify number of columns when printing in " "parallel",
            "cannot specify times from more than one source",
            "cannot stat %s",
            "cannot truncate to a length of seek=%",
            "cannot unlink %s",
            "cbBkKMGTPEZY0",
            "character offset is zero",
            "character special files not supported",
            "chdir:    %s\n",
            "clLmw",
            "cleaning environ\n",
            "close failed",
            "closing standard input",
            "compatibility mode supports at most one file",
            "conflicting empty-field replacement strings",
            "conflicting security context specifiers given",
            "cor:s:",
            "coreutils",
            "created directory %s",
            "d2",
            "d:sz",
            "d:z",
            "dI",
            "dL",
            "deleting without squeezing repeats.",
            "delimiter list ends with an unescaped backslash: %s",
            "df",
            "dfirvIR",
            "division by zero",
            "diw:",
            "dp:qtuV",
            "drain",
            "eLmPqsz",
            "efmnqsvz",
            "ei:n:o:rz",
            "empty record separator",
            "empty tab",
            "error",
            "error reading %s",
            "error reading input",
            "error waiting for command",
            "exclusive",
            "executing: %s\n",
            "extra argument %s",
            "extra operand %s",
            "extra operand %s not allowed with -%c",
            "f:b:kn:sqz",
            "fD",
            "fF",
            "failed to access %s",
            "failed to close %s",
            "failed to compute a new context",
            "failed to convert some of the input numbers",
            "failed to create directory via template %s",
            "failed to create file via template %s",
            "failed to create security context: %s",
            "failed to discard cache for: %s",
            "failed to get attributes of %s",
            "failed to get current context",
            "failed to get security context of %s",
            "failed to get supplemental groups",
            "failed to open %s",
            "failed to redirect standard error",
            "failed to remove %s",
            "failed to remove %s:",
            "failed to render standard input unusable",
            "failed to run command %s",
            "failed to set default file creation context to %s",
            "failed to set group-ID",
            "failed to set locale",
            "failed to set new range: %s",
            "failed to set new role: %s",
            "failed to set new type: %s",
            "failed to set new user: %s",
            "failed to set supplemental groups",
            "failed to set user-ID",
            "failed to truncate to %",
            "field number is zero",
            "file operands cannot be combined with ",
            "file operands cannot be combined with --files0-from",
            "file system type %s both selected and excluded",
            "fn:s:uvxz",
            "for the suffix length",
            "fork system call failed",
            "format string may not be specified",
            "getrandom",
            "ginstall",
            "grouping and printing repeat counts is meaningless",
            "grouping cannot be combined with --to",
            "grouping has no effect in this locale",
            "h:b:f:v:i:pl:s:w:n:d:",
            "help",
            "i386",
            "ignoring --no-newline with multiple arguments",
            "ignoring input",
            "ignoring input and appending output to %s",
            "ignoring input and redirecting stderr to stdout",
            "ignoring non-option arguments",
            "incompatible tabs",
            "ineffective with --inodes",
            "inf",
            "inotify cannot be used, reverting to polling",
            "input is not in sorted order",
            "install",
            "invalid --threshold argument '-0'",
            "invalid IO block size",
            "invalid PID",
            "invalid Zero increment value: %s",
            "invalid adjustment %s",
            "invalid body numbering style: %s",
            "invalid context: %s",
            "invalid conversion",
            "invalid date %s",
            "invalid date format %s",
            "invalid device %s %s",
            "invalid device type %s",
            "invalid field number: %s",
            "invalid file size",
            "invalid footer numbering style: %s",
            "invalid gap width: %s",
            "invalid header numbering style: %s",
            "invalid header value %s",
            "invalid input flag",
            "invalid input range",
            "invalid length",
            "invalid length: %s",
            "invalid line count: %s",
            "invalid line number field width",
            "invalid line number increment",
            "invalid line number of blank lines",
            "invalid line numbering format: %s",
            "invalid line width: %s",
            "invalid major device number %s",
            "invalid maximum depth %s",
            "invalid minor device number %s",
            "invalid mode",
            "invalid mode %s",
            "invalid mode: %s",
            "invalid number",
            "invalid number after ','",
            "invalid number after '-'",
            "invalid number after '.'",
            "invalid number at field start",
            "invalid number of bytes",
            "invalid number of bytes to compare",
            "invalid number of bytes to skip",
            "invalid number of chunks",
            "invalid number of columns",
            "invalid number of fields to skip",
            "invalid number of lines",
            "invalid number of passes",
            "invalid option -- %c",
            "invalid option -- %c; -WIDTH is recognized only when it "
            "is the first\n"
            "option; use -w N instead",
            "invalid option -- '%c'",
            "invalid output address radix '%c'; it must be one "
            "character from [doxn]",
            "invalid output flag",
            "invalid padding value %s",
            "invalid page range %s",
            "invalid starting line number",
            "invalid suffix %s, contains directory separator",
            "invalid suffix length",
            "invalid template, %s, contains directory separator",
            "invalid template, %s; with --tmpdir,",
            "invalid time interval %s",
            "invalid trailing option -- %c",
            "invalid width",
            "invalid wrap size",
            "invalid zero-length file name",
            "it requires an SELinux-enabled kernel",
            "it requires an SELinux/SMACK-enabled kernel",
            "kKmMGTPEZY0",
            "l/",
            "l:bctwz",
            "lcm=%d, width_per_block=%",
            "length is not a multiple of 8",
            "line buffering stdin is meaningless",
            "line count option -%s%c... is too large",
            "ln",
            "locale",
            "long-iso",
            "m:Z",
            "maximum digest length for %s is %d bits",
            "missing %s",
            "missing destination file operand after %s",
            "missing encoding type",
            "missing file operand",
            "missing operand",
            "missing operand after %s",
            "mode must specify only file permission bits",
            "multi-character separator %s",
            "multi-character tab %s",
            "multiple -i options specified",
            "multiple -l or -t options specified",
            "multiple compress programs specified",
            "multiple field specifications",
            "multiple levelranges",
            "multiple output delimiters specified",
            "multiple output files specified",
            "multiple output formats specified",
            "multiple random sources specified",
            "multiple relative modifiers specified",
            "multiple roles",
            "multiple separator characters specified",
            "multiple target directories specified",
            "multiple types",
            "multiple users",
            "must specify command with --chdir (-C)",
            "mutually exclusive",
            "new_mode: mode\n",
            "no SHELL environment variable, and no shell type option " "given",
            "no command specified",
            "no conversion option specified",
            "no file name of %s allowed",
            "no file systems processed",
            "no group specified for unknown uid: %d",
            "no input from %s",
            "no lines to repeat",
            "no login name",
            "no process ID specified",
            "no type may be specified when dumping strings",
            "no username specified; at least one must be specified " "when using -l",
            "nohup.out",
            "not a tty",
            "not specified",
            "number",
            "number-nonblank",
            "numerical suffix start value is too large ",
            "o1",
            "o2",
            "o4",
            "oS",
            "offset too large: ",
            "ok",
            "only one device may be specified",
            "only one type of list may be specified",
            "option --skip-chdir only permitted if NEWROOT is old %s",
            "option --zero not permitted in default format",
            "options %s and %s are mutually exclusive",
            "options --backup and --no-clobber are mutually " "exclusive",
            "options --compare (-C) and --preserve-timestamps are ",
            "options --compare (-C) and --strip are mutually ",
            "pm:vZ",
            "posix-",
            "powerpc",
            "printing all duplicated lines and repeat counts is " "meaningless",
            "process",
            "pv",
            "q  freq.  cum. freq.(total: %d)\n",
            "r/",
            "rb",
            "read error",
            "redirecting stderr to stdout",
            "removing directory, %s",
            "rn",
            "rs",
            "rz",
            "separator cannot be empty",
            "setenv LS_COLORS '",
            "setenv:   %s\n",
            "sfwiqbhlp",
            "show-all",
            "show-ends",
            "show-nonprinting",
            "show-tabs",
            "skip-bytes + read-bytes is too large",
            "squeeze-blank",
            "standard input",
            "standard output",
            "stray character in field spec",
            "suppressing non-delimited lines makes sense\n"
            "\tonly when operating on fields",
            "syntax error: unexpected argument %s",
            "tab stop value is too large",
            "tag",
            "target %s",
            "target %s is not a directory",
            "target directory not allowed when installing a " "directory",
            "text ordering performed using %s sorting rules",
            "text ordering performed using simple byte comparison",
            "the --binary and --text options are meaningless when ",
            "the --compare (-C) option is ignored when you",
            "the --ignore-missing option is meaningful only when ",
            "the --quiet option is meaningful only when verifying " "checksums",
            "the --status option is meaningful only when verifying " "checksums",
            "the --strict option is meaningful only when verifying " "checksums",
            "the --tag option is meaningless when ",
            "the --warn option is meaningful only when verifying " "checksums",
            "the --zero option is not supported when ",
            "the argument %s lacks a leading '+';\n",
            "the delimiter must be a single character",
            "the monitored command dumped core",
            "the options for verbose and stty-readable output styles " "are\n",
            "the options to output dircolors' internal database " "and\n",
            "the options to print and set the time may not be used " "together",
            "the options to specify dates for printing are mutually " "exclusive",
            "the strip option may not be used when installing a " "directory",
            "this kernel is not SELinux-enabled",
            "time style",
            "to select a shell syntax are mutually exclusive",
            "too few X's in template %s",
            "too many templates",
            "total",
            "u2",
            "u4",
            "uint_fast32_t const crctab[8][256] = {\n",
            "unable to set security context %s",
            "unexpected error code from argv_iter",
            "unknown",
            "unknown program %s",
            "unknown status from command (%d)",
            "unrecognized --preserve-root argument: %s",
            "use -[v]S to pass options in shebang lines",
            "verifying checksums",
            "warning: 'touch %s' is obsolete; use ",
            "warning: following standard input",
            "warning: ignoring --context",
            "warning: ignoring --context; ",
            "warning: ignoring excess arguments, starting with %s",
            "warning: invalid width %lu; using %d instead",
            "warning: options --apparent-size and -b are ",
            "warning: summarizing conflicts with --max-depth=%lu",
            "warning: summarizing is the same as using --max-depth=0",
            "when reading file names from stdin, ",
            "when specifying an output style, modes may not be set",
            "when using an option to specify date(s), any " "non-option\n",
            "with --suffix, template %s must end in X",
            "without an SELinux-enabled kernel",
            "write error",
            "write error: %s\n",
            "x2",
            "x4",
            "you may not abbreviate the --no-preserve-root option",
            "you must specify -c, -t, -u, -l, -r, or context",
            "you must specify a buffering mode option",
            "you must specify a list of bytes, characters, or fields",
            "you must specify a relative %s with %s",
            "you must specify either %s or %s",
            "{\n  0x%08x",
            "};\n",
        },
        "make_ancestor": {"failed to set default creation context for %s"},
        "make_dir_parents_private": {
            "%s exists but is not a directory",
            "cannot make directory %s",
            "failed to get attributes of %s",
            "setting permissions for %s",
        },
        "mark_key": {"^ no match for key\n"},
        "matcher_error": {"error in regular expression matcher"},
        "max_out": {
            "missing %% conversion specification in suffix",
            "too many %% conversion specifications in suffix",
        },
        "merge": {"open failed"},
        "mergefiles": {"open failed"},
        "mkancesdirs_safe_wd": {"cannot create directory %s"},
        "mode_changed": {"getting new attributes of %s"},
        "mode_to_security_class": {
            "blk_file",
            "chr_file",
            "dir",
            "fifo_file",
            "file",
            "lnk_file",
            "sock_file",
        },
        "mp_factor": {"[is number prime?] "},
        "mp_factor_using_division": {"[trial division] "},
        "mp_factor_using_pollard_rho": {
            "[composite factor--restarting " "pollard-rho] ",
            "[pollard-rho (%lu)] ",
        },
        "mp_prime_p": {"Lucas prime test failure.  This should not " "happen"},
        "next_file_name": {
            "%s",
            "0123456789",
            "0123456789abcdef",
            "invalid suffix length",
            "output file suffixes exhausted",
        },
        "nl_file": {"%s"},
        "no_leading_hyphen": {"leading '-' in a component of file name " "%s"},
        "ofile_open": {"%s"},
        "open_file": {"%s", "standard input"},
        "open_next_file": {"%s", "standard input", "rb"},
        "operand2sig": {"%s: invalid signal", "abcdefghijklmnopqrstuvwxyz"},
        "optc_to_fileno": {
            "%s%c=%",
            "%s%c=L",
            "%s/%s",
            "%s=%s",
            "%s=%s:%s",
            "+i:o:e:",
            "DYLD_FORCE_FLAT_NAMESPACE",
            "_STDBUF_",
        },
        "or": {"-o"},
        "out_epoch_sec": {"%s%.*d%-*.*d", "%d"},
        "out_file_context": {"failed to get security context of %s"},
        "out_int": {"'-+ 0"},
        "out_minus_zero": {"'-+ 0", ".0f"},
        "out_mount_point": {"failed to canonicalize %s"},
        "out_uint": {"'-0"},
        "out_uint_o": {"-#0"},
        "out_uint_x": {"-#0"},
        "output_bsd": {" %s", "%05d %5s"},
        "output_crc": {" %s", "%u %s"},
        "output_file": {" (", "%02x", ") = ", "-%", "--algorithm", "invalid length"},
        "output_one_roff_line": {'.%s "', ' "'},
        "output_one_tex_line": {"\\%s ", "}{", "$%&#_{}\\"},
        "output_primes": {
            "\n#undef FIRST_OMITTED_PRIME\n",
            "#define FIRST_OMITTED_PRIME %u\n",
            "#define WIDE_UINT_BITS %u\n",
            "),\n   UINTMAX_MAX / %u)\n",
            "/* Generated file -- DO NOT EDIT */\n",
            "P (%u, %u,\n   (",
        },
        "output_sysv": {" %s", "%d %s"},
        "overwrite_ok": {
            "%s: overwrite %s? ",
            "%s: replace %s, overriding mode %04lo (%s)? ",
            "%s: unwritable %s (mode %04lo, %s); try " "anyway? ",
        },
        "parse_additional_groups": {"invalid group %s", "invalid group list %s"},
        "parse_block_signal_params": {"%s: invalid signal"},
        "parse_chunk": {
            "invalid chunk number",
            "invalid number of bytes",
            "invalid number of chunks",
            "invalid number of lines",
        },
        "parse_column_count": {"invalid number of columns"},
        "parse_duration": {"invalid time interval %s"},
        "parse_format_string": {
            "  padding width: %ld\n  alignment: %s\n",
            "  prefix: %s\n  suffix: %s\n",
            " directive must be %%[0]['][-][N][.][N]f",
            "--format padding overriding --padding",
            "Left",
            "Right",
            "format %s ends in %%",
            "format %s has no %% directive",
            "format %s has too many %% directives",
            "format String:\n" "  input: %s\n" "  grouping: %s\n",
            "invalid format %s (width overflow)",
            "invalid format %s,",
            "invalid precision in format %s",
            "no",
            "yes",
        },
        "parse_group": {"invalid group: %s"},
        "parse_human_number": {"--from", "--invalid", "invalid suffix in input %s: %s"},
        "parse_integer": {
            "00x",
            "0x",
            "bcEGkKMPTwYZ0",
            "use %s if that is intended",
            "warning: %s is a zero multiplier; ",
        },
        "parse_ls_color": {
            "%%%02x",
            "%*s ",
            "%*s, %*s ",
            "%s %*s ",
            "*=>@|",
            "??",
            "COLORTERM",
            "LS_COLORS",
            "target",
            "unparsable value for LS_COLORS environment " "variable",
            "unrecognized prefix: %s",
        },
        "parse_obsolete_option": {"%s: %s", "--", "invalid number"},
        "parse_old_offset": {
            "Bb",
            "\\0",
            "\\a",
            "\\b",
            "\\f",
            "\\n",
            "\\r",
            "\\t",
            "\\v",
            "del",
        },
        "parse_options": {
            " only when following",
            "--follow",
            "bkKmMGTPEZY0",
            "c:n:fFqs:vz0123456789",
            "invalid PID",
            "invalid maximum number of unchanged stats " "between opens",
            "invalid number of bytes",
            "invalid number of lines",
            "invalid number of seconds: %s",
            "option used in invalid context -- %c",
            "warning: --pid=PID is not supported on this " "system",
            "warning: --retry ignored; --retry is useful",
            "warning: --retry only effective for the " "initial open",
            "warning: PID ignored; --pid=PID is useful only " "when following",
        },
        "parse_patterns": {
            "%s: invalid pattern",
            "%s: line number must be greater than zero",
            "line number %s is smaller than preceding line " "number, %s",
            "warning: line number %s is the same as " "preceding line number",
        },
        "parse_repeat_count": {
            "%s: '}' is required in repeat count",
            "%s}: integer required between '{' and " "'}'",
        },
        "parse_signal_action_params": {"%s: invalid signal"},
        "parse_size": {"EGkKMPTYZ0"},
        "parse_split_string": {"     &    %s\n", " into:    %s\n", "split -S:  %s\n"},
        "parse_symbols": {"%s: %s"},
        "parse_tab_stops": {
            "'+' specifier not at start of number: %s",
            "'/' specifier not at start of number: %s",
            "0123456789",
            "tab size contains invalid character(s): %s",
            "tab stop is too large %s",
        },
        "passname": {"%02x%02x%02x", "random"},
        "paste_parallel": {"%s", "standard input is closed"},
        "paste_serial": {"%s"},
        "patterns_match": {
            "%%%02x",
            "%*s ",
            "%*s, %*s ",
            "%s %*s ",
            "*=>@|",
            "LS_COLORS",
        },
        "pclmul_supported": {
            "%s",
            "failed to get cpuid",
            "pclmul support not detected",
            "using generic hardware support",
            "using pclmul hardware support",
        },
        "pipe_bytes": {"error reading %s"},
        "pipe_lines": {"error reading %s"},
        "plain_read": {"read error"},
        "portable_chars_only": {
            "0123456789._-",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "abcdefghijklmnopqrstuvwxyz",
            "nonportable character %s in file name " "%s",
        },
        "prepare_padded_number": {
            "  After padding: %s\n",
            " (cannot handle values > 999Y)",
            " (consider using --to)",
            "--invalid",
            "--round",
            "--to",
            "formatting output:\n" "  value: %Lf\n" "  humanized: %s\n",
            "value too large to be printed: '%Lg'",
            "value/precision too large to be " "printed: '%Lg/%",
        },
        "prime2_p": {"Lucas prime test failure.  This should not happen"},
        "prime_p": {"Lucas prime test failure.  This should not happen"},
        "print_ascii": {
            "%*s",
            "%03o",
            "%c",
            "\\0",
            "\\a",
            "\\b",
            "\\f",
            "\\n",
            "\\r",
            "\\t",
            "\\v",
            "del",
        },
        "print_boottime": {"system boot"},
        "print_clockchange": {"clock change"},
        "print_current_files": {"--classify", "--color", "--hyperlink"},
        "print_deadprocs": {"last=", "term=", "%s%d %s%d", "exit="},
        "print_dir": {
            "%%%02x",
            "%*s ",
            "%*s, %*s ",
            "%s %*s ",
            "%s: not listing already-listed directory",
            "*=>@|",
            ":\n",
            "LS_COLORS",
            "cannot determine device and inode of %s",
            "cannot open directory %s",
            "closing directory %s",
            "error canonicalizing %s",
            "reading directory %s",
            "total",
        },
        "print_element": {"powerpc", "arm", "i386"},
        "print_element_env": {"powerpc", "arm", "i386"},
        "print_entry": {
            "        ???",
            " %-19.19s",
            " %-6s",
            " %19s",
            " %c%-8.*s",
            " %s",
            " %s:%s",
            "%-8.*s",
            "?????",
        },
        "print_esc": {
            '"\\abcefnrtv',
            "invalid universal character name \\%c%0*x",
            "missing hexadecimal number in escape",
        },
        "print_esc_char": {"warning: unrecognized escape '\\%c'", "c:fLt"},
        "print_factors": {
            "%s is not a valid positive integer",
            "[using arbitrary-precision arithmetic] ",
            "[using single-precision arithmetic] ",
        },
        "print_field": {"$\\%c$", "$%&#_{}\\", "\\backslash{}"},
        "print_file_name_and_frills": {"%*s ", "--indicator-style"},
        "print_filename": {"\\r", "\\n", "\\\\"},
        "print_formatted": {
            "%.*s: invalid conversion specification",
            "invalid field width: %s",
            "invalid precision: %s",
        },
        "print_full_info": {
            " context=%s",
            " egid=%s",
            " euid=%s",
            " gid=%s",
            " groups=",
            "(%s)",
            "failed to get groups for the current process",
            "failed to get groups for user %s",
            "uid=%s",
        },
        "print_group": {"cannot find name for group ID %lu"},
        "print_group_list": {
            "failed to get groups for the current " "process",
            "failed to get groups for user %s",
        },
        "print_header": {"\n\n%*s%s%*s%s%*s%s\n\n\n", "Page %", "page number overflow"},
        "print_heading": {
            " %-*s",
            " %-19s",
            " %-6s",
            " %-9s",
            " %s",
            " TTY",
            "%-8s",
            "COMMENT",
            "EXIT",
            "IDLE",
            "Idle",
            "LINE",
            "Login",
            "NAME",
            "Name",
            "PID",
            "TIME",
            "When",
            "Where",
        },
        "print_initspawn": {"last="},
        "print_it": {
            "",
            "\n",
            "    ID: %-8i Namelen: %-7l Type: %T\n",
            '  File: "%n"\n',
            "  File: %N\n" "  Size: %-10s\tBlocks: %-10b IO Block: %-6o %F\n",
            " Birth: %w\n",
            "%s%s",
            "%s: invalid directive",
            "Access: %x\n",
            "Access: (%04a/%10.10A)  Uid: (%5u/%8U)   Gid: " "(%5g/%8G)\n",
            "Block size: %-10s Fundamental block size: %S\n",
            "Blocks: Total: %-10b Free: %-10f Available: %a\n",
            "Change: %z\n",
            "Context: %C\n",
            "Device: %Hd,%Ld\tInode: %-10i  Links: %-5h Device " "type: %Hr,%Lr\n",
            "Device: %Hd,%Ld\tInode: %-10i  Links: %h\n",
            "Inodes: Total: %-10c Free: %d\n",
            "Modify: %y\n",
            "warning: backslash at end of format",
        },
        "print_line": {
            "   .",
            " %-*s",
            " %-12.*s",
            " %-12s",
            " %-6s",
            " %-8s",
            " %10s",
            "%-8.*s",
            "%s",
            "exit=",
            "last=",
            "term=",
        },
        "print_lineno": {
            "invalid line number field width",
            "invalid line number increment",
            "line number overflow",
        },
        "print_login": {"last=", "LOGIN"},
        "print_long_entry": {
            " %s",
            "%-28s",
            "%-29s",
            "/.plan",
            "/.project",
            "???\n",
            "Directory: ",
            "In real life: ",
            "Login name: ",
            "Plan:\n",
            "Project: ",
            "Shell: ",
        },
        "print_long_format": {
            " -> ",
            "%%%02x",
            "%*s ",
            "%*s, %*s ",
            "%s %*s ",
            "*=>@|",
            "--indicator-style",
            "--time",
            "LS_COLORS",
            "TZ",
        },
        "print_named_ascii": {
            "%*s",
            "\\0",
            "\\a",
            "\\b",
            "\\f",
            "\\n",
            "\\r",
            "\\t",
            "\\v",
            "del",
        },
        "print_numbers": {"-+#0 '", "\n", "0123456789"},
        "print_only_size": {"Infinity"},
        "print_runlevel": {"%s%c", "last=", "run-level", "%s %c"},
        "print_size": {
            "\t%s%c",
            "%Y-%m-%d",
            "%Y-%m-%d %H:%M",
            "%Y-%m-%d %H:%M:%S.%N %z",
            "TZ",
        },
        "print_stat": {"UNKNOWN", "cannot read symbolic link %s", " -> "},
        "print_stats": {
            " records in\n",
            " records out\n",
            " truncated record\n",
            " truncated records\n",
            "+%",
            "invalid status level",
        },
        "print_table_row": {"%*d %-*s %s\n"},
        "print_uptime": {
            " %H:%M:%S  ",
            " ??:????  ",
            "%lu user",
            "%lu users",
            ",  load average: %.2f",
            ", %.2f",
            "/proc/uptime",
            "couldn't get boot time",
            "up  %2d:%02d,  ",
            "up %ld day %2d:%02d,  ",
            "up %ld days %2d:%02d,  ",
            "up ???? days ??:??,  ",
        },
        "print_user": {
            "  ?",
            "%.*s",
            "(%s)",
            "(%s:%s)",
            "cannot find name for user ID %s",
        },
        "print_wide_uint": {" << %d | ", "(uintmax_t) ", ")\n%*s", "0x%0*xU"},
        "print_xfer_stats": {
            " byte copied, %s, %s",
            " bytes (%s) copied, %s, %s",
            " bytes (%s, %s) copied, %s, %s",
            " bytes copied, %s, %s",
            "%*s",
            "%.0f s",
            "%g s",
            "%s B/s",
            "/s",
            "Infinity",
        },
        "proc_text": {
            "error in regular expression search",
            "invalid line number of blank lines",
        },
        "process_dir": {
            "failed to restore context for %s",
            "failed to set default creation context for %s",
        },
        "process_file": {
            "%s",
            "%s: new permissions are %s, not %s",
            "--time",
            "cannot access %s",
            "cannot operate on dangling symlink %s",
            "cannot read directory %s",
            "changing permissions of %s",
            "changing security context of %s\n",
            "kKmMGTPEZY0",
        },
        "process_files": {"fts_read failed", "fts_close failed"},
        "process_path": {"%s"},
        "process_regexp": {"error in regular expression search"},
        "process_suffixed_number": {
            "large input value %s: possible " "precision loss",
            "no valid suffix found\n",
            "setting Auto-Padding to %ld " "characters\n",
            "trimming suffix %s\n",
        },
        "prog_fprintf": {": "},
        "prompt": {
            "%s: descend into directory %s? ",
            "%s: descend into write-protected directory %s? ",
            "%s: remove %s %s? ",
            "%s: remove write-protected %s %s? ",
            "cannot remove %s",
        },
        "push_current_dired_pos": {"%*"},
        "quote_name": {"\x1b]8;;\x07", "\x1b]8;;file://%s%s%s\x07", "%*"},
        "quote_name_buf": {
            "%%%02x",
            "%*s ",
            "%*s, %*s ",
            "%s %*s ",
            "*=>@|",
            "LS_COLORS",
        },
        "random_md5_state_init": {"close failed", "getrandom", "open failed"},
        "re_protect": {
            "failed to preserve ownership for %s",
            "failed to preserve permissions for %s",
            "failed to preserve times for %s",
        },
        "read_block": {"rb"},
        "read_char": {"rb"},
        "read_input": {"read error"},
        "read_input_reservoir_sampling": {"read error", "too many input lines"},
        "reap": {"%s [-d] terminated abnormally", "waiting for %s [-d]"},
        "recheck": {
            "%s",
            "%s has appeared;  following new file",
            "%s has become accessible",
            "%s has become inaccessible",
            "%s has been replaced with an untailable file%s",
            "%s has been replaced with an untailable remote file",
            "%s has been replaced with an untailable symbolic " "link",
            "%s has been replaced;  following new file",
            "--follow",
            "; giving up on this name",
        },
        "regexp_error": {"\n", " on repetition %s\n", "%s: %s: match not found"},
        "relpath": {"generating relative path", "..", "%s", "/.."},
        "remove_parents": {
            "failed to remove %s",
            "failed to remove directory %s",
            "removing directory, %s",
        },
        "require_more_args": {"syntax error: missing argument after %s"},
        "reset_lineno": {"invalid starting line number"},
        "reset_signal_handlers": {
            " (failure ignored)",
            "DEFAULT",
            "IGNORE",
            "Reset signal %s (%d) to %s%s\n",
            "failed to get signal action for signal " "%d",
            "failed to set signal action for signal " "%d",
        },
        "restore_default_fscreatecon_or_die": {
            "failed to restore the " "default file creation " "context"
        },
        "rm": {"fts_read failed", "fts_close failed"},
        "rm_fts": {
            "..",
            "and --preserve-root=all is in effect",
            "cannot remove %s",
            "failed to stat %s: skipping %s",
            "please report to %s",
            "refusing to remove %s or %s directory: skipping %s",
            "skipping %s, since it's on a different device",
            "traversal failed: %s",
            "unexpected failure: fts_info=%d: %s\n",
        },
        "rm_option_init": {"failed to get attributes of %s"},
        "robust_getcwd": {"failed to get attributes of %s", "failed to stat %s"},
        "sane_mode": {"min"},
        "save_line_to_file": {"write error for %s"},
        "scan_arg": {
            "eE",
            "invalid %s argument: %s",
            "invalid floating point argument: %s",
            "not-a-number",
            "xX",
        },
        "scan_entries": {"%b %e %H:%M", "%Y-%m-%d %H:%M"},
        "scanargs": {
            "%s: %s",
            "bs",
            "cannot combine any two of {ascii,ebcdic,ibm}",
            "cannot combine block and unblock",
            "cannot combine direct and nocache",
            "cannot combine excl and nocreat",
            "cannot combine lcase and ucase",
            "cbs",
            "conv",
            "count",
            "count_bytes",
            "fullblock",
            "ibs",
            "if",
            "iflag",
            "invalid conversion",
            "invalid input flag",
            "invalid number",
            "invalid output flag",
            "invalid status level",
            "obs",
            "of",
            "oflag",
            "seek",
            "seek_bytes",
            "skip",
            "skip_bytes",
            "standard input",
            "standard output",
            "status",
            "unrecognized operand %s",
        },
        "screen_columns": {"COLUMNS"},
        "send_signals": {"%s", "%s: invalid process id"},
        "seq_fast": {"\n", "inf"},
        "set_LD_PRELOAD": {
            "%s%c=%",
            "%s%c=L",
            "%s/%s",
            "%s=%s",
            "%s=%s:%s",
            "DYLD_FORCE_FLAT_NAMESPACE",
            "DYLD_INSERT_LIBRARIES",
            "LD_PRELOAD",
            "PATH",
            "_STDBUF_",
            "failed to find %s",
            "failed to update the environment with %s",
        },
        "set_author": {
            "failed to lookup file %s",
            "failed to preserve authorship for %s",
        },
        "set_control_char": {"^-", "min", "time", "undef"},
        "set_extend_size": {" with the last value", "'/' specifier only allowed"},
        "set_fd_flags": {"setting flags for %s"},
        "set_fields": {
            "0123456789",
            "byte/character offset %s is too large",
            "byte/character positions are numbered from 1",
            "field number %s is too large",
            "fields are numbered from 1",
            "invalid byte or character range",
            "invalid byte/character position %s",
            "invalid decreasing range",
            "invalid field range",
            "invalid field value %s",
            "invalid range with no endpoint: -",
            "missing list of byte/character positions",
            "missing list of fields",
        },
        "set_file_security_ctx": {"failed to set the security context of " "%s"},
        "set_increment_size": {" with the last value", "'+' specifier only allowed"},
        "set_initialize": {"+AcCdst"},
        "set_input_file": {"cannot open %s for reading"},
        "set_join_field": {"incompatible join fields %lu, %lu"},
        "set_libstdbuf_options": {
            "%s%c=%",
            "%s%c=L",
            "%s/%s",
            "%s=%s",
            "%s=%s:%s",
            "DYLD_FORCE_FLAT_NAMESPACE",
            "_STDBUF_",
            "failed to update the environment with " "%s",
        },
        "set_mode": {
            "cbreak",
            "cooked",
            "ek",
            "evenp",
            "litout",
            "nl",
            "oddp",
            "parity",
            "pass8",
            "raw",
            "sane",
        },
        "set_owner": {
            "clearing permissions for %s",
            "failed to preserve ownership for %s",
        },
        "set_process_security_ctx": {
            "failed to get security context of " "%s",
            "failed to set default file creation " "context for %s",
            "failed to set default file creation " "context to %s",
        },
        "set_program_path": {"PATH", "/proc/self/exe"},
        "set_signal_proc_mask": {
            "BLOCK",
            "UNBLOCK",
            "failed to get signal process mask",
            "failed to set signal process mask",
            "signal %s (%d) mask set to %s\n",
        },
        "set_suffix_length": {
            "0123456789",
            "0123456789abcdef",
            "invalid number of bytes",
            "invalid number of chunks",
            "invalid number of lines",
            "invalid suffix length",
            "the suffix length needs to be at least %",
        },
        "set_window_size": {"%s"},
        "setdefaultfilecon": {
            "warning: %s: context lookup failed",
            "warning: %s: failed to change context to " "%s",
        },
        "settimeout": {
            "warning: setitimer",
            "warning: timer_create",
            "warning: timer_settime",
        },
        "short_pinky": {"%s"},
        "show_date": {
            "%a %b %e %H:%M:%S %Z %Y",
            "%s.%N",
            "output format: %s",
            "time %s is out of range",
        },
        "simple_cat": {"%s", "write error"},
        "simple_strtod_fatal": {
            "--invalid",
            "invalid number: %s",
            "invalid suffix in input: %s",
            "missing 'i' suffix in input: %s (e.g " "Ki/Mi/Gi)",
            "rejecting suffix in input: %s (consider " "using --from)",
            "value too large to be converted: %s",
        },
        "simple_strtod_human": {
            "  Auto-scaling, found 'i', switching to " "base %d\n",
            "  MAX_UNSCALED_DIGITS: %d\n",
            "  input precision = %d\n",
            "  locale decimal-point: %s\n",
            "  parsed numeric value: %Lf\n",
            "  returning value: %Lf (%LG)\n",
            "  suffix power=%d^%d = %Lf\n",
            "simple_strtod_human:\n" "  input string: %s\n",
        },
        "simple_strtoul": {
            "\\0",
            "\\a",
            "\\b",
            "\\f",
            "\\n",
            "\\r",
            "\\t",
            "\\v",
            "del",
        },
        "size_opt": {"%s: %s"},
        "skip": {
            "%s",
            "%s: cannot seek",
            "%s: cannot skip",
            "cannot fstat %s",
            "cannot skip past end of combined input",
            "error reading %s",
            "invalid conversion",
            "rb",
            "standard input",
        },
        "skip_to_page": {" exceeds page count %", "starting page number %"},
        "sort_buffer_size": {"stat failed"},
        "sort_die": {"%s: %s", "standard output"},
        "sort_files": {"--time"},
        "sparse_copy": {
            "error copying %s to %s",
            "error reading %s",
            "error writing %s",
            "overflow reading %s",
        },
        "specify_nmerge": {
            "--%s argument %s too large",
            "--check",
            "--sort",
            "invalid --%s argument %s",
            "invalid number after ','",
            "invalid number after '-'",
            "invalid number after '.'",
            "invalid number at field start",
            "maximum --%s argument with current rlimit is " "%s",
            "minimum --%s argument is %s",
        },
        "specify_nthreads": {
            "--check",
            "--sort",
            "invalid number after ','",
            "invalid number after '-'",
            "invalid number after '.'",
            "invalid number at field start",
            "number in parallel must be nonzero",
        },
        "specify_sort_size": {
            "--check",
            "--sort",
            "EgGkKmMPtTYZ",
            "invalid number after ','",
            "invalid number after '-'",
            "invalid number after '.'",
            "invalid number at field start",
        },
        "squeeze_filter": {"write error"},
        "start_bytes": {"error reading %s"},
        "start_lines": {"error reading %s"},
        "string2_extend": {
            "when translating with string1 longer than "
            "string2,\n"
            "the latter string must not end with a "
            "character class"
        },
        "string_to_integer": {
            "bkKmMGTPEZY0",
            "invalid number of bytes",
            "invalid number of lines",
        },
        "string_to_join_field": {"invalid field number: %s"},
        "strip": {
            "cannot run %s",
            "fork system call failed",
            "strip process terminated abnormally",
            "waiting for strip",
        },
        "swallow_file_in_memory": {"%s"},
        "sync_arg": {
            "couldn't reset non-blocking mode %s",
            "error opening %s",
            "error syncing %s",
            "failed to close %s",
            "invalid sync_mode",
        },
        "tac_file": {
            "%s: read error",
            "failed to open %s for reading",
            "standard input",
        },
        "tac_seekable": {
            "\n",
            "%s: read error",
            "%s: seek failed",
            "error in regular expression search",
            "record too large",
        },
        "tail_bytes": {"cannot fstat %s"},
        "tail_file": {
            "%s: cannot follow end of this type of file%s",
            "; giving up on this name",
            "cannot open %s for reading",
            "error reading %s",
        },
        "tail_forever": {
            "%s",
            "%s: cannot change nonblocking mode",
            "%s: file truncated",
            "--follow",
            "cannot read realtime clock",
            "invalid PID",
            "invalid maximum number of unchanged stats " "between opens",
            "no files remaining",
            "write error",
        },
        "tail_forever_inotify": {
            "%s was replaced",
            "--follow",
            "cannot watch %s",
            "cannot watch parent directory of %s",
            "directory containing watched file was " "removed",
            "error reading inotify event",
            "error waiting for inotify and output " "events",
            "inotify resources exhausted",
            "invalid PID",
            "no files remaining",
        },
        "tail_lines": {"cannot fstat %s"},
        "target_directory_operand": {
            "failed to access %s",
            "target %s is not a directory",
        },
        "tee_files": {
            "%s",
            "--output-error",
            "ab",
            "read error",
            "standard output",
            "wb",
        },
        "temp_stream": {
            "TMPDIR",
            "failed to create temporary file in %s",
            "failed to open %s for writing",
            "failed to rewind stream for %s",
            "memory exhausted",
            "tacXXXXXX",
            "w+",
            "w+b",
        },
        "term": {"-l", "%s expected, found %s", "%s expected"},
        "three_arguments": {"%s: binary operator expected", "-a", "-o"},
        "time_type_to_statx": {"--time"},
        "toarith": {"%s"},
        "touch": {
            "--time",
            "cannot touch %s",
            "failed to close %s",
            "setting times of %s",
        },
        "tsort": {
            "%s",
            "%s: input contains a loop:",
            "%s: input contains an odd number of tokens",
            "standard input",
        },
        "unary_operator": {"%s: unary operator expected"},
        "unblock_signal": {"warning: sigprocmask"},
        "unexpand": {",0123456789at:", "input line is too long", "write error"},
        "unit_to_umax": {"invalid unit size: %s", "KMGTPEZY0", "KMGTPEZY"},
        "unquote": {
            "+AcCdst",
            "at end of string is not portable",
            "warning: an unescaped backslash ",
            "warning: the ambiguous octal escape \\%c%c%c is "
            "being\n"
            "\tinterpreted as the 2-byte sequence \\0%c%c, %c",
        },
        "unset_envvars": {"cannot unset %s", "unset:    %s\n"},
        "update_current_files_info": {"--classify", "--color", "--hyperlink"},
        "uptime": {"%s"},
        "usage": {
            "\n",
            "\n"
            "\n"
            "BYTES is hex with 0x or 0X prefix, and may have a "
            "multiplier suffix:\n"
            "  b    512\n"
            "  KB   1000\n"
            "  K    1024\n"
            "  MB   1000*1000\n"
            "  M    1024*1024\n"
            "and so on for G, T, P, E, Z, Y.\n"
            "Binary prefixes can be used, too: KiB=K, MiB=M, and so "
            "on.\n",
            "\n"
            "\n"
            "TYPE is made up of one or more of these "
            "specifications:\n"
            "  a          named character, ignoring high-order bit\n"
            "  c          printable character or backslash escape\n",
            "\n"
            "\n"
            "Traditional format specifications may be intermixed; "
            "they accumulate:\n"
            "  -a   same as -t a,  select named characters, "
            "ignoring high-order bit\n"
            "  -b   same as -t o1, select octal bytes\n"
            "  -c   same as -t c,  select printable characters or "
            "backslash escapes\n"
            "  -d   same as -t u2, select unsigned decimal 2-byte "
            "units\n",
            "\n"
            "      --check-order       check that the input is "
            "correctly sorted, even\n"
            "                            if all input lines are "
            "pairable\n"
            "      --nocheck-order     do not check that the input "
            "is correctly sorted\n",
            "\n"
            "  ( EXPRESSION )               EXPRESSION is true\n"
            "  ! EXPRESSION                 EXPRESSION is false\n"
            "  EXPRESSION1 -a EXPRESSION2   both EXPRESSION1 and "
            "EXPRESSION2 are true\n"
            "  EXPRESSION1 -o EXPRESSION2   either EXPRESSION1 or "
            "EXPRESSION2 is true\n",
            "\n"
            "  -1                      suppress column 1 (lines "
            "unique to FILE1)\n"
            "  -2                      suppress column 2 (lines "
            "unique to FILE2)\n"
            "  -3                      suppress column 3 (lines "
            "that appear in both files)\n",
            "\n"
            "  -A, --show-all           equivalent to -vET\n"
            "  -b, --number-nonblank    number nonempty output "
            "lines, overrides -n\n"
            "  -e                       equivalent to -vE\n"
            "  -E, --show-ends          display $ at end of each "
            "line\n"
            "  -n, --number             number all output lines\n"
            "  -s, --squeeze-blank      suppress repeated empty "
            "output lines\n",
            "\n"
            "  -a FILENUM             also print unpairable lines "
            "from file FILENUM, where\n"
            "                           FILENUM is 1 or 2, "
            "corresponding to FILE1 or FILE2\n"
            "  -e EMPTY               replace missing input fields "
            "with EMPTY\n",
            "\n"
            "  -a, --all         same as -b -d --login -p -r -t -T "
            "-u\n"
            "  -b, --boot        time of last system boot\n"
            "  -d, --dead        print dead processes\n"
            "  -H, --heading     print line of column headings\n",
            "\n"
            "  -b FILE     FILE exists and is block special\n"
            "  -c FILE     FILE exists and is character special\n"
            "  -d FILE     FILE exists and is a directory\n"
            "  -e FILE     FILE exists\n",
            "\n"
            "  -l              produce long format output for the "
            "specified USERs\n"
            "  -b              omit the user's home directory and "
            "shell in long format\n"
            "  -h              omit the user's project file in long "
            "format\n"
            "  -p              omit the user's plan file in long "
            "format\n"
            "  -s              do short format output, this is the "
            "default\n",
            "\n"
            "  -n STRING            the length of STRING is "
            "nonzero\n"
            "  STRING               equivalent to -n STRING\n"
            "  -z STRING            the length of STRING is zero\n"
            "  STRING1 = STRING2    the strings are equal\n"
            "  STRING1 != STRING2   the strings are not equal\n",
            "\n"
            "  -r              use BSD sum algorithm (the default), "
            "use 1K blocks\n"
            "  -s, --sysv      use System V sum algorithm, use 512 "
            "bytes blocks\n",
            "\n"
            "  ARG1 * ARG2       arithmetic product of ARG1 and "
            "ARG2\n"
            "  ARG1 / ARG2       arithmetic quotient of ARG1 "
            "divided by ARG2\n"
            "  ARG1 % ARG2       arithmetic remainder of ARG1 "
            "divided by ARG2\n",
            "\n"
            "  ARG1 + ARG2       arithmetic sum of ARG1 and ARG2\n"
            "  ARG1 - ARG2       arithmetic difference of ARG1 and "
            "ARG2\n",
            "\n"
            "  ARG1 < ARG2       ARG1 is less than ARG2\n"
            "  ARG1 <= ARG2      ARG1 is less than or equal to "
            "ARG2\n"
            "  ARG1 = ARG2       ARG1 is equal to ARG2\n"
            "  ARG1 != ARG2      ARG1 is unequal to ARG2\n"
            "  ARG1 >= ARG2      ARG1 is greater than or equal to "
            "ARG2\n"
            "  ARG1 > ARG2       ARG1 is greater than ARG2\n",
            "\n"
            "  FILE1 -ef FILE2   FILE1 and FILE2 have the same "
            "device and inode numbers\n"
            "  FILE1 -nt FILE2   FILE1 is newer (modification date) "
            "than FILE2\n"
            "  FILE1 -ot FILE2   FILE1 is older than FILE2\n",
            "\n"
            "  INTEGER1 -eq INTEGER2   INTEGER1 is equal to "
            "INTEGER2\n"
            "  INTEGER1 -ge INTEGER2   INTEGER1 is greater than or "
            "equal to INTEGER2\n"
            "  INTEGER1 -gt INTEGER2   INTEGER1 is greater than "
            "INTEGER2\n"
            "  INTEGER1 -le INTEGER2   INTEGER1 is less than or "
            "equal to INTEGER2\n"
            "  INTEGER1 -lt INTEGER2   INTEGER1 is less than "
            "INTEGER2\n"
            "  INTEGER1 -ne INTEGER2   INTEGER1 is not equal to "
            "INTEGER2\n",
            "\n"
            "  STRING : REGEXP   anchored pattern match of REGEXP "
            "in STRING\n"
            "\n"
            "  match STRING REGEXP        same as STRING : REGEXP\n"
            "  substr STRING POS LENGTH   substring of STRING, POS "
            "counted from 1\n"
            "  index STRING CHARS         index in STRING where any "
            "CHARS is found, or 0\n"
            "  length STRING              length of STRING\n",
            "\n"
            "  b      create a block (buffered) special file\n"
            "  c, u   create a character (unbuffered) special file\n"
            "  p      create a FIFO\n",
            "\n" "--terse is equivalent to the following FORMAT:\n" "    %s",
            "\n"
            "A field is a run of blanks (usually spaces and/or "
            "TABs), then non-blank\n"
            "characters.  Fields are skipped before chars.\n",
            "\n"
            "A lightweight 'finger' program;  print user "
            "information.\n"
            "The utmp file will be %s.\n",
            "\n"
            "A mere - implies -i.  If no COMMAND, print the "
            "resulting environment.\n",
            "\n"
            "Adding a z suffix to any type displays printable "
            "characters at the end of\n"
            "each output line.\n",
            "\n"
            "After any flags comes an optional field width, as a "
            "decimal number;\n"
            "then an optional modifier, which is either\n"
            "E to use the locale's alternate representations if "
            "available, or\n"
            "O to use the locale's alternate numeric symbols if "
            "available.\n",
            "\n"
            "An omitted EXPRESSION defaults to false.  Otherwise,\n"
            "EXPRESSION is true or false and sets exit status.  It "
            "is one of:\n",
            "\n"
            "As a special case, cp makes a backup of SOURCE when "
            "the force and backup\n"
            "options are given and SOURCE and DEST are the same "
            "name for an existing,\n"
            "regular file.\n",
            "\n"
            "Beware that many operators need to be escaped or "
            "quoted for shells.\n"
            "Comparisons are arithmetic if both ARGs are numbers, "
            "else lexicographical.\n"
            "Pattern matches return the string matched between \\( "
            "and \\) or null; if\n"
            "\\( and \\) are not used, they return the number of "
            "characters matched or 0.\n",
            "\n"
            "Both MAJOR and MINOR must be specified when TYPE is b, "
            "c, or u, and they\n"
            "must be omitted when TYPE is p.  If MAJOR or MINOR "
            "begins with 0x or 0X,\n"
            "it is interpreted as hexadecimal; otherwise, if it "
            "begins with 0, as octal;\n"
            "otherwise, as decimal.  TYPE may be:\n",
            "\nBuilt-in programs:\n%s\n",
            "\n"
            "By default, rm does not remove directories.  Use the "
            "--recursive (-r or -R)\n"
            "option to remove each listed directory, too, along "
            "with all of its contents.\n",
            "\n"
            "By default, sparse SOURCE files are detected by a "
            "crude heuristic and the\n"
            "corresponding DEST file is made sparse as well.  That "
            "is the behavior\n"
            "selected by --sparse=auto.  Specify --sparse=always to "
            "create a sparse DEST\n"
            "file whenever the SOURCE file contains a long enough "
            "sequence of zero bytes.\n"
            "Use --sparse=never to inhibit creation of sparse "
            "files.\n",
            "\n"
            "CHUNKS may be:\n"
            "  N       split into N files based on size of input\n"
            "  K/N     output Kth of N to stdout\n"
            "  l/N     split into N files without splitting "
            "lines/records\n"
            "  l/K/N   output Kth of N to stdout without splitting "
            "lines/records\n"
            "  r/N     like 'l' but use round robin distribution\n"
            "  r/K/N   likewise but only output Kth of N to "
            "stdout\n",
            "\nCombination settings:\n",
            "\n"
            "Control settings:\n"
            "   [-]clocal     disable modem control signals\n"
            "   [-]cread      allow input to be received\n",
            "\n"
            "DIGEST determines the digest algorithm and default "
            "output format:\n"
            "  sysv      (equivalent to sum -s)\n"
            "  bsd       (equivalent to sum -r)\n"
            "  crc       (equivalent to cksum)\n"
            "  md5       (equivalent to md5sum)\n"
            "  sha1      (equivalent to sha1sum)\n"
            "  sha224    (equivalent to sha224sum)\n"
            "  sha256    (equivalent to sha256sum)\n"
            "  sha384    (equivalent to sha384sum)\n"
            "  sha512    (equivalent to sha512sum)\n"
            "  blake2b   (equivalent to b2sum)\n"
            "  sm3       (only available through cksum)\n"
            "\n",
            "\n"
            "DURATION is a floating point number with an optional "
            "suffix:\n"
            "'s' for seconds (the default), 'm' for minutes, 'h' "
            "for hours or 'd' for days.\n"
            "A duration of 0 disables the associated timeout.\n",
            "\n"
            "Default options are: -bt -d'\\:' -fn -hn -i1 -l1 "
            "-n'rn' -s<TAB> -v1 -w6\n"
            "\n"
            "CC are two delimiter characters used to construct "
            "logical page delimiters;\n"
            "a missing second character implies ':'.  As a GNU "
            "extension one can specify\n"
            "more than two characters, and also specifying the "
            "empty string (-d '')\n"
            "disables section matching.\n",
            "\n"
            "Delete FILE(s) if --remove (-u) is specified.  The "
            "default is not to remove\n"
            "the files because it is common to operate on device "
            "files like /dev/hda,\n"
            "and those files usually should not be removed.\n"
            "The optional HOW parameter indicates how to remove a "
            "directory entry:\n"
            "'unlink' => use a standard unlink call.\n"
            "'wipe' => also first obfuscate bytes in the name.\n"
            "'wipesync' => also sync each obfuscated byte to the "
            "device.\n"
            "The default mode is 'wipesync', but note it can be "
            "expensive.\n"
            "\n",
            "\n"
            "EXIT status:\n"
            "  124  if COMMAND times out, and --preserve-status is "
            "not specified\n"
            "  125  if the timeout command itself fails\n"
            "  126  if COMMAND is found but cannot be invoked\n"
            "  127  if COMMAND cannot be found\n"
            "  137  if COMMAND (or timeout itself) is sent the KILL "
            "(9) signal (128+9)\n"
            "  -    the exit status of COMMAND otherwise\n",
            "\n"
            "Each FLAG symbol may be:\n"
            "\n"
            "  append    append mode (makes sense only for output; "
            "conv=notrunc suggested)\n",
            "\n"
            "Each MODE is of the form "
            "'[ugoa]*([-+=]([rwxXst]*|[ugo]))+|[-+=][0-7]+'.\n",
            "\n"
            "Each PATTERN may be:\n"
            "  INTEGER            copy up to but not including "
            "specified line number\n"
            "  /REGEXP/[OFFSET]   copy up to but not including a "
            "matching line\n"
            "  %REGEXP%[OFFSET]   skip to, but not including a "
            "matching line\n"
            "  {INTEGER}          repeat the previous pattern "
            "specified number of times\n"
            "  {*}                repeat the previous pattern as "
            "many times as possible\n"
            "\n"
            "A line OFFSET is a required '+' or '-' followed by a "
            "positive integer.\n",
            "\n"
            "Examples:\n"
            "  $ %s --to=si 1000\n"
            '            -> "1.0K"\n'
            "  $ %s --to=iec 2048\n"
            '           -> "2.0K"\n'
            "  $ %s --to=iec-i 4096\n"
            '           -> "4.0Ki"\n'
            "  $ echo 1K | %s --from=si\n"
            '           -> "1000"\n'
            "  $ echo 1K | %s --from=iec\n"
            '           -> "1024"\n'
            "  $ df -B1 | %s --header --field 2-4 --to=si\n"
            "  $ ls -l  | %s --header --field 5 --to=iec\n"
            "  $ ls -lh | %s --header --field 5 --from=iec "
            "--padding=10\n"
            "  $ ls -lh | %s --header --field 5 --from=iec --format "
            "%%10f\n",
            "\n"
            "Examples:\n"
            "  %s -12 file1 file2  Print only lines present in both "
            "file1 and file2.\n"
            "  %s -3 file1 file2  Print lines in file1 not in "
            "file2, and vice versa.\n",
            "\n"
            "Examples:\n"
            '  %s /usr/bin/          -> "/usr"\n'
            '  %s dir1/str dir2/str  -> "dir1" followed by "dir2"\n'
            '  %s stdio.h            -> "."\n',
            "\n"
            "Examples:\n"
            '  %s /usr/bin/sort          -> "sort"\n'
            '  %s include/stdio.h .h     -> "stdio"\n'
            '  %s -s .h include/stdio.h  -> "stdio"\n'
            '  %s -a any/str1 any/str2   -> "str1" followed by '
            '"str2"\n',
            "\n"
            "Examples:\n"
            "  %s f - g  Output f's contents, then standard input, "
            "then g's contents.\n"
            "  %s        Copy standard input to standard output.\n",
            "\n"
            "Examples:\n"
            '  %s root /u        Change the owner of /u to "root".\n'
            "  %s root:staff /u  Likewise, but also change its "
            'group to "staff".\n'
            "  %s -hR root /u    Change the owner of /u and "
            'subfiles to "root".\n',
            "\n"
            "Examples:\n"
            '  %s staff /u      Change the group of /u to "staff".\n'
            "  %s -hR staff /u  Change the group of /u and subfiles "
            'to "staff".\n',
            "\n"
            "Examples:\n"
            "Convert seconds since the Epoch (1970-01-01 UTC) to a "
            "date\n"
            "  $ date --date='@2147483647'\n"
            "\n"
            "Show the time on the west coast of the US (use "
            "tzselect(1) to find TZ)\n"
            "  $ TZ='America/Los_Angeles' date\n"
            "\n"
            "Show the local time for 9AM next Friday on the west "
            "coast of the US\n"
            '  $ date --date=\'TZ="America/Los_Angeles" 09:00 next '
            "Fri'\n",
            "\n"
            "Except for -h and -L, all FILE-related tests "
            "dereference symbolic links.\n"
            "Beware that parentheses need to be escaped (e.g., by "
            "backslashes) for shells.\n"
            "INTEGER may also be -l STRING, which evaluates to the "
            "length of STRING.\n",
            "\n"
            "Exit status is 0 if EXPRESSION is neither null nor 0, "
            "1 if EXPRESSION is null\n"
            "or 0, 2 if EXPRESSION is syntactically invalid, and 3 "
            "if an error occurred.\n",
            "\n"
            "Exit status is 0 if all input numbers were "
            "successfully converted.\n"
            "By default, %s will stop at the first conversion error "
            "with exit status 2.\n"
            "With --invalid='fail' a warning is printed for each "
            "conversion error\n"
            "and the exit status is 2.  With --invalid='warn' each "
            "conversion error is\n"
            "diagnosed, but the exit status is 0.  With "
            "--invalid='ignore' conversion\n"
            "errors are not diagnosed and the exit status is 0.\n",
            "\n"
            "Exit status:\n"
            " 0  if OK,\n"
            " 1  if minor problems (e.g., cannot access "
            "subdirectory),\n"
            " 2  if serious trouble (e.g., cannot access "
            "command-line argument).\n",
            "\n"
            "FIELDS supports cut(1) style field ranges:\n"
            "  N    N'th field, counted from 1\n"
            "  N-   from N'th field, to end of line\n"
            "  N-M  from N'th to M'th field (inclusive)\n"
            "  -M   from first to M'th field (inclusive)\n"
            "  -    all fields\n"
            "Multiple fields/ranges can be separated with commas\n",
            "\n"
            "FIELD_LIST is a comma-separated list of columns to be "
            "included.  Valid\n"
            "field names are: 'source', 'fstype', 'itotal', "
            "'iused', 'iavail', 'ipcent',\n"
            "'size', 'used', 'avail', 'pcent', 'file' and 'target' "
            "(see info page).\n",
            "\n"
            "FORMAT controls the output as in C printf.  "
            "Interpreted sequences are:\n"
            "\n"
            '  \\"      double quote\n',
            "\n"
            "FORMAT controls the output.  Interpreted sequences "
            "are:\n"
            "\n"
            "  %%   a literal %\n"
            "  %a   locale's abbreviated weekday name (e.g., Sun)\n",
            "\n"
            "FORMAT is one of:\n"
            "\n"
            "  ln     left justified, no leading zeros\n"
            "  rn     right justified, no leading zeros\n"
            "  rz     right justified, leading zeros\n"
            "\n",
            "\n"
            "FORMAT must be suitable for printing one "
            "floating-point argument '%f'.\n"
            "Optional quote (%'f) will enable --grouping (if "
            "supported by current locale).\n"
            "Optional width value (%10f) will pad output. Optional "
            "zero (%010f) width\n"
            "will zero pad the number. Optional negative values "
            "(%-10f) will left align.\n"
            "Optional precision (%.1f) will override the input "
            "determined precision.\n",
            "\n"
            "Handle the tty line connected to standard input.  "
            "Without arguments,\n"
            "prints baud rate, line discipline, and deviations from "
            "stty sane.  In\n"
            "settings, CHAR is taken literally, or coded as in ^c, "
            "0x37, 0177 or\n"
            "127; special values ^- or undef used to disable "
            "special characters.\n",
            "\n"
            "If -e is in effect, the following sequences are "
            "recognized:\n"
            "\n",
            "\nIf FILE is -, shred standard output.\n",
            "\n"
            "If FILE is not specified, use %s.  %s as FILE is "
            "common.\n"
            "If ARG1 ARG2 given, -m presumed: 'am i' or 'mom likes' "
            "are usual.\n",
            "\n"
            "If FILE is specified, read it to determine which "
            "colors to use for which\n"
            "file types and extensions.  Otherwise, a precompiled "
            "database is used.\n"
            "For details on the format of these files, run "
            "'dircolors --print-database'.\n",
            "\n"
            "If FIRST or INCREMENT is omitted, it defaults to 1.  "
            "That is, an\n"
            "omitted INCREMENT defaults to 1 even when LAST is "
            "smaller than FIRST.\n"
            "The sequence of numbers ends when the sum of the "
            "current number and\n"
            "INCREMENT would become greater than LAST.\n"
            "FIRST, INCREMENT, and LAST are interpreted as floating "
            "point values.\n"
            "INCREMENT is usually positive if FIRST is smaller than "
            "LAST, and\n"
            "INCREMENT is usually negative if FIRST is greater than "
            "LAST.\n"
            "INCREMENT must not be 0; none of FIRST, INCREMENT and "
            "LAST may be NaN.\n",
            "\n" "If MODE is '0' the corresponding stream will be " "unbuffered.\n",
            "\n"
            "If MODE is 'L' the corresponding stream will be line "
            "buffered.\n"
            "This option is invalid with standard input.\n",
            "\n"
            "If first and second call formats both apply, the "
            "second format is assumed\n"
            "if the last operand begins with + or (if there are 2 "
            "operands) a digit.\n"
            "An OFFSET operand means -j OFFSET.  LABEL is the "
            "pseudo-address\n"
            "at first byte printed, incremented when dump is "
            "progressing.\n"
            "For OFFSET and LABEL, a 0x or 0X prefix indicates "
            "hexadecimal;\n"
            "suffixes may be . for octal and b for multiply by "
            "512.\n",
            "\n"
            "If no command is given, run '\"$SHELL\" -i' (default: "
            "'/bin/sh -i').\n",
            "\nIf no option is specified, -P is assumed.\n",
            "\n"
            "If standard input is a terminal, redirect it from an "
            "unreadable file.\n"
            "If standard output is a terminal, append output to "
            "'nohup.out' if possible,\n"
            "'$HOME/nohup.out' otherwise.\n"
            "If standard error is a terminal, redirect it to "
            "standard output.\n"
            "To save output to FILE, use '%s COMMAND > FILE'.\n",
            "\n"
            "Input settings:\n"
            "   [-]brkint     breaks cause an interrupt signal\n"
            "   [-]icrnl      translate carriage return to newline\n"
            "   [-]ignbrk     ignore break characters\n"
            "   [-]igncr      ignore carriage return\n"
            "   [-]ignpar     ignore characters with parity "
            "errors\n",
            "\n"
            "KEYDEF is F[.C][OPTS][,F[.C][OPTS]] for start and stop "
            "position, where F is a\n"
            "field number and C a character position in the field; "
            "both are origin 1, and\n"
            "the stop position defaults to the line's end.  If "
            "neither -t nor -b is in\n"
            "effect, characters in a field are counted from the "
            "beginning of the preceding\n"
            "whitespace.  OPTS is one or more single-letter "
            "ordering options [bdfgiMhnRrV],\n"
            "which override global ordering options for that key.  "
            "If no key is given, use\n"
            "the entire line as the key.  Use --debug to diagnose "
            "incorrect key usage.\n"
            "\n"
            "SIZE may be followed by the following multiplicative "
            "suffixes:\n",
            "\n"
            "Local settings:\n"
            "   [-]crterase   echo erase characters as "
            "backspace-space-backspace\n",
            "\n"
            "MODE determines behavior with write errors on the "
            "outputs:\n"
            "  warn           diagnose errors writing to any "
            "output\n"
            "  warn-nopipe    diagnose errors writing to any output "
            "not a pipe\n"
            "  exit           exit on error writing to any output\n"
            "  exit-nopipe    exit on error writing to any output "
            "not a pipe\n"
            "The default MODE for the -p option is 'warn-nopipe'.\n"
            "The default operation when --output-error is not "
            "specified, is to\n"
            "exit immediately on error writing to a pipe, and "
            "diagnose errors\n"
            "writing to non pipe outputs.\n",
            "\n"
            "N and BYTES may be followed by the following "
            "multiplicative suffixes:\n"
            "c=1, w=2, b=512, kB=1000, K=1024, MB=1000*1000, "
            "M=1024*1024, xM=M,\n"
            "GB=1000*1000*1000, G=1024*1024*1024, and so on for T, "
            "P, E, Z, Y.\n"
            "Binary prefixes can be used, too: KiB=K, MiB=M, and so "
            "on.\n"
            "\n"
            "Each CONV symbol may be:\n"
            "\n",
            "\n"
            "NOTE: Binary -a and -o are inherently ambiguous.  Use "
            "'test EXPR1 && test\n"
            "EXPR2' or 'test EXPR1 || test EXPR2' instead.\n",
            "\n"
            "NOTE: If COMMAND adjusts the buffering of its standard "
            "streams ('tee' does\n"
            "for example) then that will override corresponding "
            "changes by 'stdbuf'.\n"
            "Also some filters (like 'dd' and 'cat' etc.) don't use "
            "streams for I/O,\n"
            "and are thus unaffected by 'stdbuf' settings.\n",
            "\n"
            "NOTE: [ honors the --help and --version options, but "
            "test does not.\n"
            "test treats each of those as it treats any other "
            "nonempty STRING.\n",
            "\n"
            "NOTE: printf(1) is a preferred alternative,\n"
            "which does not have issues outputting option-like "
            "strings.\n",
            "\n"
            "NUM may have a multiplier suffix:\n"
            "b 512, kB 1000, K 1024, MB 1000*1000, M 1024*1024,\n"
            "GB 1000*1000*1000, G 1024*1024*1024, and so on for T, "
            "P, E, Z, Y.\n"
            "Binary prefixes can be used, too: KiB=K, MiB=M, and so "
            "on.\n",
            "\n"
            "NUM may have a multiplier suffix:\n"
            "b 512, kB 1000, K 1024, MB 1000*1000, M 1024*1024,\n"
            "GB 1000*1000*1000, G 1024*1024*1024, and so on for T, "
            "P, E, Z, Y.\n"
            "Binary prefixes can be used, too: KiB=K, MiB=M, and so "
            "on.\n"
            "\n",
            "\n"
            "Note that if you use rm to remove a file, it might be "
            "possible to recover\n"
            "some of its contents, given sufficient expertise "
            "and/or time.  For greater\n"
            "assurance that the contents are truly unrecoverable, "
            "consider using shred(1).\n",
            "\n"
            "Note that the -d and -t options accept different "
            "time-date formats.\n",
            "\n" "Note, comparisons honor the rules specified by " "'LC_COLLATE'.\n",
            "\n"
            "Note: 'uniq' does not detect repeated lines unless "
            "they are adjacent.\n"
            "You may want to sort the input first, or use 'sort -u' "
            "without 'uniq'.\n",
            "\n"
            "Optional - before SETTING indicates negation.  An * "
            "marks non-POSIX\n"
            "settings.  The underlying system defines which "
            "settings are available.\n",
            "\n"
            "Otherwise MODE is a number which may be followed by "
            "one of the following:\n"
            "KB 1000, K 1024, MB 1000*1000, M 1024*1024, and so on "
            "for G, T, P, E, Z, Y.\n"
            "Binary prefixes can be used, too: KiB=K, MiB=M, and so "
            "on.\n"
            "In this case the corresponding stream will be fully "
            "buffered with the buffer\n"
            "size set to MODE bytes.\n",
            "\nOutput settings:\n",
            "\n"
            "Owner is unchanged if missing.  Group is unchanged if "
            "missing, but changed\n"
            "to login group if implied by a ':' following a "
            "symbolic OWNER.\n"
            "OWNER and GROUP may be numeric as well as symbolic.\n",
            "\n"
            "Print the value of EXPRESSION to standard output.  A "
            "blank line below\n"
            "separates increasing precedence groups.  EXPRESSION "
            "may be:\n"
            "\n"
            "  ARG1 | ARG2       ARG1 if it is neither null nor 0, "
            "otherwise ARG2\n"
            "\n"
            "  ARG1 & ARG2       ARG1 if neither argument is null "
            "or 0, otherwise 0\n",
            "\nRead standard input if FILE is -\n",
            "\n"
            "SETs are specified as strings of characters.  Most "
            "represent themselves.\n"
            "Interpreted sequences are:\n"
            "\n"
            "  \\NNN            character with octal value NNN (1 "
            "to 3 octal digits)\n"
            "  \\\\              backslash\n"
            "  \\a              audible BEL\n"
            "  \\b              backspace\n"
            "  \\f              form feed\n"
            "  \\n              new line\n"
            "  \\r              return\n"
            "  \\t              horizontal tab\n",
            "\n"
            "SIG may be a signal name like 'PIPE', or a signal "
            "number like '13'.\n"
            "Without SIG, all known signals are included.  Multiple "
            "signals can be\n"
            "comma-separated.\n",
            "\n"
            "SIGNAL may be a signal name like 'HUP', or a signal "
            "number like '1',\n"
            "or the exit status of a process terminated by a "
            "signal.\n"
            "PID is an integer; if negative it identifies a process "
            "group.\n",
            "\n"
            "SIZE is a number.  For TYPE in [doux], SIZE may also "
            "be C for\n"
            "sizeof(char), S for sizeof(short), I for sizeof(int) "
            "or L for\n"
            "sizeof(long).  If TYPE is f, SIZE may also be F for "
            "sizeof(float), D\n"
            "for sizeof(double) or L for sizeof(long double).\n",
            "\n"
            "SIZE may also be prefixed by one of the following "
            "modifying characters:\n"
            "'+' extend by, '-' reduce by, '<' at most, '>' at "
            "least,\n"
            "'/' round down to multiple of, '%' round up to "
            "multiple of.\n",
            "\n"
            "STYLE is one of:\n"
            "\n"
            "  a      number all lines\n"
            "  t      number only nonempty lines\n"
            "  n      number no lines\n"
            "  pBRE   number only lines that contain a match for "
            "the basic regular\n"
            "         expression, BRE\n",
            "\n"
            "Sending a %s signal to a running 'dd' process makes "
            "it\n"
            "print I/O statistics to standard error and then resume "
            "copying.\n"
            "\n"
            "Options are:\n"
            "\n",
            "\nSpecial characters:\n",
            "\n"
            "Special settings:\n"
            "   N             set the input and output speeds to N "
            "bauds\n",
            "\n"
            "The MODE argument of --cached can be: always, never, "
            "or default.\n"
            "'always' will use cached attributes if available, "
            "while\n"
            "'never' will try to synchronize with the latest "
            "attributes, and\n"
            "'default' will leave it up to the underlying file "
            "system.\n",
            "\n"
            "The TIME_STYLE argument can be full-iso, long-iso, "
            "iso, locale, or +FORMAT.\n"
            "FORMAT is interpreted like in date(1).  If FORMAT is "
            "FORMAT1<newline>FORMAT2,\n"
            "then FORMAT1 applies to non-recent files and FORMAT2 "
            "to recent files.\n"
            "TIME_STYLE prefixed with 'posix-' takes effect only "
            "outside the POSIX locale.\n"
            "Also the TIME_STYLE environment variable sets the "
            "default style to use.\n",
            "\n"
            "The WHEN argument defaults to 'always' and can also be "
            "'auto' or 'never'.\n",
            "\n"
            "The data are encoded as described for the %s alphabet "
            "in RFC 4648.\n"
            "When decoding, the input may contain newlines in "
            "addition to the bytes of\n"
            "the formal %s alphabet.  Use --ignore-garbage to "
            "attempt to recover\n"
            "from any other non-alphabet bytes in the encoded "
            "stream.\n",
            "\n"
            "The following five options are useful only when "
            "verifying checksums:\n"
            "      --ignore-missing  don't fail or report status "
            "for missing files\n"
            "      --quiet           don't print OK for each "
            "successfully verified file\n"
            "      --status          don't output anything, status "
            "code shows success\n"
            "      --strict          exit non-zero for improperly "
            "formatted checksum lines\n"
            "  -w, --warn            warn about improperly "
            "formatted checksum lines\n"
            "\n",
            "\n"
            "The following options modify how a hierarchy is "
            "traversed when the -R\n"
            "option is also specified.  If more than one is "
            "specified, only the final\n"
            "one takes effect.\n"
            "\n"
            "  -H                     if a command line argument is "
            "a symbolic link\n"
            "                         to a directory, traverse it\n"
            "  -L                     traverse every symbolic link "
            "to a directory\n"
            "                         encountered\n"
            "  -P                     do not traverse any symbolic "
            "links (default)\n"
            "\n",
            "\n"
            "The options below may be used to select which counts "
            "are printed, always in\n"
            "the following order: newline, word, character, byte, "
            "maximum line length.\n"
            "  -c, --bytes            print the byte counts\n"
            "  -m, --chars            print the character counts\n"
            "  -l, --lines            print the newline counts\n",
            "\nThe sums are computed as described in %s.\n",
            "\n"
            "The valid format sequences for files (without "
            "--file-system):\n"
            "\n"
            "  %a   permission bits in octal (note '#' and '0' "
            "printf flags)\n"
            "  %A   permission bits and file type in human readable "
            "form\n"
            "  %b   number of blocks allocated (see %B)\n"
            "  %B   the size in bytes of each block reported by %b\n"
            "  %C   SELinux security context string\n",
            "\n"
            "This install program copies files (often just "
            "compiled) into destination\n"
            "locations you choose.  If you want to download and "
            "install a ready-to-use\n"
            "package on a GNU/Linux system, you should instead be "
            "using a package manager\n"
            "like yum(1) or apt-get(1).\n"
            "\n"
            "In the first three forms, copy SOURCE to DEST or "
            "multiple SOURCE(s) to\n"
            "the existing DIRECTORY, while setting permission modes "
            "and owner/group.\n"
            "In the 4th form, create all components of the given "
            "DIRECTORY(ies).\n",
            "\n"
            "To remove a file whose name starts with a '-', for "
            "example '-foo',\n"
            "use one of these commands:\n"
            "  %s -- -foo\n"
            "\n"
            "  %s ./-foo\n",
            "\n"
            "Translation occurs if -d is not given and both SET1 "
            "and SET2 appear.\n"
            "-t may be used only when translating.  SET2 is "
            "extended to length of\n"
            "SET1 by repeating its last character as necessary.  "
            "Excess characters\n"
            "of SET2 are ignored.  Only [:lower:] and [:upper:] are "
            "guaranteed to\n"
            "expand in ascending order; used in SET2 while "
            "translating, they may\n"
            "only be used in pairs to specify case conversion.  -s "
            "uses the last\n"
            "specified SET, and occurs after translation or "
            "deletion.\n",
            "\nUNIT options:\n",
            "\n"
            "Unless -t CHAR is given, leading blanks separate "
            "fields and are ignored,\n"
            "else fields are separated by CHAR.  Any FIELD is a "
            "field number counted\n"
            "from 1.  FORMAT is one or more comma or blank "
            "separated specifications,\n"
            "each being 'FILENUM.FIELD' or '0'.  Default FORMAT "
            "outputs the join field,\n"
            "the remaining fields from FILE1, the remaining fields "
            "from FILE2, all\n"
            "separated by CHAR.  If FORMAT is the keyword 'auto', "
            "then the first\n"
            "line of each file determines the number of fields "
            "output for each line.\n"
            "\n"
            "Important: FILE1 and FILE2 must be sorted on the join "
            "fields.\n"
            "E.g., use \"sort -k 1b,1\" if 'join' has no options,\n"
            "or use \"join -t ''\" if 'sort' has no options.\n"
            "Note, comparisons honor the rules specified by "
            "'LC_COLLATE'.\n"
            "If the input is not sorted and some lines cannot be "
            "joined, a\n"
            "warning message will be given.\n",
            "\n"
            "Upon timeout, send the TERM signal to COMMAND, if no "
            "other SIGNAL specified.\n"
            "The TERM signal kills any process that does not block "
            "or catch that signal.\n"
            "It may be necessary to use the KILL signal, since this "
            "signal can't be caught.\n",
            "\n"
            "Use one, and only one of -b, -c or -f.  Each LIST is "
            "made up of one\n"
            "range, or many ranges separated by commas.  Selected "
            "input is written\n"
            "in the same order that it is read, and is written "
            "exactly once.\n",
            "\n"
            "Use: '%s --coreutils-prog=PROGRAM_NAME --help' for "
            "individual program help.\n",
            "\n"
            "Using -s ignores -L and -P.  Otherwise, the last "
            "option specified controls\n"
            "behavior when a TARGET is a symbolic link, defaulting "
            "to %s.\n",
            "\n"
            "Using color to distinguish file types is disabled both "
            "by default and\n"
            "with --color=never.  With --color=auto, ls emits color "
            "codes only when\n"
            "standard output is connected to a terminal.  The "
            "LS_COLORS environment\n"
            "variable can change the settings.  Use the dircolors "
            "command to set it.\n",
            "\n"
            "When --reflink[=always] is specified, perform a "
            "lightweight copy, where the\n"
            "data blocks are copied only when modified.  If this is "
            "not possible the copy\n"
            "fails, or if --reflink=auto is specified, fall back to "
            "a standard copy.\n"
            "Use --reflink=never to ensure a standard copy is "
            "performed.\n",
            "\n" "When FILE1 or FILE2 (not both) is -, read standard " "input.\n",
            "\n"
            "When decoding, the input may contain newlines in "
            "addition to the bytes of\n"
            "the formal alphabet.  Use --ignore-garbage to attempt "
            "to recover\n"
            "from any other non-alphabet bytes in the encoded "
            "stream.\n",
            "\n"
            "With no options, produce three-column output.  Column "
            "one contains\n"
            "lines unique to FILE1, column two contains lines "
            "unique to FILE2,\n"
            "and column three contains lines common to both "
            "files.\n",
            "\n"
            "Without any OPTION, print some useful set of "
            "identified information.\n",
            "\n"
            "Write an unambiguous representation, octal bytes by "
            "default,\n"
            "of FILE to standard output.  With more than one FILE "
            "argument,\n"
            "concatenate them in the listed order to form the "
            "input.\n",
            "                         (useful only on systems that "
            "can change the\n"
            "                         ownership of a symlink)\n",
            "               [blake2b|blake2s|blake2bp|blake2sp]\n",
            "               the selected algorithm and must be a " "multiple of 8\n",
            "      --all      print the number of installed "
            "processors\n"
            "      --ignore=N  if possible, exclude N processing "
            "units\n",
            "      --backup[=CONTROL]       make a backup of each "
            "existing destination file\n"
            "  -b                           like --backup but does "
            "not accept an argument\n"
            "  -f, --force                  do not prompt before "
            "overwriting\n"
            "  -i, --interactive            prompt before "
            "overwrite\n"
            "  -n, --no-clobber             do not overwrite an "
            "existing file\n"
            "If you specify more than one of -i, -f, -n, only the "
            "final one takes effect.\n",
            "      --backup[=CONTROL]      make a backup of each "
            "existing destination file\n"
            "  -b                          like --backup but does "
            "not accept an argument\n"
            "  -d, -F, --directory         allow the superuser to "
            "attempt to hard link\n"
            "                                directories (note: "
            "will probably fail due to\n"
            "                                system restrictions, "
            "even for the superuser)\n"
            "  -f, --force                 remove existing "
            "destination files\n",
            "      --backup[=CONTROL]  make a backup of each "
            "existing destination file\n"
            "  -b                  like --backup but does not "
            "accept an argument\n"
            "  -c                  (ignored)\n"
            "  -C, --compare       compare each pair of source and "
            "destination files, and\n"
            "                        in some cases, do not modify "
            "the destination at all\n"
            "  -d, --directory     treat all arguments as directory "
            "names; create all\n"
            "                        components of the specified "
            "directories\n",
            "      --base16          hex encoding (RFC4648 section " "8)\n",
            "      --base2lsbf       bit string with least "
            "significant bit (lsb) first\n",
            "      --base2msbf       bit string with most "
            "significant bit (msb) first\n",
            "      --base32          same as 'base32' program " "(RFC4648 section 6)\n",
            "      --base32hex       extended hex alphabet base32 "
            "(RFC4648 section 7)\n",
            "      --base64          same as 'base64' program " "(RFC4648 section 4)\n",
            "      --base64url       file- and url-safe base64 "
            "(RFC4648 section 5)\n",
            "      --batch-size=NMERGE   merge at most NMERGE "
            "inputs at once;\n"
            "                            for more use temp files\n",
            "      --block-signal[=SIG]    block delivery of SIG "
            "signal(s) to COMMAND\n",
            "      --block-size=SIZE      with -l, scale sizes by "
            "SIZE when printing them;\n"
            "                               e.g., '--block-size=M'; "
            "see SIZE format below\n",
            "      --cached=MODE     specify how to use cached "
            "attributes;\n"
            "                          useful on remote file "
            "systems. See MODE below\n",
            "      --complement        complement the set of "
            "selected bytes, characters\n"
            "                            or fields\n",
            "      --debug                annotate the parsed "
            "date,\n"
            "                              and warn about "
            "questionable usage to stderr\n",
            "      --debug               annotate the part of the "
            "line used to sort,\n"
            "                              and warn about "
            "questionable usage to stderr\n"
            "      --files0-from=F       read input from the files "
            "specified by\n"
            "                            NUL-terminated names in "
            "file F;\n"
            "                            If F is - then read names "
            "from standard input\n",
            "      --debug           indicate which implementation " "used\n",
            "      --debug          print warnings about invalid " "input\n",
            "      --default-signal[=SIG]  reset handling of SIG "
            "signal(s) to the default\n",
            "      --dereference      affect the referent of each "
            "symbolic link (this is\n"
            "                         the default), rather than the "
            "symbolic link itself\n"
            "  -h, --no-dereference   affect symbolic links instead "
            "of any referenced file\n",
            "      --field=FIELDS   replace the numbers in these "
            "input fields (default=1);\n"
            "                         see FIELDS below\n",
            "      --files0-from=F    read input from the files "
            "specified by\n"
            "                           NUL-terminated names in "
            "file F;\n"
            "                           If F is - then read names "
            "from standard input\n"
            "  -L, --max-line-length  print the maximum display "
            "width\n"
            "  -w, --words            print the word counts\n",
            "      --files0-from=F   summarize device usage of the\n"
            "                          NUL-terminated file names "
            "specified in file F;\n"
            "                          if F is -, then read names "
            "from standard input\n"
            "  -H                    equivalent to "
            "--dereference-args (-D)\n"
            "  -h, --human-readable  print sizes in human readable "
            "format (e.g., 1K 234M 2G)\n"
            "      --inodes          list inode usage information "
            "instead of block usage\n",
            "      --format=FORMAT  use printf style floating-point "
            "FORMAT;\n"
            "                         see FORMAT below for "
            "details\n",
            "      --from-unit=N    specify the input unit size "
            "(instead of the default 1)\n",
            "      --from=CURRENT_OWNER:CURRENT_GROUP\n"
            "                         change the owner and/or group "
            "of each file only if\n"
            "                         its current owner and/or "
            "group match those specified\n"
            "                         here.  Either may be omitted, "
            "in which case a match\n"
            "                         is not required for the "
            "omitted attribute\n",
            "      --from=UNIT      auto-scale input numbers to "
            "UNITs; default is 'none';\n"
            "                         see UNIT below\n",
            "      --group-directories-first\n"
            "                             group directories before "
            "files;\n"
            "                               can be augmented with a "
            "--sort option, but any\n"
            "                               use of --sort=none (-U) "
            "disables grouping\n",
            "      --group[=METHOD]  show all items, separating "
            "groups with an empty line;\n"
            "                          "
            "METHOD={separate(default),prepend,append,both}\n",
            "      --grouping       use locale-defined grouping of "
            "digits, e.g. 1,000,000\n"
            "                         (which means it has no effect "
            "in the C/POSIX locale)\n",
            "      --groups=G_LIST        specify supplementary "
            "groups as g1,g2,..,gN\n",
            "      --header[=N]     print (without converting) the "
            "first N header lines;\n"
            "                         N defaults to 1 if not "
            "specified\n",
            "      --hyperlink[=WHEN]     hyperlink file names " "WHEN\n",
            "      --ignore-signal[=SIG]   set handling of SIG "
            "signal(s) to do nothing\n",
            "      --indicator-style=WORD  append indicator with "
            "style WORD to entry names:\n"
            "                               none (default), slash "
            "(-p),\n"
            "                               file-type "
            "(--file-type), classify (-F)\n"
            "  -i, --inode                print the index number of "
            "each file\n"
            "  -I, --ignore=PATTERN       do not list implied "
            "entries matching shell PATTERN\n",
            "      --invalid=MODE   failure mode for invalid "
            "numbers: MODE can be:\n"
            "                         abort (default), fail, warn, "
            "ignore\n",
            "      --list-signal-handling  list non default signal "
            "handling to stderr\n",
            "      --lookup      attempt to canonicalize hostnames "
            "via DNS\n"
            "  -m                only hostname and user associated "
            "with stdin\n"
            "  -p, --process     print active processes spawned by "
            "init\n",
            "      --no-preserve-root  do not treat '/' specially\n"
            "      --preserve-root[=all]  do not remove '/' "
            "(default);\n"
            "                              with 'all', reject any "
            "command line argument\n"
            "                              on a separate device "
            "from its parent\n",
            "      --no-preserve-root  do not treat '/' specially "
            "(the default)\n"
            "      --preserve-root    fail to operate recursively "
            "on '/'\n",
            "      --no-preserve=ATTR_LIST  don't preserve the "
            "specified attributes\n"
            "      --parents                use full source file "
            "name under DIRECTORY\n",
            "      --one-file-system  when removing a hierarchy "
            "recursively, skip any\n"
            "                          directory that is on a file "
            "system different from\n"
            "                          that of the corresponding "
            "command line argument\n",
            "      --output-delimiter=STR  separate columns with " "STR\n",
            "      --output[=FIELD_LIST]  use the output format "
            "defined by FIELD_LIST,\n"
            "                               or print all fields if "
            "FIELD_LIST is omitted.\n"
            "  -P, --portability     use the POSIX output format\n"
            "      --sync            invoke sync before getting "
            "usage info\n",
            "      --padding=N      pad the output to N characters; "
            "positive N will\n"
            "                         right-align; negative N will "
            "left-align;\n"
            "                         padding is ignored if the "
            "output is wider than N;\n"
            "                         the default is to "
            "automatically pad if a whitespace\n"
            "                         is found\n",
            "      --pid=PID            with -f, terminate after "
            "process ID, PID dies\n"
            "  -q, --quiet, --silent    never output headers giving "
            "file names\n"
            "      --retry              keep trying to open a file "
            "if it is inaccessible\n",
            "      --preserve-context  preserve SELinux security "
            "context\n"
            "  -Z                      set SELinux security context "
            "of destination\n"
            "                            file and each created "
            "directory to default type\n"
            "      --context[=CTX]     like -Z, or if CTX is "
            "specified then set the\n"
            "                            SELinux or SMACK security "
            "context to CTX\n",
            "      --preserve-status\n"
            "                 exit with the same status as COMMAND, "
            "even when the\n"
            "                   command times out\n"
            "      --foreground\n"
            "                 when not running timeout directly "
            "from a shell prompt,\n"
            "                   allow COMMAND to read from the TTY "
            "and get TTY signals;\n"
            "                   in this mode, children of COMMAND "
            "will not be timed out\n"
            "  -k, --kill-after=DURATION\n"
            "                 also send a KILL signal if COMMAND is "
            "still running\n"
            "                   this long after the initial signal "
            "was sent\n"
            "  -s, --signal=SIGNAL\n"
            "                 specify the signal to be sent on "
            "timeout;\n"
            "                   SIGNAL may be a name like 'HUP' or "
            "a number;\n"
            "                   see 'kill -l' for a list of "
            "signals\n",
            "      --reference=RFILE  use RFILE's group rather than "
            "specifying a\n"
            "                         GROUP value\n",
            "      --reference=RFILE  use RFILE's mode instead of " "MODE values\n",
            "      --reference=RFILE  use RFILE's owner and group "
            "rather than\n"
            "                         specifying OWNER:GROUP "
            "values\n",
            "      --reference=RFILE  use RFILE's security context "
            "rather than specifying\n"
            "                         a CONTEXT value\n",
            "      --rfc-3339=FMT         output date/time in RFC "
            "3339 format.\n"
            "                               FMT='date', 'seconds', "
            "or 'ns'\n"
            "                               for date and time to "
            "the indicated precision.\n"
            "                               Example: 2006-08-14 "
            "02:34:56-06:00\n",
            "      --round=METHOD   use METHOD for rounding when "
            "scaling; METHOD can be:\n"
            "                         up, down, from-zero "
            "(default), towards-zero, nearest\n",
            "      --skip-chdir           do not change working " "directory to %s\n",
            "      --sort=WORD             sort according to WORD:\n"
            "                                general-numeric -g, "
            "human-numeric -h, month -M,\n"
            "                                numeric -n, random -R, "
            "version -V\n"
            "  -V, --version-sort          natural sort of "
            "(version) numbers within text\n"
            "\n",
            "      --sparse=WHEN            control creation of "
            "sparse files. See below\n"
            "      --strip-trailing-slashes  remove any trailing "
            "slashes from each SOURCE\n"
            "                                 argument\n",
            "      --strip-trailing-slashes  remove any trailing "
            "slashes from each SOURCE\n"
            "                                 argument\n"
            "  -S, --suffix=SUFFIX          override the usual "
            "backup suffix\n",
            "      --suffix=SUFF   append SUFF to TEMPLATE; SUFF "
            "must not contain a slash.\n"
            "                        This option is implied if "
            "TEMPLATE does not end in X\n",
            "      --suffix=SUFFIX  add SUFFIX to output numbers, "
            "and accept optional\n"
            "                         SUFFIX in input numbers\n",
            "      --suppress-matched     suppress the lines " "matching PATTERN\n",
            "      --tag             create a BSD-style checksum\n",
            "      --tag             create a BSD-style checksum " "(the default)\n",
            "      --time-style=TIME_STYLE  time/date format with "
            "-l; see TIME_STYLE below\n",
            "      --to-unit=N      the output unit size (instead "
            "of the default 1)\n",
            "      --to=UNIT        auto-scale output numbers to "
            "UNITs; see UNIT below\n",
            "      --total             output a summary\n",
            "      --total           elide all entries "
            "insignificant to available space,\n"
            "                          and produce a grand total\n",
            "      --untagged        create a reversed style "
            "checksum, without digest type\n",
            "      --userspec=USER:GROUP  specify user and group "
            "(ID or name) to use\n",
            "      --verbose           print a diagnostic just "
            "before each\n"
            "                            output file is opened\n",
            "      --z85             ascii85-like encoding (ZeroMQ "
            "spec:32/Z85);\n"
            "                        when encoding, input length "
            "must be a multiple of 4;\n"
            "                        when decoding, input length "
            "must be a multiple of 5\n",
            "   [-]cstopb     use two stop bits per character (one "
            "with '-')\n"
            "   [-]hup        send a hangup signal when the last "
            "process closes the tty\n"
            "   [-]hupcl      same as [-]hup\n"
            "   [-]parenb     generate parity bit in output and "
            "expect parity bit in input\n"
            "   [-]parodd     set odd parity (or even parity with "
            "'-')\n",
            "   [-]echo       echo input characters\n",
            "   [-]echoe      same as [-]crterase\n"
            "   [-]echok      echo a newline after a kill "
            "character\n",
            "   [-]echonl     echo newline even if not echoing " "other characters\n",
            "   [-]icanon     enable special characters: %s\n"
            "   [-]iexten     enable non-POSIX special characters\n",
            "   [-]inlcr      translate newline to carriage return\n"
            "   [-]inpck      enable input parity checking\n"
            "   [-]istrip     clear high (8th) bit of input "
            "characters\n",
            "   [-]isig       enable interrupt, quit, and suspend "
            "special characters\n"
            "   [-]noflsh     disable flushing after interrupt and "
            "quit special characters\n",
            "   [-]ixoff      enable sending of start/stop "
            "characters\n"
            "   [-]ixon       enable XON/XOFF flow control\n"
            "   [-]parmrk     mark parity errors (with a "
            "255-0-character sequence)\n"
            "   [-]tandem     same as [-]ixoff\n",
            "   [-]opost      postprocess output\n",
            "   cbreak        same as -icanon\n" "   -cbreak       same as icanon\n",
            "   cooked        same as brkint ignpar istrip icrnl "
            "ixon opost isig\n"
            "                 icanon, eof and eol characters to "
            "their default values\n"
            "   -cooked       same as raw\n",
            "   crt           same as %s\n",
            "   csN           set character size to N bits, N in " "[5..8]\n",
            "   dec           same as %s intr ^c erase 0177\n"
            "                 kill ^u\n",
            "   ek            erase and kill characters to their "
            "default values\n"
            "   evenp         same as parenb -parodd cs7\n"
            "   -evenp        same as -parenb cs8\n",
            "   eof CHAR      CHAR will send an end of file "
            "(terminate the input)\n"
            "   eol CHAR      CHAR will end the line\n",
            "   erase CHAR    CHAR will erase the last character "
            "typed\n"
            "   intr CHAR     CHAR will send an interrupt signal\n"
            "   kill CHAR     CHAR will erase the current line\n",
            "   ispeed N      set the input speed to N\n",
            "   litout        same as -parenb -istrip -opost cs8\n"
            "   -litout       same as parenb istrip opost cs7\n",
            "   min N         with -icanon, set N characters "
            "minimum for a completed read\n"
            "   ospeed N      set the output speed to N\n",
            "   nl            same as %s\n" "   -nl           same as %s\n",
            "   oddp          same as parenb parodd cs7\n"
            "   -oddp         same as -parenb cs8\n"
            "   [-]parity     same as [-]evenp\n"
            "   pass8         same as -parenb -istrip cs8\n"
            "   -pass8        same as parenb istrip cs7\n",
            "   quit CHAR     CHAR will send a quit signal\n",
            "   raw           same as -ignbrk -brkint -ignpar "
            "-parmrk -inpck -istrip\n"
            "                 -inlcr -igncr -icrnl -ixon -ixoff "
            "-icanon -opost\n"
            "                 -isig%s min 1 time 0\n"
            "   -raw          same as cooked\n",
            "   sane          same as cread -ignbrk brkint -inlcr "
            "-igncr icrnl\n"
            "                 icanon iexten echo echoe echok "
            "-echonl -noflsh\n"
            "                 %s\n"
            "                 %s\n"
            "                 %s,\n"
            "                 all special characters to their "
            "default values\n",
            "   speed         print the terminal speed\n"
            "   time N        with -icanon, set read timeout of N "
            "tenths of a second\n",
            "   start CHAR    CHAR will restart the output after "
            "stopping it\n"
            "   stop CHAR     CHAR will stop the output\n"
            "   susp CHAR     CHAR will send a terminal stop "
            "signal\n",
            "  %%      a single %\n"
            "  %b      ARGUMENT as a string with '\\' escapes "
            "interpreted,\n"
            "          except that octal escapes are of the form "
            "\\0 or \\0NNN\n"
            "  %q      ARGUMENT is printed in a format that can be "
            "reused as shell input,\n"
            "          escaping non-printable characters with the "
            "proposed POSIX $'' syntax.\n"
            "\n"
            "and all C format specifications ending with one of "
            "diouxXfeEgGcs, with\n"
            "ARGUMENTs converted to proper type first.  Variable "
            "widths are handled.\n",
            "  %A   locale's full weekday name (e.g., Sunday)\n"
            "  %b   locale's abbreviated month name (e.g., Jan)\n"
            "  %B   locale's full month name (e.g., January)\n"
            "  %c   locale's date and time (e.g., Thu Mar  3 "
            "23:05:25 2005)\n",
            "  %C   century; like %Y, except omit last two digits "
            "(e.g., 20)\n"
            "  %d   day of month (e.g., 01)\n"
            "  %D   date; same as %m/%d/%y\n"
            "  %e   day of month, space padded; same as %_d\n",
            "  %F   full date; like %+4Y-%m-%d\n"
            "  %g   last two digits of year of ISO week number (see "
            "%G)\n"
            "  %G   year of ISO week number (see %V); normally "
            "useful only with %V\n",
            "  %S   second (00..60)\n"
            "  %t   a tab\n"
            "  %T   time; same as %H:%M:%S\n"
            "  %u   day of week (1..7); 1 is Monday\n",
            "  %U   week number of year, with Sunday as first day "
            "of week (00..53)\n"
            "  %V   ISO week number, with Monday as first day of "
            "week (01..53)\n"
            "  %w   day of week (0..6); 0 is Sunday\n"
            "  %W   week number of year, with Monday as first day "
            "of week (00..53)\n",
            "  %d   device number in decimal (st_dev)\n"
            "  %D   device number in hex (st_dev)\n"
            "  %Hd  major device number in decimal\n"
            "  %Ld  minor device number in decimal\n"
            "  %f   raw mode in hex\n"
            "  %F   file type\n"
            "  %g   group ID of owner\n"
            "  %G   group name of owner\n",
            "  %h   number of hard links\n"
            "  %i   inode number\n"
            "  %m   mount point\n"
            "  %n   file name\n"
            "  %N   quoted file name with dereference if symbolic "
            "link\n"
            "  %o   optimal I/O transfer size hint\n"
            "  %s   total size, in bytes\n"
            "  %r   device type in decimal (st_rdev)\n"
            "  %R   device type in hex (st_rdev)\n"
            "  %Hr  major device type in decimal, for "
            "character/block device special files\n"
            "  %Lr  minor device type in decimal, for "
            "character/block device special files\n"
            "  %t   major device type in hex, for character/block "
            "device special files\n"
            "  %T   minor device type in hex, for character/block "
            "device special files\n",
            "  %h   same as %b\n"
            "  %H   hour (00..23)\n"
            "  %I   hour (01..12)\n"
            "  %j   day of year (001..366)\n",
            "  %i   file system ID in hex\n"
            "  %l   maximum length of filenames\n"
            "  %n   file name\n"
            "  %s   block size (for faster transfers)\n"
            "  %S   fundamental block size (for block counts)\n"
            "  %t   file system type in hex\n"
            "  %T   file system type in human readable form\n",
            "  %k   hour, space padded ( 0..23); same as %_H\n"
            "  %l   hour, space padded ( 1..12); same as %_I\n"
            "  %m   month (01..12)\n"
            "  %M   minute (00..59)\n",
            "  %n   a newline\n"
            "  %N   nanoseconds (000000000..999999999)\n"
            "  %p   locale's equivalent of either AM or PM; blank "
            "if not known\n"
            "  %P   like %p, but lower case\n"
            "  %q   quarter of year (1..4)\n"
            "  %r   locale's 12-hour clock time (e.g., 11:11:04 "
            "PM)\n"
            "  %R   24-hour hour and minute; same as %H:%M\n"
            "  %s   seconds since the Epoch (1970-01-01 00:00 "
            "UTC)\n",
            "  %u   user ID of owner\n"
            "  %U   user name of owner\n"
            "  %w   time of file birth, human-readable; - if "
            "unknown\n"
            "  %W   time of file birth, seconds since Epoch; 0 if "
            "unknown\n"
            "  %x   time of last access, human-readable\n"
            "  %X   time of last access, seconds since Epoch\n"
            "  %y   time of last data modification, human-readable\n"
            "  %Y   time of last data modification, seconds since "
            "Epoch\n"
            "  %z   time of last status change, human-readable\n"
            "  %Z   time of last status change, seconds since "
            "Epoch\n"
            "\n",
            "  %x   locale's date representation (e.g., 12/31/99)\n"
            "  %X   locale's time representation (e.g., 23:13:48)\n"
            "  %y   last two digits of year (00..99)\n"
            "  %Y   year\n",
            "  %z   +hhmm numeric time zone (e.g., -0400)\n"
            "  %:z  +hh:mm numeric time zone (e.g., -04:00)\n"
            "  %::z  +hh:mm:ss numeric time zone (e.g., -04:00:00)\n"
            "  %:::z  numeric time zone with : to necessary "
            "precision (e.g., -04, +05:30)\n"
            "  %Z   alphabetic time zone abbreviation (e.g., EDT)\n"
            "\n"
            "By default, date pads numeric fields with zeroes.\n",
            "  + TOKEN                    interpret TOKEN as a "
            "string, even if it is a\n"
            "                               keyword like 'match' or "
            "an operator like '/'\n"
            "\n"
            "  ( EXPRESSION )             value of EXPRESSION\n",
            "  +FIRST_PAGE[:LAST_PAGE], "
            "--pages=FIRST_PAGE[:LAST_PAGE]\n"
            "                    begin [stop] printing with page "
            "FIRST_[LAST_]PAGE\n"
            "  -COLUMN, --columns=COLUMN\n"
            "                    output COLUMN columns and print "
            "columns down,\n"
            "                    unless -a is used. Balance number "
            "of lines in the\n"
            "                    columns on each page\n",
            "  --help       display this help and exit\n",
            "  --resolution               output the available "
            "resolution of timestamps\n"
            "                               Example: 0.000000001\n",
            "  --tag        create a BSD-style checksum\n",
            "  -0, --null            end each output line with NUL, "
            "not newline\n"
            "  -a, --all             write counts for all files, "
            "not just directories\n"
            "      --apparent-size   print apparent sizes rather "
            "than device usage; although\n"
            "                          the apparent size is usually "
            "smaller, it may be\n"
            "                          larger due to holes in "
            "('sparse') files, internal\n"
            "                          fragmentation, indirect "
            "blocks, and the like\n",
            "  -0, --null     end each output line with NUL, not " "newline\n",
            "  -A, --address-radix=RADIX   output format for file "
            "offsets; RADIX is one\n"
            "                                of [doxn], for "
            "Decimal, Octal, Hex or None\n"
            "      --endian={big|little}   swap input bytes "
            "according the specified order\n"
            "  -j, --skip-bytes=BYTES      skip BYTES input bytes "
            "first\n",
            "  -A, --auto-reference           output automatically "
            "generated references\n"
            "  -G, --traditional              behave more like "
            "System V 'ptx'\n",
            "  -B, --block-size=SIZE  scale sizes by SIZE before "
            "printing them; e.g.,\n"
            "                           '-BM' prints sizes in units "
            "of 1,048,576 bytes;\n"
            "                           see SIZE format below\n"
            "  -b, --bytes           equivalent to '--apparent-size "
            "--block-size=1'\n"
            "  -c, --total           produce a grand total\n"
            "  -D, --dereference-args  dereference only symlinks "
            "that are listed on the\n"
            "                          command line\n"
            "  -d, --max-depth=N     print the total for a "
            "directory (or file, with --all)\n"
            "                          only if it is N or fewer "
            "levels below the command\n"
            "                          line argument;  "
            "--max-depth=0 is the same as\n"
            "                          --summarize\n",
            "  -B, --ignore-backups       do not list implied "
            "entries ending with ~\n"
            "  -c                         with -lt: sort by, and "
            "show, ctime (time of last\n"
            "                               modification of file "
            "status information);\n"
            "                               with -l: show ctime and "
            "sort by name;\n"
            "                               otherwise: sort by "
            "ctime, newest first\n",
            "  -C                         list entries by columns\n"
            "      --color[=WHEN]         color the output WHEN; "
            "more info below\n"
            "  -d, --directory            list directories "
            "themselves, not their contents\n"
            "  -D, --dired                generate output designed "
            "for Emacs' dired mode\n",
            "  -C, --chdir=DIR      change working directory to " "DIR\n",
            "  -D                    print all duplicate lines\n"
            "      --all-repeated[=METHOD]  like -D, but allow "
            "separating groups\n"
            "                                 with an empty line;\n"
            "                                 "
            "METHOD={none(default),prepend,separate}\n",
            "  -D                  create all leading components of "
            "DEST except the last,\n"
            "                        or all components of "
            "--target-directory,\n"
            "                        then copy SOURCE to DEST\n"
            "  -g, --group=GROUP   set group ownership, instead of "
            "process' current group\n"
            "  -m, --mode=MODE     set permission mode (as in "
            "chmod), instead of rwxr-xr-x\n"
            "  -o, --owner=OWNER   set ownership (super-user "
            "only)\n",
            "  -D, --date-format=FORMAT\n"
            "                    use FORMAT for the header date\n"
            "  -e[CHAR[WIDTH]], --expand-tabs[=CHAR[WIDTH]]\n"
            "                    expand input CHARs (TABs) to tab "
            "WIDTH (8)\n"
            "  -F, -f, --form-feed\n"
            "                    use form feeds instead of newlines "
            "to separate pages\n"
            "                    (by a 3-line page header with -F "
            "or a 5-line header\n"
            "                    and trailer without -F)\n",
            "  -F, --flag-truncation=STRING   use STRING for "
            "flagging line truncations.\n"
            "                                 The default is '/'\n",
            "  -G, --no-group             in a long listing, don't "
            "print group names\n",
            "  -H, --dereference-command-line\n"
            "                             follow symbolic links "
            "listed on the command line\n"
            "      --dereference-command-line-symlink-to-dir\n"
            "                             follow each command line "
            "symbolic link\n"
            "                               that points to a "
            "directory\n"
            "      --hide=PATTERN         do not list implied "
            "entries matching shell PATTERN\n"
            "                               (overridden by -a or "
            "-A)\n",
            "  -I                    prompt once before removing "
            "more than three files, or\n"
            "                          when removing recursively; "
            "less intrusive than -i,\n"
            "                          while still giving "
            "protection against most mistakes\n"
            "      --interactive[=WHEN]  prompt according to WHEN: "
            "never, once (-I), or\n"
            "                          always (-i); without WHEN, "
            "prompt always\n",
            "  -I[FMT], --iso-8601[=FMT]  output date/time in ISO "
            "8601 format.\n"
            "                               FMT='date' for date "
            "only (the default),\n"
            "                               'hours', 'minutes', "
            "'seconds', or 'ns'\n"
            "                               for date and time to "
            "the indicated precision.\n"
            "                               Example: "
            "2006-08-14T02:34:56-06:00\n",
            "  -L FILE     FILE exists and is a symbolic link (same "
            "as -h)\n"
            "  -N FILE     FILE exists and has been modified since "
            "it was last read\n"
            "  -O FILE     FILE exists and is owned by the "
            "effective user ID\n"
            "  -p FILE     FILE exists and is a named pipe\n"
            "  -r FILE     FILE exists and read permission is "
            "granted\n"
            "  -s FILE     FILE exists and has a size greater than "
            "zero\n",
            "  -L, --dereference     follow links\n"
            "  -f, --file-system     display file system status "
            "instead of file status\n",
            "  -L, --logical   use PWD from environment, even if it "
            "contains symlinks\n"
            "  -P, --physical  avoid all symlinks\n",
            "  -M, --macro-name=STRING        macro name to use "
            "instead of 'xx'\n"
            "  -O, --format=roff              generate output as "
            "roff directives\n"
            "  -R, --right-side-refs          put references at "
            "right, not counted in -w\n"
            "  -S, --sentence-regexp=REGEXP   for end of lines or "
            "end of sentences\n"
            "  -T, --format=tex               generate output as "
            "TeX directives\n",
            "  -N, --read-bytes=BYTES      limit dump to BYTES "
            "input bytes\n"
            "  -S BYTES, --strings[=BYTES]  output strings of at "
            "least BYTES graphic chars;\n"
            "                                3 is implied when "
            "BYTES is not specified\n"
            "  -t, --format=TYPE           select output format or "
            "formats\n"
            "  -v, --output-duplicates     do not use * to mark "
            "line suppression\n"
            "  -w[BYTES], --width[=BYTES]  output BYTES bytes per "
            "output line;\n"
            "                                32 is implied when "
            "BYTES is not specified\n"
            "      --traditional           accept arguments in "
            "third form above\n",
            "  -P, --no-dereference  don't follow any symbolic "
            "links (this is the default)\n"
            "  -S, --separate-dirs   for directories do not include "
            "size of subdirectories\n"
            "      --si              like -h, but use powers of "
            "1000 not 1024\n"
            "  -s, --summarize       display only a total for each "
            "argument\n",
            "  -R, --recursive        change files and directories " "recursively\n",
            "  -R, --recursive        operate on files and "
            "directories recursively\n",
            "  -R, --rfc-email            output date and time in "
            "RFC 5322 format.\n"
            "                               Example: Mon, 14 Aug "
            "2006 02:34:56 -0600\n",
            "  -R, -r, --recursive          copy directories "
            "recursively\n"
            "      --reflink[=WHEN]         control clone/CoW "
            "copies. See below\n"
            "      --remove-destination     remove each existing "
            "destination file before\n"
            "                                 attempting to open it "
            "(contrast with --force)\n",
            "  -S                         sort by file size, "
            "largest first\n"
            "      --sort=WORD            sort by WORD instead of "
            "name: none (-U), size (-S),\n"
            "                               time (-t), version "
            "(-v), extension (-X), width\n"
            "      --time=WORD            change the default of "
            "using modification times;\n"
            "                               access time (-u): "
            "atime, access, use;\n"
            "                               change time (-c): "
            "ctime, status;\n"
            "                               birth time: birth, "
            "creation;\n"
            "                             with -l, WORD determines "
            "which time to show;\n"
            "                             with --sort=time, sort by "
            "WORD (newest first)\n",
            "  -S FILE     FILE exists and is a socket\n"
            "  -t FD       file descriptor FD is opened on a "
            "terminal\n"
            "  -u FILE     FILE exists and its set-user-ID bit is "
            "set\n"
            "  -w FILE     FILE exists and write permission is "
            "granted\n"
            "  -x FILE     FILE exists and execute (or search) "
            "permission is granted\n",
            "  -S, --split-string=S  process and split S into "
            "separate arguments;\n"
            "                        used to pass multiple "
            "arguments on shebang lines\n",
            "  -S, --suffix=SUFFIX         override the usual "
            "backup suffix\n"
            "  -t, --target-directory=DIRECTORY  specify the "
            "DIRECTORY in which to create\n"
            "                                the links\n"
            "  -T, --no-target-directory   treat LINK_NAME as a "
            "normal file always\n"
            "  -v, --verbose               print name of each "
            "linked file\n",
            "  -S[STRING], --sep-string[=STRING]\n"
            "                    separate columns by STRING,\n"
            "                    without -S: Default separator "
            "<TAB> with -J and <space>\n"
            '                    otherwise (same as -S" "), no '
            "effect on column options\n",
            "  -T, --omit-pagination\n"
            "                    omit page headers and trailers, "
            "eliminate any pagination\n"
            "                    by form feeds set in input files\n"
            "  -v, --show-nonprinting\n"
            "                    use octal backslash notation\n"
            "  -w, --width=PAGE_WIDTH\n"
            "                    set page width to PAGE_WIDTH (72) "
            "characters for\n"
            "                    multiple text-column output only, "
            "-s[char] turns off (72)\n",
            "  -T, -w, --mesg    add user's message status as +, - "
            "or ?\n"
            "  -u, --users       list users logged in\n"
            "      --message     same as -T\n"
            "      --writable    same as -T\n",
            "  -W, --page-width=PAGE_WIDTH\n"
            "                    set page width to PAGE_WIDTH (72) "
            "characters always,\n"
            "                    truncate lines, except -J option "
            "is set, no interference\n"
            "                    with -S or -s\n",
            "  -W, --word-regexp=REGEXP       use REGEXP to match "
            "each keyword\n"
            "  -b, --break-file=FILE          word break characters "
            "in this FILE\n"
            "  -f, --ignore-case              fold lower case to "
            "upper case for sorting\n"
            "  -g, --gap-size=NUMBER          gap size in columns "
            "between output fields\n"
            "  -i, --ignore-file=FILE         read ignore word list "
            "from FILE\n"
            "  -o, --only-file=FILE           read only word list "
            "from this FILE\n",
            "  -X, --exclude-from=FILE  exclude files that match "
            "any pattern in FILE\n"
            "      --exclude=PATTERN    exclude files that match "
            "PATTERN\n"
            "  -x, --one-file-system    skip directories on "
            "different file systems\n",
            "  -Z                           set SELinux security "
            "context of destination\n"
            "                                 file to default type\n"
            "      --context[=CTX]          like -Z, or if CTX is "
            "specified then set the\n"
            "                                 SELinux or SMACK "
            "security context to CTX\n",
            "  -Z                   set SELinux security context of "
            "each created directory\n"
            "                         to the default type\n"
            "      --context[=CTX]  like -Z, or if CTX is specified "
            "then set the SELinux\n"
            "                         or SMACK security context to "
            "CTX\n",
            "  -Z                   set the SELinux security "
            "context to default type\n"
            "      --context[=CTX]  like -Z, or if CTX is specified "
            "then set the SELinux\n"
            "                         or SMACK security context to "
            "CTX\n",
            "  -a                     change only the access time\n"
            "  -c, --no-create        do not create any files\n"
            "  -d, --date=STRING      parse STRING and use it "
            "instead of current time\n"
            "  -f                     (ignored)\n",
            "  -a             ignore, for compatibility with other "
            "versions\n"
            "  -Z, --context  print only the security context of "
            "the process\n"
            "  -g, --group    print only the effective group ID\n"
            "  -G, --groups   print all group IDs\n"
            "  -n, --name     print a name instead of a number, for "
            "-ugG\n"
            "  -r, --real     print the real ID instead of the "
            "effective ID, with -ugG\n"
            "  -u, --user     print only the effective user ID\n"
            "  -z, --zero     delimit entries with NUL characters, "
            "not whitespace;\n"
            "                   not permitted in default format\n",
            "  -a <algo>    hash algorithm (blake2b is default): \n",
            "  -a, --across      print columns across rather than "
            "down, used together\n"
            "                    with -COLUMN\n"
            "  -c, --show-control-chars\n"
            "                    use hat notation (^G) and octal "
            "backslash notation\n"
            "  -d, --double-space\n"
            "                    double space the output\n",
            "  -a, --algorithm=TYPE  select the digest type to "
            "use.  See DIGEST below.\n",
            "  -a, --all                  do not ignore entries "
            "starting with .\n"
            "  -A, --almost-all           do not list implied . and "
            "..\n"
            "      --author               with -l, print the author "
            "of each file\n"
            "  -b, --escape               print C-style escapes for "
            "nongraphic characters\n",
            "  -a, --all             include pseudo, duplicate, "
            "inaccessible file systems\n"
            "  -B, --block-size=SIZE  scale sizes by SIZE before "
            "printing them; e.g.,\n"
            "                           '-BM' prints sizes in units "
            "of 1,048,576 bytes;\n"
            "                           see SIZE format below\n"
            "  -h, --human-readable  print sizes in powers of 1024 "
            "(e.g., 1023M)\n"
            "  -H, --si              print sizes in powers of 1000 "
            "(e.g., 1.1G)\n",
            "  -a, --all          print all current settings in "
            "human-readable form\n"
            "  -g, --save         print all current settings in a "
            "stty-readable form\n"
            "  -F, --file=DEVICE  open and use the specified DEVICE "
            "instead of stdin\n",
            "  -a, --all        convert all blanks, instead of just "
            "initial blanks\n"
            "      --first-only  convert only leading sequences of "
            "blanks (overrides -a)\n"
            "  -t, --tabs=N     have tabs N characters apart "
            "instead of 8 (enables -a)\n",
            "  -a, --archive                same as -dR "
            "--preserve=all\n"
            "      --attributes-only        don't copy the file "
            "data, just the attributes\n"
            "      --backup[=CONTROL]       make a backup of each "
            "existing destination file\n"
            "  -b                           like --backup but does "
            "not accept an argument\n"
            "      --copy-contents          copy contents of "
            "special files when recursive\n"
            "  -d                           same as "
            "--no-dereference --preserve=links\n",
            "  -a, --multiple       support multiple arguments and "
            "treat each as a NAME\n"
            "  -s, --suffix=SUFFIX  remove a trailing SUFFIX; "
            "implies -a\n"
            "  -z, --zero           end each output line with NUL, "
            "not newline\n",
            "  -a, --suffix-length=N   generate suffixes of length "
            "N (default %d)\n"
            "      --additional-suffix=SUFFIX  append an additional "
            "SUFFIX to file names\n"
            "  -b, --bytes=SIZE        put SIZE bytes per output "
            "file\n"
            "  -C, --line-bytes=SIZE   put at most SIZE bytes of "
            "records per output file\n"
            "  -d                      use numeric suffixes "
            "starting at 0, not alphabetic\n"
            "      --numeric-suffixes[=FROM]  same as -d, but allow "
            "setting the start value\n"
            "  -x                      use hex suffixes starting at "
            "0, not alphabetic\n"
            "      --hex-suffixes[=FROM]  same as -x, but allow "
            "setting the start value\n"
            "  -e, --elide-empty-files  do not generate empty "
            "output files with '-n'\n"
            "      --filter=COMMAND    write to shell COMMAND; file "
            "name is $FILE\n"
            "  -l, --lines=NUMBER      put NUMBER lines/records per "
            "output file\n"
            "  -n, --number=CHUNKS     generate CHUNKS output "
            "files; see explanation below\n"
            "  -t, --separator=SEP     use SEP instead of newline "
            "as the record separator;\n"
            "                            '\\0' (zero) specifies the "
            "NUL character\n"
            "  -u, --unbuffered        immediately copy input to "
            "output with '-n r/...'\n",
            "  -b, --before             attach the separator before "
            "instead of after\n"
            "  -r, --regex              interpret the separator as "
            "a regular expression\n"
            "  -s, --separator=STRING   use STRING as the separator "
            "instead of newline\n",
            "  -b, --binary          read in binary mode\n",
            "  -b, --binary          read in binary mode (default "
            "unless reading tty stdin)\n",
            "  -b, --body-numbering=STYLE      use STYLE for "
            "numbering body lines\n"
            "  -d, --section-delimiter=CC      use CC for logical "
            "page delimiters\n"
            "  -f, --footer-numbering=STYLE    use STYLE for "
            "numbering footer lines\n",
            "  -b, --bytes         count bytes rather than columns\n"
            "  -s, --spaces        break at spaces\n"
            "  -w, --width=WIDTH   use WIDTH columns instead of "
            "80\n",
            "  -b, --bytes=LIST        select only these bytes\n"
            "  -c, --characters=LIST   select only these "
            "characters\n"
            "  -d, --delimiter=DELIM   use DELIM instead of TAB for "
            "field delimiter\n",
            "  -b, --ignore-leading-blanks  ignore leading blanks\n"
            "  -d, --dictionary-order      consider only blanks and "
            "alphanumeric characters\n"
            "  -f, --ignore-case           fold lower case to upper "
            "case characters\n",
            "  -b, --suffix-format=FORMAT  use sprintf FORMAT "
            "instead of %02d\n"
            "  -f, --prefix=PREFIX        use PREFIX instead of "
            "'xx'\n"
            "  -k, --keep-files           do not remove output "
            "files on errors\n",
            "  -c  --format=FORMAT   use the specified FORMAT "
            "instead of the default;\n"
            "                          output a newline after each "
            "use of FORMAT\n"
            "      --printf=FORMAT   like --format, but interpret "
            "backslash escapes,\n"
            "                          and do not output a "
            "mandatory trailing newline;\n"
            "                          if you want a newline, "
            "include \\n in FORMAT\n"
            "  -t, --terse           print the information in terse "
            "form\n",
            "  -c, --bytes=[+]NUM       output the last NUM bytes; "
            "or use -c +NUM to\n"
            "                             output starting with byte "
            "NUM of each file\n",
            "  -c, --bytes=[-]NUM       print the first NUM bytes "
            "of each file;\n"
            "                             with the leading '-', "
            "print all but the last\n"
            "                             NUM bytes of each file\n"
            "  -n, --lines=[-]NUM       print the first NUM lines "
            "instead of the first %d;\n"
            "                             with the leading '-', "
            "print all but the last\n"
            "                             NUM lines of each file\n",
            "  -c, --changes          like verbose but report only "
            "when a change is made\n"
            "  -f, --silent, --quiet  suppress most error messages\n"
            "  -v, --verbose          output a diagnostic for every "
            "file processed\n",
            "  -c, --check           read checksums from the FILEs " "and check them\n",
            "  -c, --check, --check=diagnose-first  check for "
            "sorted input; do not sort\n"
            "  -C, --check=quiet, --check=silent  like -c, but do "
            "not report first bad line\n"
            "      --compress-program=PROG  compress temporaries "
            "with PROG;\n"
            "                              decompress them with "
            "PROG -d\n",
            "  -c, --count           prefix lines by the number of "
            "occurrences\n"
            "  -d, --repeated        only print duplicate lines, "
            "one for each group\n",
            "  -c, --crown-margin        preserve indentation of "
            "first two lines\n"
            "  -p, --prefix=STRING       reformat only lines "
            "beginning with STRING,\n"
            "                              reattaching the prefix "
            "to reformatted lines\n"
            "  -s, --split-only          split long lines, but do "
            "not refill\n",
            "  -c, --no-create        do not create any files\n",
            "  -d, --data             sync only file data, no " "unneeded metadata\n",
            "  -d, --date=STRING          display time described by "
            "STRING, not 'now'\n",
            "  -d, --decode          decode data\n"
            "  -i, --ignore-garbage  when decoding, ignore "
            "non-alphabet characters\n"
            "  -w, --wrap=COLS       wrap encoded lines after COLS "
            "character (default 76).\n"
            "                          Use 0 to disable line "
            "wrapping\n",
            "  -d, --delimiter=X    use X instead of whitespace for "
            "field delimiter\n",
            "  -d, --delimiters=LIST   reuse characters from LIST "
            "instead of TABs\n"
            "  -s, --serial            paste one file at a time "
            "instead of in parallel\n",
            "  -d, --directory     create a directory, not a file\n"
            "  -u, --dry-run       do not create anything; merely "
            "print a name (unsafe)\n"
            "  -q, --quiet         suppress diagnostics about "
            "file/dir-creation failure\n",
            "  -e             enable interpretation of backslash "
            "escapes\n"
            "  -E             disable interpretation of backslash "
            "escapes (default)\n",
            "  -e             enable interpretation of backslash "
            "escapes (default)\n"
            "  -E             disable interpretation of backslash "
            "escapes\n",
            "  -e, --canonicalize-existing  all components of the "
            "path must exist\n"
            "  -m, --canonicalize-missing   no path components need "
            "exist or be a directory\n"
            "  -L, --logical                resolve '..' components "
            "before symlinks\n"
            "  -P, --physical               resolve symlinks as "
            "encountered (default)\n"
            "  -q, --quiet                  suppress most error "
            "messages\n"
            "      --relative-to=DIR        print the resolved path "
            "relative to DIR\n"
            "      --relative-base=DIR      print absolute paths "
            "unless paths below DIR\n"
            "  -s, --strip, --no-symlinks   don't expand symlinks\n"
            "  -z, --zero                   end each output line "
            "with NUL, not newline\n",
            "  -e, --echo                treat each ARG as an input "
            "line\n"
            "  -i, --input-range=LO-HI   treat each number LO "
            "through HI as an input line\n"
            "  -n, --head-count=COUNT    output at most COUNT "
            "lines\n"
            "  -o, --output=FILE         write result to FILE "
            "instead of standard output\n"
            "      --random-source=FILE  get random bytes from "
            "FILE\n"
            "  -r, --repeat              output lines can be "
            "repeated\n",
            "  -f                         list all entries in "
            "directory order\n"
            "  -F, --classify[=WHEN]      append indicator (one of "
            "*/=>@|) to entries WHEN\n"
            "      --file-type            likewise, except do not "
            "append '*'\n"
            "      --format=WORD          across -x, commas -m, "
            "horizontal -x, long -l,\n"
            "                               single-column -1, "
            "verbose -l, vertical -C\n"
            "      --full-time            like -l "
            "--time-style=full-iso\n",
            "  -f              omit the line of column headings in "
            "short format\n"
            "  -w              omit the user's full name in short "
            "format\n"
            "  -i              omit the user's full name and remote "
            "host in short format\n"
            "  -q              omit the user's full name, remote "
            "host and idle time\n"
            "                  in short format\n",
            "  -f   same as -t fF, select floats\n"
            "  -i   same as -t dI, select decimal ints\n"
            "  -l   same as -t dL, select decimal longs\n"
            "  -o   same as -t o2, select octal 2-byte units\n"
            "  -s   same as -t d2, select decimal 2-byte units\n"
            "  -x   same as -t x2, select hexadecimal 2-byte "
            "units\n",
            "  -f FILE     FILE exists and is a regular file\n"
            "  -g FILE     FILE exists and is set-group-ID\n"
            "  -G FILE     FILE exists and is owned by the "
            "effective group ID\n"
            "  -h FILE     FILE exists and is a symbolic link (same "
            "as -L)\n"
            "  -k FILE     FILE exists and has its sticky bit set\n",
            "  -f, --canonicalize            canonicalize by "
            "following every symlink in\n"
            "                                every component of the "
            "given name recursively;\n"
            "                                all but the last "
            "component must exist\n"
            "  -e, --canonicalize-existing   canonicalize by "
            "following every symlink in\n"
            "                                every component of the "
            "given name recursively,\n"
            "                                all components must "
            "exist\n",
            "  -f, --fields=LIST       select only these fields;  "
            "also print any line\n"
            "                            that contains no delimiter "
            "character, unless\n"
            "                            the -s option is "
            "specified\n"
            "  -n                      (ignored)\n",
            "  -f, --file-system      sync the file systems that "
            "contain the files\n",
            "  -f, --file=DATEFILE        like --date; once for "
            "each line of DATEFILE\n",
            "  -f, --follow[={name|descriptor}]\n"
            "                           output appended data as the "
            "file grows;\n"
            "                             an absent option argument "
            "means 'descriptor'\n"
            "  -F                       same as --follow=name "
            "--retry\n",
            "  -f, --force                  if an existing "
            "destination file cannot be\n"
            "                                 opened, remove it and "
            "try again (this option\n"
            "                                 is ignored when the "
            "-n option is also used)\n"
            "  -i, --interactive            prompt before overwrite "
            "(overrides a previous -n\n"
            "                                  option)\n"
            "  -H                           follow command-line "
            "symbolic links in SOURCE\n",
            "  -f, --force    change permissions to allow writing "
            "if necessary\n"
            "  -n, --iterations=N  overwrite N times instead of the "
            "default (%d)\n"
            "      --random-source=FILE  get random bytes from "
            "FILE\n"
            "  -s, --size=N   shred this many bytes (suffixes like "
            "K, M, G accepted)\n",
            "  -f, --format=FORMAT      use printf style "
            "floating-point FORMAT\n"
            "  -s, --separator=STRING   use STRING to separate "
            "numbers (default: \\n)\n"
            "  -w, --equal-width        equalize width by padding "
            "with leading zeroes\n",
            "  -f, --skip-fields=N   avoid comparing the first N " "fields\n",
            "  -g                         like -l, but do not list " "owner\n",
            "  -g, --general-numeric-sort  compare according to "
            "general numerical value\n"
            "  -i, --ignore-nonprinting    consider only printable "
            "characters\n"
            "  -M, --month-sort            compare (unknown) < "
            "'JAN' < ... < 'DEC'\n",
            "  -h, --header-numbering=STYLE    use STYLE for "
            "numbering header lines\n"
            "  -i, --line-increment=NUMBER     line number "
            "increment at each line\n"
            "  -l, --join-blank-lines=NUMBER   group of NUMBER "
            "empty lines counted as one\n"
            "  -n, --number-format=FORMAT      insert line numbers "
            "according to FORMAT\n"
            "  -p, --no-renumber               do not reset line "
            "numbers for each section\n"
            "  -s, --number-separator=STRING   add STRING after "
            "(possible) line number\n",
            "  -h, --header=HEADER\n"
            "                    use a centered HEADER instead of "
            "filename in page header,\n"
            '                    -h "" prints a blank line, don\'t '
            'use -h""\n'
            "  -i[CHAR[WIDTH]], --output-tabs[=CHAR[WIDTH]]\n"
            "                    replace spaces with CHARs (TABs) "
            "to tab WIDTH (8)\n"
            "  -J, --join-lines  merge full lines, turns off -W "
            "line truncation, no column\n"
            "                    alignment, --sep-string[=STRING] "
            "sets separators\n",
            "  -h, --human-numeric-sort    compare human readable "
            "numbers (e.g., 2K 1G)\n",
            "  -h, --human-readable       with -l and -s, print "
            "sizes like 1K 234M 2G etc.\n"
            "      --si                   likewise, but use powers "
            "of 1000 not 1024\n",
            "  -h, --no-dereference   affect each symbolic link "
            "instead of any referenced\n"
            "                         file (useful only on systems "
            "that can change the\n"
            "                         timestamps of a symlink)\n"
            "  -m                     change only the modification "
            "time\n",
            "  -i, --ignore-case      ignore differences in case "
            "when comparing fields\n"
            "  -j FIELD               equivalent to '-1 FIELD -2 "
            "FIELD'\n"
            "  -o FORMAT              obey FORMAT while "
            "constructing output line\n"
            "  -t CHAR                use CHAR as input and output "
            "field separator\n",
            "  -i, --ignore-case     ignore differences in case "
            "when comparing\n"
            "  -s, --skip-chars=N    avoid comparing the first N "
            "characters\n"
            "  -u, --unique          only print unique lines\n",
            "  -i, --ignore-environment  start with an empty "
            "environment\n"
            "  -0, --null           end each output line with NUL, "
            "not newline\n"
            "  -u, --unset=NAME     remove variable from the "
            "environment\n",
            "  -i, --initial    do not convert tabs after non "
            "blanks\n"
            "  -t, --tabs=N     have tabs N characters apart, not "
            "8\n",
            "  -i, --inodes          list inode information instead "
            "of block usage\n"
            "  -k                    like --block-size=1K\n"
            "  -l, --local           limit listing to local file "
            "systems\n"
            "      --no-sync         do not invoke sync before "
            "getting usage info (default)\n",
            "  -i, --input=MODE   adjust standard input stream "
            "buffering\n"
            "  -o, --output=MODE  adjust standard output stream "
            "buffering\n"
            "  -e, --error=MODE   adjust standard error stream "
            "buffering\n",
            "  -i, --interactive           prompt whether to remove "
            "destinations\n"
            "  -L, --logical               dereference TARGETs that "
            "are symbolic links\n"
            "  -n, --no-dereference        treat LINK_NAME as a "
            "normal file if\n"
            "                                it is a symbolic link "
            "to a directory\n"
            "  -P, --physical              make hard links directly "
            "to symbolic links\n"
            "  -r, --relative              with -s, create links "
            "relative to link location\n"
            "  -s, --symbolic              make symbolic links "
            "instead of hard links\n",
            "  -k                    like --block-size=1K\n"
            "  -L, --dereference     dereference all symbolic "
            "links\n"
            "  -l, --count-links     count sizes many times if hard "
            "linked\n"
            "  -m                    like --block-size=1M\n",
            "  -k, --key=KEYDEF          sort via a key; KEYDEF "
            "gives location and type\n"
            "  -m, --merge               merge already sorted "
            "files; do not sort\n",
            "  -k, --kibibytes            default to 1024-byte "
            "blocks for file system usage;\n"
            "                               used only with -s and "
            "per directory totals\n",
            "  -l                         use a long listing "
            "format\n"
            "  -L, --dereference          when showing file "
            "information for a symbolic\n"
            "                               link, show information "
            "for the file the link\n"
            "                               references rather than "
            "for the link itself\n"
            "  -m                         fill width with a comma "
            "separated list of entries\n",
            "  -l <length>  digest length in bits, must not exceed "
            "the maximum for\n",
            "  -l, --length=BITS     digest length in bits; must "
            "not exceed the max for\n"
            "                          the blake2 algorithm and "
            "must be a multiple of 8\n",
            "  -l, --length=PAGE_LENGTH\n"
            "                    set the page length to PAGE_LENGTH "
            "(66) lines\n"
            "                    (default number of lines of text "
            "56, and with -F 63).\n"
            "                    implies -t if PAGE_LENGTH <= 10\n",
            "  -l, --link                   hard link files instead "
            "of copying\n"
            "  -L, --dereference            always follow symbolic "
            "links in SOURCE\n",
            "  -l, --login       print system login processes\n",
            "  -m, --canonicalize-missing    canonicalize by "
            "following every symlink in\n"
            "                                every component of the "
            "given name recursively,\n"
            "                                without requirements "
            "on components existence\n"
            "  -n, --no-newline              do not output the "
            "trailing delimiter\n"
            "  -q, --quiet\n"
            "  -s, --silent                  suppress most error "
            "messages (on by default)\n"
            "  -v, --verbose                 report error messages\n"
            "  -z, --zero                    end each output line "
            "with NUL, not newline\n",
            "  -m, --merge       print all files in parallel, one "
            "in each column,\n"
            "                    truncate lines, but join lines of "
            "full length with -J\n",
            "  -m, --mode=MODE    set file permission bits to MODE, "
            "not a=rw - umask\n",
            "  -m, --mode=MODE   set file mode (as in chmod), not "
            "a=rwx - umask\n"
            "  -p, --parents     no error if existing, make parent "
            "directories as needed,\n"
            "                    with their file modes unaffected "
            "by any -m option.\n"
            "  -v, --verbose     print a message for each created "
            "directory\n",
            "  -n, --adjustment=N   add integer N to the niceness " "(default 10)\n",
            "  -n, --digits=DIGITS        use specified number of "
            "digits instead of 2\n"
            "  -s, --quiet, --silent      do not print counts of "
            "output file sizes\n"
            "  -z, --elide-empty-files    remove empty output "
            "files\n",
            "  -n, --lines=[+]NUM       output the last NUM lines, "
            "instead of the last %d;\n"
            "                             or use -n +NUM to output "
            "starting with line NUM\n"
            "      --max-unchanged-stats=N\n"
            "                           with --follow=name, reopen "
            "a FILE which has not\n"
            "                             changed size after N "
            "(default %d) iterations\n"
            "                             to see if it has been "
            "unlinked or renamed\n"
            "                             (this is the usual case "
            "of rotated log files);\n"
            "                             with inotify, this option "
            "is rarely useful\n",
            "  -n, --no-clobber             do not overwrite an "
            "existing file (overrides\n"
            "                                 a previous -i "
            "option)\n"
            "  -P, --no-dereference         never follow symbolic "
            "links in SOURCE\n",
            "  -n, --numeric-sort          compare according to "
            "string numerical value\n"
            "  -R, --random-sort           shuffle, but group "
            "identical keys.  See shuf(1)\n"
            "      --random-source=FILE    get random bytes from "
            "FILE\n"
            "  -r, --reverse               reverse the result of "
            "comparisons\n",
            "  -n, --numeric-uid-gid      like -l, but list numeric "
            "user and group IDs\n"
            "  -N, --literal              print entry names without "
            "quoting\n"
            "  -o                         like -l, but do not list "
            "group information\n"
            "  -p, --indicator-style=slash\n"
            "                             append / indicator to "
            "directories\n",
            "  -n[SEP[DIGITS]], --number-lines[=SEP[DIGITS]]\n"
            "                    number lines, use DIGITS (5) "
            "digits, then SEP (TAB),\n"
            "                    default counting starts with 1st "
            "line of input file\n"
            "  -N, --first-line-number=NUMBER\n"
            "                    start counting with NUMBER at 1st "
            "line of first\n"
            "                    page printed (see +FIRST_PAGE)\n",
            "  -o, --indent=MARGIN\n"
            "                    offset each line with MARGIN "
            "(zero) spaces, do not\n"
            "                    affect -w or -W, MARGIN will be "
            "added to PAGE_WIDTH\n"
            "  -r, --no-file-warnings\n"
            "                    omit warning when a file cannot be "
            "opened\n",
            "  -o, --io-blocks        treat SIZE as number of IO "
            "blocks instead of bytes\n",
            "  -o, --output=FILE         write result to FILE "
            "instead of standard output\n"
            "  -s, --stable              stabilize sort by "
            "disabling last-resort comparison\n"
            "  -S, --buffer-size=SIZE    use SIZE for main memory "
            "buffer\n",
            "  -p                           same as "
            "--preserve=mode,ownership,timestamps\n"
            "      --preserve[=ATTR_LIST]   preserve the specified "
            "attributes (default:\n"
            "                                 "
            "mode,ownership,timestamps), if possible\n"
            "                                 additional "
            "attributes: context, links, xattr,\n"
            "                                 all\n",
            "  -p                        diagnose errors writing to "
            "non pipes\n"
            "      --output-error[=MODE]   set behavior on write "
            "error.  See MODE below\n",
            "  -p DIR, --tmpdir[=DIR]  interpret TEMPLATE relative "
            "to DIR; if DIR is not\n"
            "                        specified, use $TMPDIR if set, "
            "else /tmp.  With\n"
            "                        this option, TEMPLATE must not "
            "be an absolute name;\n"
            "                        unlike with -t, TEMPLATE may "
            "contain slashes, but\n"
            "                        mktemp creates only the final "
            "component\n",
            "  -p, --parents   remove DIRECTORY and its ancestors; "
            "e.g., 'rmdir -p a/b/c' is\n"
            "                    similar to 'rmdir a/b/c a/b a'\n"
            "  -v, --verbose   output a diagnostic for every "
            "directory processed\n",
            "  -p, --preserve-timestamps   apply "
            "access/modification times of SOURCE files\n"
            "                        to corresponding destination "
            "files\n"
            "  -s, --strip         strip symbol tables\n"
            "      --strip-program=PROGRAM  program used to strip "
            "binaries\n"
            "  -S, --suffix=SUFFIX  override the usual backup "
            "suffix\n"
            "  -t, --target-directory=DIRECTORY  copy all SOURCE "
            "arguments into DIRECTORY\n"
            "  -T, --no-target-directory  treat DEST as a normal "
            "file\n"
            "  -v, --verbose       print the name of each directory "
            "as it is created\n",
            "  -q, --count       all login names and number of "
            "users logged on\n"
            "  -r, --runlevel    print current runlevel\n"
            "  -s, --short       print only name, line, and time "
            "(default)\n"
            "  -t, --time        print last system clock change\n",
            "  -q, --hide-control-chars   print ? instead of "
            "nongraphic characters\n"
            "      --show-control-chars   show nongraphic "
            "characters as-is (the default,\n"
            "                               unless program is 'ls' "
            "and output is a terminal)\n"
            "  -Q, --quote-name           enclose entry names in "
            "double quotes\n"
            "      --quoting-style=WORD   use quoting style WORD "
            "for entry names:\n"
            "                               literal, locale, shell, "
            "shell-always,\n"
            "                               shell-escape, "
            "shell-escape-always, c, escape\n"
            "                               (overrides "
            "QUOTING_STYLE environment variable)\n",
            "  -q, --quiet, --silent    never print headers giving "
            "file names\n"
            "  -v, --verbose            always print headers giving "
            "file names\n",
            "  -r, --reference=FILE       display the last "
            "modification time of FILE\n",
            "  -r, --reference=FILE   use this file's times instead "
            "of current time\n"
            "  -t STAMP               use [[CC]YY]MMDDhhmm[.ss] "
            "instead of current time\n"
            "      --time=WORD        change the specified time:\n"
            "                           WORD is access, atime, or "
            "use: equivalent to -a\n"
            "                           WORD is modify or mtime: "
            "equivalent to -m\n",
            "  -r, --reference=RFILE  base size on RFILE\n"
            "  -s, --size=SIZE        set or adjust the file size "
            "by SIZE bytes\n",
            "  -r, --references               first field of each "
            "line is a reference\n"
            "  -t, --typeset-mode               - not implemented "
            "-\n"
            "  -w, --width=NUMBER             output width in "
            "columns, reference excluded\n",
            "  -r, --reverse              reverse order while "
            "sorting\n"
            "  -R, --recursive            list subdirectories "
            "recursively\n"
            "  -s, --size                 print the allocated size "
            "of each file, in blocks\n",
            "  -r, -R, --recursive   remove directories and their "
            "contents recursively\n"
            "  -d, --dir             remove empty directories\n"
            "  -v, --verbose         explain what is being done\n",
            "  -s, --only-delimited    do not print lines not "
            "containing delimiters\n"
            "      --output-delimiter=STRING  use STRING as the "
            "output delimiter\n"
            "                            the default is to use the "
            "input delimiter\n",
            "  -s, --set=STRING           set time described by "
            "STRING\n"
            "  -u, --utc, --universal     print or set Coordinated "
            "Universal Time (UTC)\n",
            "  -s, --signal=SIGNAL, -SIGNAL\n"
            "                   specify the name or number of the "
            "signal to be sent\n"
            "  -l, --list       list signal names, or convert "
            "signal names to/from numbers\n"
            "  -t, --table      print a table of signal "
            "information\n",
            "  -s, --sleep-interval=N   with -f, sleep for "
            "approximately N seconds\n"
            "                             (default 1.0) between "
            "iterations;\n"
            "                             with inotify and --pid=P, "
            "check process P at\n"
            "                             least once every N "
            "seconds\n"
            "  -v, --verbose            always output headers "
            "giving file names\n",
            "  -s, --symbolic-link          make symbolic links "
            "instead of copying\n"
            "  -S, --suffix=SUFFIX          override the usual "
            "backup suffix\n"
            "  -t, --target-directory=DIRECTORY  copy all SOURCE "
            "arguments into DIRECTORY\n"
            "  -T, --no-target-directory    treat DEST as a normal "
            "file\n",
            "  -s[CHAR], --separator[=CHAR]\n"
            "                    separate columns by a single "
            "character, default for CHAR\n"
            "                    is the <TAB> character without -w "
            "and 'no char' with -w.\n"
            "                    -s[CHAR] turns off line truncation "
            "of all 3 column\n"
            "                    options (-COLUMN|-a -COLUMN|-m) "
            "except -w is set\n",
            "  -t                         sort by time, newest "
            "first; see --time\n"
            "  -T, --tabsize=COLS         assume tab stops at each "
            "COLS instead of 8\n",
            "  -t                       equivalent to -vT\n"
            "  -T, --show-tabs          display TAB characters as "
            "^I\n"
            "  -u                       (ignored)\n"
            "  -v, --show-nonprinting   use ^ and M- notation, "
            "except for LFD and TAB\n",
            "  -t                  interpret TEMPLATE as a single "
            "file name component,\n"
            "                        relative to a directory: "
            "$TMPDIR, if set; else the\n"
            "                        directory specified via -p; "
            "else /tmp [deprecated]\n",
            "  -t, --field-separator=SEP  use SEP instead of "
            "non-blank to blank transition\n"
            "  -T, --temporary-directory=DIR  use DIR for "
            "temporaries, not $TMPDIR or %s;\n"
            "                              multiple options specify "
            "multiple directories\n"
            "      --parallel=N          change the number of sorts "
            "run concurrently to N\n"
            "  -u, --unique              with -c, check for strict "
            "ordering;\n"
            "                              without -c, output only "
            "the first of an equal run\n",
            "  -t, --omit-header  omit page headers and trailers;\n"
            "                     implied if PAGE_LENGTH <= 10\n",
            "  -t, --tagged-paragraph    indentation of first line "
            "different from second\n"
            "  -u, --uniform-spacing     one space between words, "
            "two after sentences\n"
            "  -w, --width=WIDTH         maximum line width "
            "(default of 75 columns)\n"
            "  -g, --goal=WIDTH          goal width (default of 93% "
            "of width)\n",
            "  -t, --target-directory=DIRECTORY  move all SOURCE "
            "arguments into DIRECTORY\n"
            "  -T, --no-target-directory    treat DEST as a normal "
            "file\n"
            "  -u, --update                 move only when the "
            "SOURCE file is newer\n"
            "                                 than the destination "
            "file or when the\n"
            "                                 destination file is "
            "missing\n"
            "  -v, --verbose                explain what is being "
            "done\n"
            "  -Z, --context                set SELinux security "
            "context of destination\n"
            "                                 file to default "
            "type\n",
            "  -t, --text            read in text mode (default if "
            "reading tty stdin)\n",
            "  -t, --text            read in text mode (default)\n",
            "  -t, --threshold=SIZE  exclude entries smaller than "
            "SIZE if positive,\n"
            "                          or entries greater than SIZE "
            "if negative\n"
            "      --time            show time of the last "
            "modification of any file in the\n"
            "                          directory, or any of its "
            "subdirectories\n"
            "      --time=WORD       show time as WORD instead of "
            "modification time:\n"
            "                          atime, access, use, ctime or "
            "status\n"
            "      --time-style=STYLE  show times using STYLE, "
            "which can be:\n"
            "                            full-iso, long-iso, iso, "
            "or +FORMAT;\n"
            "                            FORMAT is interpreted like "
            "in 'date'\n",
            "  -t, --type=TYPE       limit listing to file systems "
            "of type TYPE\n"
            "  -T, --print-type      print file system type\n"
            "  -x, --exclude-type=TYPE   limit listing to file "
            "systems not of type TYPE\n"
            "  -v                    (ignored)\n",
            "  -u                         with -lt: sort by, and "
            "show, access time;\n"
            "                               with -l: show access "
            "time and sort by name;\n"
            "                               otherwise: sort by "
            "access time, newest first\n"
            "  -U                         do not sort; list entries "
            "in directory order\n"
            "  -v                         natural sort of (version) "
            "numbers within text\n",
            "  -u             deallocate and remove file after "
            "overwriting\n"
            "      --remove[=HOW]  like -u but give control on HOW "
            "to delete;  See below\n"
            "  -v, --verbose  show progress\n"
            "  -x, --exact    do not round file sizes up to the "
            "next full block;\n"
            "                   this is the default for non-regular "
            "files\n"
            "  -z, --zero     add a final overwrite with zeros to "
            "hide shredding\n",
            "  -u, --update                 copy only when the "
            "SOURCE file is newer\n"
            "                                 than the destination "
            "file or when the\n"
            "                                 destination file is "
            "missing\n"
            "  -v, --verbose                explain what is being "
            "done\n"
            "  -x, --one-file-system        stay on this file "
            "system\n",
            "  -u, --user=USER        set user USER in the target "
            "security context\n"
            "  -r, --role=ROLE        set role ROLE in the target "
            "security context\n"
            "  -t, --type=TYPE        set type TYPE in the target "
            "security context\n"
            "  -l, --range=RANGE      set range RANGE in the target "
            "security context\n",
            "  -v FILENUM             like -a FILENUM, but suppress "
            "joined output lines\n"
            "  -1 FIELD               join on this FIELD of file 1\n"
            "  -2 FIELD               join on this FIELD of file 2\n"
            "      --check-order      check that the input is "
            "correctly sorted, even\n"
            "                           if all input lines are "
            "pairable\n"
            "      --nocheck-order    do not check that the input "
            "is correctly sorted\n"
            "      --header           treat the first line in each "
            "file as field headers,\n"
            "                           print them without trying "
            "to pair them\n",
            "  -v, --debug          print verbose information for "
            "each processing step\n",
            "  -v, --kernel-version     print the kernel version\n"
            "  -m, --machine            print the machine hardware "
            "name\n"
            "  -p, --processor          print the processor type "
            "(non-portable)\n"
            "  -i, --hardware-platform  print the hardware platform "
            "(non-portable)\n"
            "  -o, --operating-system   print the operating "
            "system\n",
            "  -v, --starting-line-number=NUMBER  first line number "
            "for each section\n"
            "  -w, --number-width=NUMBER       use NUMBER columns "
            "for line numbers\n",
            "  -v, --verbose          output a diagnostic for every "
            "file processed\n",
            "  -v, --verbose  diagnose to stderr any signal sent " "upon timeout\n",
            "  -w, --check-chars=N   compare no more than N " "characters in lines\n",
            "  -w, --width=COLS           set output width to "
            "COLS.  0 means no limit\n"
            "  -x                         list entries by lines "
            "instead of by columns\n"
            "  -X                         sort alphabetically by "
            "entry extension\n"
            "  -Z, --context              print any security "
            "context of each file\n"
            "      --zero                 end each output line with "
            "NUL, not newline\n"
            "  -1                         list one file per line\n",
            "  -z, --zero            end each output line with NUL, "
            "not newline,\n"
            "                          and disable file name "
            "escaping\n",
            "  -z, --zero     end each output line with NUL, not " "newline\n",
            "  -z, --zero-terminated     line delimiter is NUL, not " "newline\n",
            "  -z, --zero-terminated    line delimiter is NUL, not " "newline\n",
            "  -z, --zero-terminated   line delimiter is NUL, not " "newline\n",
            "  -z, --zero-terminated  line delimiter is NUL, not " "newline\n",
            "  CONTEXT            Complete security context\n"
            "  -c, --compute      compute process transition "
            "context before modifying\n"
            "  -t, --type=TYPE    type (for same role as parent)\n"
            "  -u, --user=USER    user identity\n"
            "  -r, --role=ROLE    role\n"
            "  -l, --range=RANGE  levelrange\n",
            "  Processes in\n"
            "an uninterruptible sleep state also contribute to the "
            "load average.\n",
            "  [:graph:]       all printable characters, not "
            "including space\n"
            "  [:lower:]       all lower case letters\n"
            "  [:print:]       all printable characters, including "
            "space\n"
            "  [:punct:]       all punctuation characters\n"
            "  [:space:]       all horizontal or vertical "
            "whitespace\n"
            "  [:upper:]       all upper case letters\n"
            "  [:xdigit:]      all hexadecimal digits\n"
            "  [=CHAR=]        all characters which are equivalent "
            "to CHAR\n",
            "  \\0NNN   byte with octal value NNN (1 to 3 digits)\n"
            "  \\xHH    byte with hexadecimal value HH (1 to 2 "
            "digits)\n",
            "  \\NNN    byte with octal value NNN (1 to 3 digits)\n"
            "  \\xHH    byte with hexadecimal value HH (1 to 2 "
            "digits)\n"
            "  \\uHHHH  Unicode (ISO/IEC 10646) character with hex "
            "value HHHH (4 digits)\n"
            "  \\UHHHHHHHH  Unicode character with hex value "
            "HHHHHHHH (8 digits)\n",
            "  \\\\      backslash\n"
            "  \\a      alert (BEL)\n"
            "  \\b      backspace\n"
            "  \\c      produce no further output\n"
            "  \\e      escape\n"
            "  \\f      form feed\n"
            "  \\n      new line\n"
            "  \\r      carriage return\n"
            "  \\t      horizontal tab\n"
            "  \\v      vertical tab\n",
            "  \\v              vertical tab\n"
            "  CHAR1-CHAR2     all characters from CHAR1 to CHAR2 "
            "in ascending order\n"
            "  [CHAR*]         in SET2, copies of CHAR until length "
            "of SET1\n"
            "  [CHAR*REPEAT]   REPEAT copies of CHAR, REPEAT octal "
            "if starting with 0\n"
            "  [:alnum:]       all letters and digits\n"
            "  [:alpha:]       all letters\n"
            "  [:blank:]       all horizontal whitespace\n"
            "  [:cntrl:]       all control characters\n"
            "  [:digit:]       all digits\n",
            "  ascii     from EBCDIC to ASCII\n"
            "  ebcdic    from ASCII to EBCDIC\n"
            "  ibm       from ASCII to alternate EBCDIC\n"
            "  block     pad newline-terminated records with spaces "
            "to cbs-size\n"
            "  unblock   replace trailing spaces in cbs-size "
            "records with newline\n"
            "  lcase     change upper case to lower case\n"
            "  ucase     change lower case to upper case\n"
            "  sparse    try to seek rather than write all-NUL "
            "output blocks\n"
            "  swab      swap every pair of input bytes\n"
            "  sync      pad every input block with NULs to "
            "ibs-size; when used\n"
            "            with block or unblock, pad with spaces "
            "rather than NULs\n",
            "  auto       accept optional single/two letter "
            "suffix:\n"
            "               1K = 1000,\n"
            "               1Ki = 1024,\n"
            "               1M = 1000000,\n"
            "               1Mi = 1048576,\n",
            "  binary    use binary I/O for data\n",
            "  cio       use concurrent I/O for data\n",
            "  count_bytes  treat 'count=N' as a byte count (iflag " "only)\n",
            "  d[SIZE]    signed decimal, SIZE bytes per integer\n"
            "  f[SIZE]    floating point, SIZE bytes per float\n"
            "  o[SIZE]    octal, SIZE bytes per integer\n"
            "  u[SIZE]    unsigned decimal, SIZE bytes per integer\n"
            "  x[SIZE]    hexadecimal, SIZE bytes per integer\n",
            "  direct    use direct I/O for data\n",
            "  directory  fail unless a directory\n",
            "  dsync     use synchronized I/O for data\n",
            "  excl      fail if the output file already exists\n"
            "  nocreat   do not create the output file\n"
            "  notrunc   do not truncate the output file\n"
            "  noerror   continue after read errors\n"
            "  fdatasync  physically write output file data before "
            "finishing\n"
            "  fsync     likewise, but also write metadata\n",
            "  fullblock  accumulate full blocks of input (iflag " "only)\n",
            "  iec        accept optional single letter suffix:\n"
            "               1K = 1024,\n"
            "               1M = 1048576,\n"
            "               ...\n",
            "  iec-i      accept optional two-letter suffix:\n"
            "               1Ki = 1024,\n"
            "               1Mi = 1048576,\n"
            "               ...\n",
            "  if=FILE         read from FILE instead of stdin\n"
            "  iflag=FLAGS     read as per the comma separated "
            "symbol list\n"
            "  obs=BYTES       write BYTES bytes at a time "
            "(default: 512)\n"
            "  of=FILE         write to FILE instead of stdout\n"
            "  oflag=FLAGS     write as per the comma separated "
            "symbol list\n"
            "  seek=N          skip N obs-sized blocks at start of "
            "output\n"
            "  skip=N          skip N ibs-sized blocks at start of "
            "input\n"
            "  status=LEVEL    The LEVEL of information to print to "
            "stderr;\n"
            "                  'none' suppresses everything but "
            "error messages,\n"
            "                  'noxfer' suppresses the final "
            "transfer statistics,\n"
            "                  'progress' shows periodic transfer "
            "statistics\n",
            "  noatime   do not update access time\n",
            "  nocache   Request to drop cache.  See also " "oflag=sync\n",
            "  noctty    do not assign controlling terminal from " "file\n",
            "  nofollow  do not follow symlinks\n",
            "  nolinks   fail if multiply-linked\n",
            "  nonblock  use non-blocking I/O\n",
            "  none       no auto-scaling is done; suffixes will " "trigger an error\n",
            "  seek_bytes  treat 'seek=N' as a byte count (oflag " "only)\n",
            "  si         accept optional single letter suffix:\n"
            "               1K = 1000,\n"
            "               1M = 1000000,\n"
            "               ...\n",
            "  skip_bytes  treat 'skip=N' as a byte count (iflag " "only)\n",
            "  sync      likewise, but also for metadata\n",
            "  text      use text I/O for data\n",
            " * [-]LCASE      same as [-]lcase\n",
            " * [-]cdtrdsr    enable DTR/DSR handshaking\n",
            ' * [-]cmspar     use "stick" (mark/space) parity\n',
            " * [-]crtscts    enable RTS/CTS handshaking\n",
            " * [-]ctlecho    echo control characters in hat " "notation ('^c')\n",
            " * [-]decctlq    same as [-]ixany\n",
            " * [-]drain      wait for transmission before applying "
            "settings (%s by default)\n",
            " * [-]echoctl    same as [-]ctlecho\n",
            " * [-]echoke     same as [-]crtkill\n",
            " * [-]echoprt    echo erased characters backward, "
            "between '\\' and '/'\n",
            ' * [-]extproc    enable "LINEMODE"; useful with high ' "latency links\n",
            " * [-]flusho     discard output\n",
            " * [-]imaxbel    beep and do not flush a full input "
            "buffer on a character\n",
            " * [-]iuclc      translate uppercase characters to " "lowercase\n",
            " * [-]iutf8      assume input characters are UTF-8 " "encoded\n",
            " * [-]ixany      let any character restart output, not "
            "only start character\n",
            " * [-]lcase      same as xcase iuclc olcuc\n",
            " * [-]ocrnl      translate carriage return to " "newline\n",
            " * [-]ofdel      use delete characters for fill "
            "instead of NUL characters\n",
            " * [-]ofill      use fill (padding) characters instead "
            "of timing for delays\n",
            " * [-]olcuc      translate lowercase characters to " "uppercase\n",
            " * [-]onlcr      translate newline to carriage " "return-newline\n",
            " * [-]onlret     newline performs a carriage return\n",
            " * [-]onocr      do not print carriage returns in the " "first column\n",
            " * [-]prterase   same as [-]echoprt\n",
            " * [-]tostop     stop background jobs that try to "
            "write to the terminal\n",
            " * [-]xcase      with icanon, escape with '\\' for "
            "uppercase characters\n",
            " * bsN           backspace delay style, N in [0..1]\n",
            " * cols N        tell the kernel that the terminal has "
            "N columns\n"
            " * columns N     same as cols N\n",
            " * crN           carriage return delay style, N in " "[0..3]\n",
            " * crtkill       kill all line by obeying the echoprt "
            "and echoe settings\n"
            " * -crtkill      kill all line by obeying the echoctl "
            "and echok settings\n",
            " * discard CHAR  CHAR will toggle discarding of " "output\n",
            " * dsusp CHAR    CHAR will send a terminal stop signal "
            "once input flushed\n",
            " * eol2 CHAR     alternate CHAR for ending the line\n",
            " * ffN           form feed delay style, N in [0..1]\n",
            " * line N        use line discipline N\n",
            " * lnext CHAR    CHAR will enter the next character " "quoted\n",
            " * nlN           newline delay style, N in [0..1]\n",
            " * rows N        tell the kernel that the terminal has "
            "N rows\n"
            " * size          print the number of rows and columns "
            "according to the kernel\n",
            " * rprnt CHAR    CHAR will redraw the current line\n",
            " * status CHAR   CHAR will send an info signal\n",
            " * swtch CHAR    CHAR will switch to a different shell " "layer\n",
            " * tabN          horizontal tab delay style, N in "
            "[0..3]\n"
            " * tabs          same as tab0\n"
            " * -tabs         same as tab3\n",
            " * vtN           vertical tab delay style, N in " "[0..1]\n",
            " * werase CHAR   CHAR will erase the last word typed\n",
            " -echoprt",
            " -extproc",
            " -flusho",
            " -imaxbel",
            " -iuclc",
            " -iutf8",
            " -ixany",
            " -ocrnl",
            " -ofdel",
            " -ofill",
            " -olcuc",
            " -onlcr",
            " -onlret",
            " -onocr",
            " -tostop",
            " -xcase",
            " bs0",
            " cr0",
            " echoctl",
            " echoke",
            " ff0",
            " imaxbel",
            " nl0",
            " onlcr",
            " tab0",
            " vt0",
            "% 1% of memory, b 1, K 1024 (default), and so on for "
            "M, G, T, P, E, Z, Y.\n"
            "\n"
            "*** WARNING ***\n"
            "The locale specified by the environment affects sort "
            "order.\n"
            "Set LC_ALL=C to get the traditional sort order that "
            "uses\n"
            "native byte values.\n",
            "%s\n\n",
            ", rprnt",
            ", werase",
            "--terse --file-system is equivalent to the following "
            "FORMAT:\n"
            "    %s",
            "-L",
            "-P",
            "-icrnl",
            "-ixoff",
            "Base%d encode or decode FILE, or standard input, to " "standard output.\n",
            "CAUTION: shred assumes the file system and hardware "
            "overwrite data in place.\n"
            "Although this is common, many platforms operate "
            "otherwise.  Also, backups\n"
            "and mirrors may contain unremovable copies that will "
            "let a shredded file\n"
            "be recovered later.  See the GNU coreutils manual for "
            "details.\n",
            "Call the link function to create a link named FILE2 to "
            "an existing FILE1.\n"
            "\n",
            "Call the unlink function to remove the specified " "FILE.\n" "\n",
            "Change the SELinux security context of each FILE to "
            "CONTEXT.\n"
            "With --reference, change the security context of each "
            "FILE to that of RFILE.\n",
            "Change the group of each FILE to GROUP.\n"
            "With --reference, change the group of each FILE to "
            "that of RFILE.\n"
            "\n",
            "Change the mode of each FILE to MODE.\n"
            "With --reference, change the mode of each FILE to that "
            "of RFILE.\n"
            "\n",
            "Change the owner and/or group of each FILE to OWNER "
            "and/or GROUP.\n"
            "With --reference, change the owner and group of each "
            "FILE to those of RFILE.\n"
            "\n",
            "Compare sorted files FILE1 and FILE2 line by line.\n",
            "Concatenate FILE(s) to standard output.\n",
            "Convert blanks in each FILE to tabs, writing to " "standard output.\n",
            "Convert tabs in each FILE to spaces, writing to " "standard output.\n",
            "Copy SOURCE to DEST, or multiple SOURCE(s) to " "DIRECTORY.\n",
            "Copy a file, converting and formatting according to "
            "the operands.\n"
            "\n"
            "  bs=BYTES        read and write up to BYTES bytes at "
            "a time (default: 512);\n"
            "                  overrides ibs and obs\n"
            "  cbs=BYTES       convert BYTES bytes at a time\n"
            "  conv=CONVS      convert the file as per the comma "
            "separated symbol list\n"
            "  count=N         copy only N input blocks\n"
            "  ibs=BYTES       read up to BYTES bytes at a time "
            "(default: 512)\n",
            "Copy standard input to each FILE, and also to standard "
            "output.\n"
            "\n"
            "  -a, --append              append to the given FILEs, "
            "do not overwrite\n"
            "  -i, --ignore-interrupts   ignore interrupt signals\n",
            "Create a temporary file or directory, safely, and "
            "print its name.\n"
            "TEMPLATE must contain at least 3 consecutive 'X's in "
            "last component.\n"
            "If TEMPLATE is not specified, use tmp.XXXXXXXXXX, and "
            "--tmpdir is implied.\n",
            "Create named pipes (FIFOs) with the given NAMEs.\n",
            "Create the DIRECTORY(ies), if they do not already " "exist.\n",
            "Create the special file NAME of the given TYPE.\n",
            "DF",
            "DU",
            "Diagnose invalid or unportable file names.\n"
            "\n"
            "  -p                  check for most POSIX systems\n"
            "  -P                  check for empty names and "
            'leading "-"\n'
            "      --portability   check for all POSIX systems "
            "(equivalent to -p -P)\n",
            "Display file or file system status.\n",
            "Display the current time in the given FORMAT, or set "
            "the system date.\n",
            "Each range is one of:\n"
            "\n"
            "  N     N'th byte, character or field, counted from 1\n"
            "  N-    from N'th byte, character or field, to end of "
            "line\n"
            "  N-M   from N'th to M'th (included) byte, character "
            "or field\n"
            "  -M    from first to M'th (included) byte, character "
            "or field\n",
            "Echo the STRING(s) to standard output.\n"
            "\n"
            "  -n             do not output the trailing newline\n",
            "Execute the PROGRAM_NAME built-in program with the "
            "given PARAMETERS.\n"
            "\n",
            "Exit with a status code indicating failure.",
            "Exit with a status code indicating success.",
            "Exit with the status determined by EXPRESSION.\n\n",
            "FORMAT must be suitable for printing one argument of "
            "type 'double';\n"
            "it defaults to %.PRECf if FIRST, INCREMENT, and LAST "
            "are all fixed point\n"
            "decimal numbers with maximum precision PREC, and to %g "
            "otherwise.\n",
            "Files are created u+rw, and directories u+rwx, minus "
            "umask restrictions.\n",
            "Filter adjacent matching lines from INPUT (or standard "
            "input),\n"
            "writing to OUTPUT (or standard output).\n"
            "\n"
            "With no options, matching lines are merged to the "
            "first occurrence.\n",
            "For each pair of input lines with identical join "
            "fields, write a line to\n"
            "standard output.  The default join field is the first, "
            "delimited by blanks.\n",
            "INFO",
            "If FILE is not specified, use %s.  %s as FILE is " "common.\n" "\n",
            "In the 1st form, create a link to TARGET with the name "
            "LINK_NAME.\n"
            "In the 2nd form, create a link to TARGET in the "
            "current directory.\n"
            "In the 3rd and 4th forms, create links to each TARGET "
            "in DIRECTORY.\n"
            "Create hard links by default, symbolic links with "
            "--symbolic.\n"
            "By default, each destination (name of new link) should "
            "not already exist.\n"
            "When creating hard links, each TARGET must exist.  "
            "Symbolic links\n"
            "can hold arbitrary text; if later resolved, a relative "
            "link is\n"
            "interpreted in relation to its parent directory.\n",
            "List information about the FILEs (the current "
            "directory by default).\n"
            "Sort entries alphabetically if none of -cftuvSUX nor "
            "--sort is specified.\n",
            "Ordering options:\n\n",
            "Other options:\n\n",
            "Output a permuted index, including context, of the "
            "words in the input files.\n",
            "Output commands to set the LS_COLORS environment "
            "variable.\n"
            "\n"
            "Determine format of output:\n"
            "  -b, --sh, --bourne-shell    output Bourne shell code "
            "to set LS_COLORS\n"
            "  -c, --csh, --c-shell        output C shell code to "
            "set LS_COLORS\n"
            "  -p, --print-database        output defaults\n",
            "Output each NAME with its last non-slash component and "
            "trailing slashes\n"
            "removed; if NAME contains no /'s, output '.' (meaning "
            "the current directory).\n"
            "\n",
            "Output pieces of FILE separated by PATTERN(s) to files "
            "'xx00', 'xx01', ...,\n"
            "and output byte counts of each piece to standard "
            "output.\n",
            "Output pieces of FILE to PREFIXaa, PREFIXab, ...;\n"
            "default size is 1000 lines, and default PREFIX is "
            "'x'.\n",
            "Output platform dependent limits in a format useful "
            "for shell scripts.\n"
            "\n",
            "Output who is currently logged in according to FILE.\n"
            "If FILE is not specified, use %s.  %s as FILE is "
            "common.\n"
            "\n",
            "Overwrite the specified FILE(s) repeatedly, in order "
            "to make it harder\n"
            "for even very expensive hardware probing to recover "
            "the data.\n",
            "Paginate or columnate FILE(s) for printing.\n",
            "Print ARGUMENT(s) according to FORMAT, or execute "
            "according to OPTION:\n"
            "\n",
            "Print NAME with any leading directory components "
            "removed.\n"
            "If specified, also remove a trailing SUFFIX.\n",
            "Print certain system information.  With no OPTION, "
            "same as -s.\n"
            "\n"
            "  -a, --all                print all information, in "
            "the following order,\n"
            "                             except omit -p and -i if "
            "unknown:\n"
            "  -s, --kernel-name        print the kernel name\n"
            "  -n, --nodename           print the network node "
            "hostname\n"
            "  -r, --kernel-release     print the kernel release\n",
            "Print group memberships for each USERNAME or, if no "
            "USERNAME is specified, for\n"
            "the current process (which may differ if the groups "
            "database has changed).\n",
            "Print information about users who are currently logged " "in.\n",
            "Print machine architecture.\n\n",
            "Print newline, word, and byte counts for each FILE, "
            "and a total line if\n"
            "more than one FILE is specified.  A word is a "
            "non-zero-length sequence of\n"
            "printable characters delimited by white space.\n",
            "Print numbers from FIRST to LAST, in steps of " "INCREMENT.\n",
            "Print or change terminal characteristics.\n",
            "Print or check %s (%d-bit) checksums.\n",
            "Print or verify checksums.\n" "By default use the 32 bit CRC algorithm.\n",
            "Print selected parts of lines from each FILE to " "standard output.\n",
            "Print the current time, the length of time the system "
            "has been up,\n"
            "the number of users on the system, and the average "
            "number of jobs\n"
            "in the run queue over the last 1, 5 and 15 minutes.",
            "Print the file name of the terminal connected to "
            "standard input.\n"
            "\n"
            "  -s, --silent, --quiet   print nothing, only return "
            "an exit status\n",
            "Print the first %d lines of each FILE to standard "
            "output.\n"
            "With more than one FILE, precede each with a header "
            "giving the file name.\n",
            "Print the full filename of the current working " "directory.\n" "\n",
            "Print the last %d lines of each FILE to standard "
            "output.\n"
            "With more than one FILE, precede each with a header "
            "giving the file name.\n",
            "Print the number of processing units available to the "
            "current process,\n"
            "which may be less than the number of online "
            "processors\n"
            "\n",
            "Print the prime factors of each specified integer "
            "NUMBER.  If none\n"
            "are specified on the command line, read them from "
            "standard input.\n"
            "\n",
            "Print the resolved absolute file name;\n"
            "all but the last component must exist\n"
            "\n",
            "Print the user name associated with the current "
            "effective user ID.\n"
            "Same as id -un.\n"
            "\n",
            "Print the user's login name.\n\n",
            "Print user and group information for each specified "
            "USER,\n"
            "or (when USER omitted) for the current process.\n"
            "\n",
            "Print value of a symbolic link or canonical file name\n" "\n",
            "Reformat NUMBER(s), or the numbers from standard input "
            "if none are specified.\n",
            "Reformat each paragraph in the FILE(s), writing to "
            "standard output.\n"
            "The option -WIDTH is an abbreviated form of "
            "--width=DIGITS.\n",
            "Remove (unlink) the FILE(s).\n"
            "\n"
            "  -f, --force           ignore nonexistent files and "
            "arguments, never prompt\n"
            "  -i                    prompt before every removal\n",
            "Remove the DIRECTORY(ies), if they are empty.\n"
            "\n"
            "      --ignore-fail-on-non-empty\n"
            "                  ignore each failure that is solely "
            "because a directory\n"
            "                    is non-empty\n",
            "Rename SOURCE to DEST, or move SOURCE(s) to " "DIRECTORY.\n",
            "Repeatedly output a line with all specified STRING(s), " "or 'y'.\n" "\n",
            "Run COMMAND with an adjusted niceness, which affects "
            "process scheduling.\n"
            "With no COMMAND, print the current niceness.  Niceness "
            "values range from\n"
            "%d (most favorable to the process) to %d (least "
            "favorable to the process).\n",
            "Run COMMAND with root directory set to NEWROOT.\n\n",
            "Run COMMAND, ignoring hangup signals.\n\n",
            "Run COMMAND, with modified buffering operations for "
            "its standard streams.\n",
            "Run a program in a different SELinux security "
            "context.\n"
            "With neither CONTEXT nor COMMAND, print the current "
            "security context.\n",
            "Send signals to processes, or list signals.\n",
            "Set each NAME to VALUE in the environment and run " "COMMAND.\n",
            "Show information about the file system on which each "
            "FILE resides,\n"
            "or all file systems by default.\n",
            "Shrink or extend the size of each FILE to the "
            "specified size\n"
            "\n"
            "A FILE argument that does not exist is created.\n"
            "\n"
            "If a FILE is larger than the specified size, the extra "
            "data is lost.\n"
            "If a FILE is shorter, it is extended and the sparse "
            "extended part (hole)\n"
            "reads as zero bytes.\n",
            "Start COMMAND, and kill it if still running after " "DURATION.\n",
            "Summarize device usage of the set of FILEs, "
            "recursively for directories.\n",
            "Synchronize cached writes to persistent storage\n"
            "\n"
            "If one or more files are specified, sync only them,\n"
            "or their containing file systems.\n"
            "\n",
            "The following optional flags may follow '%':\n"
            "\n"
            "  -  (hyphen) do not pad the field\n"
            "  _  (underscore) pad with spaces\n"
            "  0  (zero) pad with zeros\n"
            "  +  pad with zeros, and put '+' before future years "
            "with >4 digits\n"
            "  ^  use upper case if possible\n"
            "  #  use opposite case if possible\n",
            "Translate, squeeze, and/or delete characters from "
            "standard input,\n"
            "writing to standard output.\n"
            "\n"
            "  -c, -C, --complement    use the complement of SET1\n"
            "  -d, --delete            delete characters in SET1, "
            "do not translate\n"
            "  -s, --squeeze-repeats   replace each sequence of a "
            "repeated character\n"
            "                            that is listed in the last "
            "specified SET,\n"
            "                            with a single occurrence "
            "of that character\n"
            "  -t, --truncate-set1     first truncate SET1 to "
            "length of SET2\n",
            "USR1",
            "Update the access and modification times of each FILE "
            "to the current time.\n"
            "\n"
            "A FILE argument that does not exist is created empty, "
            "unless -c or -h\n"
            "is supplied.\n"
            "\n"
            "A FILE argument string of - is handled specially and "
            "causes touch to\n"
            "change the times of the file associated with standard "
            "output.\n",
            "Usage: %s\n",
            "Usage: %s --coreutils-prog=PROGRAM_NAME " "[PARAMETERS]... \n",
            "Usage: %s COMMAND [ARG]...\n  or:  %s OPTION\n",
            "Usage: %s CONTEXT COMMAND [args]\n"
            "  or:  %s [ -c ] [-u USER] [-r ROLE] [-t TYPE] [-l "
            "RANGE] COMMAND [args]\n",
            "Usage: %s EXPRESSION\n  or:  %s OPTION\n",
            "Usage: %s FILE\n  or:  %s OPTION\n",
            "Usage: %s FILE1 FILE2\n  or:  %s OPTION\n",
            "Usage: %s FORMAT [ARGUMENT]...\n  or:  %s OPTION\n",
            "Usage: %s NAME [SUFFIX]\n  or:  %s OPTION... NAME...\n",
            "Usage: %s NUMBER[SUFFIX]...\n"
            "  or:  %s OPTION\n"
            "Pause for NUMBER seconds.  SUFFIX may be 's' for "
            "seconds (the default),\n"
            "'m' for minutes, 'h' for hours or 'd' for days.  "
            "NUMBER need not be an\n"
            "integer.  Given two or more arguments, pause for the "
            "amount of time\n"
            "specified by the sum of their values.\n"
            "\n",
            "Usage: %s OPTION... COMMAND\n",
            "Usage: %s OPTION... FILE...\n",
            "Usage: %s OPTION... [FILE]...\n",
            "Usage: %s [-F DEVICE | --file=DEVICE] [SETTING]...\n"
            "  or:  %s [-F DEVICE | --file=DEVICE] [-a|--all]\n"
            "  or:  %s [-F DEVICE | --file=DEVICE] [-g|--save]\n",
            "Usage: %s [-WIDTH] [OPTION]... [FILE]...\n",
            "Usage: %s [-s SIGNAL | -SIGNAL] PID...\n"
            "  or:  %s -l [SIGNAL]...\n"
            "  or:  %s -t [SIGNAL]...\n",
            "Usage: %s [NAME]\n"
            "  or:  %s OPTION\n"
            "Print or set the hostname of the current system.\n"
            "\n",
            "Usage: %s [NUMBER]...\n  or:  %s OPTION\n",
            "Usage: %s [OPERAND]...\n  or:  %s OPTION\n",
            "Usage: %s [OPTION]\n",
            "Usage: %s [OPTION]\n"
            "Print the numeric identifier (in hexadecimal) for the "
            "current host.\n"
            "\n",
            "Usage: %s [OPTION] DURATION COMMAND [ARG]...\n" "  or:  %s [OPTION]\n",
            "Usage: %s [OPTION] NAME...\n",
            "Usage: %s [OPTION] NEWROOT [COMMAND [ARG]...]\n" "  or:  %s OPTION\n",
            "Usage: %s [OPTION] [COMMAND [ARG]...]\n",
            "Usage: %s [OPTION] [FILE]\n"
            "Write totally ordered list consistent with the partial "
            "ordering in FILE.\n",
            "Usage: %s [OPTION] [FILE]...\n",
            "Usage: %s [OPTION]...\n",
            "Usage: %s [OPTION]... CONTEXT FILE...\n"
            "  or:  %s [OPTION]... [-u USER] [-r ROLE] [-l RANGE] "
            "[-t TYPE] FILE...\n"
            "  or:  %s [OPTION]... --reference=RFILE FILE...\n",
            "Usage: %s [OPTION]... DIRECTORY...\n",
            "Usage: %s [OPTION]... FILE PATTERN...\n",
            "Usage: %s [OPTION]... FILE...\n",
            "Usage: %s [OPTION]... FILE1 FILE2\n",
            "Usage: %s [OPTION]... GROUP FILE...\n"
            "  or:  %s [OPTION]... --reference=RFILE FILE...\n",
            "Usage: %s [OPTION]... LAST\n"
            "  or:  %s [OPTION]... FIRST LAST\n"
            "  or:  %s [OPTION]... FIRST INCREMENT LAST\n",
            "Usage: %s [OPTION]... MODE[,MODE]... FILE...\n"
            "  or:  %s [OPTION]... OCTAL-MODE FILE...\n"
            "  or:  %s [OPTION]... --reference=RFILE FILE...\n",
            "Usage: %s [OPTION]... NAME TYPE [MAJOR MINOR]\n",
            "Usage: %s [OPTION]... NAME...\n",
            "Usage: %s [OPTION]... SET1 [SET2]\n",
            "Usage: %s [OPTION]... [ FILE | ARG1 ARG2 ]\n",
            "Usage: %s [OPTION]... [+FORMAT]\n"
            "  or:  %s [-u|--utc|--universal] "
            "[MMDDhhmm[[CC]YY][.ss]]\n",
            "Usage: %s [OPTION]... [-T] SOURCE DEST\n"
            "  or:  %s [OPTION]... SOURCE... DIRECTORY\n"
            "  or:  %s [OPTION]... -t DIRECTORY SOURCE...\n",
            "Usage: %s [OPTION]... [-T] SOURCE DEST\n"
            "  or:  %s [OPTION]... SOURCE... DIRECTORY\n"
            "  or:  %s [OPTION]... -t DIRECTORY SOURCE...\n"
            "  or:  %s [OPTION]... -d DIRECTORY...\n",
            "Usage: %s [OPTION]... [-T] TARGET LINK_NAME\n"
            "  or:  %s [OPTION]... TARGET\n"
            "  or:  %s [OPTION]... TARGET... DIRECTORY\n"
            "  or:  %s [OPTION]... -t DIRECTORY TARGET...\n",
            "Usage: %s [OPTION]... [-] [NAME=VALUE]... [COMMAND " "[ARG]...]\n",
            "Usage: %s [OPTION]... [FILE [PREFIX]]\n",
            "Usage: %s [OPTION]... [FILE]\n",
            "Usage: %s [OPTION]... [FILE]\n"
            "  or:  %s -e [OPTION]... [ARG]...\n"
            "  or:  %s -i LO-HI [OPTION]...\n",
            "Usage: %s [OPTION]... [FILE]...\n",
            "Usage: %s [OPTION]... [FILE]...\n"
            "  or:  %s [-abcdfilosx]... [FILE] [[+]OFFSET[.][b]]\n"
            "  or:  %s --traditional [OPTION]... [FILE] "
            "[[+]OFFSET[.][b] [+][LABEL][.][b]]\n",
            "Usage: %s [OPTION]... [FILE]...\n"
            "  or:  %s [OPTION]... --files0-from=F\n",
            "Usage: %s [OPTION]... [INPUT [OUTPUT]]\n",
            "Usage: %s [OPTION]... [INPUT]...   (without -G)\n"
            "  or:  %s -G [OPTION]... [INPUT [OUTPUT]]\n",
            "Usage: %s [OPTION]... [NUMBER]...\n",
            "Usage: %s [OPTION]... [OWNER][:[GROUP]] FILE...\n"
            "  or:  %s [OPTION]... --reference=RFILE FILE...\n",
            "Usage: %s [OPTION]... [TEMPLATE]\n",
            "Usage: %s [OPTION]... [USERNAME]...\n",
            "Usage: %s [OPTION]... [USER]...\n",
            "Usage: %s [OPTION]... [VARIABLE]...\n"
            "Print the values of the specified environment "
            "VARIABLE(s).\n"
            "If no VARIABLE is specified, print name and value "
            "pairs for them all.\n"
            "\n",
            "Usage: %s [SHORT-OPTION]... [STRING]...\n" "  or:  %s LONG-OPTION\n",
            "Usage: %s [STRING]...\n  or:  %s OPTION\n",
            "Usage: %s [ignored command line arguments]\n" "  or:  %s OPTION\n",
            "Usage: test EXPRESSION\n"
            "  or:  test\n"
            "  or:  [ EXPRESSION ]\n"
            "  or:  [ ]\n"
            "  or:  [ OPTION\n",
            "Valid format sequences for file systems:\n"
            "\n"
            "  %a   free blocks available to non-superuser\n"
            "  %b   total data blocks in file system\n"
            "  %c   total file nodes in file system\n"
            "  %d   free file nodes in file system\n"
            "  %f   free blocks in file system\n",
            "When checking, the input should be a former output of "
            "this program,\n"
            "or equivalent standalone program.\n",
            "When checking, the input should be a former output of "
            "this program.\n"
            "The default mode is to print a line with: checksum, a "
            "space,\n"
            "a character indicating input mode ('*' for binary, ' ' "
            "for text\n"
            "or where binary is insignificant), and name for each "
            "FILE.\n"
            "\n"
            "Note: There is no difference between binary mode and "
            "text mode on GNU systems.\n",
            "With --follow (-f), tail defaults to following the "
            "file descriptor, which\n"
            "means that even if a tail'ed file is renamed, tail "
            "will continue to track\n"
            "its end.  This default behavior is not desirable when "
            "you really want to\n"
            "track the actual name of the file, not the file "
            "descriptor (e.g., log\n"
            "rotation).  Use --follow=name in that case.  That "
            "causes tail to track the\n"
            "named file in a way that accommodates renaming, "
            "removal and creation.\n",
            "With no FILE, or when FILE is -, read standard " "input.\n",
            "Wrap input lines in each FILE, writing to standard " "output.\n",
            "Write a random permutation of the input lines to " "standard output.\n",
            "Write each FILE to standard output, last line first.\n",
            "Write each FILE to standard output, with line numbers " "added.\n",
            "Write lines consisting of the sequentially "
            "corresponding lines from\n"
            "each FILE, separated by TABs, to standard output.\n",
            "Write sorted concatenation of all FILE(s) to standard " "output.\n",
            "basenc encode or decode FILE, or standard input, to " "standard output.\n",
            "coreutils.h",
            "echoe",
            "erase, kill",
            "icrnl -inlcr -igncr",
            "isig",
            "off",
            "on",
            "opost",
            "test and/or [",
        },
        "users": {"%s"},
        "valid_suffix": {"KMGTPEZY"},
        "validate": {
            "[=c=] expressions may not appear in string2 when " "translating",
            "only one [c*] repeat construct may appear in " "string2",
            "the [c*] construct may appear in string2 only when " "translating",
            "the [c*] repeat construct may not appear in string1",
            "when not truncating set1, string2 must be non-empty",
            "when translating with complemented character "
            "classes,\n"
            "string2 must map all characters in the domain to "
            "one",
            "when translating, the only character classes that "
            "may appear in\n"
            "string2 are 'upper' and 'lower'",
        },
        "validate_case_classes": {"misaligned [:upper:] and/or [:lower:] " "construct"},
        "validate_file_name": {
            "%s",
            "%s: unable to determine maximum file name " "length",
            "empty file name",
            "limit %lu exceeded by length %lu ",
            "limit %lu exceeded by length %lu of file " "name %s",
            "of file name component %s",
        },
        "validate_tab_stops": {
            "'/' specifier is mutually exclusive with " "'+'",
            "tab size cannot be 0",
            "tab sizes must be ascending",
        },
        "verify_numeric": {
            "%s",
            "%s: expected a numeric value",
            "%s: value not completely converted",
        },
        "wc": {"%s", "standard input"},
        "wc_file": {"%s"},
        "wc_lines": {"%s"},
        "wc_lines_avx2": {"%s"},
        "who": {"%s"},
        "wipefd": {"%s: cannot shred append-only file descriptor", "%s: fcntl failed"},
        "wipefile": {"%s: failed to close", "%s: failed to open for writing"},
        "wipename": {
            "%s: failed to close",
            "%s: failed to remove",
            "%s: removed",
            "%s: removing",
            "%s: renamed to %s",
        },
        "wrap_write": {"write error"},
        "write_block": {"%*s", "*\n"},
        "write_counts": {" %*s", " %s"},
        "write_error": {"write error"},
        "write_header": {"\n", "standard input", "%s==> %s <==\n"},
        "write_line": {"--sort", "write failed", "--check"},
        "write_output": {"writing to %s", "standard output"},
        "write_pending": {"write error"},
        "write_permuted_numbers": {"invalid input range", "%lu%c"},
        "write_random_numbers": {"invalid input range", "%lu%c"},
        "write_to_file": {"%s: line number out of range"},
        "writeline": {"%7"},
        "xalloc_die": {"memory exhausted", "%s"},
        "xfclose": {"close failed", "fflush failed"},
        "xlseek": {
            "%s: cannot seek to end-relative offset %s",
            "%s: cannot seek to offset %s",
            "%s: cannot seek to relative offset %s",
        },
        "xstrcoll": {"cannot compare file names %s and %s"},
        "xstrxfrm": {
            "set LC_ALL='C' to work around the problem",
            "string transformation failed",
            "the untransformed string was %s",
        },
        "xwrite_stdout": {"error writing %s", "standard output"},
        "z85_encode": {"invalid input (length must be multiple of 4 " "characters)"},
        "zaptemp": {"warning: cannot remove: %s"},
    }, "Parse has changed!"


def test_coreutils_binja(coreutils_source) -> None:
    """
    Test coreutils symbols with binja string backend.
    """
    parser = CParse()
    binary_path: Path = Path(__file__).with_name("binaries") / "coreutils"
    assert binary_path.exists(), "Binary path does not exist"
    for source_file in (coreutils_source / "src").rglob("**/*.c"):
        assert source_file.exists(), f"Source file {source_file} not found."
        parser.parse(source_file)
        parser.update_mapping()

    bs = BinjaSymbols(binary_path, parser.mapping, {})
    bs.add_symbols(0.85)
