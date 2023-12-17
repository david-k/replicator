import os
import sys
import stat
from pathlib import Path
import hashlib
import sqlite3
import dataclasses
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


# Have a look at:
# - unison https://github.com/bcpierce00/unison
# - https://docs.cryptomator.org/en/latest/security/architecture/
# - https://mountainduck.io/ (encrypted file sync via S3 (among others))



# I'm pretty sure I can use ROW_NUMBER()
# (https://www.sqltutorial.org/sql-window-functions/sql-row_number/) to assign the order to each
# local_files row
# - ROW_NUMBER() is a window function. I haven't heard of them yet but they seem very useful



# Remote
# ======
# - The remote stores two kind of files: bundle files and index files
#
# Bundle files
# ------------
# - Bundle files are immutable: once uploaded they are never modified
# - Their file names are random and unique among both past and future bundle names
# - Each bundle contains the data of one of more files
#
#     struct Bundle {
#         // A name that is unique across space and time
#         string name; // In the implementation, the name is stored in the filename and not in the bundle itself
#
#         Blob[] blobs;
#     }
#
#     // A bundle entry contains the data for either a complete file or for a part of a larger file
#     struct Blob {
#         string hash;
#         uint63 length;
#         byte[] data; // `length` bytes long
#     }
#
#
# Index files
# -----------
# - The remote stores two index files: the base index and the delta index
#   - The base index contains a complete description of the repository
#   - The delta index contains one or more changes to the base index
# - Once the delta index reaches a certain size (half the base index size?) it is merged into the base index and then cleared
# - The delta index is append only. Each changeset is numbered so that clients know which changes they have already applied
# - The base index also contains the sequence number of the most recent changeset that has been incorporated to protect against replay attacks
#
#     // Main structs
#     struct BaseIndex {
#         uint most_recent_sequence_number;
#
#         // These are the initial actions that bring an empty directory to the current state of the repo
#         Actions[] initial_actions;
#     }
#
#     struct DeltaIndex {
#         ChangeSet[] changes;
#     }
#
#
#     // Helper structs
#     struct ChangeSet {
#         uint sequence_number;
#         Action[] actions;
#     }
#
#     enum Action {
#         AddBundle(bundle_name: string);
#         RemoveBundle(bundle_name: string);
#
#         // Adds or updates a given file_id
#         SetFile(
#             filepath: string,
#             mtime: uint,
#             size: uint,
#             executable: bool,
#             // The hash of the file. If the file is small enough that it can be stored in a single
#             // blob, then this hash also denotes that blob.
#             // Otherwise, the blobs that make up the file must be set using the SetBlobAt() action.
#             hash: string,
#         ),
#         SetSymLink(
#             filepath: string,
#             target_filepath: uint64,
#         ),
#
#         // For large files spanning multiple bundles
#         SetBlobAt(
#             filepath: string,
#             idx: uint64,
#             bundle_name: string,
#         )
#         RemoveBlobAt(
#             filepath: string,
#             idx: uint64,
#         )
#
#         RenameFile(old_filepath: string, new_filepath: string),
#         RemoveFile(filepath: string),
#     }
#
#
# Syncing
# =======
# - Find out which files have been added, deleted, modified
# - Copy all bundles. In the following, only modify this copy
# - For each bundle, compute its ordering
#   -
# - For each deleted file:
#   - remove its blob(s) from the corresponding bundle(s). If a bundle becomes empty, also remove the bundle
# - For each updated file:
#   - Create the list of blobs for the file
#   - 
# - For each added file:
#   - 
# - For each bundle that has been modified in the previous steps: generate a new bundle name and upload it to the remote
# 


BLOB_SIZE = 15*1024*1024


# Types
#===================================================================================================
class FileKind(Enum):
    REGULAR = 0
    LINK = 1
    DIRECTORY = 2


# TODO To detect a file change, compare mtime, ctime, size and inode
#      Have a look at https://stackoverflow.com/questions/48613555/git-renamed-files-and-inodes
#      When using inodes I need to make sure not to cross filesystem boundaries
#        - stat.st_dev can be used to compare the filesystem between files
#        - But https://unix.stackexchange.com/a/374298 says stat.st_dev that "it
#          gets false positives when two filesystems are on the same device"
#        - Another way would be two rename a file across the two directories in
#          question. If it fails, then the directories are on different
#          filesystems
#      ctime cannot be modified from userspace
#      when deleting a file and then creating a new one, the inode of the first file may be reused

# kw_only is set to True to prevent the following restriction: "When a dataclass inherits from
# another dataclass, and the base class has fields with default values, then all of the fields in
# the derived class must also have defaults."
# See https://www.trueblade.com/blogs/news/python-3-10-new-dataclass-features
@dataclass(kw_only=True)
class FileMeta:
    filepath: Path
    kind: FileKind
    mtime: int
    ctime: int
    size: int
    inode: int
    executable: bool
    # If set, the file is actually a symlink and this is the target
    link_target: Optional[Path] = None


@dataclass(kw_only=True)
class File(FileMeta):
    blobs: list[bytes] = field(default_factory=list)


@dataclass(kw_only=True)
class DBFileMeta(FileMeta):
    id: int


@dataclass(kw_only=True)
class DBFile(DBFileMeta, File):
    pass


def eq_metadata(a: FileMeta, b: FileMeta) -> bool:
    for (k, v) in a.__dict__.items():
        if k == "id":
            continue

        if v != b.__dict__[k]:
            return False

    return True



# DB utils
#===================================================================================================
def db_update(cursor: sqlite3.Cursor, table: str, data: dict, where: str):
    assignments = []
    for col in data.keys():
        assignments.append(col + " = :" + col)

    cursor.execute("update " + table + " set " + ", ".join(assignments) + " where " + where, data)


def db_insert(cursor: sqlite3.Cursor, table: str, data: dict) -> int:
    col_names = data.keys()
    col_placeholders = [":" + col for col in col_names]

    cursor.execute(
        "insert into " + table + "(" + ",".join(col_names) + ") values(" + ", ".join(col_placeholders) + ")",
        data
    )

    return cursor.lastrowid # type: ignore


# Utils
#===================================================================================================
def compute_blobs(filepath: Path) -> tuple[list, bytes]:
    blobs = []
    with open(filepath, "rb") as file:
        while data := file.read(BLOB_SIZE):
            m = hashlib.sha256()
            m.update(data)
            hash_bytes = m.digest()
            blobs.append((hash_bytes, len(data)))

    combined_hash = hashlib.sha256()
    combined_hash.update(b"".join([h for (h,l) in blobs]))

    return (blobs, combined_hash.digest())


def db_insert_blobs(cursor: sqlite3.Cursor, blobs: list) -> list[int]:
    blob_ids = []
    for (digest, size) in blobs:
        cursor.execute(
            "insert into blobs(hash, size) values(?, ?) on conflict(hash) do nothing",
            (digest, size)
        )
        blob_id = cursor.execute("select id from blobs where hash = ?", (digest,)).fetchone()["id"]
        blob_ids.append(blob_id)

    return blob_ids


def db_assign_blobs_to_local_file(
    cursor: sqlite3.Cursor, file_id: int, blob_ids: list[int], combined_hash: bytes
):
    cursor.execute("delete from local_file_blobs where file_id = ?", (file_id,))

    for blob_id in blob_ids:
        cursor.execute("insert into local_file_blobs(file_id, blob_id) values(?, ?)", (file_id, blob_id))

    cursor.execute(
        "update local_files set combined_hash = :hash where id = :file_id",
        {"file_id": file_id, "hash": combined_hash}
    )


# `p` may be str, bytes or any PathLike
# If `r` is a Path object, use `bytes(r)` to get its bytes representation
def mk_path(p):
    return Path(os.fsdecode(p))

FILE_KIND_TABLE = {
    "f": FileKind.REGULAR,
    "l": FileKind.LINK,
    "d": FileKind.DIRECTORY,
}

def file_kind_to_db(kind: FileKind):
    for (k, v) in FILE_KIND_TABLE.items():
        if v == kind:
            return k

    raise RuntimeError("Invalid file kind: " + str(kind))


def db_try_load_local_file(cursor: sqlite3.Cursor, filepath: Path) -> Optional[DBFileMeta]:
    db_file = cursor.execute(
        "select * from local_files where filepath = :filepath",
        {"filepath": bytes(filepath)}
    ).fetchone()

    if not db_file:
        return None


    return DBFileMeta(
        id = db_file["id"],
        filepath=mk_path(db_file["filepath"]),
        kind=FILE_KIND_TABLE[db_file["kind"]],
        mtime=db_file["mtime"],
        ctime=db_file["ctime"],
        size=db_file["size"],
        inode=db_file["inode"],
        executable=db_file["executable"],
        link_target=mk_path(db_file["link_target"]) if db_file["link_target"] else None,
    )



def db_prepare_local_file_data(data: dict) -> dict:
    data = data.copy()
    data["filepath"] = bytes(data["filepath"])

    if "link_target" in data and data["link_target"]:
        data["link_target"] = bytes(data["link_target"])

    if "kind" in data:
        data["kind"] = file_kind_to_db(data["kind"])

    return data


def db_update_local_file(cursor: sqlite3.Cursor, data: dict):
    db_update(cursor, "local_files", db_prepare_local_file_data(data), "filepath = :filepath")

def db_insert_local_file(cursor: sqlite3.Cursor, data: dict):
    return db_insert(cursor, "local_files", db_prepare_local_file_data(data))



def file_from_stat(repo_root: Path, rel_path: Path, stat_res: os.stat_result) -> FileMeta:
    link_target = None
    size = 0
    if stat.S_ISREG(stat_res.st_mode):
        kind = FileKind.REGULAR
        size = stat_res.st_size
    elif stat.S_ISLNK(stat_res.st_mode):
        kind = FileKind.LINK
        link_target = repo_root.joinpath(rel_path).readlink()
    elif stat.S_ISDIR(stat_res.st_mode):
        kind = FileKind.DIRECTORY
    else:
        raise RuntimeError(str(rel_path) + ": Invalid file kind")

    return FileMeta(
        filepath = rel_path,
        kind = kind,
        mtime = int(stat_res.st_mtime), # TODO Why does pyright think st_mtime and st_ctime are of type float?
        ctime = int(stat_res.st_ctime),
        size = size,
        inode = stat_res.st_ino,
        executable = (stat_res.st_mode & stat.S_IXUSR) != 0,
        link_target = link_target,
    )



def refresh_db_from_fs(db: sqlite3.Connection, repo_root: Path):
    cursor = db.cursor()

    # First, mark all local_files as non-existing
    cursor.execute("update local_files set still_exists = 0")

    # TODO If st_dev of repo_root has changed, remove all local_files


    num_file_metadata_changes = 0
    num_file_hash_recomputed = 0
    for (path, _, filenames) in os.walk(repo_root):
        for filename in filenames:
            filepath = mk_path(path).joinpath(mk_path(filename))
            stat_res = filepath.stat(follow_symlinks=False)

            if stat_res.st_nlink > 1:
                raise RuntimeError(str(filepath) + ": hard links not supported yet")

            # TODO Check that stat_res.st_dev equals st_dev of repo_root


            rel_path = filepath.relative_to(mk_path(repo_root))
            db_file = db_try_load_local_file(cursor, rel_path)
            fs_file = file_from_stat(repo_root, rel_path, stat_res)

            if db_file and eq_metadata(fs_file, db_file):
                # Nothing has changed. Just mark the file as still existing
                cursor.execute("update local_files set still_exists = 1 where filepath = ?", (bytes(rel_path),))
            else:
                new_file_data = dataclasses.asdict(fs_file)
                new_file_data["still_exists"] = 1

                if db_file:
                    if new_file_data["kind"] != db_file.kind and new_file_data["kind"] != FileKind.REGULAR:
                        new_file_data["combined_hash"] = None

                    db_update_local_file(cursor, new_file_data)
                    file_id = db_file.id
                else:
                    file_id = db_insert_local_file(cursor, new_file_data)

                # If the file contents may have been modified we need to recompute the blob hashes
                if fs_file.kind == FileKind.REGULAR:
                    content_may_be_modified = (
                        not db_file or (
                                fs_file.size != db_file.size or
                                fs_file.mtime != db_file.mtime or
                                fs_file.ctime != db_file.ctime or
                                fs_file.inode != db_file.inode
                        )
                    )
                    if content_may_be_modified:
                        (blobs, combined_hash) = compute_blobs(filepath)
                        blob_ids = db_insert_blobs(cursor, blobs)
                        db_assign_blobs_to_local_file(cursor, file_id, blob_ids, combined_hash)

                        num_file_hash_recomputed += 1

                num_file_metadata_changes += 1
                print("Updating " + str(rel_path))


    # Delete unused files
    cursor.execute("delete from local_files where still_exists = 0")
    num_files_deleted = cursor.rowcount

    # Delete unused blobs
    cursor.execute(
        """delete from blobs as b
        where
            (not exists(select * from local_file_blobs where blob_id = b.id)) and
            (not exists(select * from remote_file_blobs where blob_id = b.id))"""
    )
    num_blobs_deleted = cursor.rowcount

    db.commit()

    print(str(num_file_metadata_changes) + " file metadata updates")
    print(str(num_file_hash_recomputed) + " file hashes recomputed")
    print(str(num_files_deleted) + " files deleted")
    print(str(num_blobs_deleted) + " blobs deleted")


def compare_local_with_remote(db: sqlite3.Connection):
    cursor = db.cursor()

    new_files = cursor.execute(
        """select lf.filepath from local_files lf
        where not exists (select * from remote_files rf where rf.filepath = lf.filepath)"""
    ).fetchall()

    modified_files = cursor.execute(
        """select lf.filepath from local_files lf
        where exists (
            select * from remote_files rf
            where rf.filepath = lf.filepath and (
                      rf.kind != lf.kind or
                      rf.size != lf.size or
                      rf.mtime != lf.mtime or
                      rf.executable != lf.executable or
                      rf.combined_hash != lf.combined_hash or
                      rf.link_target != lf.link_target
                 )
        )"""
    ).fetchall()

    deleted_files = cursor.execute(
        """select rf.filepath from remote_files rf
        where not exists (select * from local_files lf where rf.filepath = lf.filepath)"""
    ).fetchall()


    print("Files added:    " + str(len(new_files)))
    print("Files modified: " + str(len(modified_files)))
    print("Files delelted: " + str(len(deleted_files)))


def assign_blobs_to_bundles(db: sqlite3.Connection):
    cursor = db.cursor()

    # Create temp table `ordered_blobs(blob_id, filepath)` that stores for each blob the smallest
    # filepath (in lexicographical order) that is associated with that blob
    cursor.executescript(
        """drop table if exists ordered_blobs;

        create temp table ordered_blobs(
            blob_id integer primary key,
            filepath blob,
            bundle_uuid blob,
            hash blob,
            size integer
        );

        insert into ordered_blobs(blob_id, filepath, bundle_uuid, hash, size)
        select blobs.id, min(local_files.filepath), blobs.bundle_uuid, blobs.hash, blobs.size
        from local_file_blobs
        inner join local_files on local_files.id = local_file_blobs.file_id
        inner join blobs on blobs.id = local_file_blobs.blob_id
        group by local_file_blobs.blob_id
        order by min(local_files.filepath);"""
    )


    # Get a list of all bundles, ordered by the first file (in lexicographical order) that has a
    # blob associated with the bundle
    ordered_bundles = cursor.execute(
        """select
            bundles.uuid, min(ordered_blobs.filepath), sum(ordered_blobs.size) as size
        from bundles
        left join ordered_blobs on ordered_blobs.bundle_uuid = bundles.uuid
        group by bundles.uuid
        order by min(ordered_blobs.filepath)"""
    ).fetchall()

    bundles_by_uuid = {}
    for bundle in ordered_bundles:
        bundles_by_uuid[bundle["uuid"]] = {"size": bundle["size"]}


    # Get a list of all bundles, ordered by the first file (in lexicographical order) that has a
    # blob associated with the bundle
    ordered_blobs = cursor.execute(
        """select ordered_blobs.blob_id, ordered_blobs.filepath from ordered_blobs
        order by ordered_blobs.filepath"""
    )

    for blob in ordered_blobs:
        pass


# MAIN
#===================================================================================================
def main():
    db = sqlite3.connect("test.db")
    db.execute("PRAGMA foreign_keys = ON")
    db.row_factory = sqlite3.Row

    #refresh_db_from_fs(db, mk_path(sys.argv[1]))
    #compare_local_with_remote(db)
    assign_blobs_to_bundles(db)


main()
