# PR 36735 delete pruned files after a failed flush

## In one breath

A prune flush can mark blk and rev files pruned in memory.

That same flush can fail before the block index write.

The next successful flush used to write the pruned metadata and leave the files on disk until the next startup.

`m_files_to_unlink` remembers the file numbers on `BlockManager`.

A later flush deletes those files after the index write.

## What the author is solving

ryanofsky's post-merge review of #35714 point 7 describes this hole.

`setFilesToPrune` lived as a local inside `FlushStateToDisk`.

A block file flush failure returned before `UnlinkPrunedFiles`.

A blocks directory `CheckDiskSpace` failure also returned before `UnlinkPrunedFiles`.

Only `ScanAndUnlinkAlreadyPrunedFiles` cleaned up, and only on the next startup.

The author also wants a unit path for the kernel pruning refactor in #36738.

## What to notice in the commits

Commit one wires `ApplyArgsManOptions` into the chain test fixture.

`-prune` and `-fastprune` in `extra_args` then reach `BlockManager`.

Commit two turns the destroy-the-blk sabotage into a restoreable `.bak` rename.

Commit two also asserts a `FORCE_FLUSH` retry writes what the failed flush skipped.

Commit three is the characterization test `prune_flush_failure`.

`prune_flush_failure` shows in-memory prune, on-disk index lag, and blk/rev files still present after a successful retry.

Commit four adds `m_files_to_unlink`.

Commit four inserts file numbers at prune selection.

Commit four uses `std::exchange` before `WriteBlockIndexDB`, then unlinks from that snapshot.

`FindNextBlockPos` erases a file number from `m_files_to_unlink` when a new block is about to use that file.

Pending unlink numbers do not force a write by themselves.

The disk-space failure path and automatic pruning share the same fix with no dedicated test in this PR.
