# PR 36870 mining waitNext steady clock

## In one breath

`waitNext` times the wait and the one-second fee tick with the steady clock.

Wall clock jumps no longer stretch or shrink the wait.

Frozen mocktime no longer blocks the timeout.

## What the author is solving

`waitNext` measured timeout and fee tick with `NodeClock`.

`waitTipChanged` already used the steady clock.

A wall clock jump changed how long `waitNext` waited.

Frozen mocktime stopped `waitNext` from timing out.

Steady clock now drives the deadline and the fee tick.

`NodeClock` stays only for the testnet twenty-minute rule.

The testnet rule must compare node time with the tip timestamp.

## What to notice in the commits

One commit touches `WaitAndCreateNewBlock` in `block_template_manager.cpp`.

Loop start and loop refresh call `std::chrono::steady_clock::now()`.

The testnet twenty-minute check calls `NodeClock::now()` on purpose.

Until #36862 merges, `faketime --exclude-monotonic` can expose a `waitNext` race in `interface_ipc_mining.py`.

The race was hidden when `waitNext` followed wall time under faketime.
