#!/usr/bin/env python3

import argparse
import logging
import sys

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

try:
    from bcc import BPF, USDT
except ImportError:
    print(
        "Failed to import bcc module, please see https://github.com/iovisor/bcc/blob/master/INSTALL.md for how to install",
        file=sys.stderr,
    )
    sys.exit(1)


LOG = logging.getLogger(__name__)


def debug(msg: str) -> None:
    return LOG.debug(msg)


def info(msg: str) -> None:
    return LOG.info(msg)


TRACE_FUNC_TEMPLATE = """
int {name}(struct pt_regs* ctx) {{
  struct event_t ev;

  uintptr_t addr = 0;
  bpf_usdt_readarg(1, ctx, &addr);
  int result = bpf_probe_read_user(
    ev.module_name,
    sizeof(ev.module_name),
    (void*)addr
  );
  if (result != 0) {{
    return result;
  }}

  int success = 0;
  #if {done}
  bpf_usdt_readarg(2, ctx, &success);
  #endif

  ev.timestamp = bpf_ktime_get_ns();
  ev.pid = bpf_get_current_pid_tgid();
  ev.done = {done};
  ev.success = (u8)success;

  events.perf_submit(ctx, &ev, sizeof(ev));

  return 0;
}}
"""

TRACE_FUNC_START = TRACE_FUNC_TEMPLATE.format(name="trace_import_start", done=0)

TRACE_FUNC_DONE = TRACE_FUNC_TEMPLATE.format(
    name="trace_import_done",
    done=1,
)


PROGRAM = rf"""
#define MODULE_NAME_LEN 128

struct event_t {{
  char module_name[MODULE_NAME_LEN];
  u64 timestamp;
  u32 pid;
  u8 done;
  u8 success;
}};
BPF_PERF_OUTPUT(events);

{TRACE_FUNC_START}

{TRACE_FUNC_DONE}
"""


@dataclass(frozen=True, slots=True)
class ImportEvent:
    pid: int
    module_name: str
    timestamp: int
    done: bool
    success: bool

    @property
    def start(self) -> bool:
        return not self.done


@dataclass(frozen=True, slots=True)
class ImportResult:
    pid: int
    module_name: str
    load_time_ns: int
    success: bool


class ImportTracker:
    def __init__(self, callback: Callable[[ImportResult], None]) -> None:
        self._callback = callback
        self._events: dict[int, dict[str, ImportEvent]] = {}
        self._log: list[ImportEvent] = []

    def register_import_event(self, event: ImportEvent) -> None:
        """
        Register that a module either started or finished loading.
        """

        debug(f"Received event {event!r}")

        self._log.append(event)

        pid = event.pid
        module_name = event.module_name
        events = self._events.setdefault(pid, {})

        # If an event already exists, it should be the start event and this new
        # one should be the end event.
        if existing := events.get(module_name):
            assert existing.start
            if event.done:
                delta_ns = event.timestamp - existing.timestamp
                success = event.success
                self._callback(ImportResult(pid, module_name, delta_ns, success))
            else:
                debug(
                    "Got duplicate event for process {pid} starting to load {module_name!r}"
                )
                events[module_name] = event
            return

        # Otherwise this should be a new start event.
        if event.start:
            events[module_name] = event
            return

        # If it's an unmatched end event, it just gets dropped.
        debug("Missed an event for process {pid} starting to load {module_name!r}")

    def get_log(self) -> Sequence[ImportEvent]:
        """
        Get all import events, in the order that they were registered.
        """

        return self._log


def get_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print extra messages for debugging purposes",
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "-p",
        "--pid",
        type=int,
        help="ID of the process to profile",
    )
    input_group.add_argument(
        "-l",
        "--lib",
        type=Path,
        help="Path to a library or executable to load USDT probes from",
    )
    return parser.parse_args()


def enable_probes(usdt: USDT) -> None:
    usdt.enable_probe("python:import__find__load__start", "trace_import_start")
    usdt.enable_probe("python:import__find__load__done", "trace_import_done")


def init_usdt(args: argparse.Namespace) -> None:
    if args.pid:
        debug(f"Loading USDT probes from process {args.pid}")
        usdt = USDT(pid=args.pid)
    elif args.lib:
        debug(f"Loading USDT probes from file {args.lib}")
        usdt = USDT(path=str(args.lib))
    else:
        raise RuntimeError("Expected one of --pid or --lib")

    debug("Listing USDT probes found:")
    for probe in usdt.enumerate_probes():
        debug(f"  {probe.provider.decode()}:{probe.name.decode()}")

    enable_probes(usdt)

    info("Probes activated:")
    for probe in usdt.enumerate_active_probes():
        info(f"  Binary: {probe[0].decode()}, Function: {probe[1].decode()}")

    return usdt


def print_import_result(result: ImportResult) -> None:
    pid = result.pid
    module_name = result.module_name
    time_us = result.load_time_ns // 1000
    successfully = "successfully" if result.success else "unsuccessfully"
    print(f"Process {pid} {successfully} loaded module {module_name!r} in {time_us}us")


def main() -> None:
    args = get_args()

    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=log_level, format="%(message)s")

    usdt = init_usdt(args)

    bpf = BPF(text=PROGRAM, usdt_contexts=[usdt], cflags=["-Wno-macro-redefined"])
    tracker = ImportTracker(print_import_result)

    def process_event(cpu: int, data: object, size: int) -> None:
        nonlocal tracker

        event = bpf["events"].event(data)
        pid = event.pid
        module_name = event.module_name.decode("ascii")

        tracker.register_import_event(
            ImportEvent(pid, module_name, event.timestamp, event.done, event.success)
        )

    bpf["events"].open_perf_buffer(process_event)

    while True:
        try:
            bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            break


if __name__ == "__main__":
    main()
