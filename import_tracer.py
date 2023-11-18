#!/usr/bin/env python3

import argparse
import logging

from pathlib import Path

from bcc import BPF, USDT


TRACE_FUNC_TEMPLATE="""
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

  ev.timestamp = bpf_ktime_get_ns();
  ev.pid = bpf_get_current_pid_tgid();
  ev.is_done = {done};

  events.perf_submit(ctx, &ev, sizeof(ev));

  return 0;
}}
"""

TRACE_FUNC_START = TRACE_FUNC_TEMPLATE.format(name="trace_import_start", done=0)

TRACE_FUNC_DONE = TRACE_FUNC_TEMPLATE.format(
    name="trace_import_done",
    done=1,
)


PROGRAM=rf"""
#define MODULE_NAME_LEN 128

struct event_t {{
  char module_name[MODULE_NAME_LEN];
  u64 timestamp;
  u32 pid;
  u8 is_done;
}};
BPF_PERF_OUTPUT(events);

{TRACE_FUNC_START}

{TRACE_FUNC_DONE}
"""


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


LOG = logging.getLogger(__name__)

def debug(msg: str) -> None:
    return LOG.debug(msg)


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

    debug("Probes activated:")
    for probe in usdt.enumerate_active_probes():
        debug(f"  Binary: {probe[0].decode()}, Function: {probe[1].decode()}")

    return usdt


def main() -> None:
    args = get_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format="%(message)s")

    usdt = init_usdt(args)

    bpf = BPF(text=PROGRAM, usdt_contexts=[usdt], cflags=["-Wno-macro-redefined"])
    events = {}

    def process_event(cpu, data, size) -> None:
        event = bpf["events"].event(data)
        pid = event.pid
        module_name = event.module_name.decode("ascii")

        pid_events = events.setdefault(pid, {})

        if not event.is_done:
            if prev_event := pid_events.get(module_name):
                debug("Got duplicate event for process {pid} starting to load {module_name!r}")

            pid_events[module_name] = event.timestamp
            return

        prev_timestamp = pid_events.get(module_name)
        if prev_timestamp is not None:
            delta_ns = event.timestamp - prev_timestamp
            delta_us = delta_ns // 1000
            print(f"Process {pid} loaded module {module_name!r} in {delta_us}us")
        else:
            debug("Missed an event for process {pid} starting to load {module_name!r}")

    bpf["events"].open_perf_buffer(process_event)

    while True:
        bpf.perf_buffer_poll()


if __name__ == "__main__":
    main()
