#!/usr/bin/env python3
#
# Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only
#

from io import BufferedReader
from typing import Any, Dict
import click
import logging
import sys
import struct
from . import lttngindex


def print_file_properties(props: Dict[str, Any]) -> None:
    longest_name_len = 0
    for name in props.keys():
        longest_name_len = max(longest_name_len, len(name))

    for name, value in props.items():
        padded_name = name + (" " * (longest_name_len - len(name)))
        click.echo(
            click.style(padded_name, fg="cyan", bold=True)
            + click.style(" ")
            + click.style(str(value), fg="white", bold=True)
        )


def print_entry_properties(props: Dict[str, Any]) -> None:
    longest_name_len = 0
    for name in props.keys():
        longest_name_len = max(longest_name_len, len(name))

    for name, value in props.items():
        if value is None:
            continue

        padded_name = name + (" " * (longest_name_len - len(name)))
        if type(value) is int:
            click.echo(
                click.style("\t")
                + click.style(padded_name, fg="green", bold=True)
                + click.style(" ")
                + click.style(
                    f"{value:,}".format(value=value).replace(",", " "),
                    fg="white",
                    bold=True,
                ),
            )
        else:
            click.echo(
                click.style("\t")
                + click.style(padded_name, fg="green", bold=True)
                + click.style(" ")
                + click.style(str(value), fg="white", bold=True),
            )


@click.group()
@click.option("-d", "--debug", is_flag=True, help="Set logging level to DEBUG")
def cli(debug: bool) -> None:
    """
    IndieCTF is an LTTng CTF index visualizer.

    Supported commands:
      - dump-index:
        dump an index file's content to the terminal

    Use --help on any of the commands for more information on their role and options.
    """
    logging.basicConfig(level=logging.DEBUG if debug else logging.INFO)


@cli.command(
    name="dump-index", short_help="dump the contents of an index file to the terminal"
)
@click.argument("index_file", nargs=1, type=click.File(mode="rb"))
def dump_index(
    index_file: BufferedReader,
) -> None:
    """
    Dump the contents of an index file to stdout.
    """
    logging.debug("Opening index file: path=`{}`".format(index_file.name))
    index = lttngindex.IndexFile(index_file)
    print_file_properties({"name": index_file.name, "version": index.format_version})

    entry_id = 0
    for entry in index.entries:
        click.echo(
            click.style(
                "Index entry #{index}".format(index=entry_id), fg="yellow", bold=True
            )
        )
        print_entry_properties(
            {
                "offset (bytes)": entry.offset_bytes,
                "packet size (bits)": entry.packet_size_bits,
                "content size (bits)": entry.content_size_bits,
                "timestamp begin (cycles)": entry.timestamp_begin_cycles,
                "timestamp end (cycles)": entry.timestamp_end_cycles,
                "discarded events": entry.events_discarded_count,
                "channel id": entry.channel_id,
                "stream id": entry.stream_id,
                "packet sequence number": entry.packet_sequence_number,
            }
        )
        click.echo()
        entry_id = entry_id + 1


if __name__ == "__main__":
    sys.exit(cli())  # pragma: no cover
