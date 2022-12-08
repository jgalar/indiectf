#!/usr/bin/env python3
#
# Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only
#

from ensurepip import version
from io import BufferedReader
from typing import Generator, Tuple, Optional, Type
import struct
import logging
import abc


class InvalidIndexFile(Exception):
    def __init__(self, msg: str) -> None:
        super().__init__(msg)


class IndexVersion:
    def __init__(self, major, minor) -> None:
        self._major = major
        self._minor = minor

    def __eq__(self, other) -> bool:
        if not isinstance(other, type(self)):
            return False

        return self._major == other._major and self._minor == other._minor

    def __str__(self) -> str:
        return "{major}.{minor}".format(major=self._major, minor=self._minor)


class IndexEntry(abc.ABC):
    def __init__(self) -> None:
        logging.debug("Creating index")
        pass

    @abc.abstractproperty
    def offset_bytes(self) -> int:
        return 0

    @abc.abstractproperty
    def packet_size_bits(self) -> int:
        return 0

    @abc.abstractproperty
    def content_size_bits(self) -> int:
        return 0

    @abc.abstractproperty
    def timestamp_begin_cycles(self) -> int:
        return 0

    @abc.abstractproperty
    def timestamp_end_cycles(self) -> int:
        return 0

    @abc.abstractproperty
    def events_discarded_count(self) -> int:
        return 0

    @abc.abstractproperty
    def channel_id(self) -> int:
        return 0

    @abc.abstractproperty
    def stream_id(self) -> Optional[int]:
        return None

    @abc.abstractproperty
    def packet_sequence_number(self) -> Optional[int]:
        return None


class _IndexEntry10(IndexEntry):
    def __init__(self, file: BufferedReader) -> None:
        super().__init__()
        index_entry_fmt = ">QQQQQQQ"
        (
            self._offset_bytes,
            self._packet_size,
            self._content_size,
            self._timestamp_begin,
            self._timestamp_end,
            self._discarded_events,
            self._stream_id,
        ) = struct.unpack(index_entry_fmt, file.read(struct.calcsize(index_entry_fmt)))

    @property
    def offset_bytes(self) -> int:
        return self._offset_bytes

    @property
    def packet_size_bits(self) -> int:
        return self._packet_size

    @property
    def content_size_bits(self) -> int:
        return self._content_size

    @property
    def timestamp_begin_cycles(self) -> int:
        return self._timestamp_begin

    @property
    def timestamp_end_cycles(self) -> int:
        return self._timestamp_end

    @property
    def events_discarded_count(self) -> int:
        return self._discarded_events

    @property
    def channel_id(self) -> int:
        return self._stream_id


class _IndexEntry11(_IndexEntry10):
    def __init__(self, file: BufferedReader) -> None:
        index_entry_supplementary_fields_fmt = ">QQ"
        super().__init__(file)
        self._stream_instance_id, self._packet_sequence_number = struct.unpack(
            index_entry_supplementary_fields_fmt,
            file.read(struct.calcsize(index_entry_supplementary_fields_fmt)),
        )

    @property
    def stream_id(self) -> int:
        return self._stream_instance_id

    @property
    def packet_sequence_number(self) -> int:
        return self._packet_sequence_number


class IndexFile:
    def __init__(self, file: BufferedReader) -> None:
        self._file: BufferedReader = file

        # Read and decode file header
        index_file_header_fmt = ">IIII"
        logging.debug(
            "Expected file header size is {} bytes".format(
                struct.calcsize(index_file_header_fmt)
            )
        )
        (
            magic,
            major_version,
            minor_version,
            packet_index_entry_size_bytes,
        ) = struct.unpack(
            index_file_header_fmt,
            self._file.read(struct.calcsize(index_file_header_fmt)),
        )

        if magic != int("0xC1F1DCC1", base=16):
            raise InvalidIndexFile(
                "Unexepected magic value: expected=0xC1F1DCC1, got={}".format(
                    hex(magic)
                )
            )
        logging.debug("Magic value validated successfully")
        logging.debug(
            "Packet file header read: version=`{version_major}.{version_minor}`, index_entry_size=`{index_entry_size}`".format(
                version_major=major_version,
                version_minor=minor_version,
                index_entry_size=packet_index_entry_size_bytes,
            )
        )

        self._version: IndexVersion = IndexVersion(major_version, minor_version)
        self._position_after_file_header = self._file.tell()

    @property
    def format_version(self) -> IndexVersion:
        return self._version

    @property
    def entries(self) -> Generator[Type[IndexEntry], None, None]:
        self._file.seek(self._position_after_file_header)

        while len(self._file.peek()) != 0:
            if self.format_version == IndexVersion(1, 0):
                yield _IndexEntry10(self._file)
            elif self.format_version == IndexVersion(1, 1):
                yield _IndexEntry11(self._file)
            else:
                raise NotImplementedError(
                    "Unknown index format {version}".format(
                        version=str(self.format_version)
                    )
                )
