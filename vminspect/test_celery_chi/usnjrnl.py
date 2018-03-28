# Copyright (c) 2016-2017, Matteo Cafasso
# All rights reserved.

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:

# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.

# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.

# 3. Neither the name of the copyright holder nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.

# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


"""Module for parsing Windows Update Sequence Number Journal."""


import io
import struct

from itertools import count
from collections import namedtuple
from datetime import datetime, timedelta


def usn_journal(path):
    """Iterates over the Windows Update Sequence Number entries
    contained in the file at the given path.

    """
    with open(path, 'rb') as journal_file:
        yield from parse_journal_file(journal_file)


def parse_journal_file(journal_file):
    """Iterates over the journal's file taking care of paddings."""
    counter = count()

    for block in read_next_block(journal_file):
        block = remove_nullchars(block)

        while len(block) > MIN_RECORD_SIZE:
            header = RECORD_HEADER.unpack_from(block)
            size = header[0]

            try:
                yield parse_record(header, block[:size])

                next(counter)
            except RuntimeError:
                yield CorruptedUsnRecord(next(counter))
            finally:
                block = remove_nullchars(block[size:])

        journal_file.seek(- len(block), 1)


def parse_record(header, record):
    """Parses a record according to its version."""
    major_version = header[1]

    try:
        return RECORD_PARSER[major_version](header, record)
    except (KeyError, struct.error) as error:
        raise RuntimeError("Corrupted USN Record") from error


def usn_v2_record(header, record):
    """Extracts USN V2 record information."""
    length, major_version, minor_version = header
    fields = V2_RECORD.unpack_from(record, RECORD_HEADER.size)

    return UsnRecord(length,
                     float('{}.{}'.format(major_version, minor_version)),
                     fields[0] | fields[1] << 16,  # 6 bytes little endian mft
                     fields[2],  # 2 bytes little endian mft sequence
                     fields[3] | fields[4] << 16,  # 6 bytes little endian mft
                     fields[5],  # 2 bytes little endian mft sequence
                     fields[6],
                     (datetime(1601, 1, 1) +
                      timedelta(microseconds=(fields[7] / 10))).isoformat(' '),
                     unpack_flags(fields[8], REASONS),
                     unpack_flags(fields[9], SOURCEINFO),
                     fields[10],
                     unpack_flags(fields[11], ATTRIBUTES),
                     str(struct.unpack_from('{}s'.format(fields[12]).encode(),
                                            record, fields[13])[0], 'utf16'))


def usn_v3_record(header, record):
    """Extracts USN V3 record information."""
    length, major_version, minor_version = header
    fields = V3_RECORD.unpack_from(record, RECORD_HEADER.size)

    return UsnRecord(length,
                     float('{}.{}'.format(major_version, minor_version)),
                     fields[0],
                     fields[1],
                     fields[2],
                     fields[3],
                     fields[4],
                     (datetime(1601, 1, 1) +
                      timedelta(microseconds=(fields[5] / 10))).isoformat(' '),
                     unpack_flags(fields[6], REASONS),
                     unpack_flags(fields[7], SOURCEINFO),
                     fields[8],
                     unpack_flags(fields[9], ATTRIBUTES),
                     str(struct.unpack_from('{}s'.format(fields[10]).encode(),
                                            record, fields[11])[0], 'utf16'))


def usn_v4_record(header, record):
    """Extracts USN V4 record information."""
    length, major_version, minor_version = header
    fields = V4_RECORD.unpack_from(record, RECORD_HEADER.size)

    raise NotImplementedError('Not implemented')


def unpack_flags(value, flags):
    """Multiple flags might be packed in the same field."""
    try:
        return [flags[value]]
    except KeyError:
        return [flags[k] for k in sorted(flags.keys()) if k & value > 0]


def read_next_block(infile, block_size=io.DEFAULT_BUFFER_SIZE):
    """Iterates over the file in blocks."""
    chunk = infile.read(block_size)

    while chunk:
        yield chunk

        chunk = infile.read(block_size)


def remove_nullchars(block):
    """Strips NULL chars taking care of bytes alignment."""
    data = block.lstrip(b'\00')

    padding = b'\00' * ((len(block) - len(data)) % 8)

    return padding + data


RECORD_PARSER = {2: usn_v2_record,
                 3: usn_v3_record,
                 4: usn_v4_record}


RECORD_HEADER = struct.Struct('Ihh')
# https://msdn.microsoft.com/en-us/library/windows/desktop/aa365722%28v=vs.85%29.aspx
V2_RECORD = struct.Struct('<LHHLHHqqIIIIhh')
# https://msdn.microsoft.com/en-us/library/windows/desktop/hh802708%28v=vs.85%29.aspx
V3_RECORD = struct.Struct('<QQQQqqIIIIhh')
# https://msdn.microsoft.com/en-us/library/windows/desktop/mt684964%28v=vs.85%29.aspx
V4_RECORD = struct.Struct('QQqqIIIIhh')  # TODO


MIN_RECORD_SIZE = RECORD_HEADER.size + min(V2_RECORD.size,
                                           V3_RECORD.size,
                                           V4_RECORD.size)


UsnRecord = namedtuple('UsnRecord', ('length',
                                     'version',
                                     'file_reference_number',
                                     'file_reference_number_sequence',
                                     'parent_file_reference_number',
                                     'parent_file_reference_number_sequence',
                                     'update_sequence_number',
                                     'timestamp',
                                     'reasons',
                                     'source_info',
                                     'security_id',
                                     'file_attributes',
                                     'file_name'))
CorruptedUsnRecord = namedtuple('CorruptedUsnRecord', ('index'))


REASONS = {0x00: " ",
           0x01: "DATA_OVERWRITE",
           0x02: "DATA_EXTEND",
           0x04: "DATA_TRUNCATION",
           0x10: "NAMED_DATA_OVERWRITE",
           0x20: "NAMED_DATA_EXTEND",
           0x40: "NAMED_DATA_TRUNCATION",
           0x100: "FILE_CREATE",
           0x200: "FILE_DELETE",
           0x400: "EA_CHANGE",
           0x800: "SECURITY_CHANGE",
           0x1000: "RENAME_OLD_NAME",
           0x2000: "RENAME_NEW_NAME",
           0x4000: "INDEXABLE_CHANGE",
           0x8000: "BASIC_INFO_CHANGE",
           0x10000: "HARD_LINK_CHANGE",
           0x20000: "COMPRESSION_CHANGE",
           0x40000: "ENCRYPTION_CHANGE",
           0x80000: "OBJECT_ID_CHANGE",
           0x100000: "REPARSE_POINT_CHANGE",
           0x200000: "STREAM_CHANGE",
           0x80000000: "CLOSED"}


# https://msdn.microsoft.com/en-us/library/windows/desktop/gg258117%28v=vs.85%29.aspx
ATTRIBUTES = {0x01: "READONLY",
              0x02: "HIDDEN",
              0x04: "SYSTEM",
              0x10: "DIRECTORY",
              0x20: "ARCHIVE",
              0x40: "DEVICE",
              0x80: "NORMAL",
              0x100: "TEMPORARY",
              0x200: "SPARSE_FILE",
              0x400: "REPARSE_POINT",
              0x800: "COMPRESSED",
              0x1000: "OFFLINE",
              0x2000: "NOT_CONTENT_INDEXED",
              0x4000: "ENCRYPTED",
              0x8000: "INTEGRITY_STREAM",
              0x10000: "VIRTUAL",
              0x20000: "NO_SCRUB_DATA"}


SOURCEINFO = {0x00: " ",
              0x01: "DATA_MANAGEMENT",
              0x02: "AUXILIARY_DATA",
              0x04: "REPLICATION_MANAGEMENT"}
