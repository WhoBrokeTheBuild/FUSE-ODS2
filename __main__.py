# MIT License
# 
# Copyright (c) 2021 Stephen Lane-Walsh
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os
import sys
import struct

from stat import *
from fuse import FUSE, Operations

BLOCK_SIZE = int(512)

def VMStoUNIX(timestamp):
    # VMS Timestamp of Jan 1, 1970
    offset = 35067168003000000
    return (timestamp - 35067168003000000) / 1e7

class FileID:
    FORMAT = '<HHBB'
    SIZE = struct.calcsize(FORMAT)

    def __init__(self, disk):
        (
            W_NUM,
            W_SEQ,
            B_RVN,
            B_NMX,
        ) = struct.unpack_from(self.FORMAT, disk)

        self.file_number = (B_NMX << 16) | W_NUM
        self.sequence_number = W_SEQ
        self.relative_volume_number = B_RVN

    def __repr__(self):
        return "{}/{}".format(self.file_number, self.sequence_number)

class DirectoryEntry:
    FORMAT = '<H6s'
    SIZE = struct.calcsize(FORMAT)

    def __init__(self, disk, offset):
        (
            W_VERSION,
            W_FID,
        ) = struct.unpack_from(self.FORMAT, disk, offset)

        self.fid = FileID(W_FID)

    def __repr__(self):
        return repr(self.fid)

class DirectoryRecord:
    def __init__(self, disk, offset):
        FORMAT = '<HHBB'
        (
            W_SIZE,
            W_VERLIMIT,
            B_FLAGS,
            B_NAMECOUNT,
        ) = struct.unpack_from(FORMAT, disk, offset)
        offset += struct.calcsize(FORMAT)

        self.size = W_SIZE + 2

        T_NAME = disk[offset:offset + B_NAMECOUNT]
        offset += B_NAMECOUNT

        self.name = T_NAME.decode("ascii")
        if self.name.endswith('.'):
            self.name = self.name[:-1]
            
        # Align
        if (offset & 1) == 1:
            offset += 1

        self.entries = []
        entries_count = int((self.size - B_NAMECOUNT) / DirectoryEntry.SIZE)
        for i in range(entries_count):
            self.entries.append(DirectoryEntry(disk, offset))
            offset += DirectoryEntry.SIZE

class File:
    def __init__(self, disk, offset):
        FORMAT = '<BBBBHH6s6s32sI2xB'
        (
            B_IDOFFSET,
            B_MPOFFSET,
            B_ACOFFSET,
            B_RSOFFSET,
            W_SEG_NUM,
            W_STRUCLEV,
            W_FID,
            W_EXT_FID,
            W_RECATTR,
            L_FILECHAR,
            B_MAP_INUSE,
        ) = struct.unpack_from(FORMAT, disk, offset)

        self.fid = FileID(W_FID)
        self.ext_fid = FileID(W_EXT_FID)

        self.is_directory = (L_FILECHAR & 8192) == 8192

        self.create_time = 0
        self.revision_time = 0
        if B_IDOFFSET != 0xFF:
            self.read_ident(disk, offset + (B_IDOFFSET * 2))
        
        self.map = []
        self.total_block_count = 0
        self.size = BLOCK_SIZE # ?
        if B_MPOFFSET != 0xFF:
            self.read_map(disk, offset + (B_MPOFFSET * 2), B_MAP_INUSE)

        self.records = []
        if self.is_directory:
            self.read_directory_records(disk)
    
    def read_ident(self, disk, offset):
        FORMAT = '<20sHQQQQ66s'
        (
            T_FILENAME,
            W_REVISION,
            Q_CREATE,
            Q_REVDATE,
            Q_EXPDATE,
            Q_BAKDATE,
            T_FILENAMEEXT,
        ) = struct.unpack_from(FORMAT, disk, offset)

        self.create_time = VMStoUNIX(Q_CREATE)
        self.revision_time = VMStoUNIX(Q_REVDATE)

        self.name = (T_FILENAME + T_FILENAMEEXT).decode('ascii').strip()
        self.name = self.name.rsplit(';', 1)[0]
        if self.name.endswith('.'):
            self.name = self.name[:-1]

    def read_map(self, disk, offset, B_MAP_INUSE):
        end_offset = offset + (B_MAP_INUSE * 2)

        while offset < end_offset:
            V_FORMAT = (disk[offset + 1] & 0xC0) >> 6

            block_count = 0
            lbn = 0

            if V_FORMAT == 0:
                (
                    W_WORD0,
                ) = struct.unpack_from('<H', disk, offset)
                offset += 2

                print("V_FORMAT == 0, unsupported")

            elif V_FORMAT == 1:
                (
                    B_COUNT1,
                    V_HIGHLBN,
                    W_LOWLBN,
                ) = struct.unpack_from('<BBH', disk, offset)
                offset += 4

                # Mask V_FORMAT
                V_HIGHLBN &= 0x3F

                block_count = B_COUNT1
                lbn = (V_HIGHLBN << 16) | W_LOWLBN

            elif V_FORMAT == 2:
                (
                    V_COUNT2,
                    W_LBN2,
                ) = struct.unpack_from('<HH', disk, offset)
                offset += 6

                # Mask V_FORMAT
                V_COUNT2 &= 0x3FFF

                block_count = V_COUNT2
                lbn = W_LBN2

            elif V_FORMAT == 3:
                (
                    V_COUNT2,
                    W_LOWCOUNT,
                    L_LBN3,
                ) = struct.unpack_from('BBH', disk, offset)
                offset += 8

                # Mask V_FORMAT
                V_COUNT2 &= 0x3FFF

                block_count = (V_COUNT2 << 16) | W_LOWCOUNT
                lbn = L_LBN3

            self.map.append({
                'lbn': lbn,
                'block_count': block_count,
            })
            self.total_block_count += block_count

        self.size = self.total_block_count * BLOCK_SIZE

    def read_directory_records(self, disk):
        for vbn in range(1, self.total_block_count):
            lbn = self.get_lbn_for_vbn(vbn)
            offset = lbn * BLOCK_SIZE
            for i in range(62):
                ( record_size, ) = struct.unpack_from('h', disk, offset)
                if record_size < 0:
                    break

                record = DirectoryRecord(disk, offset)
                offset += record.size

                self.records.append(record)

    def get_lbn_for_vbn(self, vbn):
        vbn -= 1

        base_block_count = 0
        for ptr in self.map:
            r = range(base_block_count, base_block_count + ptr['block_count'])
            if vbn in r:
                return ptr['lbn'] + (vbn - base_block_count)
            
            base_block_count += ptr['block_count']

    def get_record_by_name(self, name):
        for r in self.records:
            if r.name == name:
                return r

class ODS2(Operations):

    def __init__(self, filename, mountpoint):
        file = open(filename, 'rb')
        self.disk = file.read()
        file.close()

        self.mountpoint = mountpoint

        print("Disk has {} Logical Blocks".format(int(len(self.disk) / BLOCK_SIZE)))

        self.read_home_block()

    def read_home_block(self):
        FORMAT = '<IIIHHHHHHIIHHHHHHI4xHH2xHQBBHQQQ20s20s320xI12s12s12s12s2xH'
        (
            L_HOMELBN,
            L_ALHOMELBN,
            L_ALTIDXLBN,
            W_STRUCLEV,
            W_CLUSTER,
            W_HOMEVBN,
            W_ALHOMEVBN,
            W_ALTIDXVBN,
            W_IBMAPVBN,
            L_IBMAPLBN,
            L_MAXFILES,
            W_IBMAPSIZE,
            W_RESFILES,
            W_DEVTYPE,
            W_RVN,
            W_SETCOUNT,
            W_VOLCHAR,
            L_VOLOWNER,
            W_PROTECT,
            W_FILEPROT,
            W_CHECKSUM1,
            Q_CREDATE,
            B_WINDOW,
            B_LRU_LIM,
            W_EXTEND,
            Q_RETAINMIN,
            Q_RETAINMAX,
            Q_REVDATE,
            R_MIN_CLASS,
            R_MAX_CLASS,
            L_SERIALNUM,
            T_STRUCNAME,
            T_VOLNAME,
            T_OWNERNAME,
            T_FORMAT,
            W_CHECKSUM2,
        ) = struct.unpack_from(FORMAT, self.disk, BLOCK_SIZE)

        self.structure_name = T_STRUCNAME.decode("ascii")
        self.volume_name = T_VOLNAME.decode("ascii")
        self.owner_name = T_OWNERNAME.decode("ascii")
        self.format = T_FORMAT.decode("ascii")
        self.reserved_file_count = W_RESFILES

        self.bitmap_blocks = W_IBMAPSIZE

        print("Structure Name: {}".format(self.structure_name))
        print("Volume Name: {}".format(self.volume_name))
        print("Owner Name: {}".format(self.owner_name))
        print("Format: {}".format(self.format))

        index_offset = (L_IBMAPLBN + W_IBMAPSIZE) * BLOCK_SIZE
        self.index_file = File(self.disk, index_offset)

        # Skip the first 3 clusters
        for m in self.index_file.map[:3]:
            self.index_file.total_block_count -= m['block_count']
        self.index_file.map = self.index_file.map[3:]

        count = 0

        self.mfd = None
        self.files = [None] * self.index_file.total_block_count
        for vbn in range(1, self.index_file.total_block_count):
            lbn = self.index_file.get_lbn_for_vbn(self.bitmap_blocks + vbn)
            offset = lbn * BLOCK_SIZE

            if self.disk[offset] == 0:
                break
            
            file = File(self.disk, offset)
            if file.name == '000000.DIR':
                self.mfd = file

            index = file.fid.file_number - 1
            self.files[index] = File(self.disk, offset)
            count += 1

        print("Read {} files".format(count))

        self.mfd.size = 666

    def get_file_by_path(self, path):
        if path.startswith('/'):
            path = path[1:]

        if path.endswith('/'):
            path = path[:-1]

        parts = []
        if len(path) > 0:
            parts = path.split('/')

        file = self.mfd
        for p in parts:
            rec = file.get_record_by_name(p)
            index = rec.entries[0].fid.file_number - 1
            file = self.files[index]
        return file

    def getattr(self, path, fh):
        disk_st = os.lstat(sys.argv[1])

        file = self.get_file_by_path(path)

        st = {
            'st_size': file.size,
            'st_ctime': file.create_time,
            'st_atime': file.revision_time,
            'st_mtime': file.revision_time,
            'st_mode': S_IFREG | 0o444,
            'st_nlink': 0,
            'st_uid': disk_st.st_uid,
            'st_gid': disk_st.st_gid,
        }

        if file.is_directory:
            st['st_mode'] = S_IFDIR | 0o555

        return st

    def readdir(self, path, fh):
        dirents = ['.', '..']
        file = self.get_file_by_path(path)

        for r in file.records:
            file_number = r.entries[0].fid.file_number
            if file_number <= self.reserved_file_count:
                continue
            
            dirents.append(r.name)

        for r in dirents:
            yield r

    def readlink(self, path):
        if path == '/000000.DIR':
            return self.mountpoint

        return ''

    def read(self, path, length, offset, fh):
        if (offset % BLOCK_SIZE) != 0:
            print("unaligned offset")
            return bytes()

        file = self.get_file_by_path(path)
        if file == None:
            return bytes()

        data = bytearray()

        data_offset = 0
        end_offset = offset + length
        if end_offset > file.size:
            end_offset = file.size

        while offset < end_offset:
            vbn = int(offset / BLOCK_SIZE) + 1
            lbn = file.get_lbn_for_vbn(vbn)
            disk_offset = lbn * BLOCK_SIZE
            data[data_offset:data_offset + BLOCK_SIZE] = self.disk[disk_offset:disk_offset + BLOCK_SIZE]

            offset += BLOCK_SIZE
            data_offset += BLOCK_SIZE

        return bytes(data)

if __name__ == '__main__':
    FUSE(ODS2(sys.argv[1], sys.argv[2]), sys.argv[2], nothreads=True, foreground=True)
