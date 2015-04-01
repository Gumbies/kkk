import random
import struct

try:
    import cStringIO as StringIO
except ImportError:
    import StringIO


class Chunk(object):
    """
    A chunk to read from the client
    """

    def __init__(self, offset, size, data=None):
        self.offset = offset
        self.size = size
        self.address = self.offset
        self.blob_size = self.size
        self.data = data
        self.blob_data = None

    def compile(self, data):
        if self.data:
            chunk = self.data[self.offset:self.offset+self.size]
        else:
            chunk = data[self.offset:self.offset+self.size]

        header = struct.pack('!LL', self.address, self.size)
        return header + chunk


class GarbageChunk(Chunk):
    """
    A chunk which really sends garbage data
    """

    def __init__(self, offset, size, data):
        super(GarbageChunk, self).__init__(offset, size, data)


class PhysChunk(Chunk):
    """
    A chunk of physical (encrypted) memory to read
    """
    pass


class EccChunk(Chunk):
    """
    A chunk of memory to calculate the ecc for
    """

    def __init__(self, offset, size):
        super(EccChunk, self).__init__(offset, size)
        # calculate the magic address crap
        self.address = (self.offset >> 6) + 0x80010000
        self.blob_size = (self.size >> 6)


class PhysGarbageChunk(GarbageChunk, PhysChunk):
    """
    A physical chunk which actually sends garbage
    """
    pass


class EccGarbageChunk(GarbageChunk, EccChunk):
    """
    An ecc chunk which actually sends garbage
    """
    pass


# list of chunks we always need
CHUNKS = (
    PhysChunk(0x40,      0x30),
    PhysChunk(0x100C0,   0x40),
    PhysChunk(0x10350,   0x30),
    PhysChunk(0x16100,   0x40),
    PhysChunk(0x16D20,   0x60),
    EccChunk(0x80,     0xFF80),
    EccChunk(0x10380,  0x5D80),
    EccChunk(0x16D80,  0x9280),
    EccChunk(0x20000, 0x10000),
    EccChunk(0x30000, 0x10000)
)


# parameters to control obfuscation
PHYS_MIN = 1
PHYS_MAX = len(CHUNKS) / 4
ECC_MIN = 1
ECC_MAX = len(CHUNKS) / 4
GARBAGE = True
SHUFFLE = True
SCRAMBLE = False


class ChunkBuilder(object):
    """
    Given clean HV data, build a payload to send to the client which
    is random in order and contains obfuscation
    """

    def __init__(self, hv_data, garbage_data):
        self.hv_data = hv_data
        self.garbage_data = garbage_data

    def garbage(self, chunks):
        """
        add garbage chunks
        """
        pass

    def scramble(self, chunks):
        """
        scramble the addresses in each chunk
        """
        pass

    def compile(self, chunks):
        """
        compile each chunk
        """

        data = ''.join([chunk.compile(self.hv_data) for chunk in chunks])
        num = len(chunks)
        return num, data

    def __call__(self):
        """
        build the list of chunks and add the obfuscation
        """

        # copy chunks local
        chunks = list(CHUNKS)

        # add garbage chunks
        if GARBAGE:
            self.garbage(chunks)

        # scramble addresses of chunks
        if SCRAMBLE:
            self.scramble(chunks)

        # shuffle the chunks
        if SHUFFLE:
            random.shuffle(chunks)

        return self.compile(chunks)


HEADER_FMT = '!LL'


class ChunkReader(object):
    """
    Read chunks from a byte string
    """

    @classmethod
    def read(cls, data):
        return cls()(data)

    def __init__(self):
        # construct copies of the chunks
        self.chunks = [chunk.__class__(chunk.offset, chunk.size) for chunk in CHUNKS]

    def find_chunk(self, address, blob_size):
        for chunk in self.chunks:
            if chunk.address == address and chunk.blob_size == blob_size:
                return chunk
        return None

    def __call__(self, data):
        ds = StringIO.StringIO(data)

        # fill in all the chunks
        while True:
            # read the chunk header
            header = ds.read(struct.calcsize(HEADER_FMT))

            # end of data
            if header == '':
                break

            # unpack the chunk header
            try:
                addr, size = struct.unpack(HEADER_FMT, header)
            except struct.error:
                raise ValueError('not enough data for header')

            # read the chunk data
            chunk_data = ds.read(size)
            if size != len(chunk_data):
                raise ValueError('not enough data')

            # if not found, its garbage
            chunk = self.find_chunk(addr, size)
            if not chunk:
                continue

            # do not overwrite the same chunk
            if chunk.blob_data:
                raise ValueError('duplicate chunks')

            # save the chunk data
            chunk.blob_data = chunk_data

        # make sure we have the required chunks
        for chunk in self.chunks:
            if not chunk.blob_data:
                raise ValueError('missing chunk')

        # return the chunks
        return self.chunks

    def __getitem__(self, item):
        addr = item
        size = None
        if isinstance(item, slice):
            addr = item.start
            size = item.stop - item.start

        for chunk in self.chunks:
            if chunk.offset != addr:
                continue

            if size and chunk.blob_size != size:
                continue

            return chunk.blob_data

        raise IndexError('chunk not found')