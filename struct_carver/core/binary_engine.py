class BinaryOffsetEngine:
    """
    Engine for binary formats (ZIP, PDF) that rely on
    embedded chunk sizes, offsets, and binary signatures
    instead of hierarchical textual tags.
    """
    def __init__(self):
        self.is_corrupted = False
        self.is_complete = False
        self.bytes_remaining = 0

    def process_binary(self, is_corrupted: bool, is_complete: bool, bytes_remaining: int = 0) -> bool:
        self.is_corrupted = is_corrupted
        self.is_complete = is_complete
        self.bytes_remaining = bytes_remaining
        return not self.is_corrupted

    def is_empty(self) -> bool:
        # for the binary engine, "empty stack" conceptually translates to "file is complete"
        return self.is_complete

    def clone(self) -> 'BinaryOffsetEngine':
        new_engine = BinaryOffsetEngine()
        new_engine.is_corrupted = self.is_corrupted
        new_engine.is_complete = self.is_complete
        new_engine.bytes_remaining = self.bytes_remaining
        return new_engine

    def reset(self):
        self.is_corrupted = False
        self.is_complete = False
        self.bytes_remaining = 0
