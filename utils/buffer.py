"""
Buffer utilities for Python Logging Agent

This module provides thread-safe buffering capabilities for log data
with configurable size limits and overflow handling.
"""

import threading
import time
from collections import deque
from typing import Any, List, Optional, Callable
import logging


class LogBuffer:
    """Thread-safe buffer for storing log entries with size limits."""
    
    def __init__(
        self,
        max_size: int = 1000,
        overflow_handler: Optional[Callable[[List[Any]], None]] = None
    ):
        """
        Initialize the log buffer.
        
        Args:
            max_size: Maximum number of items to store in buffer
            overflow_handler: Function to call when buffer overflows
        """
        self.max_size = max_size
        self.overflow_handler = overflow_handler
        self._buffer = deque(maxlen=max_size)
        self._lock = threading.RLock()
        self._overflow_count = 0
        self.logger = logging.getLogger(__name__)
        
    def add(self, item: Any) -> bool:
        """
        Add an item to the buffer.
        
        Args:
            item: Item to add to the buffer
            
        Returns:
            True if item was added successfully, False if buffer is full
        """
        with self._lock:
            if len(self._buffer) >= self.max_size:
                # Handle overflow
                if self.overflow_handler:
                    try:
                        # Get items to overflow
                        overflow_items = list(self._buffer)[:self.max_size // 2]
                        self.overflow_handler(overflow_items)
                        
                        # Remove overflowed items
                        for _ in range(len(overflow_items)):
                            self._buffer.popleft()
                            
                    except Exception as e:
                        self.logger.error(f"Error in overflow handler: {e}")
                        return False
                else:
                    # No overflow handler, drop oldest item
                    self._buffer.popleft()
                    self._overflow_count += 1
                    
                    if self._overflow_count % 100 == 0:
                        self.logger.warning(
                            f"Buffer overflow: {self._overflow_count} items dropped"
                        )
            
            self._buffer.append(item)
            return True
            
    def get_all(self, clear: bool = True) -> List[Any]:
        """
        Get all items from the buffer.
        
        Args:
            clear: Whether to clear the buffer after getting items
            
        Returns:
            List of all items in the buffer
        """
        with self._lock:
            items = list(self._buffer)
            if clear:
                self._buffer.clear()
            return items
            
    def get_batch(self, batch_size: int, clear: bool = True) -> List[Any]:
        """
        Get a batch of items from the buffer.
        
        Args:
            batch_size: Maximum number of items to return
            clear: Whether to remove returned items from buffer
            
        Returns:
            List of items (up to batch_size)
        """
        with self._lock:
            actual_size = min(batch_size, len(self._buffer))
            items = []
            
            for _ in range(actual_size):
                if self._buffer:
                    if clear:
                        items.append(self._buffer.popleft())
                    else:
                        items.append(self._buffer[0])
                        
            return items
            
    def size(self) -> int:
        """
        Get the current size of the buffer.
        
        Returns:
            Number of items in the buffer
        """
        with self._lock:
            return len(self._buffer)
            
    def is_empty(self) -> bool:
        """
        Check if the buffer is empty.
        
        Returns:
            True if buffer is empty, False otherwise
        """
        with self._lock:
            return len(self._buffer) == 0
            
    def is_full(self) -> bool:
        """
        Check if the buffer is full.
        
        Returns:
            True if buffer is full, False otherwise
        """
        with self._lock:
            return len(self._buffer) >= self.max_size
            
    def clear(self) -> int:
        """
        Clear all items from the buffer.
        
        Returns:
            Number of items that were cleared
        """
        with self._lock:
            count = len(self._buffer)
            self._buffer.clear()
            return count
            
    def get_overflow_count(self) -> int:
        """
        Get the number of items that have been dropped due to overflow.
        
        Returns:
            Number of overflowed items
        """
        return self._overflow_count
        
    def reset_overflow_count(self) -> None:
        """Reset the overflow counter."""
        self._overflow_count = 0


class TimedBuffer(LogBuffer):
    """Buffer that automatically flushes items after a specified time."""
    
    def __init__(
        self,
        max_size: int = 1000,
        flush_interval: float = 30.0,
        flush_handler: Optional[Callable[[List[Any]], None]] = None,
        overflow_handler: Optional[Callable[[List[Any]], None]] = None
    ):
        """
        Initialize the timed buffer.
        
        Args:
            max_size: Maximum number of items to store in buffer
            flush_interval: Time in seconds between automatic flushes
            flush_handler: Function to call when buffer is flushed
            overflow_handler: Function to call when buffer overflows
        """
        super().__init__(max_size, overflow_handler)
        self.flush_interval = flush_interval
        self.flush_handler = flush_handler
        self._last_flush = time.time()
        self._flush_timer = None
        self._stop_timer = False
        
        if flush_handler:
            self._start_flush_timer()
            
    def _start_flush_timer(self) -> None:
        """Start the automatic flush timer."""
        def flush_timer():
            while not self._stop_timer:
                time.sleep(1)  # Check every second
                
                if time.time() - self._last_flush >= self.flush_interval:
                    self._auto_flush()
                    
        self._flush_timer = threading.Thread(target=flush_timer, daemon=True)
        self._flush_timer.start()
        
    def _auto_flush(self) -> None:
        """Automatically flush the buffer."""
        if self.flush_handler and not self.is_empty():
            try:
                items = self.get_all(clear=True)
                if items:
                    self.flush_handler(items)
                    self._last_flush = time.time()
            except Exception as e:
                self.logger.error(f"Error in auto flush: {e}")
                
    def manual_flush(self) -> None:
        """Manually flush the buffer."""
        self._auto_flush()
        
    def stop(self) -> None:
        """Stop the automatic flush timer."""
        self._stop_timer = True
        if self._flush_timer and self._flush_timer.is_alive():
            self._flush_timer.join(timeout=5)


class PriorityBuffer:
    """Buffer that maintains items in priority order."""
    
    def __init__(
        self,
        max_size: int = 1000,
        priority_key: Optional[Callable[[Any], int]] = None
    ):
        """
        Initialize the priority buffer.
        
        Args:
            max_size: Maximum number of items to store in buffer
            priority_key: Function to extract priority from items (higher = more important)
        """
        self.max_size = max_size
        self.priority_key = priority_key or (lambda x: 0)
        self._items = []
        self._lock = threading.RLock()
        self.logger = logging.getLogger(__name__)
        
    def add(self, item: Any) -> bool:
        """
        Add an item to the priority buffer.
        
        Args:
            item: Item to add to the buffer
            
        Returns:
            True if item was added successfully
        """
        with self._lock:
            priority = self.priority_key(item)
            
            # Insert item in priority order (highest priority first)
            inserted = False
            for i, (existing_priority, _) in enumerate(self._items):
                if priority > existing_priority:
                    self._items.insert(i, (priority, item))
                    inserted = True
                    break
                    
            if not inserted:
                self._items.append((priority, item))
                
            # Remove lowest priority items if over capacity
            while len(self._items) > self.max_size:
                self._items.pop()  # Remove last (lowest priority) item
                
            return True
            
    def get_all(self, clear: bool = True) -> List[Any]:
        """
        Get all items from the buffer in priority order.
        
        Args:
            clear: Whether to clear the buffer after getting items
            
        Returns:
            List of items in priority order (highest first)
        """
        with self._lock:
            items = [item for _, item in self._items]
            if clear:
                self._items.clear()
            return items
            
    def get_highest_priority(self, count: int = 1, clear: bool = True) -> List[Any]:
        """
        Get the highest priority items from the buffer.
        
        Args:
            count: Number of items to return
            clear: Whether to remove returned items from buffer
            
        Returns:
            List of highest priority items
        """
        with self._lock:
            actual_count = min(count, len(self._items))
            items = []
            
            for _ in range(actual_count):
                if self._items:
                    if clear:
                        _, item = self._items.pop(0)
                    else:
                        _, item = self._items[0]
                    items.append(item)
                    
            return items
            
    def size(self) -> int:
        """Get the current size of the buffer."""
        with self._lock:
            return len(self._items)
            
    def is_empty(self) -> bool:
        """Check if the buffer is empty."""
        with self._lock:
            return len(self._items) == 0
            
    def clear(self) -> int:
        """Clear all items from the buffer."""
        with self._lock:
            count = len(self._items)
            self._items.clear()
            return count
